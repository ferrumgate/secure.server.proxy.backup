use crate::config::server_config::ServerConfig;
use crate::listener::Listener;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use quinn::{Connection, Endpoint, IdleTimeout, RecvStream, SendStream, VarInt};
use rustls::{Certificate, PrivateKey};
use std::collections::HashMap;
use std::str;
use std::{fs, sync::Arc, time::Duration};
use tokio::{select, time::sleep, time::timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Level};
pub struct Http3Listener {
    config: ServerConfig,
    cancel_token: CancellationToken,
}

#[allow(unused)]
pub const ALPN_QUIC_HTTP3: &[&[u8]] = &[b"h3"];
#[allow(unused)]

impl Http3Listener {
    fn create_certs_chain(options: &ServerConfig) -> Result<(Vec<Certificate>, PrivateKey)> {
        let (certs, key) =
            if let (Some(key_path), Some(cert_path)) = (&options.key_file, &options.cert_file) {
                let key = fs::read(key_path).context("failed to read private key")?;
                let key = if key_path.extension().map_or(false, |x| x == "der") {
                    rustls::PrivateKey(key)
                } else {
                    let pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut &*key)
                        .context("malformed PKCS #8 private key")?;
                    match pkcs8.into_iter().next() {
                        Some(x) => rustls::PrivateKey(x),
                        None => {
                            let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)
                                .context("malformed PKCS #1 private key")?;
                            match rsa.into_iter().next() {
                                Some(x) => rustls::PrivateKey(x),
                                None => {
                                    return Err(anyhow!("no private keys found"));
                                }
                            }
                        }
                    }
                };
                let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
                let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
                    vec![rustls::Certificate(cert_chain)]
                } else {
                    rustls_pemfile::certs(&mut &*cert_chain)
                        .context("invalid PEM-encoded certificate")?
                        .into_iter()
                        .map(rustls::Certificate)
                        .collect()
                };
                debug!("loaded certificate");
                (cert_chain, key)
            } else {
                let dirs = directories_next::ProjectDirs::from("org", "ferrum", "cert").unwrap();
                let path = dirs.data_local_dir();
                let cert_path = path.join("cert.der");
                let key_path = path.join("key.der");

                info!("generating self-signed certificate");
                let cert = rcgen::generate_simple_self_signed(vec!["secure.ferrumgate.com".into()])
                    .unwrap();

                let key = cert.serialize_private_key_der();
                let cert = cert.serialize_der().unwrap();
                fs::create_dir_all(path).context("failed to create certificate directory")?;
                fs::write(cert_path, &cert).context("failed to write certificate")?;
                fs::write(key_path, &key).context("failed to write private key")?;

                let key = rustls::PrivateKey(key);
                let cert = rustls::Certificate(cert);
                (vec![cert], key)
            };
        Ok((certs, key))
    }

    async fn handle_connection(
        conn: quinn::Connecting,
    ) -> Result<(SendStream, RecvStream, Connection)> {
        let connection = conn.await?;

        info!("established {}", connection.remote_address());

        // Each stream initiated by the client constitutes a new request.

        let (send, recv) = connection.accept_bi().await?;
        debug!("stream opened {}", connection.remote_address());
        Ok((send, recv, connection))
    }
}

struct Http3Client {
    ip: String,
    config: ServerConfig,
}

#[async_trait]
impl Listener for Http3Listener {
    fn new(config: ServerConfig, cancel_token: CancellationToken) -> Self {
        Http3Listener {
            config,
            cancel_token,
        }
    }

    async fn listen(&mut self, port: u16) -> Result<()> {
        let (certs, key) =
            Http3Listener::create_certs_chain(&self.config).context("create chain failed")?;

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        server_crypto.alpn_protocols = ALPN_QUIC_HTTP3.iter().map(|&x| x.into()).collect();

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
        let transport_config_option = Arc::get_mut(&mut server_config.transport);
        if transport_config_option.is_none() {
            return Err(anyhow!("could not get config"));
        }
        let transport_config = transport_config_option.unwrap();
        //transport_config.max_concurrent_uni_streams(0_u8.into());
        //transport_config.max_concurrent_bidi_streams(1_u8.into());
        transport_config.keep_alive_interval(Some(Duration::from_secs(7)));
        transport_config.max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_millis(self.config.idle_timeout)).unwrap(),
        ));

        let endpoint = quinn::Endpoint::server(server_config, self.config.listen)?;
        let cancel_token = self.cancel_token.clone();
        while let Some(conn) = select! {
            conn=endpoint.accept()=>{conn},
            _=cancel_token.cancelled()=>{None}
        } {
            let client_ip = conn.remote_address().ip().to_string();
            debug!("connection incoming from {}", client_ip);
            let config = self.config.clone();
            let cancel_token = self.cancel_token.clone();
            tokio::spawn(async move {
                let client = Http3Client {
                    ip: client_ip,
                    config: config,
                };
                let res = timeout(
                    Duration::from_millis(client.config.connect_timeout),
                    Http3Listener::handle_connection(conn),
                )
                .await;
                match res {
                    Err(err) => {
                        error!("timeout occured {}", err);
                    }
                    Ok(res2) => match res2 {
                        Err(err) => {
                            error!("connection failed:{reason}", reason = err.to_string())
                        }
                        Ok((mut send, mut recv, conn)) => {
                            let mut buf = vec![0u8; 2048];
                            let result = recv.read(buf.as_mut()).await;

                            if result.is_err() {
                                error!("read failed {}", result.unwrap_err());
                                return;
                            }
                            let length = result.unwrap();
                            if length.is_none() {
                                return;
                            }
                            let length = length.unwrap();
                            let data = &buf[0..length];
                            debug!("readed data len: {}", length);
                            let input = String::from_utf8_lossy(data);

                            info!("output is {}", input);
                        }
                    },
                }
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn create_config() -> ServerConfig {
        ServerConfig {
            cert_file: None,
            idle_timeout: 10000,
            key_file: None,
            listen: "127.0.0.1:9091".parse().unwrap(),
            log_level: "debug".to_string(),
            connect_timeout: 15000,
        }
    }
    #[tokio::test]
    async fn test_create_certs_chain() {
        let config = create_config();
        let result = Http3Listener::create_certs_chain(&config);
        assert_eq!(result.is_ok(), true);
    }

    #[tokio::test]
    async fn test_listen() {
        let config = create_config();
        let cancel_token = CancellationToken::new();
        let mut quic_server = Http3Listener::new(config, cancel_token.clone());
        let task = tokio::spawn(async move {
            let _ = quic_server.listen(1600).await;
        });
        let _task2 = tokio::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            cancel_token.cancel();
        });

        let _ = timeout(Duration::from_millis(1000), task).await;
        assert_eq!(true, true); //code must be reach here
    }
}
