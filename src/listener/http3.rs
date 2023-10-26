use crate::config::server_config::ServerConfig;
use crate::listener::listener::{
    Cert, Listener, ALPN_QUIC_HTTP1, ALPN_QUIC_HTTP2, ALPN_QUIC_HTTP3,
};

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

impl Http3Listener {
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
        let (certs, key) = Cert::create_certs_chain(
            self.config.key_file,
            self.config.cert_file,
            "secure.ferrumgate.com",
        )
        .context("create chain failed")?;

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
