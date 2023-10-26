use crate::config::ServerConfig;
use async_trait::async_trait;

use std::borrow::BorrowMut;
use std::fs;
use std::net::SocketAddr;
use std::rc::Rc;
use std::str;
use std::sync::Arc;
use tokio::io::{copy, sink, split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use tokio_rustls::server::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Level};

use crate::listener::listener::Listener;
use anyhow::{anyhow, Context, Result};
use rustls::{Certificate, PrivateKey};

use crate::service::tunnel::tunnel_proxy;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::client::conn::http1::Builder;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
pub const ALPN_QUIC_HTTP2: &[&[u8]] = &[b"h2"];
#[allow(unused)]
pub const ALPN_QUIC_HTTP1: &[&[u8]] = &[b"http/1.1"];

pub struct Http2Listener {
    config: ServerConfig,
    cancel_token: CancellationToken,
}

impl Http2Listener {
    fn create_certs_chain(&self, options: &ServerConfig) -> Result<ServerCertChain> {
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

        Ok(ServerCertChain { certs, key })
    }
}

#[async_trait]
impl Listener for Http2Listener {
    fn new(config: ServerConfig, cancel_token: CancellationToken) -> Self {
        Http2Listener {
            config,
            cancel_token,
        }
    }

    async fn listen(&mut self, port: u16) -> Result<()> {
        let certs = self.create_certs_chain(&self.config)?;
        let mut config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs.certs, certs.key)?;
        config.alpn_protocols = ALPN_QUIC_HTTP1.iter().map(|&x| x.into()).collect();

        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind(&self.config.listen).await?;
        loop {
            let (stream, peer_addr) = listener.accept().await?;
            debug!("client connected from  {}", peer_addr);
            let acceptor = acceptor.clone();
            let token = self.cancel_token.clone();
            let _task = tokio::spawn(async move {
                let mut client = Http2Client::new(peer_addr, token, true);
                let res = client.handle(acceptor, stream).await;
                if res.is_err() {
                    error!("client handle failed\n");
                    return;
                }
            });
        }
        Ok(())
    }
}

struct ServerCertChain {
    certs: Vec<Certificate>,
    key: PrivateKey,
}

#[derive()]
struct Http2Client {
    peer_addr: SocketAddr,
    is_echo: bool,
    reader: Option<ReadHalf<TlsStream<TcpStream>>>,
    writer: Option<WriteHalf<TlsStream<TcpStream>>>,
    cancel_token: CancellationToken,
    stream: Option<TokioIo<TlsStream<TcpStream>>>,
}

impl Http2Client {
    fn new(peer_addr: SocketAddr, cancel_token: CancellationToken, is_echo: bool) -> Self {
        Http2Client {
            peer_addr,
            reader: None,
            writer: None,
            is_echo,
            cancel_token,
            stream: None,
        }
    }
    async fn handle(&mut self, acceptor: TlsAcceptor, stream: TcpStream) -> Result<()> {
        let mut accepted_stream = acceptor.accept(stream).await.map_err(|err| {
            error!("client accept failed {}", err);
            err
        })?;

        //let (mut reader, mut writer) = split(accepted_stream);
        //self.reader = Some(reader);
        //self.writer = Some(writer);
        //self.stream = Some(TokioIo::new(accepted_stream));

        let io = TokioIo::new(accepted_stream);
        if let Err(err) = http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(io, service_fn(tunnel_proxy))
            .with_upgrades()
            .await
        {
            println!("Failed to serve connection: {:?}", err);
        }
        Ok(())
    }

    async fn handle2(&mut self) {
        let mut buf = vec![0u8; 2048];
        let result = self.reader.as_mut().unwrap().read(buf.as_mut()).await;
        if result.is_err() {
            error!("read failed {}", result.unwrap_err());
            return;
        }
        let length = result.unwrap();
        let data = &buf[0..length];
        debug!("readed data len: {}", length);
        let input = String::from_utf8_lossy(data);

        info!("output is {}", input);
    }
}
