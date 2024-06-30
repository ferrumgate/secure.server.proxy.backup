use anyhow::Result;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

use async_trait::async_trait;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use std::fs;
use tracing::{debug,info,error};
use anyhow::{anyhow,Context}
use rustls::PrivateKey;
use crate::config::ServerConfig;

pub const ALPN_QUIC_HTTP2: &[&[u8]] = &[b"h2"];
#[allow(unused)]
pub const ALPN_QUIC_HTTP1: &[&[u8]] = &[b"http/1.1"];

#[allow(unused)]
pub const ALPN_QUIC_HTTP3: &[&[u8]] = &[b"h3"];

/// a listener trait for http/2 and http3/listener
#[async_trait]
pub trait Listener {
    fn new(config: ServerConfig, cancel_token: CancellationToken) -> Self;
    async fn listen(&mut self, port: u16) -> Result<()>;
}

pub struct Cert();
impl Cert {
    pub fn create_certs_chain(key_file:Option<PathBuf>,cert_file:Option<PathBuf>,default_domain:&str) -> Result<(Vec<Certificate>, PrivateKey)> {
        let (certs, key) =
            if let (Some(key_path), Some(cert_path)) = (key_file, cert_file) {
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
                let cert = rcgen::generate_simple_self_signed(vec![default_domain.into()])
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
}


#[cfg(test)]
mod tests {
    use super::*;
    
    fn test_create_certs_chain() {

        let result = Cert::create_certs_chain(None,None,"secure.ferrumgate.com");
        assert_eq!(result.is_ok(), true);
    }


}