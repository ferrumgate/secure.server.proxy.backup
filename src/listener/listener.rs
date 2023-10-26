use anyhow::Result;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio_util::sync::CancellationToken;

use async_trait::async_trait;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::config::ServerConfig;

/// a listener trait for http/2 and http3/listener
#[async_trait]
pub trait Listener {
    fn new(config: ServerConfig, cancel_token: CancellationToken) -> Self;
    async fn listen(&mut self, port: u16) -> Result<()>;
}
