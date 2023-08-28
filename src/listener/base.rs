use anyhow::Result;
use std::convert::Infallible;
use std::net::SocketAddr;

use async_trait::async_trait;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::server_config::ServerConfig;

/// a listener trait for http/2 and http3/listener
#[async_trait]
pub trait Listener {
    fn new(config: ServerConfig) -> Self;
    fn listen(port: u16) -> Result<()>;
}
