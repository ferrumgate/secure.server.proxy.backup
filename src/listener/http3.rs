use crate::config::ServerConfig;
use crate::listener::Listener;
use anyhow::Result;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Level};
pub struct Http3Listener {
    config: ServerConfig,
    cancel_token: CancellationToken,
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
        Ok(())
    }
}
