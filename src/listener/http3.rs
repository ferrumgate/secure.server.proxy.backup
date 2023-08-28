use crate::server_config::ServerConfig;
use async_trait::async_trait;

use crate::listener::base::Listener;
use anyhow::Result;
pub struct Http3Listener {
    config: ServerConfig,
}

#[async_trait]
impl Listener for Http3Listener {
    fn new(config: ServerConfig) -> Self {
        Http3Listener { config: config }
    }

    fn listen(port: u16) -> Result<()> {
        todo!()
    }
}
