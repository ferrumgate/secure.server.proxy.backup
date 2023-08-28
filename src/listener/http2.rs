use crate::server_config::ServerConfig;
use async_trait::async_trait;

use crate::listener::base::Listener;
use anyhow::Result;

pub struct Http2Listener {
    config: ServerConfig,
}

#[async_trait]
impl Listener for Http2Listener {
    fn new(config: ServerConfig) -> Self {
        Http2Listener { config: config }
    }

    fn listen(port: u16) -> Result<()> {
        todo!()
    }
}
