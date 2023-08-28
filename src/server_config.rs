use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone)]
/// server configuration
pub struct ServerConfig {
    /// socket listen address
    pub listen: SocketAddr,

    /// log level info debug warn fatal
    pub log_level: String,
    /// tls key file as pem
    pub key_file: Option<PathBuf>,
    /// tls cert file as der
    pub cert_file: Option<PathBuf>,
    /// wait for client
    pub idle_timeout: u64,
}
