use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::Parser;
use tracing::Level;

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
    /// connect timeout
    pub connect_timeout: u64,
}

impl ServerConfig {
    pub fn parse() -> Result<Self> {
        let opt = ServerOptions::parse();
        ServerConfig::parse_from(opt)
    }
    pub fn parse_from(opt: ServerOptions) -> Result<Self> {
        let ip;
        ip = match opt.listen {
            None => {
                format!("[::]:{}", opt.port)
            }
            Some(a) => a,
        };
        Ok(ServerConfig {
            listen: ip.parse().unwrap(),
            log_level: opt.log_level,
            key_file: opt.key,
            cert_file: opt.cert,
            idle_timeout: opt.timeout,
            connect_timeout: opt.connect_timeout,
        })
    }
}

#[derive(Parser, Debug, Clone)]
#[clap(name = "server")]
pub struct ServerOptions {
    /// TLS private key in PEM format
    #[clap(long = "key", requires = "cert", env = "KEY")]
    pub key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[clap(long = "cert", requires = "key", env = "CERT")]
    pub cert: Option<PathBuf>,
    /// Address to listen on
    #[clap(long = "listen", default_value = "[::]:8443", env = "LISTEN")]
    pub listen: Option<String>,

    #[clap(long = "log-level", default_value = "info", env = "LOG_LEVEL")]
    pub log_level: String,
    #[clap(long = "port", default_value = "8443", env = "PORT")]
    pub port: u16,

    #[clap(long = "timeout", default_value = "3000", env = "TIMEOUT")]
    pub timeout: u64,
    #[clap(
        long = "connect-timeout",
        default_value = "3000",
        env = "CONNECT_TIMEOUT"
    )]
    pub connect_timeout: u64,
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse_config() {
        let opt = ServerOptions {
            cert: None,
            key: Some(PathBuf::from("/tmp/abc.file")),
            listen: None,
            port: 513,
            log_level: "info".to_string(),
            timeout: 5000,
            connect_timeout: 10000,
        };
        let result = ServerConfig::parse_from(opt);
        assert_eq!(result.is_ok(), true);
        let config = result.unwrap();
        assert_eq!(config.cert_file, None);
        assert_eq!(config.key_file, Some(PathBuf::from("/tmp/abc.file")));
        assert_eq!(config.listen, "[::]:513".parse().unwrap());
        assert_eq!(config.log_level, "info");
        assert_eq!(config.idle_timeout, 5000);
        assert_eq!(config.connect_timeout, 10000);
    }
}
