use anyhow::{anyhow, Result};
use clap::Parser;
use fproxy::{
    config::ServerConfig,
    listener::{http2::Http2Listener, http3::Http3Listener, Listener},
    util::get_log_level,
};
use std::path::PathBuf;
use tokio::{select, signal, task};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Level};

#[derive(Parser, Debug, Clone)]
#[clap(name = "server")]
pub struct Options {
    /// TLS private key in PEM format
    #[clap(long = "key", requires = "cert")]
    pub key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[clap(long = "cert", requires = "key")]
    pub cert: Option<PathBuf>,
    /// Address to listen on
    #[clap(long = "listen", default_value = "[::]:8443")]
    pub listen: Option<String>,

    #[clap(long = "log-level", default_value = "info")]
    pub log_level: String,
    #[clap(long = "port", default_value = "8443")]
    pub port: u16,

    #[clap(long = "timeout", default_value = "3000")]
    pub timeout: u64,
}

fn parse_config(opt: Options) -> Result<ServerConfig> {
    let mut ip;
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
    })
}

fn main() {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    println!("version: {}", VERSION);

    let copt = Options::parse();
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(get_log_level(&copt.log_level))
            .finish(),
    )
    .unwrap();

    let opt = parse_config(copt);
    if let Err(e) = opt {
        error!("ERROR: parse failed: {}", e);
        ::std::process::exit(1);
    }
    let options = opt.unwrap();
    let _rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    _rt.block_on(async move {
        let code = {
            if let Err(e) = run(options).await {
                error!("ERROR: {e}");
                1
            } else {
                0
            }
        };
        ::std::process::exit(code);
    });
}

async fn run<'a>(config: ServerConfig) -> Result<()> {
    let token = CancellationToken::new();
    let config = config.clone();
    let token = token.clone();
    let http2_task = tokio::spawn(async move {
        let http_listener = Http2Listener::new(config, token);
    });

    let config = config.clone();
    let token = token.clone();
    let http3_task = tokio::spawn(async move {
        let http_listener = Http3Listener::new(config, token);
    });

    let res = select! {
        http3= http3_task=>http3,
        http2= http2_task=>http2,
        signal=signal::ctrl_c()=>{
            match signal {
            Ok(()) => {
                info!("canceling");
                token.cancel();

            },
            Err(err) => {
                error!("Unable to listen for shutdown signal: {}", err);
                // we also shut down in case of error
            }
            }
            Ok(())

        }
    };
    res.map_err(|err| anyhow!(err))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse_config() {
        let opt = Options {
            cert: None,
            key: Some(PathBuf::from("/tmp/abc.file")),
            listen: None,
            port: 513,
            log_level: "info".to_string(),
            timeout: 5000,
        };
        let result = parse_config(opt);
        assert_eq!(result.is_ok(), true);
        let config = result.unwrap();
        assert_eq!(config.cert_file, None);
        assert_eq!(config.key_file, Some(PathBuf::from("/tmp/abc.file")));
        assert_eq!(config.listen, "[::]:513".parse().unwrap());
        assert_eq!(config.log_level, "info");
        assert_eq!(config.idle_timeout, 5000);
    }
}
