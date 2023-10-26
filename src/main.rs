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

fn main() {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    println!("version: {}", VERSION);

    let opt = ServerConfig::parse();
    if let Err(e) = opt {
        error!("ERROR: config parse failed: {}", e);
        ::std::process::exit(1);
    }
    let opt = opt.unwrap();
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(get_log_level(&opt.log_level))
            .finish(),
    )
    .unwrap();

    let _rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    _rt.block_on(async move {
        let code = {
            if let Err(e) = run(opt).await {
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
    let cloned_token = token.clone();
    let cloned_config = config.clone();

    //let mut quic_listener = Http3Listener::new(cloned_config, cloned_token);
    let mut http_listener = Http2Listener::new(cloned_config, cloned_token);

    let res = select! {
        //http3= quic_listener.listen(1600)=>http3,
        http= http_listener.listen(1600)=>http,
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
}
