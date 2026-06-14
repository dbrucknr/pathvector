mod config;
mod daemon;
mod fib;
mod grpc;
mod outbound;
mod proto;

pub(crate) use daemon::{DaemonState, LOCAL_ORIGIN_PEER, RibSnapshot};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: pathvectord <config.toml>");
        std::process::exit(1);
    });

    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("failed to read {path}: {e}");
        std::process::exit(1);
    });

    let cfg: config::Config = toml::from_str(&text).unwrap_or_else(|e| {
        eprintln!("failed to parse config: {e}");
        std::process::exit(1);
    });

    daemon::run(cfg).await;
}
