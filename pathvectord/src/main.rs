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

    let mut cfg: config::Config = toml::from_str(&text).unwrap_or_else(|e| {
        eprintln!("failed to parse config: {e}");
        std::process::exit(1);
    });

    // Derive the sidecar path from the config file's directory.  Peers added
    // via `add_peer` are persisted there and re-loaded on every startup.
    let sidecar_path = std::path::PathBuf::from(&path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("dynamic_peers.toml");
    let store = config::DynamicPeerStore::new(sidecar_path.clone());
    let dynamic_peers = store.load();
    if !dynamic_peers.is_empty() {
        tracing::info!(
            count = dynamic_peers.len(),
            "loaded dynamic peers from sidecar"
        );
        for peer in dynamic_peers {
            if !cfg.peers.iter().any(|p| p.address == peer.address) {
                cfg.peers.push(peer);
            }
        }
    }
    cfg.sidecar_path = Some(sidecar_path);

    daemon::run(cfg).await;
}
