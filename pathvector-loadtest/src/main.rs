//! `loadtest` — multi-peer full-table load harness for `pathvectord`.
//!
//! Spawns a real `pathvectord`, connects N "loader" peers that each announce a
//! full table from an MRT dump, plus one quiet "control" peer with a short
//! hold timer, then drives the PR-1 scenarios while measuring from outside
//! (control-peer keepalive spacing, gRPC latency) and from inside (the
//! daemon's own lock-hold / channel-blocked / keepalive-lateness histograms).
//!
//! See `pathvector-loadtest/README.md`.

use std::{
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
    time::{Duration, Instant},
};

use clap::Parser;
use pathvector_loadtest::{
    config::{Topology, preflight},
    daemon::{Daemon, Monitor, wait_ready},
    peer::PeerHandle,
    report::{Verdict, WindowReport, render},
    scenarios::{self, Ctx},
};
use pathvector_mrt::{read_mrt, speaker::build_update_messages};

#[derive(Parser, Debug)]
#[command(
    name = "loadtest",
    about = "Multi-peer full-table load harness for pathvectord (PR-1)"
)]
struct Args {
    /// MRT `TABLE_DUMP_V2` file (.mrt or .gz) used as every loader's table
    #[arg(long)]
    mrt: PathBuf,

    /// Path to the pathvectord binary (build with `cargo build --release -p pathvectord`)
    #[arg(long, default_value = "target/release/pathvectord")]
    daemon_bin: PathBuf,

    /// Number of full-table loader peers
    #[arg(long, default_value_t = 2)]
    loaders: u8,

    /// Use only the first N prefixes of the dump (quick runs); 0 = all
    #[arg(long, default_value_t = 0)]
    limit: usize,

    /// Hold time the control peer negotiates (daemon KEEPALIVEs every hold/3)
    #[arg(long, default_value_t = 9)]
    control_hold: u16,

    /// First three octets of the loopback range used for peer source addresses
    /// (loaders take .2, .3, …; the control peer the next one)
    #[arg(long, default_value = "127.0.0")]
    source_prefix: String,

    /// Explicit comma-separated source addresses instead of --source-prefix:
    /// every address but the last is a loader, the last is the control peer
    #[arg(long, value_delimiter = ',')]
    source_addrs: Vec<std::net::Ipv4Addr>,

    /// Comma-separated scenarios, in order: idle,converge,cow,teardown,reconverge,export
    #[arg(long, default_value = "idle,converge,cow,teardown,reconverge,export")]
    scenarios: String,

    /// Prefixes withdrawn/re-announced per churn cycle in the COW scenario
    #[arg(long, default_value_t = 2000)]
    churn_prefixes: usize,

    /// Seconds each COW churn phase runs
    #[arg(long, default_value_t = 12)]
    churn_secs: u64,

    /// Interval between gRPC `list_peers` latency probes in ms; 0 disables the
    /// probe (it is itself a management client that loads a big RIB)
    #[arg(long, default_value_t = 100)]
    probe_interval_ms: u64,

    /// Seconds to wait for the daemon to settle after each step
    #[arg(long, default_value_t = 300)]
    timeout_secs: u64,

    /// `RUST_LOG` filter for the daemon (WARN/ERROR lines are summarised at the end)
    #[arg(long, default_value = "warn")]
    daemon_log: String,

    /// Directory for the generated config and daemon log
    #[arg(long, default_value = "target/loadtest")]
    work_dir: PathBuf,
}

fn parse_prefix(s: &str) -> Result<[u8; 3], String> {
    let parts: Vec<u8> = s
        .split('.')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| format!("invalid --source-prefix {s:?}"))?;
    <[u8; 3]>::try_from(parts)
        .map_err(|_| format!("--source-prefix must be three octets, got {s:?}"))
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(failed) if failed => ExitCode::from(1),
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

/// Returns `Ok(true)` if any window's verdict was a failure.
#[allow(clippy::too_many_lines)]
async fn run(args: Args) -> Result<bool, String> {
    let topo = if args.source_addrs.is_empty() {
        Topology::new(
            parse_prefix(&args.source_prefix)?,
            args.loaders,
            args.control_hold,
        )
    } else if args.source_addrs.len() < 2 {
        return Err("--source-addrs needs at least two addresses (loader(s) + control)".into());
    } else {
        Topology::from_addrs(&args.source_addrs, args.control_hold)
    };
    preflight(&topo.all_addrs())?;
    if !args.daemon_bin.exists() {
        return Err(format!(
            "{} not found — build it with `cargo build --release -p pathvectord`",
            args.daemon_bin.display()
        ));
    }

    println!("Parsing {} …", args.mrt.display());
    let t = Instant::now();
    let mut entries = read_mrt(&args.mrt).map_err(|e| e.to_string())?;
    if args.limit > 0 {
        entries.truncate(args.limit);
    }
    let expected = scenarios::unique_prefixes(&entries);
    println!(
        "  {} entries ({expected} unique prefixes) in {:.1?}",
        entries.len(),
        t.elapsed()
    );
    let batch = build_update_messages(&entries);
    println!(
        "  encoded into {} UPDATE messages ({} attribute sets)",
        batch.messages.len(),
        batch.unique_attr_sets
    );

    let mut daemon = Daemon::spawn(&args.daemon_bin, &topo, &args.work_dir, &args.daemon_log)
        .map_err(|e| e.to_string())?;
    wait_ready(&topo, Duration::from_secs(30)).await?;
    println!(
        "pathvectord ready (pid {}, log {})",
        daemon.pid,
        daemon.log_path.display()
    );
    let monitor = Monitor::start(
        &topo,
        daemon.pid,
        (args.probe_interval_ms > 0).then(|| Duration::from_millis(args.probe_interval_ms)),
    );

    let bgp = std::net::SocketAddr::from(([127, 0, 0, 1], topo.bgp_port));
    let control = PeerHandle::connect(
        "control",
        topo.control.addr,
        bgp,
        topo.control.remote_as,
        topo.control_hold,
        true,
    )
    .await
    .map_err(|e| format!("control peer connect failed: {e}"))?;

    let loaders = topo.loaders.iter().map(|_| None).collect();
    let mut ctx = Ctx {
        topo,
        monitor,
        control,
        loaders,
        table_msgs: Arc::new(batch.messages),
        expected_prefixes: expected,
        accepted: None,
        entries: Arc::new(entries),
        timeout: Duration::from_secs(args.timeout_secs),
        churn_prefixes: args.churn_prefixes,
        churn_secs: args.churn_secs,
    };

    let mut reports: Vec<WindowReport> = Vec::new();
    let mut error: Option<String> = None;
    for name in args
        .scenarios
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        println!("\n▶ {name}");
        let result = match name {
            "idle" => scenarios::idle(&ctx, 2 * u64::from(args.control_hold))
                .await
                .map(|r| vec![r]),
            "converge" => scenarios::converge(&mut ctx).await.map(|r| vec![r]),
            "cow" => scenarios::cow_snapshot(&ctx).await,
            "teardown" => scenarios::teardown(&mut ctx).await.map(|r| vec![r]),
            "reconverge" => scenarios::reconverge(&mut ctx).await.map(|r| vec![r]),
            "export" => scenarios::export_reeval(&ctx).await,
            other => Err(format!("unknown scenario {other:?}")),
        };
        match result {
            Ok(rs) => {
                for r in rs {
                    print!("{}", render(&r));
                    reports.push(r);
                }
            }
            Err(e) => {
                eprintln!("scenario {name} failed: {e}");
                error = Some(format!("scenario {name}: {e}"));
                break;
            }
        }
        if !daemon.is_running() {
            error = Some("pathvectord exited during the run".to_string());
            break;
        }
    }

    println!("\n══ summary ══════════════════════════════════════════════════════");
    let mut failed = error.is_some();
    for r in &reports {
        let v = r.control.verdict();
        let tag = match &v {
            Verdict::Ok => "ok    ",
            Verdict::Late(_) => "LATE  ",
            Verdict::Failed(_) => "FAILED",
        };
        failed |= matches!(v, Verdict::Failed(_));
        println!(
            "  {tag} {}  (control silence {:.2?}, gRPC max {:.2?})",
            r.title, r.control.gaps.max_gap, r.mgmt.max
        );
    }
    let log = daemon.log_summary();
    println!(
        "  pathvectord log: {} WARN, {} ERROR",
        log.warnings, log.errors
    );
    for s in &log.samples {
        println!("    {s}");
    }
    if let Some(e) = &error {
        println!("  run aborted: {e}");
    }
    daemon.shutdown().await;
    Ok(failed)
}

#[cfg(test)]
mod tests {
    use super::parse_prefix;

    #[test]
    fn source_prefix_parsing() {
        assert_eq!(parse_prefix("127.0.0"), Ok([127, 0, 0]));
        assert!(parse_prefix("127.0").is_err());
        assert!(parse_prefix("127.0.0.1").is_err());
        assert!(parse_prefix("a.b.c").is_err());
    }
}
