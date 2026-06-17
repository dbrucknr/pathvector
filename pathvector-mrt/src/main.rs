//! pathvector-mrt — MRT `TABLE_DUMP_V2` replay against a live pathvectord.
//!
//! ## Usage
//!
//! ```text
//! # 1. Start pathvectord with mrt-pathvectord.toml (peer = 127.0.0.1, AS 65001)
//! pathvectord e2e/fixtures/mrt-pathvectord.toml &
//!
//! # 2. Run the replayer (accepts .mrt or .mrt.gz)
//! pathvector-mrt --mrt /path/to/latest-bview.gz
//! ```
//!
//! Download a RouteViews/RIPE RIS snapshot:
//! ```text
//! curl -O https://data.ris.ripe.net/rrc00/latest-bview.gz
//! ```
//!
//! ## What it measures
//!
//! - BGP announcement throughput (prefixes/second into pathvectord)
//! - RIB convergence time: from first UPDATE sent to when two consecutive
//!   `watch_routes` snapshots report the same route count (stable RIB)
//! - Accepted vs rejected route count

use std::{
    fmt::Write as _,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::{Duration, Instant},
};

use clap::Parser;
use futures::StreamExt as _;
use pathvector_client::{DaemonClient, PathvectorClient, types::RouteEventType};
use tokio::time::sleep;

mod mrt;
mod speaker;

use mrt::RibEntry;
use speaker::BgpSpeaker;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "pathvector-mrt",
    about = "Replay an MRT TABLE_DUMP_V2 file against a running pathvectord"
)]
struct Args {
    /// MRT file to replay (.mrt or .mrt.gz)
    #[arg(long, value_name = "FILE")]
    mrt: PathBuf,

    /// Address and port of the pathvectord BGP listener to connect to
    #[arg(long, default_value = "127.0.0.1:1179")]
    peer: SocketAddr,

    /// Our BGP AS number (must match the peer config in pathvectord)
    #[arg(long, default_value = "65001")]
    my_as: u32,

    /// Our BGP router-id
    #[arg(long, default_value = "10.0.0.1")]
    router_id: Ipv4Addr,

    /// pathvectord gRPC address for the `watch_routes` stream
    #[arg(long, default_value = "http://127.0.0.1:51200")]
    grpc: String,

    /// How long to wait with no new route events before declaring convergence
    #[arg(long, default_value = "1000")]
    idle_ms: u64,

    /// Hard timeout in seconds — abort if convergence never happens
    #[arg(long, default_value = "120")]
    timeout_secs: u64,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Err(e) = run(args).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_lines)]
async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    // ── 1. Parse MRT file ─────────────────────────────────────────────────────
    println!("Parsing MRT dump: {}", args.mrt.display());

    let parse_start = Instant::now();
    let entries = read_mrt(&args.mrt)?;
    let parse_elapsed = parse_start.elapsed();

    println!("  Prefixes:   {}", fmt_count(entries.len() as u64));
    println!("  Parse time: {:.1}s", parse_elapsed.as_secs_f64());
    println!();

    if entries.is_empty() {
        return Err("MRT file contains no IPv4 unicast entries".into());
    }

    // ── 2. Verify gRPC connectivity ───────────────────────────────────────────
    println!("Connecting to gRPC at {}...", args.grpc);
    // Quick connectivity check — open and immediately close.
    PathvectorClient::connect(args.grpc.clone())
        .map_err(|e| format!("gRPC connect failed: {e}"))?;
    println!("  gRPC reachable");
    println!();

    // ── 3. Establish BGP session ──────────────────────────────────────────────
    println!(
        "Connecting to BGP peer {} as AS{} (router-id {})",
        args.peer, args.my_as, args.router_id
    );
    let mut spkr = BgpSpeaker::connect(args.peer, args.my_as, args.router_id).await?;
    println!("  Session established");
    println!();

    // ── 4. Announce all prefixes ──────────────────────────────────────────────
    println!("Announcing {} prefixes...", fmt_count(entries.len() as u64));
    let announce_start = Instant::now();
    let result = spkr.announce(&entries).await?;
    let announce_elapsed = announce_start.elapsed();

    println!(
        "  Done: {} prefixes, {} UPDATE messages, {:.2}s ({}/s)",
        fmt_count(result.prefixes_sent),
        fmt_count(result.updates_sent),
        announce_elapsed.as_secs_f64(),
        fmt_count(prefixes_per_sec(result.prefixes_sent, announce_elapsed)),
    );
    println!();

    // ── 5. Poll snapshots until RIB stabilises ────────────────────────────────
    // We open a fresh watch_routes stream after each poll interval and count
    // the Current events in the snapshot (before EndInitial).  When two
    // consecutive snapshots agree the RIB has converged.
    //
    // This avoids the broadcast-channel lag problem: individual Announced
    // delta events are never observed; only the point-in-time snapshot is
    // used, which has no size limit.
    println!("Waiting for RIB convergence (snapshot polling)...");

    let poll_interval = Duration::from_millis(args.idle_ms);
    let hard_deadline = Instant::now() + Duration::from_secs(args.timeout_secs);

    let mut prev_count: Option<u64> = None;
    let mut rib_count: u64 = 0;
    let convergence_start = Instant::now();

    loop {
        if Instant::now() >= hard_deadline {
            return Err(format!(
                "timed out after {}s — last RIB count: {}",
                args.timeout_secs,
                fmt_count(rib_count),
            )
            .into());
        }

        // Open a fresh stream and count the snapshot.
        let mut client = PathvectorClient::connect(args.grpc.clone())
            .map_err(|e| format!("gRPC reconnect failed: {e}"))?;
        let mut stream = client
            .watch_routes(None)
            .await
            .map_err(|e| format!("watch_routes failed: {e}"))?;

        let mut snap_count: u64 = 0;
        loop {
            match stream.next().await {
                Some(Ok(ev)) if ev.event_type == RouteEventType::Current => snap_count += 1,
                Some(Ok(ev)) if ev.event_type == RouteEventType::EndInitial => break,
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(format!("stream error during snapshot: {e}").into()),
                None => break,
            }
        }

        rib_count = snap_count;
        println!("  snapshot: {} routes", fmt_count(rib_count));

        if prev_count == Some(rib_count) {
            break; // stable
        }
        prev_count = Some(rib_count);
        sleep(poll_interval).await;
    }

    let convergence_elapsed = convergence_start.elapsed();
    let total_elapsed = announce_elapsed + convergence_elapsed;

    // ── 6. Report ─────────────────────────────────────────────────────────────
    println!();
    println!("── Results ──────────────────────────────────────────────────────");
    println!(
        "  Announcement:   {:.2}s  ({} prefixes, {}/s)",
        announce_elapsed.as_secs_f64(),
        fmt_count(result.prefixes_sent),
        fmt_count(prefixes_per_sec(result.prefixes_sent, announce_elapsed)),
    );
    println!(
        "  RIB convergence:{:.2}s  (announcement start to stable snapshot)",
        convergence_elapsed.as_secs_f64(),
    );
    println!("  Total:          {:.2}s", total_elapsed.as_secs_f64());
    println!(
        "  Unique attr sets: {}",
        fmt_count(result.unique_attr_sets as u64)
    );
    println!(
        "  Accepted:  {} / {} sent",
        fmt_count(rib_count),
        fmt_count(result.prefixes_sent),
    );

    if rib_count < result.prefixes_sent {
        let rejected = result.prefixes_sent - rib_count;
        #[allow(clippy::cast_precision_loss)]
        let pct = rejected as f64 / result.prefixes_sent as f64 * 100.0;
        println!("  Rejected:  {} ({:.1}%)", fmt_count(rejected), pct);
    }

    println!("─────────────────────────────────────────────────────────────────");
    println!();

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read and parse an MRT file, handling optional gzip compression.
fn read_mrt(path: &PathBuf) -> Result<Vec<RibEntry>, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(path)?;
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    if ext == "gz" {
        Ok(mrt::parse(flate2::read::GzDecoder::new(file))?)
    } else {
        Ok(mrt::parse(std::io::BufReader::new(file))?)
    }
}

/// Compute prefixes-per-second as a u64.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn prefixes_per_sec(count: u64, elapsed: Duration) -> u64 {
    let secs = elapsed.as_secs_f64();
    if secs == 0.0 {
        0
    } else {
        (count as f64 / secs) as u64
    }
}

/// Format a large number with thousands separators.
fn fmt_count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    let start = s.len() % 3;
    if start > 0 {
        out.push_str(&s[..start]);
    }
    for chunk in s.as_bytes()[start..].chunks(3) {
        if !out.is_empty() {
            out.push(',');
        }
        let _ = write!(out, "{}", std::str::from_utf8(chunk).unwrap_or(""));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_count_examples() {
        assert_eq!(fmt_count(0), "0");
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(1000), "1,000");
        assert_eq!(fmt_count(912_849), "912,849");
        assert_eq!(fmt_count(1_000_000), "1,000,000");
    }
}
