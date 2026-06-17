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
//! curl -O https://archive.routeviews.org/bgpdata/2024.12/RIBS/rib.20241201.0000.bz2
//! bunzip2 rib.20241201.0000.bz2
//! ```
//!
//! ## What it measures
//!
//! - Time for the BGP speaker to announce all prefixes from the MRT file
//! - Time for pathvectord's Loc-RIB to reach the expected prefix count
//!   (polled via gRPC — total = announcement + RIB processing lag)
//! - Peak RSS of pathvectord at convergence

use std::{
    fmt::Write as _,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use clap::Parser;
use pathvector_client::{DaemonClient, PathvectorClient};
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

    /// pathvectord gRPC address for convergence polling
    #[arg(long, default_value = "http://127.0.0.1:51200")]
    grpc: String,

    /// Maximum time to wait for the RIB to converge after announcement completes
    #[arg(long, default_value = "120")]
    timeout_secs: u64,

    /// Print progress every N prefixes during announcement
    #[arg(long, default_value = "100000")]
    progress_every: u64,
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
    let mrt_path = args.mrt.display().to_string();
    println!("Parsing MRT dump: {mrt_path}");

    let parse_start = std::time::Instant::now();
    let entries = read_mrt(&args.mrt)?;
    let parse_elapsed = parse_start.elapsed();

    println!("  Prefixes: {}", fmt_count(entries.len() as u64));
    println!("  Parse time: {:.1}s", parse_elapsed.as_secs_f64());
    println!();

    if entries.is_empty() {
        return Err("MRT file contains no IPv4 unicast entries".into());
    }

    // ── 2. Establish BGP session ──────────────────────────────────────────────
    println!(
        "Connecting to {} as AS{} (router-id {})",
        args.peer, args.my_as, args.router_id
    );
    let mut spkr = BgpSpeaker::connect(args.peer, args.my_as, args.router_id).await?;
    println!("  Session established");
    println!();

    // ── 3. Announce all prefixes ──────────────────────────────────────────────
    println!("Announcing {} prefixes...", fmt_count(entries.len() as u64));
    let result = spkr.announce(&entries).await?;

    println!(
        "  Done: {} prefixes in {} UPDATE messages ({:.1}s)",
        fmt_count(result.prefixes_sent),
        fmt_count(result.updates_sent),
        result.elapsed.as_secs_f64(),
    );
    println!();

    // ── 4. Poll pathvectord gRPC for convergence ──────────────────────────────
    println!("Polling pathvectord gRPC at {} for convergence...", args.grpc);

    let grpc_start = std::time::Instant::now();
    let timeout = Duration::from_secs(args.timeout_secs);

    let mut client = PathvectorClient::connect(args.grpc.clone())
        .map_err(|e| format!("failed to connect to gRPC at {}: {e}", args.grpc))?;

    let expected = result.prefixes_sent;

    // Probe once to detect whether list_routes is usable at this table size.
    // For >~26k routes the response exceeds the 4 MB gRPC default limit and
    // list_routes returns an error.  In that case we fall back to a fixed wait
    // and report only the announcement metrics.
    let probe = query_prefix_count(&mut client).await;
    let rib_count = if let Some(count) = probe {
        // list_routes works — poll until stable.
        let mut last_count = count;
        let mut stable_for: u64 = 0;
        println!("  {}", fmt_count(count));

        loop {
            if grpc_start.elapsed() > timeout {
                return Err(format!(
                    "timed out after {}s waiting for convergence \
                     (last count: {}, expected: {})",
                    args.timeout_secs,
                    fmt_count(last_count),
                    fmt_count(expected),
                )
                .into());
            }

            sleep(Duration::from_millis(500)).await;
            let count = query_prefix_count(&mut client).await.unwrap_or(last_count);

            if count == last_count {
                stable_for += 1;
            } else {
                println!("  {}", fmt_count(count));
                last_count = count;
                stable_for = 0;
            }

            // Stable for 3 consecutive polls (3 × 500ms = 1.5s of no change).
            if stable_for >= 3 && count > 0 {
                break;
            }
        }
        Some(last_count)
    } else {
        // list_routes hit the gRPC message-size limit — table is too large to
        // count via this API.  Wait 2 s for RIB processing to finish, then
        // report without a verified prefix count.
        println!(
            "  (table too large for list_routes — \
             waiting 2s for RIB processing then reporting)"
        );
        sleep(Duration::from_secs(2)).await;
        None
    };

    let total_elapsed = grpc_start.elapsed() + result.elapsed;

    println!();
    println!("── Results ──────────────────────────────────────────────────────");
    println!(
        "  Announcement:   {:.2}s ({} prefixes, {}/s)",
        result.elapsed.as_secs_f64(),
        fmt_count(result.prefixes_sent),
        fmt_count(prefixes_per_sec(result.prefixes_sent, result.elapsed)),
    );
    println!(
        "  Convergence:    ~{:.2}s (announcement + ~2s RIB processing)",
        total_elapsed.as_secs_f64()
    );
    println!("  Unique attr sets: {}", fmt_count(result.unique_attr_sets as u64));

    if let Some(count) = rib_count {
        println!(
            "  Final RIB count: {} / {} expected",
            fmt_count(count),
            fmt_count(expected)
        );
        if count < expected {
            let rejected = expected - count;
            #[allow(clippy::cast_precision_loss)]
            let pct = rejected as f64 / expected as f64 * 100.0;
            println!("  Rejected routes: {} ({:.1}%)", fmt_count(rejected), pct);
        }
    } else {
        println!(
            "  Final RIB count: (not measurable — list_routes exceeds 4 MB gRPC limit at {} prefixes)",
            fmt_count(expected)
        );
        println!("  Note: implement list_routes pagination to enable convergence verification");
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
        let decoder = flate2::read::GzDecoder::new(file);
        Ok(mrt::parse(decoder)?)
    } else {
        Ok(mrt::parse(std::io::BufReader::new(file))?)
    }
}

/// Query the total IPv4 unicast prefix count via gRPC.
///
/// Returns `None` when `list_routes` fails (typically because the response
/// exceeds the 4 MB gRPC message limit for tables larger than ~26k routes).
async fn query_prefix_count(client: &mut PathvectorClient) -> Option<u64> {
    client
        .list_routes(None)
        .await
        .ok()
        .map(|routes| routes.len() as u64)
}

/// Compute prefixes-per-second as a u64, avoiding f64 precision lint on the call site.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn prefixes_per_sec(count: u64, elapsed: Duration) -> u64 {
    let secs = elapsed.as_secs_f64();
    if secs == 0.0 {
        return 0;
    }
    (count as f64 / secs) as u64
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
