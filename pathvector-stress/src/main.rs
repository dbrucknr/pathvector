mod gobgp_bench;

use std::{
    net::Ipv4Addr,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use pathvector_client::{
    DaemonClient, PathvectorClient,
    types::{Origin, OriginateRouteParams},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    time::sleep,
};

// ── Config ────────────────────────────────────────────────────────────────────

/// Sizes for the three stress phases.
const PHASES: &[(u32, &str)] = &[(10_000, "10k"), (100_000, "100k"), (500_000, "500k")];

/// Batch size for `originate_routes` / `withdraw_originated_routes` calls.
const BATCH: usize = 500;

/// Number of prefixes used in the churn phase (announce → withdraw cycles).
const CHURN_ROUTES: u32 = 10_000;

/// Number of announce/withdraw cycles in the churn phase.
const CHURN_CYCLES: u32 = 5;

/// gRPC port pathvectord will listen on.
/// Chosen to be well above Docker's default port range and the standard 51200.
const GRPC_PORT: u16 = 59_372;

/// Minimal pathvectord config for the stress harness.
///
/// A dummy peer (RFC 5737 TEST-NET — 192.0.2.1) is included so that
/// `run_event_loop`'s mpsc channel has a live sender and does not exit
/// immediately.  The peer will never connect; that is intentional.
const CONFIG: &str = r#"
[daemon]
local_as = 65001
bgp_id   = "127.0.0.1"
grpc_port = 59372
bgp_port  = 11179

[[peers]]
address   = "192.0.2.1"
remote_as = 65002
"#;

struct PvPhaseResult {
    label: &'static str,
    elapsed_secs: f64,
    peak_rss: String,
}

// ── Route generation ──────────────────────────────────────────────────────────

/// Produce the Nth /24 prefix across the full IPv4 space.
/// Starts at 1.0.0.0 to avoid the reserved 0.x.x.x block.
fn prefix_for(n: u32) -> String {
    let base = n + 1;
    let a = (base >> 16) & 0xff;
    let b = (base >> 8) & 0xff;
    let c = base & 0xff;
    format!("{a}.{b}.{c}.0/24")
}

// ── RSS sampling ──────────────────────────────────────────────────────────────

/// Read the RSS of `pid` in kibibytes via `ps`.
/// Returns 0 if the process is not found or `ps` fails.
fn sample_rss_kb(pid: u32) -> u64 {
    // Argument order matters on macOS: -p must precede -o.
    std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "rss="])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Poll RSS every 500 ms and record the peak until `running` is cleared.
async fn rss_sampler(pid: u32, peak_kb: Arc<AtomicU64>, running: Arc<AtomicUsize>) {
    while running.load(Ordering::Relaxed) != 0 {
        let kb = sample_rss_kb(pid);
        peak_kb.fetch_max(kb, Ordering::Relaxed);
        sleep(Duration::from_millis(500)).await;
    }
}

// ── Stderr logger ─────────────────────────────────────────────────────────────

/// Read pathvectord stderr line-by-line, count ERROR/WARN lines, and print them.
async fn stderr_logger(
    stderr: tokio::process::ChildStderr,
    error_count: Arc<AtomicUsize>,
    warn_count: Arc<AtomicUsize>,
) {
    let mut reader = BufReader::new(stderr).lines();
    while let Ok(Some(log_line)) = reader.next_line().await {
        if log_line.contains("ERROR") {
            error_count.fetch_add(1, Ordering::Relaxed);
            eprintln!("[pathvectord] {log_line}");
        } else if log_line.contains("WARN") {
            warn_count.fetch_add(1, Ordering::Relaxed);
            eprintln!("[pathvectord] {log_line}");
        }
        // DEBUG/INFO suppressed — uncomment to see full daemon output:
        // else { eprintln!("[pathvectord] {log_line}"); }
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg_path = std::env::temp_dir().join("pathvectord-stress.toml");
    std::fs::write(&cfg_path, CONFIG)?;

    let bin = workspace_bin("pathvectord")?;
    println!("Starting pathvectord from {bin}");
    println!("Config: {}", cfg_path.display());
    println!();

    let mut child = Command::new(&bin)
        .arg(cfg_path.to_str().unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    let pid = child.id().expect("child has a PID");
    let stderr = child.stderr.take().expect("stderr is piped");
    println!("pathvectord PID: {pid}  (verify: ps -p {pid} -o rss=)");

    let error_count = Arc::new(AtomicUsize::new(0));
    let warn_count = Arc::new(AtomicUsize::new(0));
    let peak_kb = Arc::new(AtomicU64::new(0));
    let rss_running = Arc::new(AtomicUsize::new(1));

    tokio::spawn(stderr_logger(
        stderr,
        Arc::clone(&error_count),
        Arc::clone(&warn_count),
    ));
    tokio::spawn(rss_sampler(
        pid,
        Arc::clone(&peak_kb),
        Arc::clone(&rss_running),
    ));

    let endpoint = format!("http://127.0.0.1:{GRPC_PORT}");
    let mut client = wait_for_grpc(&endpoint, pid).await?;

    println!(
        "{:<8}  {:>12}  {:>10}  {:>10}  {:>10}  {:>8}  {:>8}",
        "Phase", "Routes", "Time (s)", "Peak RSS", "Final RSS", "ERRORs", "WARNs"
    );
    println!("{}", "-".repeat(80));

    let mut total_originated: u32 = 0;
    let mut pv_phase_results: Vec<PvPhaseResult> = Vec::with_capacity(PHASES.len());

    for &(target, label) in PHASES {
        // Seed peak with the current RSS so the sampler's fetch_max is accurate.
        let rss_before = sample_rss_kb(pid);
        peak_kb.store(rss_before, Ordering::Relaxed);

        let start = Instant::now();

        let mut batch = Vec::with_capacity(BATCH);
        for i in total_originated..target {
            batch.push(OriginateRouteParams {
                prefix: prefix_for(i),
                next_hop: Ipv4Addr::new(192, 0, 2, 1).to_string(),
                origin: Origin::Igp,
                communities: vec![],
                large_communities: vec![],
                extended_communities: vec![],
                local_pref: Some(100),
                med: None,
            });
            if batch.len() == BATCH {
                client.originate_routes(std::mem::take(&mut batch)).await?;
            }
        }
        if !batch.is_empty() {
            client.originate_routes(batch).await?;
        }

        // originate_routes is synchronous — returns after the daemon commits all
        // routes, so no polling needed. (list_routes hits the 4 MB gRPC limit at
        // ~26k routes; tracked in TODO.md and plans/stress-test-full-table.md.)
        let elapsed = start.elapsed();

        let final_kb = sample_rss_kb(pid);
        // Give the background sampler one more tick to record the post-load peak.
        sleep(Duration::from_millis(600)).await;
        let phase_peak = peak_kb.load(Ordering::Relaxed).max(final_kb);

        let elapsed_secs = elapsed.as_secs_f64();
        println!(
            "{:<8}  {:>12}  {:>10.2}  {:>10}  {:>10}  {:>8}  {:>8}",
            label,
            target,
            elapsed_secs,
            fmt_kb(phase_peak),
            fmt_kb(final_kb),
            error_count.load(Ordering::Relaxed),
            warn_count.load(Ordering::Relaxed),
        );

        pv_phase_results.push(PvPhaseResult {
            label,
            elapsed_secs,
            peak_rss: fmt_kb(phase_peak),
        });
        total_originated = target;
    }

    // ── Withdrawal phase ──────────────────────────────────────────────────────
    // Withdraw all 500k routes and verify RSS returns toward the baseline.
    // A daemon that does not release memory on withdrawal will silently grow
    // under normal BGP churn (peer flaps, route updates).

    println!();
    println!("Withdrawal (500k routes)");
    println!("{}", "-".repeat(80));

    let rss_pre_withdraw = sample_rss_kb(pid);
    peak_kb.store(rss_pre_withdraw, Ordering::Relaxed);
    let start = Instant::now();

    let mut batch: Vec<String> = Vec::with_capacity(BATCH);
    for i in 0..total_originated {
        batch.push(prefix_for(i));
        if batch.len() == BATCH {
            client
                .withdraw_originated_routes(std::mem::take(&mut batch))
                .await?;
        }
    }
    if !batch.is_empty() {
        client.withdraw_originated_routes(batch).await?;
    }
    let withdraw_elapsed = start.elapsed();

    // Give the allocator a moment to release pages before sampling.
    sleep(Duration::from_millis(600)).await;
    let rss_post_withdraw = sample_rss_kb(pid);
    let reclaimed_kb = rss_pre_withdraw.saturating_sub(rss_post_withdraw);

    println!("  Before:    {}", fmt_kb(rss_pre_withdraw),);
    println!(
        "  After:     {}  ({:.2}s)",
        fmt_kb(rss_post_withdraw),
        withdraw_elapsed.as_secs_f64(),
    );
    println!(
        "  Reclaimed: {}  ({:.0}%)",
        fmt_kb(reclaimed_kb),
        reclaim_pct(reclaimed_kb, rss_pre_withdraw),
    );

    // ── Churn phase ───────────────────────────────────────────────────────────
    // Repeatedly announce and withdraw the same 10k prefixes for N cycles.
    // RSS should remain stable across cycles — any growth indicates a leak.

    println!();
    println!("Churn ({CHURN_ROUTES} routes × {CHURN_CYCLES} announce/withdraw cycles)");
    println!("{}", "-".repeat(80));
    println!(
        "  {:<8}  {:>10}  {:>10}  {:>10}",
        "Cycle", "Ann (s)", "With (s)", "RSS after"
    );

    for cycle in 1..=CHURN_CYCLES {
        // Announce.
        let mut batch = Vec::with_capacity(BATCH);
        let ann_start = Instant::now();
        for i in 0..CHURN_ROUTES {
            batch.push(OriginateRouteParams {
                prefix: prefix_for(i),
                next_hop: Ipv4Addr::new(192, 0, 2, 1).to_string(),
                origin: Origin::Igp,
                communities: vec![],
                large_communities: vec![],
                extended_communities: vec![],
                local_pref: Some(100),
                med: None,
            });
            if batch.len() == BATCH {
                client.originate_routes(std::mem::take(&mut batch)).await?;
            }
        }
        if !batch.is_empty() {
            client.originate_routes(batch).await?;
        }
        let ann_elapsed = ann_start.elapsed();

        // Withdraw.
        let mut batch: Vec<String> = Vec::with_capacity(BATCH);
        let with_start = Instant::now();
        for i in 0..CHURN_ROUTES {
            batch.push(prefix_for(i));
            if batch.len() == BATCH {
                client
                    .withdraw_originated_routes(std::mem::take(&mut batch))
                    .await?;
            }
        }
        if !batch.is_empty() {
            client.withdraw_originated_routes(batch).await?;
        }
        let with_elapsed = with_start.elapsed();

        sleep(Duration::from_millis(300)).await;
        let rss = sample_rss_kb(pid);

        println!(
            "  {:<8}  {:>10.2}  {:>10.2}  {:>10}",
            cycle,
            ann_elapsed.as_secs_f64(),
            with_elapsed.as_secs_f64(),
            fmt_kb(rss),
        );
    }

    println!();
    let total_errors = error_count.load(Ordering::Relaxed);
    if total_errors > 0 {
        println!("FAILED — pathvectord logged {total_errors} ERROR(s) during the run.");
        rss_running.store(0, Ordering::Relaxed);
        child.kill().await?;
        std::process::exit(1);
    }
    println!("OK — zero errors logged by pathvectord.");

    rss_running.store(0, Ordering::Relaxed);
    child.kill().await?;

    // ── GoBGP benchmark ───────────────────────────────────────────────────────
    println!();
    println!("═══════════════════════════════════════════════════════════════════");
    println!("  GoBGP 1:1 comparison  (same phases, same batch size, same host)");
    println!("═══════════════════════════════════════════════════════════════════");
    println!();

    let gobgp_results = gobgp_bench::run(PHASES, BATCH).await?;

    println!("{:<8}  {:>10}  {:>10}", "Phase", "Time (s)", "Peak RSS",);
    println!("{}", "-".repeat(32));
    for r in &gobgp_results {
        println!(
            "{:<8}  {:>10.2}  {:>10}",
            r.label, r.elapsed_secs, r.peak_rss,
        );
    }

    // ── Side-by-side summary ──────────────────────────────────────────────────
    println!();
    println!("── Side-by-side: convergence time ──────────────────────────────────");
    println!(
        "{:<8}  {:>14}  {:>14}  {:>10}",
        "Phase", "pathvectord", "GoBGP", "Ratio (pv/go)",
    );
    println!("{}", "-".repeat(55));
    for (pv, go) in pv_phase_results.iter().zip(gobgp_results.iter()) {
        #[allow(clippy::cast_precision_loss)]
        let ratio = if go.elapsed_secs > 0.0 {
            pv.elapsed_secs / go.elapsed_secs
        } else {
            f64::NAN
        };
        println!(
            "{:<8}  {:>11.2} s  {:>11.2} s  {:>10.2}×",
            pv.label, pv.elapsed_secs, go.elapsed_secs, ratio,
        );
    }

    println!();
    println!("── Side-by-side: peak RSS ───────────────────────────────────────────");
    println!("{:<8}  {:>14}  {:>14}", "Phase", "pathvectord", "GoBGP",);
    println!("{}", "-".repeat(40));
    for (pv, go) in pv_phase_results.iter().zip(gobgp_results.iter()) {
        println!("{:<8}  {:>14}  {:>14}", pv.label, pv.peak_rss, go.peak_rss);
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn wait_for_grpc(
    endpoint: &str,
    pid: u32,
) -> Result<PathvectorClient, Box<dyn std::error::Error>> {
    for _ in 0..60 {
        // Fail fast if the process has already exited (e.g. port conflict).
        if sample_rss_kb(pid) == 0 {
            return Err(format!(
                "pathvectord (PID {pid}) exited before becoming ready — \
                 check for port conflicts with: lsof -i :{GRPC_PORT}"
            )
            .into());
        }
        if let Ok(mut c) = PathvectorClient::connect(endpoint)
            && c.list_peers().await.is_ok()
        {
            return Ok(c);
        }
        sleep(Duration::from_millis(250)).await;
    }
    Err("pathvectord did not become ready within 15 seconds".into())
}

fn workspace_bin(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    let target_dir = exe
        .ancestors()
        .find(|p| p.join("debug").is_dir() || p.join("release").is_dir())
        .map(std::path::Path::to_path_buf)
        .ok_or("could not locate target directory")?;

    for profile in ["release", "debug"] {
        let candidate = target_dir.join(profile).join(name);
        if candidate.exists() {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }

    Err(format!("'{name}' binary not found — run `cargo build -p pathvectord` first").into())
}

#[allow(clippy::cast_precision_loss)]
fn reclaim_pct(reclaimed: u64, total: u64) -> f64 {
    if total > 0 {
        reclaimed as f64 / total as f64 * 100.0
    } else {
        0.0
    }
}

#[allow(clippy::cast_precision_loss)]
fn fmt_kb(kb: u64) -> String {
    if kb >= 1024 * 1024 {
        format!("{:.1} GB", kb as f64 / (1024.0 * 1024.0))
    } else if kb >= 1024 {
        format!("{:.1} MB", kb as f64 / 1024.0)
    } else {
        format!("{kb} KB")
    }
}
