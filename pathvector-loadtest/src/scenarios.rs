//! The PR-1 scenarios. Each one opens a measurement `Window`, does its
//! work against the live daemon, waits for the daemon to settle, and closes
//! the window into a [`WindowReport`].
//!
//! Waiting is driven by `/metrics` (which is served independently of the
//! daemon's state lock), so the harness's own observation never adds
//! contention to what it is measuring.

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use futures::StreamExt as _;
use pathvector_client::{
    DaemonClient, PathvectorClient,
    types::{RouteEventType, SessionState},
};
use pathvector_mrt::{
    mrt::RibEntry,
    speaker::{build_update_messages, build_withdraw_messages},
};
use tokio::time::sleep;

use crate::{
    config::Topology,
    daemon::{Monitor, grpc_url},
    gaps::{gap_stats, latency_stats},
    peer::PeerHandle,
    promtext::{Snapshot, histogram_deltas},
    report::{ControlSummary, WindowReport},
};

type Res<T> = Result<T, String>;

/// Shared state for a harness run.
pub struct Ctx {
    pub topo: Topology,
    pub monitor: Monitor,
    pub control: PeerHandle,
    /// One slot per loader; `None` while that loader is disconnected.
    pub loaders: Vec<Option<PeerHandle>>,
    /// Pre-encoded full-table UPDATEs, shared by every loader.
    pub table_msgs: Arc<Vec<Vec<u8>>>,
    /// Unique prefixes in the table (what each loader should end up with).
    pub expected_prefixes: u64,
    /// Prefixes the daemon actually kept per loader (Adj-RIB-In size once the
    /// first convergence settles). Real MRT dumps can contain entries the
    /// daemon rejects or treats as withdrawn, so later scenarios wait for
    /// *this*, not the raw prefix count. `None` until `converge` has run.
    pub accepted: Option<u64>,
    pub entries: Arc<Vec<RibEntry>>,
    pub timeout: Duration,
    pub churn_prefixes: usize,
    /// How long each churn phase runs.
    pub churn_secs: u64,
}

impl Ctx {
    fn bgp_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.topo.bgp_port))
    }

    /// (Re)connects loader `i`.
    pub async fn connect_loader(&mut self, i: usize) -> Res<()> {
        let spec = self.topo.loaders[i];
        let p = PeerHandle::connect(
            &format!("loader{i}"),
            spec.addr,
            self.bgp_addr(),
            spec.remote_as,
            90,
            false,
        )
        .await
        .map_err(|e| format!("loader{i} connect failed: {e}"))?;
        self.loaders[i] = Some(p);
        Ok(())
    }

    /// Connects loader `i`, retrying until it works or `self.timeout`
    /// passes. Returns how long it took.
    ///
    /// A peer that just lost an Established session is not accepted again
    /// immediately: the daemon's FSM sits in Idle (which ignores inbound
    /// connections) until its `ConnectRetry` timer fires. The harness lowers
    /// that timer to a few seconds so this wait is short; the returned
    /// duration makes the effect visible instead of hiding it.
    pub async fn connect_loader_with_retry(&mut self, i: usize) -> Res<Duration> {
        let start = Instant::now();
        loop {
            match self.connect_loader(i).await {
                Ok(()) => return Ok(start.elapsed()),
                Err(e) if start.elapsed() > self.timeout => {
                    return Err(format!("{e} (gave up after {:?})", start.elapsed()));
                }
                Err(_) => sleep(Duration::from_secs(1)).await,
            }
        }
    }

    /// Daemon-reported state for loader `i`, read over gRPC. Unlike the
    /// Prometheus gauges this reads the live RIB state directly, so it is the
    /// ground truth for "how many prefixes does the daemon hold".
    async fn peer_state(&self, i: usize) -> Res<pathvector_client::types::PeerState> {
        let addr: IpAddr = self.topo.loaders[i].addr.into();
        let mut c = PathvectorClient::connect(grpc_url(&self.topo)).map_err(|e| e.to_string())?;
        c.get_peer(addr).await.map_err(|e| e.to_string())
    }

    /// Cross-checks the `pathvectord_bgp_session_up` gauge against reality.
    /// Returns a `METRIC DISCREPANCY` note if it disagrees with `expect_up`.
    /// Guards against GH #105: the gauge used to stay stale when the
    /// Established/Terminated event was coalesced into a batch.
    async fn session_up_cross_check(&self, i: usize, expect_up: bool) -> Res<Vec<String>> {
        let ip = self.loader_ip(i);
        let (_, snap) = self.monitor.scrape().await.map_err(|e| e.to_string())?;
        let got = snap.value("pathvectord_bgp_session_up", &[("peer", &ip)]);
        let want = if expect_up { 1.0 } else { 0.0 };
        Ok(if got == Some(want) {
            Vec::new()
        } else {
            vec![format!(
                "METRIC DISCREPANCY loader{i}: pathvectord_bgp_session_up is {got:?} but the session is {}",
                if expect_up { "up" } else { "down" }
            )]
        })
    }

    /// Waits until the daemon reports loader `i`'s session as not Established.
    async fn wait_peer_idle(&self, i: usize) -> Res<()> {
        let start = Instant::now();
        loop {
            if self.peer_state(i).await?.session_state != SessionState::Idle {
                if start.elapsed() > self.timeout {
                    return Err(format!(
                        "timed out after {:?} waiting for loader{i}'s session to go down",
                        self.timeout
                    ));
                }
                sleep(Duration::from_millis(100)).await;
                continue;
            }
            return Ok(());
        }
    }

    /// Waits until the sum of every write-lock hold count stops changing for
    /// `quiet` — i.e. the daemon has finished whatever it was doing — after
    /// first requiring at least one new hold since `since`. The hold is only
    /// recorded when the guard *drops*, so this observes the end of the work,
    /// unlike gauges that some code paths update before the work happens.
    async fn wait_daemon_quiet(&self, since: &Snapshot, quiet: Duration) -> Res<()> {
        let total = |s: &Snapshot| -> f64 {
            s.histograms("pathvectord_state_lock_hold_seconds")
                .iter()
                .filter(|h| h.labels.get("kind").is_none_or(|k| k != "mrai"))
                .map(|h| h.count)
                .sum()
        };
        let baseline = total(since);
        let start = Instant::now();
        let mut last = (baseline, Instant::now());
        loop {
            let (_, snap) = self.monitor.scrape().await.map_err(|e| e.to_string())?;
            let t = total(&snap);
            if (t - last.0).abs() > f64::EPSILON {
                last = (t, Instant::now());
            }
            if last.0 > baseline && last.1.elapsed() >= quiet {
                return Ok(());
            }
            if start.elapsed() > self.timeout {
                return Err(format!(
                    "timed out after {:?} waiting for the daemon to go quiet",
                    self.timeout
                ));
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    fn loader(&self, i: usize) -> Res<&PeerHandle> {
        self.loaders[i]
            .as_ref()
            .ok_or_else(|| format!("loader{i} is not connected"))
    }

    fn loader_ip(&self, i: usize) -> String {
        self.topo.loaders[i].addr.to_string()
    }

    /// What a scenario should expect each loader's table to hold.
    fn want_prefixes(&self) -> u64 {
        self.accepted.unwrap_or(self.expected_prefixes)
    }

    /// How the management plane looks right now, for timeout diagnostics: the
    /// most recent probe's age and outcome. A probe that is old, failed, or
    /// slow says the daemon (or its lock) is wedged rather than merely busy.
    fn probe_summary(&self) -> String {
        let probes = self.monitor.probes.lock().unwrap();
        match probes.last() {
            None => "no gRPC probes recorded".to_string(),
            Some(p) => format!(
                "last gRPC probe {:.1?} ago: {} in {:.1?}; daemon_alive_to_grpc={}",
                p.at.elapsed(),
                if p.ok { "ok" } else { "FAILED" },
                p.latency,
                p.at.elapsed() < Duration::from_secs(5) && p.ok
            ),
        }
    }

    /// Current RIB-size gauges, for timeout diagnostics.
    fn gauge_summary(&self, snap: &Snapshot) -> String {
        let fmt = |v: Option<f64>| v.map_or_else(|| "n/a".to_string(), |v| format!("{v:.0}"));
        let mut parts: Vec<String> = self
            .topo
            .loaders
            .iter()
            .map(|l| {
                let ip = l.addr.to_string();
                format!(
                    "adj_in[{ip}]={} adj_out[{ip}]={}",
                    fmt(snap.value("pathvectord_bgp_adj_rib_in_prefixes", &[("peer", &ip)])),
                    fmt(snap.value("pathvectord_bgp_adj_rib_out_prefixes", &[("peer", &ip)])),
                )
            })
            .collect();
        parts.push(format!(
            "loc_rib_v4={}",
            fmt(snap.value("pathvectord_bgp_loc_rib_prefixes", &[("afi", "ipv4")]))
        ));
        parts.push(self.probe_summary());
        parts.join(", ")
    }

    /// Waits until the gauge `name{labels}` is non-zero and has not changed
    /// for `quiet`, returning `(settled value, time waited)`. Used where the
    /// settled count is itself a result — how much of the table the daemon
    /// kept.
    async fn wait_stable(
        &self,
        name: &str,
        labels: &[(&str, &str)],
        quiet: Duration,
    ) -> Res<(f64, Duration)> {
        let start = Instant::now();
        let mut last: Option<(f64, Instant)> = None;
        loop {
            let (_, snap) = self.monitor.scrape().await.map_err(|e| e.to_string())?;
            let v = snap.value(name, labels).unwrap_or(0.0);
            match last {
                Some((lv, _)) if (lv - v).abs() < f64::EPSILON => {}
                _ => last = Some((v, Instant::now())),
            }
            if let Some((lv, since)) = last
                && lv > 0.0
                && since.elapsed() >= quiet
            {
                return Ok((lv, start.elapsed()));
            }
            if start.elapsed() > self.timeout {
                return Err(format!(
                    "timed out after {:?} waiting for {name}{labels:?} to settle (last {v}; {})",
                    self.timeout,
                    self.gauge_summary(&snap)
                ));
            }
            sleep(Duration::from_millis(250)).await;
        }
    }

    async fn begin(&self) -> Res<Window> {
        let (t0, before) = self.monitor.scrape().await.map_err(|e| e.to_string())?;
        Ok(Window { t0, before })
    }

    async fn finish(&self, w: Window, title: &str, notes: Vec<String>) -> Res<WindowReport> {
        let (t1, after) = self.monitor.scrape().await.map_err(|e| e.to_string())?;
        let stats = &self.control.stats;
        let alive = !stats.is_closed();
        let hold = Duration::from_secs(u64::from(self.topo.control_hold));

        let lat = latency_stats(&self.monitor.probes.lock().unwrap(), w.t0, t1);
        let gaps = gap_stats(&stats.arrivals(), w.t0, t1, alive);

        let d = |base: &str| histogram_deltas(&w.before, &after, base);
        Ok(WindowReport {
            title: title.to_string(),
            duration: t1.duration_since(w.t0),
            control: ControlSummary {
                gaps,
                expected_gap: hold / 3,
                hold,
                alive,
                notification: stats.notification(),
            },
            mgmt: lat,
            lock_hold: d("pathvectord_state_lock_hold_seconds"),
            lock_wait: d("pathvectord_state_lock_wait_seconds"),
            batch_events: d("pathvectord_event_loop_batch_events").into_iter().next(),
            send_blocked: d("pathvector_session_event_send_blocked_seconds"),
            keepalive_lateness: d("pathvector_session_keepalive_lateness_seconds"),
            peak_rss_kb: self.monitor.peak_rss_kb(w.t0, t1),
            notes,
        })
    }
}

struct Window {
    t0: Instant,
    before: Snapshot,
}

/// Idle baseline: no load. Validates the measurement itself — the control
/// peer should see keepalives at exactly the negotiated cadence and the lock
/// histograms should be near-empty.
pub async fn idle(ctx: &Ctx, secs: u64) -> Res<WindowReport> {
    let w = ctx.begin().await?;
    sleep(Duration::from_secs(secs)).await;
    ctx.finish(w, "idle baseline", vec![]).await
}

/// Initial convergence: every loader sends the full table at once.
pub async fn converge(ctx: &mut Ctx) -> Res<WindowReport> {
    for i in 0..ctx.loaders.len() {
        if ctx.loaders[i].is_none() {
            ctx.connect_loader(i).await?;
        }
    }
    let w = ctx.begin().await?;
    let started = Instant::now();

    let sends = ctx
        .loaders
        .iter()
        .flatten()
        .map(|l| l.send_all(Arc::clone(&ctx.table_msgs)));
    let results = futures::future::join_all(sends).await;
    let mut notes = Vec::new();
    for (i, r) in results.into_iter().enumerate() {
        let d = r.map_err(|e| format!("loader{i} send failed: {e}"))?;
        notes.push(format!(
            "loader{i} finished writing {} prefixes in {d:.2?}",
            ctx.expected_prefixes
        ));
    }

    // Settle on Loc-RIB size, which the daemon updates once per processed
    // batch *after* its final flush — so it is correct at rest. (The per-peer
    // Adj-RIB-In gauge is not: see the cross-check below.)
    let quiet = Duration::from_millis(1500);
    ctx.wait_stable(
        "pathvectord_bgp_loc_rib_prefixes",
        &[("afi", "ipv4")],
        quiet,
    )
    .await?;

    let (_, snap) = ctx.monitor.scrape().await.map_err(|e| e.to_string())?;
    let mut kept = Vec::new();
    for i in 0..ctx.loaders.len() {
        let ip = ctx.loader_ip(i);
        let kept_i = u64::from(ctx.peer_state(i).await?.prefixes_received);
        let gauge = snap.value("pathvectord_bgp_adj_rib_in_prefixes", &[("peer", &ip)]);
        notes.push(format!(
            "loader{i}: daemon holds {kept_i} of {} prefixes sent ({} not accepted)",
            ctx.expected_prefixes,
            ctx.expected_prefixes.saturating_sub(kept_i)
        ));
        #[allow(clippy::cast_precision_loss)]
        if gauge.is_some_and(|g| (g - kept_i as f64).abs() > 0.5) {
            notes.push(format!(
                "METRIC DISCREPANCY loader{i}: pathvectord_bgp_adj_rib_in_prefixes says {} but the daemon's own state says {kept_i}                  (gauge only refreshed for the first event of each coalesced batch)",
                gauge.unwrap_or(0.0)
            ));
        }
        kept.push(kept_i);
    }
    ctx.accepted = Some(kept[0]);
    notes.push(format!(
        "everything settled {:.2?} after start (includes {quiet:?} of required quiet)",
        started.elapsed()
    ));
    ctx.finish(
        w,
        &format!(
            "initial convergence ({} loaders × {} prefixes)",
            ctx.loaders.len(),
            ctx.expected_prefixes
        ),
        notes,
    )
    .await
}

/// Churn: loader 0 repeatedly withdraws and re-announces a small prefix set.
async fn churn_loop(ctx: &Ctx, secs: u64) -> Res<u64> {
    let n = ctx.churn_prefixes.min(ctx.entries.len());
    let slice = &ctx.entries[..n];
    let withdraw = Arc::new(build_withdraw_messages(
        &slice
            .iter()
            .map(|e| (e.prefix, e.prefix_len))
            .collect::<Vec<_>>(),
    ));
    let announce = Arc::new(build_update_messages(slice).messages);

    let l = ctx.loader(0)?;
    let end = Instant::now() + Duration::from_secs(secs);
    let mut cycles = 0u64;
    while Instant::now() < end {
        l.send_all(Arc::clone(&withdraw))
            .await
            .map_err(|e| e.to_string())?;
        sleep(Duration::from_millis(100)).await;
        l.send_all(Arc::clone(&announce))
            .await
            .map_err(|e| e.to_string())?;
        sleep(Duration::from_millis(100)).await;
        cycles += 1;
    }
    Ok(cycles)
}

/// Copy-on-write hypothesis: does a management client holding a route
/// snapshot make the *next* RIB mutation clone the whole Loc-RIB under the
/// write lock? Runs the identical churn twice — alone, then while a client
/// continuously streams `watch_routes` snapshots — so the two reports can be
/// compared directly.
pub async fn cow_snapshot(ctx: &Ctx) -> Res<Vec<WindowReport>> {
    // A: churn only.
    let window = ctx.begin().await?;
    let cycles = churn_loop(ctx, ctx.churn_secs).await?;
    let alone = ctx
        .finish(
            window,
            &format!("churn only ({} prefixes)", ctx.churn_prefixes),
            vec![format!("{cycles} withdraw/announce cycles")],
        )
        .await?;

    // B: same churn with a snapshot reader hammering the daemon.
    let stop = Arc::new(AtomicBool::new(false));
    let snapshots = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let reader = {
        let (stop, snapshots, url) = (
            Arc::clone(&stop),
            Arc::clone(&snapshots),
            grpc_url(&ctx.topo),
        );
        tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let Ok(mut c) = PathvectorClient::connect(url.clone()) else {
                    return;
                };
                let Ok(mut s) = c.watch_routes(None).await else {
                    return;
                };
                while let Some(ev) = s.next().await {
                    match ev {
                        Ok(e) if e.event_type == RouteEventType::EndInitial => break,
                        Ok(_) => {}
                        Err(_) => return,
                    }
                }
                snapshots.fetch_add(1, Ordering::Relaxed);
            }
        })
    };
    // Let the first snapshot get underway so the reader is mid-stream when churn starts.
    sleep(Duration::from_millis(500)).await;

    let window = ctx.begin().await?;
    let cycles = churn_loop(ctx, ctx.churn_secs).await?;
    stop.store(true, Ordering::Relaxed);
    let with_reader = ctx
        .finish(
            window,
            &format!(
                "churn + concurrent watch_routes snapshots ({} prefixes)",
                ctx.churn_prefixes
            ),
            vec![
                format!("{cycles} withdraw/announce cycles"),
                format!(
                    "{} full snapshots completed by the reader",
                    snapshots.load(Ordering::Relaxed)
                ),
            ],
        )
        .await?;
    reader.abort();
    Ok(vec![alone, with_reader])
}

/// Peer teardown: loader 0 vanishes abruptly while holding a full table.
pub async fn teardown(ctx: &mut Ctx) -> Res<WindowReport> {
    let held = ctx.want_prefixes();
    let peer = ctx.loaders[0].take().ok_or("loader0 is not connected")?;
    let w = ctx.begin().await?;
    let started = Instant::now();
    peer.close_abruptly().await;

    // Ask the daemon, not the `session_up` gauge: the gauge is skipped when
    // the Terminated event is coalesced into a batch behind other events (it
    // then stays 1 forever), which this scenario triggers intermittently.
    ctx.wait_peer_idle(0).await?;
    // Even then the RIB is cleared *after* the state flips, so wait for the
    // write-lock holds to stop rather than trusting any single indicator.
    ctx.wait_daemon_quiet(&w.before, Duration::from_millis(1000))
        .await?;
    let took = started.elapsed();
    let mut notes = vec![format!(
        "daemon finished processing the teardown within {took:.2?} of the TCP close (includes 1s of required quiet)"
    )];
    notes.extend(ctx.session_up_cross_check(0, false).await?);
    ctx.finish(
        w,
        &format!("peer teardown (loader0, {held} prefixes)"),
        notes,
    )
    .await
}

/// Reconvergence: loader 0 returns and re-sends the full table while the
/// other loaders' tables are already in the RIB.
pub async fn reconverge(ctx: &mut Ctx) -> Res<WindowReport> {
    let reconnect = ctx.connect_loader_with_retry(0).await?;
    let w = ctx.begin().await?;
    let sent = ctx
        .loader(0)?
        .send_all(Arc::clone(&ctx.table_msgs))
        .await
        .map_err(|e| e.to_string())?;
    ctx.wait_daemon_quiet(&w.before, Duration::from_millis(1500))
        .await?;
    let held = u64::from(ctx.peer_state(0).await?.prefixes_received);
    let mut notes = vec![
        format!(
            "loader0 re-established {reconnect:.2?} after teardown. A connection made right after the teardown got no OPEN for the 10 s handshake timeout: the FSM is Idle after an Established session ends and ignores inbound connections until its ConnectRetry timer fires (harness sets connect_retry_time = 3 s; the default is 120 s)"
        ),
        format!(
            "write finished in {sent:.2?}; daemon holds {held} of {} prefixes from loader0",
            ctx.want_prefixes()
        ),
    ];
    if held != ctx.want_prefixes() {
        notes.push("MISMATCH: reconverged table differs from the original convergence".to_string());
    }
    notes.extend(ctx.session_up_cross_check(0, true).await?);
    ctx.finish(
        w,
        "reconvergence (loader0 re-announces into an existing table)",
        notes,
    )
    .await
}

/// Full export-policy re-evaluation: flip one peer's export policy to accept
/// (the daemon must evaluate and send the entire Loc-RIB to it), then back to
/// reject (withdrawing it all). The recipient drains everything it is sent.
pub async fn export_reeval(ctx: &Ctx) -> Res<Vec<WindowReport>> {
    // A prefix is never advertised back to the peer its best path came from.
    // With a single loader every best route was learned from it, so flipping
    // its export policy would send nothing and measure nothing.
    if ctx.loaders.len() < 2 {
        println!(
            "  skipped: needs at least 2 loaders — with one, every best route was learned from it \
             and is never advertised back, so there is no export dump to measure"
        );
        return Ok(Vec::new());
    }
    let target = 1;
    let ip = ctx.loader_ip(target);
    let peer = ctx.loader(target)?;
    let mut client = PathvectorClient::connect(grpc_url(&ctx.topo)).map_err(|e| e.to_string())?;
    let want = ctx.want_prefixes();

    // accept
    let w = ctx.begin().await?;
    let rx_before = peer.stats.updates_rx.load(Ordering::Relaxed);
    let t = Instant::now();
    client
        .set_export_default(&ip, true)
        .await
        .map_err(|e| e.to_string())?;
    let rpc = t.elapsed();
    ctx.wait_daemon_quiet(&w.before, Duration::from_millis(1500))
        .await?;
    let advertised = u64::from(ctx.peer_state(target).await?.prefixes_advertised);
    let received = peer.stats.updates_rx.load(Ordering::Relaxed) - rx_before;
    let mut notes = vec![
        format!("set_export_default RPC returned after {rpc:.2?}"),
        format!(
            "Adj-RIB-Out holds {advertised} of {want} prefixes; recipient got {received} UPDATE messages"
        ),
    ];
    if advertised != want {
        notes.push("MISMATCH: Adj-RIB-Out differs from the Loc-RIB size".to_string());
    }
    let up = ctx
        .finish(
            w,
            &format!("export policy reject→accept on {ip} (full Loc-RIB dump)"),
            notes,
        )
        .await?;

    // reject
    let w = ctx.begin().await?;
    let t = Instant::now();
    client
        .set_export_default(&ip, false)
        .await
        .map_err(|e| e.to_string())?;
    let rpc = t.elapsed();
    ctx.wait_daemon_quiet(&w.before, Duration::from_millis(1500))
        .await?;
    let left = ctx.peer_state(target).await?.prefixes_advertised;
    let mut notes = vec![
        format!("set_export_default RPC returned after {rpc:.2?}"),
        format!("Adj-RIB-Out holds {left} prefixes afterwards"),
    ];
    if left != 0 {
        notes.push("MISMATCH: Adj-RIB-Out not empty after export reject".to_string());
    }
    let down = ctx
        .finish(
            w,
            &format!("export policy accept→reject on {ip} (full withdraw)"),
            notes,
        )
        .await?;
    Ok(vec![up, down])
}

/// Number of distinct prefixes in `entries`.
#[must_use]
pub fn unique_prefixes(entries: &[RibEntry]) -> u64 {
    entries
        .iter()
        .map(|e| (e.prefix, e.prefix_len))
        .collect::<HashSet<_>>()
        .len() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn entry(second_octet: u8, prefix_len: u8, attr_byte: u8) -> RibEntry {
        RibEntry {
            prefix: Ipv4Addr::new(10, second_octet, 0, 0),
            prefix_len,
            attrs: vec![attr_byte],
        }
    }

    /// The convergence wait compares Adj-RIB-In to this count, so it must be
    /// *distinct prefixes*, not entries: the same prefix under two attribute
    /// sets is one RIB entry per peer.
    #[test]
    fn unique_prefixes_counts_distinct_prefix_and_length() {
        let entries = vec![
            entry(1, 16, 1),
            entry(1, 16, 2),
            entry(2, 16, 1),
            entry(1, 24, 1),
        ];
        assert_eq!(unique_prefixes(&entries), 3);
        assert_eq!(unique_prefixes(&[]), 0);
    }
}
