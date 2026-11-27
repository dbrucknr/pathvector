//! Composition root: builds [`DaemonState`], starts every adapter around it
//! and hands control to the event loop.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use pathvector_session::{
    message::UpdateMessage,
    transport::{
        self, DEFAULT_CONNECT_RETRY_TIME, SendHoldTime, SessionCommand, SessionConfig,
        SessionEvent, SessionHandle, listener::ListenerKeys, tcp_md5::Md5Enforcement,
    },
};
use tokio::sync::{RwLock, mpsc, watch};

use super::{
    DaemonCommand, DaemonState,
    capabilities::{
        Md5Keys, SpawnConfig, build_local_capabilities, session_tcp_md5, set_listener_key,
        warn_if_md5_best_effort,
    },
    deferral::SelectionDeferral,
    event_loop::{forward_events, run_event_loop},
    fib::withdraw_stale_bgp_routes,
    peer::{run_bgp_listener, run_command_processor},
    peering::{
        config_peer_type, effective_confederation_member, effective_role, effective_session_as,
    },
    rpki_feed::install_rpki,
};
use crate::{config, fib as crate_fib, grpc};

pub(crate) async fn run(cfg: config::Config) {
    run_with(cfg, transport::spawn).await;
}

pub(crate) async fn run_with<H, F>(cfg: config::Config, spawn_fn: F)
where
    H: SessionHandle + 'static,
    F: Fn(SessionConfig) -> H + Clone + Send + Sync + 'static,
{
    let daemon_start = std::time::Instant::now();
    let grpc_port = cfg.daemon.grpc_port;
    let bgp_port = cfg.daemon.bgp_port;
    let metrics_port = cfg.daemon.metrics_port;
    let fib_table = cfg.daemon.fib_table;
    let fib_metric = cfg.daemon.fib_metric;
    let local_as = cfg.daemon.local_as;
    let local_bgp_id = cfg.daemon.bgp_id;
    let hold_time = cfg.daemon.hold_time;
    let (state, event_rx, event_tx, stop_senders, incoming_senders, md5_passwords) =
        build_daemon(&cfg, spawn_fn.clone()).await;

    let kernel = start_kernel_fib(fib_table, fib_metric).await;
    let fib_change_rx = kernel.changes;

    // Wire the live oracle and FIB writer into the daemon state now that
    // KernelFib is initialised.  Sessions have not yet started, so no
    // best-path recomputes are in flight — the update is safe.
    {
        let mut guard = state.write().await;
        #[cfg(target_os = "linux")]
        guard.set_oracles(kernel.oracle_v4, kernel.oracle_v6);
        if let Some(writer) = kernel.writer {
            guard.fib_manager = Some(Arc::new(crate_fib::FibManager::new(writer)));
        }
        guard.selection_deferral =
            SelectionDeferral::new(daemon_start, cfg.daemon.selection_deferral_time);
    }

    // Channel for gRPC → event-loop command injection (AddPeer / RemovePeer).
    let (cmd_tx, cmd_rx) = mpsc::channel::<DaemonCommand>(32);

    // Spawn the gRPC management API server alongside the BGP event loop.
    let grpc_state = Arc::clone(&state);
    let grpc_stop_senders = Arc::clone(&stop_senders);
    tokio::spawn(async move {
        grpc::serve(grpc_state, grpc_port, cmd_tx, grpc_stop_senders).await;
    });

    start_metrics(metrics_port, &cfg.peers);
    start_rpki(cfg.daemon.rpki.clone(), &state).await;
    start_bgp_listeners(bgp_port, &incoming_senders, &md5_passwords);

    // Spawn the command processor that handles AddPeer / RemovePeer at runtime.
    {
        let state_cmd = Arc::clone(&state);
        let stop_cmd = Arc::clone(&stop_senders);
        let incoming_cmd = Arc::clone(&incoming_senders);
        let keys_cmd = Arc::clone(&md5_passwords);
        let peer_store = cfg
            .sidecar_path
            .as_ref()
            .map(|p| Arc::new(config::DynamicPeerStore::new(p.clone())));
        let proc_handle = tokio::spawn(run_command_processor(
            cmd_rx,
            state_cmd,
            stop_cmd,
            incoming_cmd,
            keys_cmd,
            event_tx,
            spawn_fn,
            SpawnConfig {
                local_as,
                local_bgp_id,
                hold_time,
                graceful_restart_time: cfg.daemon.graceful_restart_time,
                configured_restarting: cfg.daemon.restarting,
                confederation_id: cfg.daemon.confederation_id,
                startup_instant: daemon_start, // R-bit expires after graceful_restart_time secs
                md5_enforcement: cfg.daemon.tcp_md5_enforcement.into(),
            },
            peer_store,
        ));
        // Log a clear error if the command processor panics so operators know
        // why AddPeer / RemovePeer gRPC calls are failing.
        tokio::spawn(async move {
            if let Err(e) = proc_handle.await {
                tracing::error!(
                    error = %e,
                    "command processor task panicked — AddPeer/RemovePeer are unavailable"
                );
            }
        });
    }

    run_event_loop(event_rx, state, stop_senders, Some(fib_change_rx)).await;
}

/// What [`start_kernel_fib`] hands back for wiring into the daemon.
struct KernelFibParts {
    #[cfg(target_os = "linux")]
    oracle_v4: crate_fib::DaemonOracle,
    #[cfg(target_os = "linux")]
    oracle_v6: crate_fib::DaemonOracle,
    /// `None` when the kernel route table cannot be written.
    writer: Option<pathvector_sys::FibWriter>,
    changes: watch::Receiver<()>,
}

/// Starts kernel FIB tracking and opens the route writer, after removing any
/// BGP routes a previous run left behind.
async fn start_kernel_fib(fib_table: u32, fib_metric: u32) -> KernelFibParts {
    // Spawn the kernel FIB tracker and install the FibManager.
    //
    // KernelFib dumps the initial routing table and then tracks RTM_NEWROUTE /
    // RTM_DELROUTE events; KernelOracle exposes the snapshot for next-hop
    // reachability queries.  FibWriter handles the write side (route install /
    // remove).  On non-Linux platforms both are no-ops.
    let (kernel_fib, fib_change_rx) = pathvector_sys::KernelFib::new(fib_table);
    // oracle() takes &self; build oracles before spawn() moves kernel_fib into
    // the background task.  Only constructed on Linux where spawn() actually
    // populates the FIB snapshot via rtnetlink — on non-Linux the snapshot stays
    // empty (stub spawn is a no-op), so wiring DaemonOracle would mark every
    // next-hop unreachable and silently drop all peer routes from best-path
    // selection.  AlwaysReachable (the DaemonState default) is correct there.
    #[cfg(target_os = "linux")]
    let oracle_v4 = crate_fib::DaemonOracle(kernel_fib.oracle());
    #[cfg(target_os = "linux")]
    let oracle_v6 = crate_fib::DaemonOracle(kernel_fib.oracle());

    let fib_writer = match pathvector_sys::FibWriter::new(fib_table, fib_metric) {
        Ok(w) => {
            // Gap 4: delete any RTPROT_BGP routes left by a previous daemon run
            // before the event loop starts. See `withdraw_stale_bgp_routes`.
            match kernel_fib.stale_bgp_routes().await {
                Ok((stale_v4, stale_v6)) => {
                    if !stale_v4.is_empty() || !stale_v6.is_empty() {
                        tracing::info!(
                            v4 = stale_v4.len(),
                            v6 = stale_v6.len(),
                            "removing stale BGP routes from previous run"
                        );
                    }
                    withdraw_stale_bgp_routes(stale_v4, stale_v6, &w).await;
                }
                Err(e) => {
                    tracing::warn!("failed to query stale BGP routes: {e}");
                }
            }
            // The supervisor recovers from netlink loss on its own and
            // reports through the status channel; it returns only if no
            // netlink socket can be opened at all.
            tokio::spawn(crate_fib::log_fib_status(kernel_fib.status()));
            tokio::spawn(async move {
                if let Err(e) = kernel_fib.spawn().await {
                    tracing::error!(
                        "kernel FIB tracking unavailable: {e} — next-hop reachability will \
                         not reflect the kernel routing table"
                    );
                }
            });
            Some(w)
        }
        Err(e) => {
            tracing::warn!(
                "FIB integration unavailable: {e} — running without kernel route install"
            );
            None
        }
    };

    KernelFibParts {
        #[cfg(target_os = "linux")]
        oracle_v4,
        #[cfg(target_os = "linux")]
        oracle_v6,
        writer: fib_writer,
        changes: fib_change_rx,
    }
}

/// Starts the Prometheus endpoint when a port is configured, and publishes
/// the series that must exist before any event has happened.
fn start_metrics(metrics_port: Option<u16>, peers: &[config::PeerConfig]) {
    // Install Prometheus metrics endpoint when configured.  A bind failure
    // (e.g. port already in use) degrades observability only — BGP session
    // management and route propagation do not depend on it — so we log and
    // continue rather than crash the daemon, matching the FIB integration's
    // failure-handling pattern above.
    if let Some(port) = metrics_port {
        match crate::metrics::install(port) {
            Ok(()) => {
                // Pre-register every statically-configured peer so a peer
                // that never reaches Established (misconfigured, unreachable)
                // is still visible as "down" rather than having no metrics
                // series at all — see metrics.rs's `register_peer` doc comment.
                for peer in peers {
                    crate::metrics::register_peer(peer.address);
                }
                // Same reasoning for the global Loc-RIB gauges: update_rib_sizes
                // is only called from event-driven sites (post-Established,
                // post-flush), so a daemon with zero established peers would
                // otherwise show no Loc-RIB size at all instead of a real 0.
                crate::metrics::update_rib_sizes(0, 0, &HashMap::new());
                // Same reasoning again for self-originated routes: only
                // touched by origination.rs's event-driven functions, so a
                // daemon that has not yet originated anything would
                // otherwise show no series at all instead of a real 0.
                crate::metrics::update_originated_routes(0, 0);
                // Same reasoning again for the kernel FIB gauge: only touched
                // by fib::process_batch's event-driven success arms, so a
                // daemon that has not yet written anything to the kernel
                // would otherwise show no series at all instead of a real 0.
                crate::metrics::init_fib_routes_installed();
            }
            Err(e) => {
                tracing::warn!(
                    port,
                    error = %e,
                    "metrics endpoint unavailable — running without Prometheus export"
                );
            }
        }
    }
}

/// Spawns the RPKI RTR client when configured.
async fn start_rpki(rpki: Option<config::RpkiConfig>, state: &Arc<RwLock<DaemonState>>) {
    // Spawn the RPKI RTR client when configured. Unlike FibWriter::new (sync,
    // fails fast), this is async-forever — there's no Result to match at
    // spawn time. "Failure" (connect refused, version mismatch, etc.)
    // surfaces later via RtrStatus.connected == false, which is why the
    // read-only gRPC/CLI status surface matters for operator visibility.
    if let Some(rpki_cfg) = rpki {
        let (handle, _join) = pathvector_rpki::RtrClient::spawn(pathvector_rpki::RtrConfig {
            host: rpki_cfg.host.clone(),
            port: rpki_cfg.port,
            ..Default::default()
        });
        install_rpki(handle, rpki_cfg.reject_invalid, state).await;
        tracing::info!(
            host = %rpki_cfg.host,
            port = rpki_cfg.port,
            reject_invalid = rpki_cfg.reject_invalid,
            "RPKI RTR client started"
        );
    }
}

/// Spawns the IPv4 and IPv6 BGP listeners.
fn start_bgp_listeners(
    bgp_port: u16,
    incoming_senders: &Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>,
    md5_passwords: &Md5Keys,
) {
    // Spawn the BGP TCP listeners for inbound connections (RFC 4271 §6.8).
    // Two independent listeners (IPv4 and IPv6) rather than one dual-stack
    // socket — see run_bgp_listener's doc comment for why. Each family's
    // bind failure is independent, so e.g. an environment with IPv6 disabled
    // still gets a working IPv4 listener (dial-only for v6 in that case).
    {
        let incoming = Arc::clone(incoming_senders);
        let md5 = Arc::clone(md5_passwords);
        let bind_addr_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), bgp_port);
        tokio::spawn(async move {
            run_bgp_listener(bind_addr_v4, incoming, md5).await;
        });
    }
    {
        let incoming = Arc::clone(incoming_senders);
        let md5 = Arc::clone(md5_passwords);
        let bind_addr_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), bgp_port);
        tokio::spawn(async move {
            run_bgp_listener(bind_addr_v6, incoming, md5).await;
        });
    }
}

/// Sets up BGP sessions for every configured peer and constructs the initial
/// [`DaemonState`].
///
/// `spawn_fn` is called once per peer to create a [`SessionHandle`]; `start()`
/// is then called on each handle so the session task begins the TCP connect /
/// BGP open exchange.  The returned tuple contains:
///
/// - The shared daemon state (pre-populated with per-peer RIBs and policies).
/// - The event receiver that drains `(peer_ip, SessionEvent)` messages from
///   the per-peer forwarding tasks, and a sender for it.
/// - The stop-sender map so the event loop can close a session whose outbound
///   channel overflowed.
/// - The incoming-sender map the BGP listeners use to hand inbound
///   connections to sessions.
/// - The TCP MD5 key table for inbound connections, holding every static
///   peer's key. No listener is bound yet; each installs its family's keys
///   when it binds, before it listens.
///
/// Extracted from `run_with()` so it can be driven in tests by supplying a
/// mock `spawn_fn` — no real TCP sockets needed.
pub(crate) async fn build_daemon<H, F>(
    cfg: &config::Config,
    spawn_fn: F,
) -> (
    Arc<RwLock<DaemonState>>,
    mpsc::Receiver<(IpAddr, SessionEvent)>,
    mpsc::Sender<(IpAddr, SessionEvent)>, // kept alive for AddPeer forwarding
    Arc<Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>,
    Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>,
    Md5Keys, // RFC 2385 keys for inbound connections
)
where
    H: SessionHandle,
    F: Fn(SessionConfig) -> H,
{
    let local_as = cfg.daemon.local_as;
    let local_bgp_id = cfg.daemon.bgp_id;

    let (event_tx, event_rx) = mpsc::channel::<(IpAddr, SessionEvent)>(256);
    let mut update_senders: HashMap<IpAddr, mpsc::Sender<UpdateMessage>> = HashMap::new();
    // stop_senders: shared with the command processor so AddPeer/RemovePeer can
    // insert/remove without touching the event loop directly.
    let stop_senders: Arc<Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    // incoming_senders: shared with the BGP listener so AddPeer immediately
    // accepts inbound connections from newly configured peers.
    let incoming_senders: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    // md5_passwords: TCP MD5 keys for inbound connections. The listeners
    // install them on their sockets when they bind, before listening.
    let md5_passwords: Md5Keys = Arc::new(ListenerKeys::default());
    let md5_enforcement = Md5Enforcement::from(cfg.daemon.tcp_md5_enforcement);
    warn_if_md5_best_effort(md5_enforcement, &cfg.peers);

    // Capture startup instant here; used to expire the R-bit window per-session.
    let startup_instant = std::time::Instant::now();

    for peer in &cfg.peers {
        let confed_member = effective_confederation_member(peer, cfg.daemon.confederation_id);
        let peer_type = config_peer_type(local_as, peer.remote_as, confed_member);
        let public_as = effective_session_as(local_as, cfg.daemon.confederation_id, peer_type);
        // Recompute capabilities for each session so the R-bit correctly reflects
        // elapsed time since startup (RFC 4724 §3: R-bit must be cleared after restart).
        let capabilities = build_local_capabilities(
            public_as,
            cfg.daemon.graceful_restart_time,
            cfg.daemon.restarting
                && cfg.daemon.graceful_restart_time > 0
                && startup_instant.elapsed()
                    < std::time::Duration::from_secs(u64::from(cfg.daemon.graceful_restart_time)),
            effective_role(peer, local_as),
        );
        let session_cfg = SessionConfig {
            local_as,
            public_as,
            local_bgp_id,
            hold_time: peer.hold_time.unwrap_or(cfg.daemon.hold_time),
            capabilities,
            required_capabilities: vec![],
            peer_as: Some(peer.remote_as),
            confederation_member: confed_member,
            peer_addr: SocketAddr::new(peer.address, peer.port),
            tcp_md5: session_tcp_md5(peer, md5_enforcement),
            connect_retry_time: peer
                .connect_retry_time
                .map_or(DEFAULT_CONNECT_RETRY_TIME, |s| {
                    std::time::Duration::from_secs(u64::from(s))
                }),
            // RFC 9687 §6 RECOMMENDS enabling it without configuration.
            send_hold_time: SendHoldTime::RECOMMENDED,
        };

        // The listener key is configured before the peer can appear in
        // incoming_senders.
        if let Some(auth) = session_tcp_md5(peer, md5_enforcement) {
            set_listener_key(&md5_passwords, peer.address, auth);
        }

        let handle = spawn_fn(session_cfg);
        handle.start().await;

        update_senders.insert(peer.address, handle.update_sender());
        stop_senders
            .lock()
            .unwrap()
            .insert(peer.address, handle.stop_sender());
        incoming_senders
            .write()
            .await
            .insert(peer.address, handle.incoming_sender());
        tokio::spawn(forward_events(handle, peer.address, event_tx.clone()));
    }
    // Keep a clone of event_tx alive; the caller returns it so the command
    // processor can forward events from dynamically added sessions.  The
    // channel closes when every forwarding task exits AND this clone is dropped.

    // Build a reference capability set for DaemonState.config_capabilities.
    // This is used to check whether we advertise GR (for the "peer doesn't
    // support GR" warning in on_established) — not for per-session OPENs.
    // The R-bit is not relevant here; we use restarting=false.
    let config_capabilities =
        build_local_capabilities(local_as, cfg.daemon.graceful_restart_time, false, None);
    let state = Arc::new(RwLock::new(DaemonState::new(
        local_as,
        local_bgp_id,
        cfg.daemon.local_ipv6,
        cfg.daemon.cluster_id,
        cfg.daemon.confederation_id,
        &cfg.peers,
        update_senders,
        config_capabilities,
    )));

    (
        state,
        event_rx,
        event_tx,
        stop_senders,
        incoming_senders,
        md5_passwords,
    )
}
