use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use pathvector_session::message::{PathAttribute, UpdateMessage};
use pathvector_session::transport::{
    SessionCommand, SessionConfig, SessionEvent, SessionHandle, TerminationReason,
};
use pathvector_types::{AsPath, Asn, Origin, PeerType};
use tokio::sync::mpsc;

use crate::config;
use crate::daemon::*;

// ── MockSessionHandle ─────────────────────────────────────────────────────

/// A zero-cost session handle for unit tests: no TCP, no background tasks.
///
/// Events are injected through a channel whose sender is held by
/// [`MockPeer`]; `start()` records that it was called via an `AtomicBool`.
struct MockSessionHandle {
    event_rx: mpsc::Receiver<SessionEvent>,
    update_tx: mpsc::Sender<UpdateMessage>,
    stop_tx: mpsc::Sender<SessionCommand>,
    started: Arc<AtomicBool>,
}

impl SessionHandle for MockSessionHandle {
    async fn start(&self) {
        self.started.store(true, Ordering::SeqCst);
    }

    async fn next_event(&mut self) -> Option<SessionEvent> {
        self.event_rx.recv().await
    }

    fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
        self.update_tx.clone()
    }

    fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
        self.stop_tx.clone()
    }

    fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
        self.stop_tx.clone()
    }

    async fn send_route_refresh(&self, _rr: pathvector_session::message::RouteRefreshMessage) {}

    async fn set_capabilities(&self, _caps: Vec<pathvector_session::message::Capability>) {}
}

/// Test-side view of a spawned mock session.
struct MockPeer {
    /// Send events into the forwarding task that `build_daemon` spawned.
    event_tx: mpsc::Sender<SessionEvent>,
    /// `true` after `start()` has been called on the handle.
    started: Arc<AtomicBool>,
}

/// Returns a `spawn_fn` compatible with [`build_daemon`] together with a
/// shared list that is appended to on each invocation.
fn make_mock_spawn() -> (
    impl Fn(SessionConfig) -> MockSessionHandle,
    Arc<Mutex<Vec<MockPeer>>>,
) {
    let peers: Arc<Mutex<Vec<MockPeer>>> = Arc::new(Mutex::new(vec![]));
    let peers_clone = Arc::clone(&peers);
    let spawn_fn = move |_cfg: SessionConfig| {
        let (event_tx, event_rx) = mpsc::channel(8);
        let (update_tx, _update_rx) = mpsc::channel(8);
        let (stop_tx, _stop_rx) = mpsc::channel(8);
        let started = Arc::new(AtomicBool::new(false));
        peers_clone.lock().unwrap().push(MockPeer {
            event_tx,
            started: Arc::clone(&started),
        });
        MockSessionHandle {
            event_rx,
            update_tx,
            stop_tx,
            started,
        }
    };
    (spawn_fn, peers)
}

fn make_config(peer_ips: &[(IpAddr, u32)]) -> config::Config {
    config::Config {
        daemon: config::DaemonConfig {
            local_as: 65001,
            bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            hold_time: 90,
            grpc_port: 0,
            bgp_port: 0, // 0 = OS assigns; listener will fail to bind but tests don't need it
            metrics_port: None,
            local_ipv6: None,
            cluster_id: None,
            confederation_id: None,
            fib_table: 254,
            fib_metric: 20,
            graceful_restart_time: 0,
            restarting: false,
            selection_deferral_time: 0,
            rpki: None,
            tcp_md5_enforcement: config::TcpMd5EnforcementConfig::Required,
        },
        peers: peer_ips
            .iter()
            .map(|&(address, remote_as)| config::PeerConfig {
                address,
                port: 179,
                remote_as,
                import_default: None,
                export_default: None,
                import_default_v6: None,
                md5_password: None,
                is_rr_client: false,
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
                confederation_member: false,
                blackhole_authorized_prefixes: None,
            })
            .collect(),
        sidecar_path: None,
    }
}

// ── tests ─────────────────────────────────────────────────────────────────

/// `DaemonState.rpki` starts `None` when `[daemon.rpki]` is absent — the
/// common case for most deployments. Confirms `build_daemon` never
/// populates it unprompted.
#[tokio::test]
async fn daemon_state_rpki_is_none_when_unconfigured() {
    let (spawn_fn, _peers) = make_mock_spawn();
    let cfg = make_config(&[]);
    let (state, ..) = build_daemon(&cfg, spawn_fn).await;
    assert!(state.read().await.rpki.is_none());
}

/// Mirrors the exact spawn-and-wire sequence `run_with` performs for
/// `[daemon.rpki]`, pointed at a closed port. `RtrClient::spawn` must
/// return immediately regardless of whether the TCP connect will
/// eventually succeed — confirms the RPKI wiring can never block daemon
/// startup, matching the FIB/metrics graceful-degradation pattern.
#[tokio::test]
async fn rpki_client_spawn_never_blocks_and_populates_daemon_state() {
    let (spawn_fn, _peers) = make_mock_spawn();
    let cfg = make_config(&[]);
    let (state, ..) = build_daemon(&cfg, spawn_fn).await;

    let spawn_started = std::time::Instant::now();
    let (handle, _join) = pathvector_rpki::RtrClient::spawn(pathvector_rpki::RtrConfig {
        host: "127.0.0.1".to_string(),
        port: 1, // reserved; nothing listens here — connect will fail
        ..Default::default()
    });
    assert!(
        spawn_started.elapsed() < std::time::Duration::from_millis(100),
        "RtrClient::spawn must return immediately, not block on the TCP connect"
    );

    state.write().await.rpki = Some(handle);
    assert!(state.read().await.rpki.is_some());
}

/// Exercises the exact production wiring in `install_rpki` (the
/// function `run_with` calls) end-to-end: a route accepted while the
/// ROA cache is empty must be automatically rejected once the cache
/// changes — *without* the test calling `reevaluate_all_import_policies`
/// itself. Proves the background task `install_rpki` spawns actually
/// fires, not just that the method it calls is correct in isolation
/// (already covered directly in `daemon::tests`).
///
/// Uses a `for_testing()`/`insert_roa_v4`-driven handle rather than a
/// real TCP RTR server — the wire protocol itself is already covered by
/// `pathvector-rpki`'s own mock-server tests; this test is only
/// responsible for proving pathvectord's reaction to a cache change.
#[tokio::test]
async fn rpki_reactive_task_reevaluates_on_cache_change() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (spawn_fn, _peers) = make_mock_spawn();
    let mut cfg = make_config(&[(peer_ip, 65002)]);
    // RFC 8212 default-rejects eBGP peers with no explicit import policy —
    // opt this peer in to accept-by-default so ROV alone governs whether
    // the test route is accepted.
    cfg.peers[0].import_default = Some(config::ImportDefault::Accept);
    let (state, ..) = build_daemon(&cfg, spawn_fn).await;

    let rtr = pathvector_rpki::for_testing(std::iter::empty(), std::iter::empty());
    install_rpki(rtr.clone(), true, &state).await;

    let nlri: pathvector_types::Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
    {
        let mut guard = state.write().await;
        guard.on_established(
            peer_ip,
            must_v4(peer_ip),
            PeerType::External,
            65002,
            90,
            &[],
            None,
        );
        guard.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(must_v4(peer_ip)),
                ],
                announced: vec![nlri],
            },
        );
    }
    assert!(
        state.read().await.rib.loc_rib.best(&nlri).is_some(),
        "route should be accepted while the cache is still empty (NotFound)"
    );

    // A ROA arrives making the already-accepted route Invalid. Nothing
    // in this test calls reevaluate_all_import_policies — only the
    // background task install_rpki spawned should react.
    rtr.insert_roa_v4(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 99999);

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if state.read().await.rib.loc_rib.best(&nlri).is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reactive task did not reject the route within 5s of the cache change");
}

/// Regression test for a subscribe-after-spawn race: `RtrClient::spawn`
/// starts its background sync task before `install_rpki` gets a chance
/// to call `handle.subscribe()`, so if the first sync completes first,
/// its `watch` notification is sent to no receiver and would otherwise
/// be silently missed — leaving an already-accepted-but-now-Invalid
/// route unrejected until the next unrelated cache change.
///
/// `for_testing()` conveniently starts in exactly that "sync already
/// happened" state (`status().connected == true`, ROA data already
/// loaded, no watch notification ever fired for it) — a deterministic
/// stand-in for the race, no real timing dependency needed. The route
/// must be rejected the instant `install_rpki` returns, without this
/// test ever calling `reevaluate_all_import_policies` or
/// `insert_roa_v4` (which would exercise the normal, already-covered
/// watch-notification path instead of the eager catch-up check).
#[tokio::test]
async fn install_rpki_catches_up_when_first_sync_precedes_subscribe() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (spawn_fn, _peers) = make_mock_spawn();
    let mut cfg = make_config(&[(peer_ip, 65002)]);
    cfg.peers[0].import_default = Some(config::ImportDefault::Accept);
    let (state, ..) = build_daemon(&cfg, spawn_fn).await;

    let nlri: pathvector_types::Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
    {
        let mut guard = state.write().await;
        guard.on_established(
            peer_ip,
            must_v4(peer_ip),
            PeerType::External,
            65002,
            90,
            &[],
            None,
        );
        guard.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(must_v4(peer_ip)),
                ],
                announced: vec![nlri],
            },
        );
    }
    assert!(
        state.read().await.rib.loc_rib.best(&nlri).is_some(),
        "route should be accepted before RPKI is installed at all"
    );

    // Already "synced" before install_rpki ever calls subscribe() —
    // stands in for the background task's first sync winning the race.
    let rtr = pathvector_rpki::for_testing(
        [(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 99999)],
        std::iter::empty(),
    );
    install_rpki(rtr, true, &state).await;

    assert!(
        state.read().await.rib.loc_rib.best(&nlri).is_none(),
        "install_rpki must eagerly re-evaluate once if the handle was already \
         synced when subscribe() was called, not only react to later changes"
    );
}

/// `build_daemon` calls the spawn function exactly once per configured peer.
#[tokio::test]
async fn build_daemon_calls_spawn_once_per_peer() {
    let (spawn_fn, peers) = make_mock_spawn();
    let cfg = make_config(&[
        (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65002),
        (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65003),
    ]);
    let _ = build_daemon(&cfg, spawn_fn).await;
    assert_eq!(peers.lock().unwrap().len(), 2);
}

/// `build_daemon` calls `start()` on every handle it spawns.
#[tokio::test]
async fn build_daemon_starts_each_session() {
    let (spawn_fn, peers) = make_mock_spawn();
    let cfg = make_config(&[
        (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65002),
        (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65003),
    ]);
    let _ = build_daemon(&cfg, spawn_fn).await;
    for peer in peers.lock().unwrap().iter() {
        assert!(peer.started.load(Ordering::SeqCst), "start() not called");
    }
}

/// The returned stop-sender map contains an entry for every peer address.
#[tokio::test]
async fn build_daemon_provides_stop_sender_per_peer() {
    let peer_a = Ipv4Addr::new(10, 0, 0, 1);
    let peer_b = Ipv4Addr::new(10, 0, 0, 2);
    let (spawn_fn, _peers) = make_mock_spawn();
    let cfg = make_config(&[(IpAddr::V4(peer_a), 65002), (IpAddr::V4(peer_b), 65003)]);
    let (_state, _rx, _event_tx, stop_senders, _, _) = build_daemon(&cfg, spawn_fn).await;
    assert!(
        stop_senders
            .lock()
            .unwrap()
            .contains_key(&IpAddr::V4(peer_a))
    );
    assert!(
        stop_senders
            .lock()
            .unwrap()
            .contains_key(&IpAddr::V4(peer_b))
    );
}

/// An event injected through a mock peer's sender appears on the returned
/// event receiver — verifying the per-peer forwarding task is wired up.
#[tokio::test]
async fn build_daemon_forwards_events_to_receiver() {
    let peer_a = Ipv4Addr::new(10, 0, 0, 1);
    let (spawn_fn, peers) = make_mock_spawn();
    let cfg = make_config(&[(IpAddr::V4(peer_a), 65002)]);
    let (_state, mut event_rx, _event_tx, _stop, _, _) = build_daemon(&cfg, spawn_fn).await;

    let event_tx = peers.lock().unwrap()[0].event_tx.clone();
    event_tx
        .send(SessionEvent::Terminated(TerminationReason::Unclean))
        .await
        .unwrap();

    let (ip, event) = event_rx.recv().await.unwrap();
    assert_eq!(ip, peer_a);
    assert!(matches!(event, SessionEvent::Terminated(_)));
}

/// The returned `DaemonState` has an update-sender entry for every
/// configured peer — i.e. the state is fully pre-populated at startup.
#[tokio::test]
async fn build_daemon_state_has_entry_per_peer() {
    let peer_a = Ipv4Addr::new(10, 0, 0, 1);
    let peer_b = Ipv4Addr::new(10, 0, 0, 2);
    let (spawn_fn, _peers) = make_mock_spawn();
    let cfg = make_config(&[(IpAddr::V4(peer_a), 65002), (IpAddr::V4(peer_b), 65003)]);
    let (state, _rx, _event_tx, _stop, _, _) = build_daemon(&cfg, spawn_fn).await;
    let s = state.read().await;
    assert!(s.update_senders.contains_key(&IpAddr::V4(peer_a)));
    assert!(s.update_senders.contains_key(&IpAddr::V4(peer_b)));
}

/// With no configured peers `build_daemon` succeeds and the event receiver
/// closes immediately (all senders were dropped, no peers to forward from).
#[tokio::test]
async fn build_daemon_no_peers_closes_event_channel() {
    let (spawn_fn, peers) = make_mock_spawn();
    let cfg = make_config(&[]);
    let (_state, mut event_rx, event_tx, _stop, _, _) = build_daemon(&cfg, spawn_fn).await;
    assert_eq!(peers.lock().unwrap().len(), 0);
    // Drop the returned event_tx; since there are no per-peer forwarding
    // tasks, no other senders remain and recv() returns None.
    drop(event_tx);
    assert!(event_rx.recv().await.is_none());
}

// ── TCP MD5 wiring tests ──────────────────────────────────────────────────

/// A peer configured with `md5_password` must appear in the password map
/// returned by `build_daemon` so `run_bgp_listener` can apply the key to
/// the listener socket before any SYN arrives.
#[tokio::test]
async fn build_daemon_md5_password_present_in_map() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (spawn_fn, _peers) = make_mock_spawn();

    let mut cfg = make_config(&[(peer_ip, 65002)]);
    cfg.peers[0].md5_password = Some("s3cr3t".parse().unwrap());

    let (_state, _rx, _event_tx, _stop, _incoming, md5_passwords) =
        build_daemon(&cfg, spawn_fn).await;

    assert_eq!(
        md5_passwords.configured(peer_ip),
        Some(TcpMd5Auth::required("s3cr3t".parse().unwrap())),
        "MD5 key must be present in the listener key table"
    );
}

/// A peer without `md5_password` must not appear in the password map.
#[tokio::test]
async fn build_daemon_no_md5_password_absent_from_map() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (spawn_fn, _peers) = make_mock_spawn();
    let cfg = make_config(&[(peer_ip, 65002)]); // md5_password = None

    let (_state, _rx, _event_tx, _stop, _incoming, md5_passwords) =
        build_daemon(&cfg, spawn_fn).await;

    assert_eq!(
        md5_passwords.configured(peer_ip),
        None,
        "no MD5 password configured → no listener key"
    );
}

/// When multiple peers are configured, only the ones with a password appear
/// in the map; the others are absent.
#[tokio::test]
async fn build_daemon_md5_map_contains_only_configured_peers() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (spawn_fn, _peers) = make_mock_spawn();

    let mut cfg = make_config(&[(IpAddr::V4(peer_a), 65002), (IpAddr::V4(peer_b), 65003)]);
    cfg.peers[0].md5_password = Some("key-for-a".parse().unwrap());
    // peer_b has no password

    let (_state, _rx, _event_tx, _stop, _incoming, md5_passwords) =
        build_daemon(&cfg, spawn_fn).await;
    assert_eq!(
        md5_passwords.configured(IpAddr::V4(peer_a)),
        Some(TcpMd5Auth::required("key-for-a".parse().unwrap())),
    );
    assert_eq!(
        md5_passwords.configured(IpAddr::V4(peer_b)),
        None,
        "peer_b has no MD5 password and must not be in the table"
    );
}

/// `md5_password` is threaded into `SessionConfig` so the outbound connect
/// task can apply `TCP_MD5SIG` before dialling the peer. Verify the value
/// reaches the spawned session config.
#[tokio::test]
async fn build_daemon_md5_password_reaches_session_config() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();

    // Capture the SessionConfig that build_daemon passes to spawn_fn.
    let captured: std::sync::Arc<
        std::sync::Mutex<Option<pathvector_session::transport::SessionConfig>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(None));
    let captured_clone = std::sync::Arc::clone(&captured);

    let (base_spawn, _peers) = make_mock_spawn();
    let spawn_fn = move |cfg: pathvector_session::transport::SessionConfig| {
        *captured_clone.lock().unwrap() = Some(cfg.clone());
        base_spawn(cfg)
    };

    let mut config = make_config(&[(peer_ip, 65002)]);
    config.peers[0].md5_password = Some("session-key".parse().unwrap());

    build_daemon(&config, spawn_fn).await;

    let session_cfg = captured
        .lock()
        .unwrap()
        .take()
        .expect("spawn_fn must be called");
    assert_eq!(
        session_cfg.tcp_md5,
        Some(TcpMd5Auth::required("session-key".parse().unwrap())),
        "md5_password must reach SessionConfig with enforcement required by default"
    );
}

/// `[daemon] tcp_md5_enforcement = "best-effort"` is the only way a
/// session may connect without enforcement (issue #58: the fallback must
/// be an explicit choice). It must reach the static peer's session and
/// the listener key table unchanged.
#[tokio::test]
async fn build_daemon_best_effort_md5_reaches_session_config() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let captured: std::sync::Arc<
        std::sync::Mutex<Option<pathvector_session::transport::SessionConfig>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(None));
    let captured_clone = std::sync::Arc::clone(&captured);
    let (base_spawn, _peers) = make_mock_spawn();
    let spawn_fn = move |cfg: pathvector_session::transport::SessionConfig| {
        *captured_clone.lock().unwrap() = Some(cfg.clone());
        base_spawn(cfg)
    };

    let mut config = make_config(&[(peer_ip, 65002)]);
    config.daemon.tcp_md5_enforcement = config::TcpMd5EnforcementConfig::BestEffort;
    config.peers[0].md5_password = Some("session-key".parse().unwrap());

    let (_state, _rx, _event_tx, _stop, _incoming, md5_passwords) =
        build_daemon(&config, spawn_fn).await;

    let expected = TcpMd5Auth::new("session-key".parse().unwrap(), Md5Enforcement::BestEffort);
    let session_cfg = captured.lock().unwrap().take().unwrap();
    assert_eq!(session_cfg.tcp_md5.as_ref(), Some(&expected));
    assert_eq!(md5_passwords.configured(peer_ip), Some(expected));
}

/// Dynamic peers (gRPC `AddPeer`) get the daemon-wide
/// `tcp_md5_enforcement` from `SpawnConfig`, the same as static peers, so
/// the unenforced fallback is never applied to one path but not the other.
#[tokio::test]
async fn add_peer_wires_md5_key_and_enforcement_into_session_config() {
    for enforcement in [Md5Enforcement::Required, Md5Enforcement::BestEffort] {
        let captured: Arc<Mutex<Option<SessionConfig>>> = Arc::new(Mutex::new(None));
        let captured_clone = Arc::clone(&captured);
        let (base_spawn, _peers) = make_mock_spawn();
        let spawn_fn = move |cfg: SessionConfig| {
            *captured_clone.lock().unwrap() = Some(cfg.clone());
            base_spawn(cfg)
        };

        let (unused_spawn, _) = make_mock_spawn();
        let (state, _rx, event_tx, stop_senders, incoming, md5) =
            build_daemon(&make_config(&[]), unused_spawn).await;
        let (cmd_tx, cmd_rx) = mpsc::channel(4);
        let processor = tokio::spawn(run_command_processor(
            cmd_rx,
            state,
            stop_senders,
            incoming,
            md5,
            event_tx,
            spawn_fn,
            SpawnConfig {
                local_as: 65001,
                local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
                hold_time: 90,
                graceful_restart_time: 0,
                configured_restarting: false,
                confederation_id: None,
                startup_instant: std::time::Instant::now(),
                md5_enforcement: enforcement,
            },
            None,
        ));

        let mut peer = make_config(&[("10.0.5.2".parse().unwrap(), 65050)])
            .peers
            .remove(0);
        peer.md5_password = Some("dyn-key".parse().unwrap());
        cmd_tx.send(DaemonCommand::AddPeer(peer)).await.unwrap();
        drop(cmd_tx);
        processor.await.unwrap();

        let session_cfg = captured.lock().unwrap().take().expect("session spawned");
        assert_eq!(
            session_cfg.tcp_md5,
            Some(TcpMd5Auth::new("dyn-key".parse().unwrap(), enforcement))
        );
    }
}

// ── NOTIFICATION pipeline: malformed UPDATE → SessionCommand ─────────────
//
// Variant of make_mock_spawn that also captures the stop_rx so tests can
// observe SessionCommand::Notification sent by the event loop.

/// Test-side view with access to the stop receiver.
struct MockPeerWithStop {
    event_tx: mpsc::Sender<SessionEvent>,
    /// The capability set the session was spawned with.
    spawn_capabilities: Vec<pathvector_session::message::Capability>,
    stop_rx: mpsc::Receiver<SessionCommand>,
    /// Keep the update receiver alive so `try_send` on the update channel
    /// does not fail with `TrySendError::Closed` when the EOR is sent.
    update_rx: mpsc::Receiver<UpdateMessage>,
}

fn make_mock_spawn_capturing_stop() -> (
    impl Fn(SessionConfig) -> MockSessionHandle,
    Arc<Mutex<Vec<MockPeerWithStop>>>,
) {
    let peers: Arc<Mutex<Vec<MockPeerWithStop>>> = Arc::new(Mutex::new(vec![]));
    let peers_clone = Arc::clone(&peers);
    let spawn_fn = move |cfg: SessionConfig| {
        let (event_tx, event_rx) = mpsc::channel(8);
        let (update_tx, update_rx) = mpsc::channel(8);
        let (stop_tx, stop_rx) = mpsc::channel(8);
        let started = Arc::new(AtomicBool::new(false));
        peers_clone.lock().unwrap().push(MockPeerWithStop {
            event_tx,
            spawn_capabilities: cfg.capabilities,
            stop_rx,
            update_rx,
        });
        MockSessionHandle {
            event_rx,
            update_tx,
            stop_tx,
            started,
        }
    };
    (spawn_fn, peers)
}

fn established_info_for_peer(peer_as: u32) -> SessionEvent {
    use pathvector_session::fsm::SessionInfo;
    use pathvector_session::message::Capability;
    use pathvector_types::PeerType;
    SessionEvent::Established(SessionInfo {
        peer_as,
        peer_bgp_id: Ipv4Addr::new(10, 0, 0, 2),
        hold_time: 90,
        peer_capabilities: vec![Capability::FourByteAsn(peer_as)],
        peer_type: PeerType::External,
        local_addr: None,
    })
}

/// RFC 7606 §3(d): "If any of the well-known mandatory attributes are
/// not present in an UPDATE message, then 'treat-as-withdraw' MUST be
/// used." A malformed UPDATE (missing ORIGIN) sent through the full
/// event loop must NOT result in a SessionCommand on the peer's stop
/// channel (no NOTIFICATION, session stays up), and the announced
/// prefix must not be installed in LocRib.
#[tokio::test]
async fn malformed_update_missing_origin_no_notification_route_not_installed() {
    use pathvector_session::message::PathAttribute;
    use pathvector_types::{AsPath, Asn};

    let peer_ip = Ipv4Addr::new(10, 0, 0, 2);
    let (spawn_fn, peers) = make_mock_spawn_capturing_stop();
    let cfg = make_config(&[(IpAddr::V4(peer_ip), 65002)]);
    let (state, event_rx, _event_tx, stop_senders, _, _) = build_daemon(&cfg, spawn_fn).await;
    let state_check = Arc::clone(&state);

    // Run the event loop in the background; inject events via the mock peer.
    tokio::spawn(run_event_loop(event_rx, state, stop_senders, None));

    // Allow the spawned task to start.
    tokio::task::yield_now().await;

    let (event_tx, mut stop_rx, _update_rx) = {
        let mut guard = peers.lock().unwrap();
        let p = guard.pop().expect("one peer spawned");
        (p.event_tx, p.stop_rx, p.update_rx)
    };

    // Establish the session so the daemon has peer state.
    event_tx
        .send(established_info_for_peer(65002))
        .await
        .unwrap();
    tokio::task::yield_now().await;

    let n: pathvector_types::Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();

    // Send a malformed UPDATE: announced NLRI but ORIGIN is absent.
    event_tx
        .send(SessionEvent::RouteUpdate(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                // No Origin!
            ],
            announced: vec![n],
        }))
        .await
        .unwrap();
    tokio::task::yield_now().await;

    // No SessionCommand (in particular, no Notification) must be sent —
    // treat-as-withdraw keeps the session up, unlike the pre-fix
    // session-reset behavior this test used to assert.
    let result = tokio::time::timeout(std::time::Duration::from_millis(300), stop_rx.recv()).await;
    assert!(
        result.is_err(),
        "expected no SessionCommand after a treat-as-withdraw UPDATE, got {result:?}"
    );

    // The malformed announcement must not have installed a route.
    assert!(
        state_check.read().await.rib.loc_rib.best(&n).is_none(),
        "RFC 7606 §2: prefix from an UPDATE missing a mandatory attribute \
         must not be installed in LocRib"
    );
}

// ── Reconnect capability refresh ──────────────────────────────────────────

/// On an unclean, non-removal termination, the event loop rebuilds and
/// resends this peer's capability set via `SessionCommand::SetCapabilities`
/// before the peer reconnects — so per-session dynamic state (the RFC 4724
/// R-bit, and RFC 9234 Role) survives a reconnect instead of reverting to
/// whatever `DaemonState::new()` computed once at startup.
///
/// This is the exact call site the Role reconnect fix (mirroring the
/// pre-existing GR R-bit fix) touches, but until now nothing exercised it
/// through the real event loop — every other capability test calls the
/// pure `build_local_capabilities`/`SpawnConfig::capabilities` functions
/// directly, never `run_event_loop` end-to-end. Closes the gap tracked in
/// `TODO.md` under "No event-loop integration test for the reconnect
/// capability-refresh path".
#[tokio::test]
async fn reconnect_resends_role_and_gr_capabilities_via_set_capabilities() {
    let peer_ip = Ipv4Addr::new(10, 0, 0, 2);
    let (spawn_fn, peers) = make_mock_spawn_capturing_stop();
    let mut cfg = make_config(&[(IpAddr::V4(peer_ip), 65002)]);
    cfg.daemon.graceful_restart_time = 120;
    cfg.peers[0].role = Some(config::PeerRole::Provider);
    let (state, event_rx, _event_tx, stop_senders, _, _) = build_daemon(&cfg, spawn_fn).await;

    tokio::spawn(run_event_loop(event_rx, state, stop_senders, None));
    tokio::task::yield_now().await;

    let (event_tx, mut stop_rx, _update_rx) = {
        let mut guard = peers.lock().unwrap();
        let p = guard.pop().expect("one peer spawned");
        (p.event_tx, p.stop_rx, p.update_rx)
    };

    // Establish, then terminate uncleanly (not an operator-initiated
    // removal) — this is the reconnect-eligible path.
    event_tx
        .send(established_info_for_peer(65002))
        .await
        .unwrap();
    tokio::task::yield_now().await;
    event_tx
        .send(SessionEvent::Terminated(TerminationReason::Unclean))
        .await
        .unwrap();

    let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), stop_rx.recv())
        .await
        .expect("timed out waiting for SessionCommand")
        .expect("stop channel closed without sending SetCapabilities");

    let caps = match cmd {
        SessionCommand::SetCapabilities(caps) => caps,
        other => panic!("expected SetCapabilities, got {other:?}"),
    };

    assert!(
        caps.iter()
            .any(|c| matches!(c, Capability::Role(Role::Provider))),
        "Role(Provider) must survive the reconnect capability refresh, got {caps:?}"
    );
    let (restart_flags, restart_time) = caps
        .iter()
        .find_map(|c| {
            if let Capability::GracefulRestart {
                restart_flags,
                restart_time,
                ..
            } = c
            {
                Some((*restart_flags, *restart_time))
            } else {
                None
            }
        })
        .expect("GracefulRestart capability must be present");
    assert_eq!(
        restart_time, 120,
        "restart_time must reflect the configured GR window"
    );
    assert_eq!(
        restart_flags & 0x08,
        0,
        "R-bit must always be 0 on reconnect — see `handle_session_terminated`"
    );
}

// ── Capability refresh for coalesced teardowns (GH #148) ──────────────────

const GR_PEER_A: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
const GR_PEER_B: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

/// Two peers on a daemon that has itself just restarted, so both sessions
/// are spawned with R=1 and F=0 (RFC 4724 §4.1).
async fn build_restarting_daemon() -> (
    Arc<RwLock<DaemonState>>,
    mpsc::Receiver<(IpAddr, SessionEvent)>,
    mpsc::Sender<(IpAddr, SessionEvent)>,
    Arc<Mutex<std::collections::HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>,
    MockPeerWithStop,
    MockPeerWithStop,
) {
    let (spawn_fn, peers) = make_mock_spawn_capturing_stop();
    let mut cfg = make_config(&[(GR_PEER_A, 65002), (GR_PEER_B, 65003)]);
    cfg.daemon.graceful_restart_time = 120;
    cfg.daemon.restarting = true;
    let (state, event_rx, event_tx, stop_senders, _, _) = build_daemon(&cfg, spawn_fn).await;
    // Mocks are pushed in `cfg.peers` order.
    let mut spawned = std::mem::take(&mut *peers.lock().unwrap()).into_iter();
    let a = spawned.next().expect("peer A spawned");
    let b = spawned.next().expect("peer B spawned");
    (state, event_rx, event_tx, stop_senders, a, b)
}

/// `(R bit set, F bit per advertised family)` of the GR capability.
fn restart_bits(
    caps: &[pathvector_session::message::Capability],
) -> (bool, Vec<(pathvector_types::AfiSafi, bool)>) {
    caps.iter()
        .find_map(|c| match c {
            pathvector_session::message::Capability::GracefulRestart {
                restart_flags,
                families,
                ..
            } => Some((
                restart_flags & 0x08 != 0,
                families
                    .iter()
                    .map(|f| (f.afi_safi, f.forwarding_preserved))
                    .collect(),
            )),
            _ => None,
        })
        .expect("GracefulRestart capability must be present")
}

async fn next_command(rx: &mut mpsc::Receiver<SessionCommand>) -> SessionCommand {
    tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for a SessionCommand")
        .expect("command channel closed")
}

/// RFC 4724 §4.2: in re-establishing a session the R bit "MUST NOT be set
/// unless the Receiving Speaker has restarted", and the F bit depends on the
/// actual forwarding state, which a session drop does not disturb (RFC 8538
/// §4: speakers SHOULD set F once re-established; with F clear the peer
/// deletes the routes it retained, RFC 4724 §4.2).
fn assert_post_session_drop_refresh(cmd: SessionCommand) {
    use pathvector_types::AfiSafi;
    let SessionCommand::SetCapabilities(caps) = cmd else {
        panic!("expected SetCapabilities, got {cmd:?}");
    };
    assert_eq!(
        restart_bits(&caps),
        (
            false,
            vec![(AfiSafi::IPV4_UNICAST, true), (AfiSafi::IPV6_UNICAST, true)]
        )
    );
}

fn assert_spawned_as_restarting(peer: &MockPeerWithStop) {
    let (r_bit, families) = restart_bits(&peer.spawn_capabilities);
    assert!(r_bit, "precondition: spawned with R=1");
    assert!(
        families.iter().all(|&(_, forwarding)| !forwarding),
        "precondition: spawned with F=0"
    );
}

/// Everything is queued before the loop starts, so peer B's teardown is
/// drained behind peer A's Established rather than starting a batch.
async fn queue_coalesced_teardown(event_tx: &mpsc::Sender<(IpAddr, SessionEvent)>) {
    for event in [
        (GR_PEER_A, established_info_for_peer(65002)),
        (GR_PEER_B, established_info_for_peer(65003)),
        (
            GR_PEER_B,
            SessionEvent::Terminated(TerminationReason::Unclean),
        ),
    ] {
        event_tx.send(event).await.unwrap();
    }
}

#[tokio::test]
async fn coalesced_teardown_refreshes_capabilities() {
    let (state, event_rx, event_tx, stop_senders, _a, mut b) = build_restarting_daemon().await;
    assert_spawned_as_restarting(&b);
    queue_coalesced_teardown(&event_tx).await;

    tokio::spawn(run_event_loop(event_rx, state, stop_senders, None));

    assert_post_session_drop_refresh(next_command(&mut b.stop_rx).await);
}

/// A later coalesced UPDATE that resets its session leaves the drain loop
/// early; refreshes already owed must still be sent on that path.
#[tokio::test]
async fn coalesced_teardown_refreshes_capabilities_when_batch_ends_in_notification() {
    let (state, event_rx, event_tx, stop_senders, mut a, mut b) = build_restarting_daemon().await;
    queue_coalesced_teardown(&event_tx).await;
    // Attributes, a missing ORIGIN and no NLRI: session reset
    // (RFC 7606 §5.2).
    event_tx
        .send((
            GR_PEER_A,
            SessionEvent::RouteUpdate(UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::AsPath(AsPath::from_sequence(vec![
                    Asn::new(65002),
                ]))],
                announced: vec![],
            }),
        ))
        .await
        .unwrap();

    tokio::spawn(run_event_loop(event_rx, state, stop_senders, None));

    assert_post_session_drop_refresh(next_command(&mut b.stop_rx).await);
    let cmd = next_command(&mut a.stop_rx).await;
    assert!(
        matches!(cmd, SessionCommand::AutomaticStop(_)),
        "precondition: the batch must end on the NOTIFICATION path, got {cmd:?}"
    );
}

/// A session that is slow to take commands must not stall every other user
/// of the state lock.
#[tokio::test]
async fn coalesced_capability_refresh_is_sent_without_the_state_lock() {
    let (state, event_rx, event_tx, stop_senders, _a, mut b) = build_restarting_daemon().await;
    let b_commands = stop_senders.lock().unwrap()[&GR_PEER_B].clone();
    while b_commands.try_send(SessionCommand::Stop).is_ok() {}
    queue_coalesced_teardown(&event_tx).await;

    tokio::spawn(run_event_loop(
        event_rx,
        Arc::clone(&state),
        stop_senders,
        None,
    ));

    // The refresh cannot be delivered until B's channel is drained, yet
    // the lock must become free once the teardown has been applied.
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            tokio::task::yield_now().await;
            if let Ok(s) = state.try_write()
                && s.rib.peer_types.contains_key(&GR_PEER_A)
                && !s.rib.peer_types.contains_key(&GR_PEER_B)
            {
                break;
            }
        }
    })
    .await
    .expect("state lock still held while the refresh is blocked");

    let cmd = loop {
        match next_command(&mut b.stop_rx).await {
            SessionCommand::Stop => {}
            other => break other,
        }
    };
    assert_post_session_drop_refresh(cmd);
}

// ── withdraw_stale_bgp_routes ─────────────────────────────────────────────
//
// Full integration coverage (actual netlink withdrawals against a Linux
// kernel) belongs in the Gap 8 e2e test.  These unit tests verify the
// portable logic: empty inputs are a no-op, and the function completes
// without panicking.  On non-Linux platforms FibWriter::new always fails so
// the stale lists are always empty — the tests reflect that reality.

#[tokio::test]
async fn withdraw_stale_bgp_routes_empty_lists_is_noop() {
    // On non-Linux, FibWriter::new fails so this test exercises the
    // `stale_bgp_routes` → empty path.  On Linux it exercises the real
    // writer with no routes to delete (ESRCH suppressed by withdraw_v4/v6).
    // Either way the function must complete without error or panic.
    let (kernel_fib, _rx) = pathvector_sys::KernelFib::new(254);
    let (stale_v4, stale_v6) = kernel_fib
        .stale_bgp_routes()
        .await
        .unwrap_or((vec![], vec![]));

    // If a writer is available, run the cleanup; otherwise just verify the
    // stale list query itself didn't panic.
    if let Ok(writer) = pathvector_sys::FibWriter::new(254, 20) {
        withdraw_stale_bgp_routes(stale_v4, stale_v6, &writer).await;
    }
}

// ── Dynamic peer persistence (sidecar) ───────────────────────────────────

/// Simulates a daemon restart: a peer is written to the sidecar, then the
/// sidecar is loaded and merged into a fresh config.  `build_daemon` must
/// spawn a session for the peer as if it had been statically configured.
///
/// This is the integration-level proof that the `main.rs` startup path
/// correctly re-hydrates dynamic peers from the sidecar after a restart —
/// without requiring a real Docker container restart.
#[tokio::test]
async fn dynamic_peer_from_sidecar_is_loaded_on_restart() {
    let dir = tempfile::tempdir().unwrap();
    let sidecar_path = dir.path().join("dynamic_peers.toml");
    let store = config::DynamicPeerStore::new(sidecar_path.clone());

    // Write a peer into the sidecar as if it had been added via add_peer
    // during a previous run.
    let peer_ip = Ipv4Addr::new(10, 0, 0, 5);
    store
        .upsert(config::PeerConfig {
            address: IpAddr::V4(peer_ip),
            port: 179,
            remote_as: 65099,
            import_default: None,
            import_default_v6: None,
            export_default: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
            confederation_member: false,
            blackhole_authorized_prefixes: None,
        })
        .await;

    // Replicate what main.rs does on startup: load sidecar, merge into cfg.
    let mut cfg = make_config(&[]);
    for p in store.load() {
        if !cfg.peers.iter().any(|x| x.address == p.address) {
            cfg.peers.push(p);
        }
    }
    cfg.sidecar_path = Some(sidecar_path);

    // Build daemon — the sidecar peer must be treated as a static peer.
    let (spawn_fn, spawned_peers) = make_mock_spawn();
    let _ = build_daemon(&cfg, spawn_fn).await;

    let peers = spawned_peers.lock().unwrap();
    assert_eq!(
        peers.len(),
        1,
        "exactly one session must be spawned for the sidecar peer"
    );
    assert!(
        peers[0].started.load(Ordering::SeqCst),
        "sidecar peer session must have start() called"
    );
}

/// A peer in the sidecar must not be duplicated if it also appears in the
/// static config — the deduplication in main.rs must prevent a double-add.
#[tokio::test]
async fn sidecar_peer_already_in_static_config_not_duplicated() {
    let dir = tempfile::tempdir().unwrap();
    let sidecar_path = dir.path().join("dynamic_peers.toml");
    let store = config::DynamicPeerStore::new(sidecar_path.clone());

    let peer_ip = Ipv4Addr::new(10, 0, 0, 5);
    store
        .upsert(config::PeerConfig {
            address: IpAddr::V4(peer_ip),
            port: 179,
            remote_as: 65099,
            import_default: None,
            import_default_v6: None,
            export_default: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
            confederation_member: false,
            blackhole_authorized_prefixes: None,
        })
        .await;

    // Same peer already in the static config — dedup must skip the sidecar entry.
    let mut cfg = make_config(&[(IpAddr::V4(peer_ip), 65099)]);
    for p in store.load() {
        if !cfg.peers.iter().any(|x| x.address == p.address) {
            cfg.peers.push(p);
        }
    }
    cfg.sidecar_path = Some(sidecar_path);

    let (spawn_fn, spawned_peers) = make_mock_spawn();
    let _ = build_daemon(&cfg, spawn_fn).await;

    assert_eq!(
        spawned_peers.lock().unwrap().len(),
        1,
        "peer must not be spawned twice when present in both static config and sidecar"
    );
}

#[tokio::test]
async fn withdraw_stale_bgp_routes_skips_absent_routes_gracefully() {
    // Feed routes that are not in the kernel FIB.  On Linux, withdraw_v4/v6
    // treat ESRCH as Ok(()); on non-Linux, FibWriter::new fails so the
    // block is skipped.  Either way: no panic, no error propagation.
    let routes_v4 = vec![
        ("192.0.2.0".parse().unwrap(), 24u8),
        ("198.51.100.0".parse().unwrap(), 24u8),
    ];
    let routes_v6 = vec![("2001:db8::".parse().unwrap(), 32u8)];

    if let Ok(writer) = pathvector_sys::FibWriter::new(254, 20) {
        withdraw_stale_bgp_routes(routes_v4, routes_v6, &writer).await;
    }
}
