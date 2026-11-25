//! TCP MD5 keys on the BGP listener, through the daemon (issue #66).
//!
//! The listener itself is proven in `pathvector-session`
//! (`transport::listener` unit tests and `tests/listener_md5_loopback.rs`).
//! These tests prove the daemon wiring: static peers' keys reach the
//! listener, `AddPeer` installs a key before the peer's inbound connections
//! are routed, `RemovePeer` removes it, and a key that cannot be enforced
//! keeps the peer's inbound connections away from its session.
//!
//! Each test observes the outcome where an attacker would see it: whether a
//! TCP client from the peer's address completes its handshake, and whether
//! that connection reaches the session as `SessionCommand::IncomingConnection`.
//!
//! RFC 4271 Security Considerations: a BGP implementation "MUST support the
//! authentication mechanism specified in RFC 2385" and "must allow a network
//! administrator to activate it on a per-peer basis". RFC 5925 §8: required
//! TCP MD5 must be "validated on all incoming segments". RFC 2385 §2.0:
//! failing segments are "dropped" with no response, so a client without the
//! right key times out (§4.1).

#![allow(clippy::too_many_lines)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use pathvector_session::transport::tcp_md5::{TcpMd5Error, TcpMd5Key, TcpMd5Unsupported};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpSocket, TcpStream};

use super::*;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const CONNECT_WAIT: Duration = Duration::from_millis(1500);

/// Long enough for the command processor to apply a command and for the
/// listener to replace its socket after a key change (see
/// `pathvector_session::transport::listener`).
const APPLY_WAIT: Duration = Duration::from_millis(300);

// ── test doubles ─────────────────────────────────────────────────────────────

/// A session handle whose inbound connections arrive on a test channel.
struct ProbeHandle {
    incoming: mpsc::Sender<SessionCommand>,
}

impl SessionHandle for ProbeHandle {
    async fn start(&self) {}
    async fn next_event(&mut self) -> Option<SessionEvent> {
        std::future::pending().await
    }
    fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
        mpsc::channel(1).0
    }
    fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
        mpsc::channel(1).0
    }
    fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
        self.incoming.clone()
    }
    async fn send_route_refresh(&self, _rr: pathvector_session::message::RouteRefreshMessage) {}
    async fn set_capabilities(&self, _caps: Vec<Capability>) {}
}

/// A [`TcpMd5Port`] that records calls and either "installs" every key or
/// reports that the host cannot enforce TCP MD5. It never touches the
/// kernel, so it proves wiring, not enforcement.
struct FakePort {
    supported: bool,
    calls: StdMutex<Vec<(&'static str, IpAddr)>>,
}

impl FakePort {
    fn new(supported: bool) -> Self {
        Self {
            supported,
            calls: StdMutex::new(Vec::new()),
        }
    }
    fn calls(&self) -> Vec<(&'static str, IpAddr)> {
        self.calls.lock().unwrap().clone()
    }
}

impl TcpMd5Port for FakePort {
    fn install(
        &self,
        _socket: BorrowedFd<'_>,
        peer: IpAddr,
        _key: &TcpMd5Key,
    ) -> Result<(), TcpMd5Error> {
        self.calls.lock().unwrap().push(("install", peer));
        if self.supported {
            Ok(())
        } else {
            Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Platform))
        }
    }

    fn remove(&self, _socket: BorrowedFd<'_>, peer: IpAddr) -> Result<(), TcpMd5Error> {
        self.calls.lock().unwrap().push(("remove", peer));
        Ok(())
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn key(s: &str) -> TcpMd5Key {
    s.parse().unwrap()
}

fn peer_config(address: IpAddr, md5: Option<&str>) -> config::PeerConfig {
    config::PeerConfig {
        address,
        port: 179,
        remote_as: 65002,
        import_default: None,
        export_default: None,
        import_default_v6: None,
        md5_password: md5.map(|k| k.parse().unwrap()),
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
    }
}

fn daemon_config(peers: Vec<config::PeerConfig>) -> config::Config {
    config::Config {
        daemon: config::DaemonConfig {
            local_as: 65001,
            bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            hold_time: 90,
            grpc_port: 0,
            bgp_port: 0,
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
        peers,
        sidecar_path: None,
    }
}

fn spawn_config() -> SpawnConfig {
    SpawnConfig {
        local_as: 65001,
        local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        graceful_restart_time: 0,
        configured_restarting: false,
        confederation_id: None,
        startup_instant: std::time::Instant::now(),
        md5_enforcement: Md5Enforcement::Required,
    }
}

type Incoming = Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>;

/// Starts `run_bgp_listener` on a free loopback port and waits until it is
/// accepting.
async fn start_listener<P: TcpMd5Port + Send + Sync + 'static>(
    incoming: Incoming,
    keys: Md5Keys<P>,
) -> SocketAddr {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    tokio::spawn(run_bgp_listener(addr, incoming, keys));
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

/// Starts the command processor; returns its command sender and the channel
/// on which the spawned session's inbound connections arrive.
async fn start_processor<P: TcpMd5Port + Send + Sync + 'static>(
    incoming: Incoming,
    keys: Md5Keys<P>,
    on_spawn: impl Fn() + Send + 'static,
) -> (
    mpsc::Sender<DaemonCommand>,
    mpsc::Receiver<SessionCommand>,
    Arc<RwLock<DaemonState>>,
) {
    let (state, _event_rx, event_tx, stop_senders, _incoming, _keys) =
        build_daemon(&daemon_config(vec![]), |_| ProbeHandle {
            incoming: mpsc::channel(1).0,
        })
        .await;
    let (cmd_tx, cmd_rx) = mpsc::channel(4);
    let (session_tx, session_rx) = mpsc::channel(4);
    tokio::spawn(run_command_processor(
        cmd_rx,
        Arc::clone(&state),
        stop_senders,
        incoming,
        keys,
        event_tx,
        move |_cfg: SessionConfig| {
            on_spawn();
            ProbeHandle {
                incoming: session_tx.clone(),
            }
        },
        spawn_config(),
        None,
    ));
    (cmd_tx, session_rx, state)
}

/// Connects from loopback, signing with `md5` if given (real kernel). `None`
/// if the handshake did not complete within [`CONNECT_WAIT`].
async fn connect(addr: SocketAddr, md5: Option<&TcpMd5Key>) -> Option<TcpStream> {
    let s = TcpSocket::new_v4().unwrap();
    if let Some(k) = md5 {
        KernelTcpMd5
            .install(s.as_fd(), LOOPBACK, k)
            .expect("install client key");
    }
    match tokio::time::timeout(CONNECT_WAIT, s.connect(addr)).await {
        Ok(Ok(stream)) => Some(stream),
        Ok(Err(e)) => panic!("connect failed instead of timing out (RFC 2385 §4.1): {e}"),
        Err(_) => None,
    }
}

/// Whether the session received an inbound connection within a short wait.
async fn session_got_connection(rx: &mut mpsc::Receiver<SessionCommand>) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_millis(300), rx.recv()).await,
        Ok(Some(SessionCommand::IncomingConnection(_)))
    )
}

/// `true` if the daemon closed `client` without sending anything.
async fn closed_by_daemon(mut client: TcpStream) -> bool {
    let mut buf = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await {
        Ok(Ok(0)) => true,
        Ok(Err(e)) => e.kind() == std::io::ErrorKind::ConnectionReset,
        Ok(Ok(_)) | Err(_) => false,
    }
}

/// Whether this host enforces TCP MD5. Fails under `CI` on Linux if not.
fn host_supports_md5(test: &str) -> bool {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    match KernelTcpMd5.install(probe.as_fd(), LOOPBACK, &key("probe")) {
        Ok(()) => true,
        Err(TcpMd5Error::Unsupported(why)) => {
            assert!(
                !(cfg!(target_os = "linux") && std::env::var_os("CI").is_some()),
                "{test}: CI kernels must support TCP_MD5SIG ({why})"
            );
            eprintln!("{test}: host cannot enforce TCP MD5 ({why}); checking fail-closed");
            false
        }
        Err(e) => panic!("{test}: unexpected error probing TCP_MD5SIG: {e:?}"),
    }
}

// ── wiring (fake port, every platform) ──────────────────────────────────────

/// `AddPeer` installs the key on the listener before the session exists, so
/// before the peer is in `incoming_senders`; afterwards the peer's inbound
/// connection reaches its session.
#[tokio::test]
async fn add_peer_installs_listener_key_before_routing_inbound() {
    let keys: Md5Keys<FakePort> = Arc::new(ListenerKeys::new(FakePort::new(true)));
    let incoming: Incoming = Arc::default();
    let addr = start_listener(Arc::clone(&incoming), Arc::clone(&keys)).await;

    let installed_before_spawn = Arc::new(StdMutex::new(None));
    let (cmd_tx, mut session_rx, _state) = {
        let keys = Arc::clone(&keys);
        let flag = Arc::clone(&installed_before_spawn);
        start_processor(Arc::clone(&incoming), Arc::clone(&keys), move || {
            *flag.lock().unwrap() = Some(keys.port().calls().contains(&("install", LOOPBACK)));
        })
        .await
    };

    cmd_tx
        .send(DaemonCommand::AddPeer(peer_config(LOOPBACK, Some("k"))))
        .await
        .unwrap();
    tokio::time::sleep(APPLY_WAIT).await;

    assert_eq!(*installed_before_spawn.lock().unwrap(), Some(true));
    assert_eq!(
        keys.configured(LOOPBACK),
        Some(TcpMd5Auth::required(key("k")))
    );
    let _client = TcpStream::connect(addr).await.unwrap();
    assert!(session_got_connection(&mut session_rx).await);
}

/// Issue #66: a required key that the host cannot enforce on the listener
/// must not leave the inbound path open. The handshake completes (nothing
/// in the kernel checks it), but the connection never reaches the session.
#[tokio::test]
async fn add_peer_with_unenforceable_required_key_refuses_inbound() {
    let keys: Md5Keys<FakePort> = Arc::new(ListenerKeys::new(FakePort::new(false)));
    let incoming: Incoming = Arc::default();
    let addr = start_listener(Arc::clone(&incoming), Arc::clone(&keys)).await;
    let (cmd_tx, mut session_rx, _state) =
        start_processor(Arc::clone(&incoming), Arc::clone(&keys), || {}).await;

    cmd_tx
        .send(DaemonCommand::AddPeer(peer_config(LOOPBACK, Some("k"))))
        .await
        .unwrap();
    tokio::time::sleep(APPLY_WAIT).await;
    assert!(
        incoming.read().await.contains_key(&LOOPBACK),
        "the peer is configured; only its inbound path is refused"
    );

    let client = TcpStream::connect(addr).await.unwrap();
    assert!(!session_got_connection(&mut session_rx).await);
    assert!(closed_by_daemon(client).await);
}

/// `RemovePeer` takes the key off the listener (with the remove operation)
/// and forgets it.
#[tokio::test]
async fn remove_peer_removes_the_listener_key() {
    let keys: Md5Keys<FakePort> = Arc::new(ListenerKeys::new(FakePort::new(true)));
    let incoming: Incoming = Arc::default();
    let _addr = start_listener(Arc::clone(&incoming), Arc::clone(&keys)).await;
    let (cmd_tx, _session_rx, _state) =
        start_processor(Arc::clone(&incoming), Arc::clone(&keys), || {}).await;

    cmd_tx
        .send(DaemonCommand::AddPeer(peer_config(LOOPBACK, Some("k"))))
        .await
        .unwrap();
    tokio::time::sleep(APPLY_WAIT).await;
    cmd_tx
        .send(DaemonCommand::RemovePeer(LOOPBACK))
        .await
        .unwrap();
    tokio::time::sleep(APPLY_WAIT).await;

    assert_eq!(
        keys.port().calls(),
        vec![
            ("install", LOOPBACK), // on the live listener by AddPeer
            ("install", LOOPBACK), // on the listener's replacement socket
            ("remove", LOOPBACK),
        ]
    );
    assert_eq!(keys.configured(LOOPBACK), None);
}

/// Codex review of PR #127: a connection accepted unkeyed just before
/// `AddPeer` installs the peer's key could be looked up in `incoming_senders`
/// just after `AddPeer` added the session, and so reach it without ever
/// having been authenticated. `route_inbound` re-checks the connection's
/// stamp after the lookup; `AddPeer` sets the key before adding the session,
/// so a connection that finds the session also sees the key change.
#[tokio::test]
async fn connection_accepted_before_add_peer_is_not_routed_to_the_new_session() {
    let keys: Md5Keys<FakePort> = Arc::new(ListenerKeys::new(FakePort::new(true)));
    let mut listener =
        BgpListener::bind("127.0.0.1:0".parse().unwrap(), Arc::clone(&keys)).unwrap();
    let (tx, mut session_rx) = mpsc::channel(4);
    let incoming: Incoming = Arc::default();

    // Positive control: an unkeyed peer's connection is routed.
    incoming.write().await.insert(LOOPBACK, tx.clone());
    let _routed = TcpStream::connect(listener.local_addr()).await.unwrap();
    let inbound = listener.accept().await.unwrap();
    super::peer::route_inbound(&listener, inbound, &incoming).await;
    assert!(session_got_connection(&mut session_rx).await);
    incoming.write().await.clear();

    // The race: accepted before AddPeer, routed after it.
    let client = TcpStream::connect(listener.local_addr()).await.unwrap();
    let inbound = listener.accept().await.unwrap();
    set_listener_key(&keys, LOOPBACK, TcpMd5Auth::required(key("k")));
    incoming.write().await.insert(LOOPBACK, tx);
    super::peer::route_inbound(&listener, inbound, &incoming).await;

    assert!(!session_got_connection(&mut session_rx).await);
    assert!(closed_by_daemon(client).await);
}

/// A peer without `md5_password` puts nothing on the listener.
#[tokio::test]
async fn add_peer_without_password_installs_nothing() {
    let keys: Md5Keys<FakePort> = Arc::new(ListenerKeys::new(FakePort::new(true)));
    let incoming: Incoming = Arc::default();
    let _addr = start_listener(Arc::clone(&incoming), Arc::clone(&keys)).await;
    let (cmd_tx, _session_rx, _state) =
        start_processor(Arc::clone(&incoming), Arc::clone(&keys), || {}).await;

    cmd_tx
        .send(DaemonCommand::AddPeer(peer_config(LOOPBACK, None)))
        .await
        .unwrap();
    tokio::time::sleep(APPLY_WAIT).await;
    assert!(keys.port().calls().is_empty());
}

// ── live kernel ──────────────────────────────────────────────────────────────

/// A statically configured peer with `md5_password`: on a host that
/// enforces TCP MD5, an unsigned or wrongly signed client from the peer's
/// address never completes its handshake and never reaches the session,
/// while the matching key does. On a host that cannot enforce it, the
/// unsigned client gets a TCP connection that the daemon closes without
/// routing it.
#[tokio::test]
async fn static_peer_inbound_requires_the_key() {
    let enforced = host_supports_md5("static_peer_inbound_requires_the_key");
    let (session_tx, mut session_rx) = mpsc::channel(4);
    let cfg = daemon_config(vec![peer_config(LOOPBACK, Some("static-key"))]);
    let (_state, _rx, _event_tx, _stop, incoming, keys) =
        build_daemon(&cfg, move |_| ProbeHandle {
            incoming: session_tx.clone(),
        })
        .await;
    let addr = start_listener(incoming, keys).await;

    if enforced {
        assert!(connect(addr, None).await.is_none(), "unsigned SYN dropped");
        assert!(connect(addr, Some(&key("wrong"))).await.is_none());
        assert!(!session_got_connection(&mut session_rx).await);
        let _c = connect(addr, Some(&key("static-key")))
            .await
            .expect("matching key connects");
        assert!(session_got_connection(&mut session_rx).await);
    } else {
        let client = connect(addr, None).await.expect("kernel does not check");
        assert!(!session_got_connection(&mut session_rx).await);
        assert!(closed_by_daemon(client).await);
    }
}

/// The same for a peer added with `AddPeer` while the listener runs, then
/// removed with `RemovePeer`: after removal a client that still signs is
/// dropped, because the key is gone from the listener (`TCP_MD5UNEXPECTED`).
#[tokio::test]
async fn dynamic_peer_inbound_requires_the_key_until_removed() {
    let enforced = host_supports_md5("dynamic_peer_inbound_requires_the_key_until_removed");
    let keys: Md5Keys = Arc::new(ListenerKeys::default());
    let incoming: Incoming = Arc::default();
    let addr = start_listener(Arc::clone(&incoming), Arc::clone(&keys)).await;
    let (cmd_tx, mut session_rx, _state) =
        start_processor(Arc::clone(&incoming), Arc::clone(&keys), || {}).await;

    cmd_tx
        .send(DaemonCommand::AddPeer(peer_config(
            LOOPBACK,
            Some("dynamic-key"),
        )))
        .await
        .unwrap();
    tokio::time::sleep(APPLY_WAIT).await;

    if enforced {
        assert!(connect(addr, None).await.is_none(), "unsigned SYN dropped");
        assert!(connect(addr, Some(&key("wrong"))).await.is_none());
        assert!(!session_got_connection(&mut session_rx).await);
        let _c = connect(addr, Some(&key("dynamic-key")))
            .await
            .expect("matching key connects");
        assert!(session_got_connection(&mut session_rx).await);

        cmd_tx
            .send(DaemonCommand::RemovePeer(LOOPBACK))
            .await
            .unwrap();
        tokio::time::sleep(APPLY_WAIT).await;
        assert!(
            connect(addr, Some(&key("dynamic-key"))).await.is_none(),
            "key removed from the listener"
        );
    } else {
        let client = connect(addr, None).await.expect("kernel does not check");
        assert!(!session_got_connection(&mut session_rx).await);
        assert!(closed_by_daemon(client).await);
    }
}
