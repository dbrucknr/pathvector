//! Unit tests for [`ListenerKeys`] and [`BgpListener`] with a fake
//! [`TcpMd5Port`].
//!
//! The fake never puts a key in the kernel, so these tests prove the
//! listener's own logic (what it installs, when, and what it admits) on every
//! platform. That the kernel then enforces an installed key is proven
//! against a live kernel in `tests/listener_md5_loopback.rs`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::BorrowedFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use super::*;
use crate::transport::tcp_md5::{TcpMd5Key, TcpMd5Unsupported};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const OTHER_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
const PEER_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    /// An install: the peer, the key, and (when the fake probes for it)
    /// whether the socket was already listening at the time.
    Install {
        peer: IpAddr,
        key: TcpMd5Key,
        listening: Option<bool>,
    },
    Remove(IpAddr),
}

#[derive(Clone, Copy)]
enum Outcome {
    Ok,
    Unsupported,
    NoMemory,
}

impl Outcome {
    fn result(self) -> Result<(), TcpMd5Error> {
        match self {
            Self::Ok => Ok(()),
            Self::Unsupported => Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Platform)),
            Self::NoMemory => Err(TcpMd5Error::Os(io::Error::from_raw_os_error(libc_enomem()))),
        }
    }
}

/// `ENOMEM`, the same on Linux and macOS.
const fn libc_enomem() -> i32 {
    12
}

/// A [`TcpMd5Port`] whose install result is scripted and which records
/// every call.
struct FakePort {
    install: Mutex<Outcome>,
    calls: Mutex<Vec<Call>>,
    /// Probe whether the socket is listening at each install. Only for
    /// tests with nothing queued, since the probe would take a connection.
    probe_listening: bool,
}

impl FakePort {
    fn new(install: Outcome) -> Self {
        Self {
            install: Mutex::new(install),
            calls: Mutex::new(Vec::new()),
            probe_listening: false,
        }
    }
}

/// Whether `socket` is listening: `accept()` on a non-listening socket fails
/// with `EINVAL`; on a listening non-blocking one with nothing queued it
/// would block.
fn is_listening(socket: BorrowedFd<'_>) -> bool {
    match socket2::SockRef::from(&socket).accept() {
        Ok(_) => panic!("probe_listening used with a connection queued"),
        Err(e) => e.kind() == io::ErrorKind::WouldBlock,
    }
}

impl TcpMd5Port for FakePort {
    fn install(
        &self,
        socket: BorrowedFd<'_>,
        peer: IpAddr,
        key: &TcpMd5Key,
    ) -> Result<(), TcpMd5Error> {
        self.calls.lock().unwrap().push(Call::Install {
            peer,
            key: key.clone(),
            listening: self.probe_listening.then(|| is_listening(socket)),
        });
        self.install.lock().unwrap().result()
    }

    fn remove(&self, _socket: BorrowedFd<'_>, peer: IpAddr) -> Result<(), TcpMd5Error> {
        self.calls.lock().unwrap().push(Call::Remove(peer));
        Ok(())
    }
}

fn key(s: &str) -> TcpMd5Key {
    s.parse().unwrap()
}

fn required(k: &str) -> TcpMd5Auth {
    TcpMd5Auth::required(key(k))
}

fn best_effort(k: &str) -> TcpMd5Auth {
    TcpMd5Auth::new(key(k), Md5Enforcement::BestEffort)
}

fn keys(outcome: Outcome) -> Arc<ListenerKeys<FakePort>> {
    Arc::new(ListenerKeys::new(FakePort::new(outcome)))
}

/// Keys whose fake records whether each install happened before `listen()`.
fn probing_keys() -> Arc<ListenerKeys<FakePort>> {
    let mut port = FakePort::new(Outcome::Ok);
    port.probe_listening = true;
    Arc::new(ListenerKeys::new(port))
}

/// Connects to `addr` and waits until the server side of the handshake has
/// completed, so the connection is in the accept queue. `connect()` returns
/// on the SYN-ACK, which can be before the server has processed the final
/// ACK.
async fn queued_connection(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    s
}

fn calls(keys: &ListenerKeys<FakePort>) -> Vec<Call> {
    keys.port.calls.lock().unwrap().clone()
}

fn bind(keys: &Arc<ListenerKeys<FakePort>>) -> BgpListener<FakePort> {
    BgpListener::bind("127.0.0.1:0".parse().unwrap(), Arc::clone(keys)).unwrap()
}

/// The next admitted connection, or `None` within a short wait.
async fn try_accept(l: &mut BgpListener<FakePort>) -> Option<Inbound> {
    tokio::time::timeout(Duration::from_millis(200), l.accept())
        .await
        .ok()
        .map(|r| r.expect("accept"))
}

/// `true` if the server closed `client` without sending anything.
async fn closed_by_server(mut client: TcpStream) -> bool {
    let mut buf = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await {
        Ok(Ok(0)) => true,
        Ok(Err(e)) => e.kind() == io::ErrorKind::ConnectionReset,
        Ok(Ok(_)) | Err(_) => false,
    }
}

// ── keys present at bind time ────────────────────────────────────────────────

/// Keys configured before the listener exists wait for it, and are
/// installed when it binds, before `listen()`, so no handshake can complete
/// without them (RFC 5925 §8: validated "on all incoming segments").
#[tokio::test]
async fn key_configured_before_bind_is_installed_before_listen() {
    let keys = probing_keys();
    assert_eq!(
        keys.set_peer(LOOPBACK, required("k")),
        Ok(ListenerProtection::Deferred)
    );
    assert_eq!(
        keys.admission(LOOPBACK),
        Admission::Rejected(Rejection::NoListener)
    );

    let _l = bind(&keys);

    assert_eq!(
        calls(&keys),
        vec![Call::Install {
            peer: LOOPBACK,
            key: key("k"),
            listening: Some(false)
        }]
    );
    assert_eq!(keys.admission(LOOPBACK), Admission::Authenticated);
}

/// An IPv4 listener installs only IPv4 keys. An IPv6 peer's key needs the
/// IPv6 listener: Linux rejects an `AF_INET6` key on an `AF_INET` socket
/// (`tcp_v4_parse_md5_keys`: `if (sin->sin_family != AF_INET) return
/// -EINVAL`).
#[tokio::test]
async fn listener_installs_only_its_own_family() {
    let keys = keys(Outcome::Ok);
    let _ = keys.set_peer(PEER_V6, required("v6"));
    let _ = keys.set_peer(OTHER_V4, required("v4"));

    let _l = bind(&keys);

    assert_eq!(
        calls(&keys),
        vec![Call::Install {
            peer: OTHER_V4,
            key: key("v4"),
            listening: None
        }]
    );
    assert_eq!(
        keys.admission(PEER_V6),
        Admission::Rejected(Rejection::NoListener)
    );
}

#[tokio::test]
async fn unknown_peer_is_unkeyed_and_admitted() {
    let keys = keys(Outcome::Ok);
    let _ = keys.set_peer(OTHER_V4, required("k"));
    let mut l = bind(&keys);
    let addr = l.local_addr();

    assert_eq!(keys.admission(LOOPBACK), Admission::Unkeyed);
    let client = TcpStream::connect(addr).await.unwrap();
    let inbound = try_accept(&mut l).await.expect("unkeyed peer admitted");
    assert_eq!(inbound.peer(), client.local_addr().unwrap());
}

#[tokio::test]
async fn second_listener_for_the_same_family_is_refused() {
    let keys = keys(Outcome::Ok);
    let _l = bind(&keys);
    let err = BgpListener::bind("127.0.0.1:0".parse().unwrap(), Arc::clone(&keys)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
}

/// Dropping the listener forgets its socket; binding again reinstalls the
/// keys on the new socket before it listens.
#[tokio::test]
async fn rebinding_reinstalls_keys() {
    let keys = probing_keys();
    let _ = keys.set_peer(LOOPBACK, required("k"));
    drop(bind(&keys));
    assert_eq!(
        keys.admission(LOOPBACK),
        Admission::Rejected(Rejection::NoListener)
    );

    let _l = bind(&keys);
    let installs = calls(&keys);
    assert_eq!(installs.len(), 2);
    assert!(matches!(
        installs[1],
        Call::Install {
            listening: Some(false),
            ..
        }
    ));
    assert_eq!(keys.admission(LOOPBACK), Admission::Authenticated);
}

// ── keys that cannot be installed ───────────────────────────────────────────

/// Issue #66 / RFC 5925 §8: a required key that this host cannot enforce
/// must not leave the listener open to the peer. The kernel does not drop
/// the unsigned handshake, so the listener must close the connection itself.
#[tokio::test]
async fn required_key_that_cannot_be_enforced_rejects_the_peer() {
    let keys = keys(Outcome::Unsupported);
    let _ = keys.set_peer(LOOPBACK, required("k"));
    let mut l = bind(&keys);
    let addr = l.local_addr();

    let refusal = KeyRefusal::NotEnforceable(TcpMd5Unsupported::Platform);
    assert_eq!(
        keys.admission(LOOPBACK),
        Admission::Rejected(Rejection::KeyNotInstalled(refusal))
    );

    let client = TcpStream::connect(addr).await.unwrap();
    assert!(try_accept(&mut l).await.is_none(), "must not be returned");
    assert!(closed_by_server(client).await, "must be closed");
}

/// Same, for a key added after the listener is bound: `set_peer` reports the
/// refusal to its caller.
#[tokio::test]
async fn set_peer_reports_a_required_key_it_cannot_enforce() {
    let keys = keys(Outcome::Unsupported);
    let mut l = bind(&keys);
    let addr = l.local_addr();

    let err = keys.set_peer(LOOPBACK, required("k")).unwrap_err();
    assert_eq!(err.peer(), LOOPBACK);
    assert_eq!(
        err.refusal(),
        KeyRefusal::NotEnforceable(TcpMd5Unsupported::Platform)
    );

    let client = TcpStream::connect(addr).await.unwrap();
    assert!(try_accept(&mut l).await.is_none());
    assert!(closed_by_server(client).await);
}

/// The `BestEffort` opt-in accepts the peer unauthenticated, and says so.
#[tokio::test]
async fn best_effort_key_that_cannot_be_enforced_admits_unauthenticated() {
    let keys = keys(Outcome::Unsupported);
    let mut l = bind(&keys);
    let addr = l.local_addr();

    assert_eq!(
        keys.set_peer(LOOPBACK, best_effort("k")),
        Ok(ListenerProtection::Unenforced(TcpMd5Unsupported::Platform))
    );
    assert_eq!(
        keys.admission(LOOPBACK),
        Admission::Unauthenticated(TcpMd5Unsupported::Platform)
    );
    let _client = TcpStream::connect(addr).await.unwrap();
    assert!(try_accept(&mut l).await.is_some());
}

/// `BestEffort` covers only "this host cannot do TCP MD5". Any other
/// failure to install the key rejects the peer.
#[tokio::test]
async fn os_error_rejects_even_a_best_effort_peer() {
    let keys = keys(Outcome::NoMemory);
    let _l = bind(&keys);

    let err = keys.set_peer(LOOPBACK, best_effort("k")).unwrap_err();
    assert_eq!(
        err.refusal(),
        KeyRefusal::Os {
            kind: io::Error::from_raw_os_error(libc_enomem()).kind(),
            errno: Some(libc_enomem())
        }
    );
    assert!(matches!(
        keys.admission(LOOPBACK),
        Admission::Rejected(Rejection::KeyNotInstalled(KeyRefusal::Os { .. }))
    ));
}

/// A refused key elsewhere does not affect other peers.
#[tokio::test]
async fn refused_key_does_not_affect_other_peers() {
    let keys = keys(Outcome::Unsupported);
    let _ = keys.set_peer(OTHER_V4, required("k"));
    let mut l = bind(&keys);
    let addr = l.local_addr();

    let _client = TcpStream::connect(addr).await.unwrap();
    assert!(try_accept(&mut l).await.is_some());
}

// ── keys changed while listening ─────────────────────────────────────────────

/// Unsettled keys per family, checked against a full scan of the table.
fn unsettled(keys: &ListenerKeys<FakePort>, family: AddressFamily) -> usize {
    let inner = keys.lock();
    let scanned = inner
        .peers
        .iter()
        .filter(|(ip, e)| AddressFamily::of(**ip) == family && e.state.is_unsettled())
        .count();
    assert_eq!(
        inner.unsettled[family.index()],
        scanned,
        "count out of sync"
    );
    scanned
}

/// The race this module closes. Linux copies the listener's key into a
/// connection when its handshake completes (`tcp_v4_syn_recv_sock`, "Copy
/// over the MD5 key from the original socket"), so a connection that
/// completed before the key was installed carries no key, even if it is
/// accepted afterwards. It must be rejected; a connection made after the
/// socket was replaced is admitted.
#[tokio::test]
async fn connection_queued_before_a_new_key_is_rejected() {
    let keys = keys(Outcome::Ok);
    let mut l = bind(&keys);
    let addr = l.local_addr();

    // Handshake completes with no key; the connection waits in the queue.
    let early = queued_connection(addr).await;

    assert_eq!(
        keys.set_peer(LOOPBACK, required("k")),
        Ok(ListenerProtection::Enforced)
    );
    assert_eq!(
        calls(&keys),
        vec![Call::Install {
            peer: LOOPBACK,
            key: key("k"),
            listening: None
        }]
    );
    assert_eq!(
        keys.admission(LOOPBACK),
        Admission::Rejected(Rejection::KeyChangePending)
    );

    assert!(
        try_accept(&mut l).await.is_none(),
        "the pre-key connection must not be returned"
    );
    assert!(closed_by_server(early).await, "and must be closed");
    assert_eq!(keys.admission(LOOPBACK), Admission::Authenticated);
    assert_eq!(l.local_addr(), addr, "replacement keeps the address");

    let late = TcpStream::connect(addr).await.unwrap();
    let inbound = try_accept(&mut l).await.expect("post-key connection");
    assert_eq!(inbound.peer(), late.local_addr().unwrap());
}

/// A key installed while listening makes the listener replace its socket:
/// the new socket at the same address gets every key before `listen()`, so
/// no connection it produces can predate the key. Waiting cannot prove that
/// about the old socket (a connection whose key was copied before the
/// change can be appended to the queue after any check), so the old socket
/// is shut down instead (`inet_shutdown` → `tcp_disconnect` →
/// `inet_csk_listen_stop`).
#[tokio::test]
async fn key_change_replaces_the_socket_with_keys_installed_before_listen() {
    let keys = probing_keys();
    let mut l = bind(&keys);
    let addr = l.local_addr();

    let _ = keys.set_peer(LOOPBACK, required("k"));
    assert!(try_accept(&mut l).await.is_none());

    assert_eq!(
        calls(&keys),
        vec![
            Call::Install {
                peer: LOOPBACK,
                key: key("k"),
                listening: Some(true)
            },
            Call::Install {
                peer: LOOPBACK,
                key: key("k"),
                listening: Some(false)
            },
        ],
        "installed on the live socket, then on the replacement before listen()"
    );
    assert_eq!(keys.admission(LOOPBACK), Admission::Authenticated);
    assert_eq!(unsettled(&keys, AddressFamily::V4), 0);

    let client = TcpStream::connect(addr).await.unwrap();
    let inbound = try_accept(&mut l).await.expect("replacement listens");
    assert_eq!(inbound.peer(), client.local_addr().unwrap());
}

/// Rotation: the new key replaces the old one on the socket, connections
/// queued under the old key are discarded, and the socket is replaced.
#[tokio::test]
async fn rotation_installs_the_new_key_and_replaces_the_socket() {
    let keys = keys(Outcome::Ok);
    let _ = keys.set_peer(LOOPBACK, required("old"));
    let mut l = bind(&keys);
    let addr = l.local_addr();
    let queued = queued_connection(addr).await;

    assert_eq!(
        keys.set_peer(LOOPBACK, required("new")),
        Ok(ListenerProtection::Enforced)
    );
    assert_eq!(keys.configured(LOOPBACK), Some(required("new")));
    assert_eq!(
        calls(&keys).last(),
        Some(&Call::Install {
            peer: LOOPBACK,
            key: key("new"),
            listening: None
        })
    );
    assert!(try_accept(&mut l).await.is_none());
    assert!(closed_by_server(queued).await);
    assert_eq!(
        calls(&keys).len(),
        3,
        "old, new live, new on the replacement"
    );
    assert_eq!(keys.admission(LOOPBACK), Admission::Authenticated);
}

/// Setting the key a peer already has touches nothing and keeps admitting.
#[tokio::test]
async fn setting_the_same_key_again_is_a_no_op() {
    let keys = keys(Outcome::Ok);
    let _ = keys.set_peer(LOOPBACK, required("k"));
    let _l = bind(&keys);

    assert_eq!(
        keys.set_peer(LOOPBACK, required("k")),
        Ok(ListenerProtection::Enforced)
    );
    assert_eq!(calls(&keys).len(), 1);
    assert_eq!(keys.admission(LOOPBACK), Admission::Authenticated);
}

/// The per-family count behind the constant-time `has_unsettled` check
/// stays equal to a scan of the table through every transition: install
/// while listening, removal, a failed rotation, and socket replacement.
#[tokio::test]
async fn unsettled_count_follows_every_transition() {
    let keys = keys(Outcome::Ok);
    let mut l = bind(&keys);
    let _ = keys.set_peer(PEER_V6, required("v6")); // deferred: no IPv6 socket

    let _ = keys.set_peer(LOOPBACK, required("a"));
    let _ = keys.set_peer(OTHER_V4, required("b"));
    assert_eq!(unsettled(&keys, AddressFamily::V4), 2);
    assert!(keys.has_unsettled(AddressFamily::V4));
    assert!(!keys.has_unsettled(AddressFamily::V6));

    assert!(keys.remove_peer(LOOPBACK).unwrap());
    assert_eq!(unsettled(&keys, AddressFamily::V4), 1);

    *keys.port.install.lock().unwrap() = Outcome::NoMemory;
    assert!(keys.set_peer(OTHER_V4, required("b2")).is_err());
    assert_eq!(unsettled(&keys, AddressFamily::V4), 0);

    *keys.port.install.lock().unwrap() = Outcome::Ok;
    let _ = keys.set_peer(OTHER_V4, required("b3"));
    assert_eq!(unsettled(&keys, AddressFamily::V4), 1);
    assert!(try_accept(&mut l).await.is_none(), "replaces the socket");
    assert_eq!(unsettled(&keys, AddressFamily::V4), 0);
    assert_eq!(unsettled(&keys, AddressFamily::V6), 0);
}

// ── connections accepted around a key change ─────────────────────────────────

/// Codex review of PR #127: a connection taken off the old socket while
/// replacing it for peer A's key, from peer B that had no key yet, was
/// buffered and later returned even after B got a required key. It predates
/// B's key, so it must be discarded, also once B's key is fully in force.
#[tokio::test]
async fn buffered_connection_is_dropped_when_its_peer_gains_a_key() {
    let keys = keys(Outcome::Ok);
    let mut l = bind(&keys);
    let client = queued_connection(l.local_addr()).await;

    let _ = keys.set_peer(OTHER_V4, required("a"));
    l.replace_socket().unwrap();
    assert_eq!(
        l.ready.len(),
        1,
        "the unkeyed loopback connection is buffered"
    );

    let _ = keys.set_peer(LOOPBACK, required("b"));
    assert!(
        try_accept(&mut l).await.is_none(),
        "stale connection dropped"
    );
    assert_eq!(keys.admission(LOOPBACK), Admission::Authenticated);
    assert!(closed_by_server(client).await);
}

/// Same, when B's required key cannot be installed: B's connections are
/// refused, including the buffered one.
#[tokio::test]
async fn buffered_connection_is_dropped_when_its_peers_key_is_refused() {
    let keys = keys(Outcome::Ok);
    let mut l = bind(&keys);
    let client = queued_connection(l.local_addr()).await;

    let _ = keys.set_peer(OTHER_V4, required("a"));
    l.replace_socket().unwrap();
    assert_eq!(l.ready.len(), 1);

    *keys.port.install.lock().unwrap() = Outcome::Unsupported;
    assert!(keys.set_peer(LOOPBACK, required("b")).is_err());
    assert!(try_accept(&mut l).await.is_none());
    assert!(closed_by_server(client).await);
}

/// A connection handed over before its peer got a key stops being current,
/// so a caller that checks `is_current` after making the peer reachable
/// never uses a connection that predates the key.
#[tokio::test]
async fn accepted_connection_stops_being_current_when_its_peer_gains_a_key() {
    let keys = keys(Outcome::Ok);
    let mut l = bind(&keys);
    let _client = TcpStream::connect(l.local_addr()).await.unwrap();
    let inbound = try_accept(&mut l).await.expect("unkeyed peer admitted");
    assert!(l.is_current(&inbound));

    let _ = keys.set_peer(OTHER_V4, required("other"));
    assert!(l.is_current(&inbound), "another peer's key does not matter");

    let _ = keys.set_peer(LOOPBACK, required("k"));
    assert!(!l.is_current(&inbound));
    assert!(!keys.is_current(LOOPBACK, inbound.stamp()));
}

// ── removal ──────────────────────────────────────────────────────────────────

/// Removal takes the key off the socket with the separate remove operation
/// (an empty key would be a delete request to Linux, `tcp_v4_parse_md5_keys`:
/// `if (!cmd.tcpm_keylen) return tcp_md5_do_del(...)`), and the peer becomes
/// unkeyed.
#[tokio::test]
async fn removing_an_installed_key_takes_it_off_the_socket() {
    let keys = keys(Outcome::Ok);
    let _ = keys.set_peer(LOOPBACK, required("k"));
    let _l = bind(&keys);

    assert!(keys.remove_peer(LOOPBACK).unwrap());
    assert_eq!(calls(&keys).last(), Some(&Call::Remove(LOOPBACK)));
    assert_eq!(keys.admission(LOOPBACK), Admission::Unkeyed);
    assert_eq!(keys.configured(LOOPBACK), None);
    assert!(!keys.remove_peer(LOOPBACK).unwrap(), "already gone");
}

/// A key that never reached the socket is not removed from it (Linux would
/// answer `ENOENT`).
#[tokio::test]
async fn removing_a_key_that_was_never_installed_skips_the_socket() {
    let keys = keys(Outcome::Unsupported);
    let _ = keys.set_peer(LOOPBACK, required("k"));
    let _l = bind(&keys);

    assert!(keys.remove_peer(LOOPBACK).unwrap());
    assert!(!calls(&keys).contains(&Call::Remove(LOOPBACK)));
}

/// A failed rotation leaves the old key on the socket, so removal must
/// still take it off.
#[tokio::test]
async fn failed_rotation_still_removes_the_old_key() {
    let keys = keys(Outcome::Ok);
    let _ = keys.set_peer(LOOPBACK, required("old"));
    let _l = bind(&keys);
    *keys.port.install.lock().unwrap() = Outcome::NoMemory;

    assert!(keys.set_peer(LOOPBACK, required("new")).is_err());
    assert!(matches!(
        keys.admission(LOOPBACK),
        Admission::Rejected(Rejection::KeyNotInstalled(_))
    ));
    assert!(keys.remove_peer(LOOPBACK).unwrap());
    assert_eq!(calls(&keys).last(), Some(&Call::Remove(LOOPBACK)));
}

#[test]
fn debug_output_does_not_contain_keys() {
    let keys = ListenerKeys::new(FakePort::new(Outcome::Ok));
    let _ = keys.set_peer(LOOPBACK, required("hunter2"));
    assert!(!format!("{keys:?}").contains("hunter2"));
}
