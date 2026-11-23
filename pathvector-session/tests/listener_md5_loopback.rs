//! Live-kernel proof that [`BgpListener`] enforces TCP MD5 keys on inbound
//! connections (issue #66).
//!
//! A successful `setsockopt` is not evidence of protection, so these tests
//! open real TCP connections over loopback and observe the outcome on both
//! sides: whether the client's handshake completes, and whether
//! [`BgpListener::accept`] hands the connection over. Client and listener
//! are both `127.0.0.1`, so the client signs with a key "for 127.0.0.1" and
//! the listener verifies with its key "for 127.0.0.1". No privileges are
//! needed: `TCP_MD5SIG` is a per-socket option.
//!
//! Expected behaviour, from the primary sources:
//!
//! - RFC 2385 §2.0: "A failing comparison must result in the segment being
//!   dropped and must not produce any response back to the sender." §4.1:
//!   such a connection attempt "will time out instead of being refused".
//! - RFC 5925 §8: when TCP MD5 is required for a connection "it must be
//!   added to all outgoing segments and validated on all incoming segments".
//! - Linux `tcp_inbound_hash` (`net/ipv4/tcp.c`), run on the listening
//!   socket for every inbound segment: unsigned from an address with a key
//!   → `TCP_MD5NOTFOUND`; signed with no key → `TCP_MD5UNEXPECTED`; wrong
//!   digest → `TCP_MD5FAILURE`. All three drop the segment.
//! - Linux `tcp_v4_syn_recv_sock` copies the listener's key into the new
//!   connection when the handshake completes, so a connection that completed
//!   before the key was installed has none.
//!
//! **Kernel support.** On a kernel without `CONFIG_TCP_MD5SIG` (Docker
//! Desktop) or a non-Linux host, the enforcement tests skip, and
//! `required_key_on_a_host_without_md5_rejects_the_peer` runs instead. When
//! `CI` is set on Linux, the kernel must support TCP MD5 and these tests
//! fail rather than skip, so CI never passes vacuously.

#![cfg(unix)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::Arc;
use std::time::Duration;

use pathvector_session::transport::listener::{
    Admission, BgpListener, KeyRefusal, ListenerKeys, ListenerProtection, Rejection,
};
use pathvector_session::transport::tcp_md5::{
    KernelTcpMd5, TcpMd5Auth, TcpMd5Error, TcpMd5Key, TcpMd5Port,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Bounds how long a dropped handshake is waited for. A loopback handshake
/// takes well under a millisecond; a dropped SYN never gets an answer.
const CONNECT_WAIT: Duration = Duration::from_millis(1500);

fn key(s: &str) -> TcpMd5Key {
    s.parse().expect("valid test key")
}

fn required(s: &str) -> TcpMd5Auth {
    TcpMd5Auth::required(key(s))
}

/// Whether this host enforces TCP MD5. Fails under `CI` on Linux if not.
fn host_supports_md5(test: &str) -> bool {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    match KernelTcpMd5.install(probe.as_fd(), LOOPBACK, &key("probe")) {
        Ok(()) => true,
        Err(TcpMd5Error::Unsupported(why)) => {
            assert!(
                !(cfg!(target_os = "linux") && std::env::var_os("CI").is_some()),
                "{test}: CI kernels must support TCP_MD5SIG ({why}); refusing to pass \
                 without proving enforcement"
            );
            eprintln!("SKIP {test}: {why}");
            false
        }
        Err(e) => panic!("{test}: unexpected error probing TCP_MD5SIG: {e:?}"),
    }
}

fn bind(keys: &Arc<ListenerKeys>) -> (BgpListener, SocketAddr) {
    let l = BgpListener::bind("127.0.0.1:0".parse().unwrap(), Arc::clone(keys)).expect("bind");
    let addr = l.local_addr().unwrap();
    (l, addr)
}

/// Connects to `addr`, signing with `md5` if given. `None` if the handshake
/// did not complete within [`CONNECT_WAIT`]; panics if it was refused,
/// which would mean the listener answered instead of dropping silently.
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

/// The next connection the listener hands over within a short wait.
async fn try_accept(l: &mut BgpListener) -> Option<(TcpStream, SocketAddr)> {
    tokio::time::timeout(Duration::from_millis(300), l.accept())
        .await
        .ok()
        .map(|r| r.expect("accept"))
}

/// Accepts `client`'s connection and exchanges a few bytes each way, so
/// every data segment is signed and verified too.
async fn accept_and_talk(l: &mut BgpListener, mut client: TcpStream) {
    let (mut server, from) = try_accept(l).await.expect("connection must be handed over");
    assert_eq!(from, client.local_addr().unwrap());
    client.write_all(b"OPEN").await.unwrap();
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"OPEN");
    server.write_all(b"KEEP").await.unwrap();
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"KEEP");
}

/// `true` if the listener closed `client` without sending anything.
async fn closed_by_server(mut client: TcpStream) -> bool {
    let mut buf = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await {
        Ok(Ok(0)) => true,
        Ok(Err(e)) => e.kind() == std::io::ErrorKind::ConnectionReset,
        Ok(Ok(_)) | Err(_) => false,
    }
}

/// A key configured before the listener binds (a statically configured
/// peer): only a client signing with that key gets through. Unsigned and
/// wrongly signed SYNs are dropped, so those clients time out and nothing
/// is handed over.
#[tokio::test]
async fn static_key_admits_only_the_matching_key() {
    if !host_supports_md5("static_key_admits_only_the_matching_key") {
        return;
    }
    let keys = Arc::new(ListenerKeys::default());
    let _ = keys.set_peer(LOOPBACK, required("static-key"));
    let (mut l, addr) = bind(&keys);
    assert_eq!(keys.admission(LOOPBACK), Admission::Authenticated);

    assert!(connect(addr, None).await.is_none(), "unsigned SYN dropped");
    assert!(
        connect(addr, Some(&key("wrong-key"))).await.is_none(),
        "wrongly signed SYN dropped"
    );
    assert!(try_accept(&mut l).await.is_none(), "nothing handed over");

    let client = connect(addr, Some(&key("static-key")))
        .await
        .expect("matching key connects");
    accept_and_talk(&mut l, client).await;
}

/// A key added while the listener is running (a dynamically added peer)
/// takes effect without rebinding: before it, an unsigned client gets in;
/// after it, only the matching key does.
#[tokio::test]
async fn dynamically_added_key_is_enforced() {
    if !host_supports_md5("dynamically_added_key_is_enforced") {
        return;
    }
    let keys = Arc::new(ListenerKeys::default());
    let (mut l, addr) = bind(&keys);
    let before = connect(addr, None).await.expect("no key yet");
    accept_and_talk(&mut l, before).await;

    assert_eq!(
        keys.set_peer(LOOPBACK, required("added-key")),
        Ok(ListenerProtection::Enforced)
    );

    assert!(connect(addr, None).await.is_none(), "unsigned SYN dropped");
    assert!(connect(addr, Some(&key("wrong-key"))).await.is_none());
    let client = connect(addr, Some(&key("added-key")))
        .await
        .expect("matching key connects");
    accept_and_talk(&mut l, client).await;
}

/// Rotation replaces the listener's key (`__tcp_md5_do_add`: "Pre-existing
/// entry - just update that one"): the old key stops working, the new one
/// works, and a connection accepted under the old key keeps working because
/// it holds its own copy.
#[tokio::test]
async fn rotated_key_replaces_the_old_one() {
    if !host_supports_md5("rotated_key_replaces_the_old_one") {
        return;
    }
    let keys = Arc::new(ListenerKeys::default());
    let _ = keys.set_peer(LOOPBACK, required("old-key"));
    let (mut l, addr) = bind(&keys);
    let mut established = connect(addr, Some(&key("old-key"))).await.expect("old key");
    let (mut server, _) = try_accept(&mut l).await.expect("accepted");

    assert_eq!(
        keys.set_peer(LOOPBACK, required("new-key")),
        Ok(ListenerProtection::Enforced)
    );

    assert!(connect(addr, Some(&key("old-key"))).await.is_none());
    let client = connect(addr, Some(&key("new-key")))
        .await
        .expect("new key connects");
    accept_and_talk(&mut l, client).await;

    established.write_all(b"STILL").await.unwrap();
    let mut buf = [0u8; 5];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"STILL", "existing connection keeps its old key");
}

/// Removing the key (with the separate remove operation) ends enforcement:
/// unsigned clients get through again, and a client that still signs is
/// now dropped (`TCP_MD5UNEXPECTED`).
#[tokio::test]
async fn removed_key_is_no_longer_enforced() {
    if !host_supports_md5("removed_key_is_no_longer_enforced") {
        return;
    }
    let keys = Arc::new(ListenerKeys::default());
    let _ = keys.set_peer(LOOPBACK, required("temporary"));
    let (mut l, addr) = bind(&keys);

    assert_eq!(keys.remove_peer(LOOPBACK).ok(), Some(true));
    assert_eq!(keys.admission(LOOPBACK), Admission::Unkeyed);

    assert!(connect(addr, Some(&key("temporary"))).await.is_none());
    let client = connect(addr, None).await.expect("unsigned connects");
    accept_and_talk(&mut l, client).await;
}

/// The race: a connection whose handshake completed before the key was
/// added carries no key, so the kernel would not check its segments. The
/// listener must close it instead of handing it over.
#[tokio::test]
async fn connection_completed_before_a_dynamic_key_is_rejected() {
    if !host_supports_md5("connection_completed_before_a_dynamic_key_is_rejected") {
        return;
    }
    let keys = Arc::new(ListenerKeys::default());
    let (mut l, addr) = bind(&keys);
    let early = connect(addr, None).await.expect("no key yet");
    // Let the server finish its side of the handshake so it is queued.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let _ = keys.set_peer(LOOPBACK, required("late-key"));

    assert!(
        try_accept(&mut l).await.is_none(),
        "early connection held back"
    );
    assert!(closed_by_server(early).await, "and closed");
    let client = connect(addr, Some(&key("late-key")))
        .await
        .expect("matching key connects");
    accept_and_talk(&mut l, client).await;
}

/// On a host that cannot enforce TCP MD5 (non-Linux, or a kernel without
/// `CONFIG_TCP_MD5SIG`), a required key fails closed: the handshake
/// completes because nothing in the kernel checks it, but the listener
/// closes the connection and never hands it over.
#[tokio::test]
async fn required_key_on_a_host_without_md5_rejects_the_peer() {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let Err(TcpMd5Error::Unsupported(why)) =
        KernelTcpMd5.install(probe.as_fd(), LOOPBACK, &key("probe"))
    else {
        eprintln!("SKIP: this host enforces TCP MD5; see the enforcement tests");
        return;
    };

    let keys = Arc::new(ListenerKeys::default());
    let (mut l, addr) = bind(&keys);
    let err = keys
        .set_peer(LOOPBACK, required("k"))
        .expect_err("required key that cannot be enforced");
    assert_eq!(err.refusal(), KeyRefusal::NotEnforceable(why));
    assert_eq!(
        keys.admission(LOOPBACK),
        Admission::Rejected(Rejection::KeyNotInstalled(KeyRefusal::NotEnforceable(why)))
    );

    let client = connect(addr, None).await.expect("kernel does not drop it");
    assert!(try_accept(&mut l).await.is_none(), "never handed over");
    assert!(closed_by_server(client).await, "closed by the listener");
}
