//! Live-kernel proof that an installed TCP MD5 key is enforced (issue #58).
//!
//! A successful `setsockopt` is not evidence of protection, so these tests
//! open real TCP connections over loopback and watch what the kernel does
//! with them. Both ends are `127.0.0.1`, so a key "for 127.0.0.1" on the
//! listener and on the client covers both directions. No privileges or
//! network namespace are needed: `TCP_MD5SIG` is a per-socket option.
//!
//! Expected behaviour, from the primary sources:
//!
//! - RFC 2385 §2.0: a receiver "must validate" each signed segment; "A
//!   failing comparison must result in the segment being dropped and must
//!   not produce any response back to the sender." RFC 5925 §8: when MD5 is
//!   required for a connection "it must be added to all outgoing segments
//!   and validated on all incoming segments".
//! - RFC 2385 §4.1: such a connection attempt "will time out instead of
//!   being refused".
//! - Linux `net/ipv4/tcp.c`, `tcp_inbound_hash`: an unsigned segment from a
//!   peer that has a key is dropped (`SKB_DROP_REASON_TCP_MD5NOTFOUND`);
//!   `tcp_inbound_md5_hash` drops a signed segment when no key is configured
//!   (`TCP_MD5UNEXPECTED`) or the digest does not match (`TCP_MD5FAILURE`).
//! - Linux `net/ipv4/tcp_ipv4.c`: `__tcp_md5_do_add` updates a pre-existing
//!   entry for the same address (key rotation); a zero key length goes to
//!   `tcp_md5_do_del`, which returns `-ENOENT` when there is no key.
//!
//! **Kernel support.** Kernels built without `CONFIG_TCP_MD5SIG` (Docker
//! Desktop's `LinuxKit` kernel, for one) reject the option. There the
//! enforcement tests check that the adapter reports
//! `TcpMd5Unsupported::Kernel` and stop. When the `CI` environment variable is
//! set (GitHub Actions sets it) the kernel must support TCP MD5, and an
//! unsupported kernel fails the test instead, so CI never passes vacuously.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsFd;
use std::time::Duration;

use pathvector_sys::{
    TcpMd5Error, TcpMd5Key, TcpMd5Unsupported, install_tcp_md5_key, remove_tcp_md5_key,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// How long to wait for a handshake. A loopback handshake takes well under a
/// millisecond; a dropped SYN never gets any answer, so the exact value only
/// bounds how long the negative tests take.
const CONNECT_WAIT: Duration = Duration::from_millis(1500);

fn key(s: &str) -> TcpMd5Key {
    s.parse().expect("valid test key")
}

/// Returns `true` if this kernel enforces TCP MD5. If it does not, checks
/// that the adapter said so precisely, and fails when running under CI.
fn kernel_supports_md5(test: &str) -> bool {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    match install_tcp_md5_key(probe.as_fd(), LOOPBACK, &key("probe")) {
        Ok(()) => true,
        Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Kernel { errno })) => {
            assert!(
                errno == libc::ENOPROTOOPT || errno == libc::EOPNOTSUPP,
                "Kernel reason must carry ENOPROTOOPT/EOPNOTSUPP, got {errno}"
            );
            assert!(
                std::env::var_os("CI").is_none(),
                "{test}: CI kernels must support TCP_MD5SIG (errno {errno}); \
                 refusing to pass without proving enforcement"
            );
            eprintln!(
                "SKIP {test}: kernel lacks CONFIG_TCP_MD5SIG (errno {errno}); \
                 the adapter correctly reported Unsupported"
            );
            false
        }
        Err(e) => panic!("{test}: unexpected error probing TCP_MD5SIG: {e:?}"),
    }
}

/// A loopback listener with an optional key for 127.0.0.1.
async fn listener(md5: Option<&TcpMd5Key>) -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    if let Some(k) = md5 {
        install_tcp_md5_key(l.as_fd(), LOOPBACK, k).expect("install listener key");
    }
    let addr = l.local_addr().unwrap();
    (l, addr)
}

/// Connects to `addr` with an optional key. `None` if nothing answered
/// within [`CONNECT_WAIT`]; panics on a refused or failed connect, which
/// would mean the kernel answered instead of silently dropping.
async fn connect(addr: SocketAddr, md5: Option<&TcpMd5Key>) -> Option<TcpStream> {
    let s = TcpSocket::new_v4().unwrap();
    if let Some(k) = md5 {
        install_tcp_md5_key(s.as_fd(), LOOPBACK, k).expect("install client key");
    }
    match tokio::time::timeout(CONNECT_WAIT, s.connect(addr)).await {
        Ok(Ok(stream)) => Some(stream),
        Ok(Err(e)) => panic!("connect failed instead of timing out (RFC 2385 §4.1): {e}"),
        Err(_) => None,
    }
}

/// `true` if the listener has a connection ready within a short wait.
async fn accepted(l: &TcpListener) -> bool {
    tokio::time::timeout(Duration::from_millis(200), l.accept())
        .await
        .is_ok()
}

/// Matching keys on both ends: the handshake completes and data flows both
/// ways (every segment is signed and verified, RFC 2385 §2.0).
#[tokio::test]
async fn matching_keys_connect_and_exchange_data() {
    if !kernel_supports_md5("matching_keys_connect_and_exchange_data") {
        return;
    }
    let k = key("bgp-shared-secret");
    let (l, addr) = listener(Some(&k)).await;
    let mut client = connect(addr, Some(&k))
        .await
        .expect("matching keys must connect");
    let (mut server, _) = l.accept().await.unwrap();

    client.write_all(b"OPEN").await.unwrap();
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"OPEN");
    server.write_all(b"KEEP").await.unwrap();
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"KEEP");
}

/// Listener has a key, client sends unsigned segments: the SYN is dropped
/// (`TCP_MD5NOTFOUND`) with no reply, so the connect times out (RFC 2385
/// §4.1) and nothing is accepted.
#[tokio::test]
async fn unsigned_client_cannot_reach_keyed_listener() {
    if !kernel_supports_md5("unsigned_client_cannot_reach_keyed_listener") {
        return;
    }
    let (l, addr) = listener(Some(&key("bgp-shared-secret"))).await;
    assert!(
        connect(addr, None).await.is_none(),
        "unsigned SYN must be dropped"
    );
    assert!(!accepted(&l).await, "no connection may be accepted");
}

/// Wrong key: the digest comparison fails (`TCP_MD5FAILURE`) and the segment
/// is dropped without a response (RFC 2385 §2.0).
#[tokio::test]
async fn wrong_key_cannot_connect() {
    if !kernel_supports_md5("wrong_key_cannot_connect") {
        return;
    }
    let (l, addr) = listener(Some(&key("right-key"))).await;
    assert!(
        connect(addr, Some(&key("wrong-key"))).await.is_none(),
        "wrongly signed SYN must be dropped"
    );
    assert!(!accepted(&l).await, "no connection may be accepted");
}

/// Client signs but the listener has no key for it: Linux drops the signed
/// SYN (`TCP_MD5UNEXPECTED`). The client's key does not depend on the peer
/// agreeing (RFC 2385 §2.0: "the absence of the option in the SYN,ACK
/// segment must not cause the sender to disable its sending of signatures").
#[tokio::test]
async fn signed_client_cannot_reach_unkeyed_listener() {
    if !kernel_supports_md5("signed_client_cannot_reach_unkeyed_listener") {
        return;
    }
    let (l, addr) = listener(None).await;
    assert!(
        connect(addr, Some(&key("only-client-has-it")))
            .await
            .is_none(),
        "signed SYN to a listener without a key must be dropped"
    );
    assert!(!accepted(&l).await, "no connection may be accepted");
}

/// Installing a second key for the same peer replaces the first
/// (`__tcp_md5_do_add`: "Pre-existing entry - just update that one").
#[tokio::test]
async fn reinstalling_replaces_the_key() {
    if !kernel_supports_md5("reinstalling_replaces_the_key") {
        return;
    }
    let (l, addr) = listener(Some(&key("old-key"))).await;
    install_tcp_md5_key(l.as_fd(), LOOPBACK, &key("new-key")).expect("rotate");

    assert!(
        connect(addr, Some(&key("old-key"))).await.is_none(),
        "old key must no longer be accepted"
    );
    assert!(
        connect(addr, Some(&key("new-key"))).await.is_some(),
        "new key must be accepted"
    );
}

/// `remove_tcp_md5_key` really deletes the key: afterwards an unsigned
/// client connects. Removing it again fails with `NotFound`, since
/// `tcp_md5_do_del` returns `-ENOENT` when there is no key to delete.
#[tokio::test]
async fn removing_the_key_stops_enforcement() {
    if !kernel_supports_md5("removing_the_key_stops_enforcement") {
        return;
    }
    let (l, addr) = listener(Some(&key("temporary"))).await;
    remove_tcp_md5_key(l.as_fd(), LOOPBACK).expect("remove installed key");

    assert!(
        connect(addr, None).await.is_some(),
        "unsigned client must connect once the key is removed"
    );

    match remove_tcp_md5_key(l.as_fd(), LOOPBACK) {
        Err(TcpMd5Error::Os(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
        }
        other => panic!("removing an absent key must be ENOENT, got {other:?}"),
    }
}

/// On a kernel without TCP MD5, both operations say so precisely, never
/// `Ok(())`. Runs on every Linux kernel: where MD5 is supported it checks
/// that install and remove succeed instead.
#[tokio::test]
async fn unsupported_kernel_is_never_reported_as_enforced() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let install = install_tcp_md5_key(l.as_fd(), LOOPBACK, &key("k"));
    let remove = remove_tcp_md5_key(l.as_fd(), LOOPBACK);
    match (install, remove) {
        (Ok(()), Ok(())) => {}
        (
            Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Kernel { errno: a })),
            Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Kernel { errno: b })),
        ) => {
            assert_eq!(a, b);
            assert!(a == libc::ENOPROTOOPT || a == libc::EOPNOTSUPP, "errno {a}");
        }
        other => panic!("inconsistent or unexpected outcome: {other:?}"),
    }
}
