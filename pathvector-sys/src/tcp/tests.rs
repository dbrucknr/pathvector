//! Unit tests for the TCP MD5 adapter. Live-kernel behaviour (signing,
//! dropping, deletion) is in `tests/tcp_md5_loopback.rs`.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsFd;

use proptest::prelude::*;

use super::*;

fn loopback_listener() -> std::net::TcpListener {
    std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback listener")
}

// ── TcpMd5Key validation ──────────────────────────────────────────────────

/// Linux `tcp_v4_parse_md5_keys`: `if (!cmd.tcpm_keylen) return
/// tcp_md5_do_del(...)`. A zero-length key deletes protection, so it must
/// never be accepted as a key to install.
#[test]
fn empty_key_is_rejected() {
    assert_eq!(TcpMd5Key::new(b""), Err(TcpMd5KeyError::Empty));
    assert_eq!("".parse::<TcpMd5Key>(), Err(TcpMd5KeyError::Empty));
    assert_eq!(TcpMd5Key::try_from(""), Err(TcpMd5KeyError::Empty));
}

/// Linux `tcp_v4_parse_md5_keys`: `if (cmd.tcpm_keylen >
/// TCP_MD5SIG_MAXKEYLEN) return -EINVAL;` with `TCP_MD5SIG_MAXKEYLEN 80`
/// (`include/uapi/linux/tcp.h`).
#[test]
fn key_longer_than_80_bytes_is_rejected() {
    assert_eq!(
        TcpMd5Key::new(&[b'x'; 81]),
        Err(TcpMd5KeyError::TooLong { len: 81 })
    );
}

/// RFC 2385 §4.5: support "at minimum a key composed of a string of
/// printable ASCII of 80 bytes or less". Both ends of that range are valid.
#[test]
fn keys_of_1_and_80_bytes_are_accepted() {
    assert_eq!(TcpMd5Key::new(b"k").unwrap().as_bytes(), b"k");
    let max = "~".repeat(80);
    assert_eq!(
        TcpMd5Key::try_from(max.as_str()).unwrap().as_bytes(),
        max.as_bytes()
    );
}

/// The key is a secret: `Debug` must not print it, and neither may the
/// validation error.
#[test]
fn debug_output_redacts_the_key() {
    let key: TcpMd5Key = "hunter2-very-secret".parse().unwrap();
    let shown = format!("{key:?} {key:#?}");
    assert!(!shown.contains("hunter2"), "key leaked: {shown}");
    assert_eq!(format!("{key:?}"), "TcpMd5Key(<redacted>)");
}

proptest! {
    /// RFC 2385 §2.0 leaves the key's form open and Linux stores it as
    /// binary (`__u8 tcpm_key[...]`), so every byte string of 1..=80 bytes
    /// is a key, byte for byte.
    #[test]
    fn prop_any_1_to_80_bytes_is_a_key(bytes in proptest::collection::vec(any::<u8>(), 1..=80)) {
        let key = TcpMd5Key::new(&bytes).unwrap();
        prop_assert_eq!(key.as_bytes(), bytes.as_slice());
    }

    /// Anything longer than `TCP_MD5SIG_MAXKEYLEN` is rejected with its length.
    #[test]
    fn prop_over_80_bytes_is_rejected(len in 81usize..1024) {
        prop_assert_eq!(
            TcpMd5Key::new(&vec![b'a'; len]),
            Err(TcpMd5KeyError::TooLong { len })
        );
    }
}

// ── Errno classification ──────────────────────────────────────────────────

/// `net/ipv4/tcp.c` `do_tcp_setsockopt`: without `CONFIG_TCP_MD5SIG` the
/// `TCP_MD5SIG` case is compiled out and the call reaches
/// `default: err = -ENOPROTOOPT`. That means "no key was installed", so it
/// must be `Unsupported`, never success.
#[test]
fn enoprotoopt_and_eopnotsupp_mean_unsupported() {
    for errno in [libc::ENOPROTOOPT, libc::EOPNOTSUPP] {
        match classify(io::Error::from_raw_os_error(errno)) {
            TcpMd5Error::Unsupported(TcpMd5Unsupported::Kernel { errno: got }) => {
                assert_eq!(got, errno);
            }
            other => panic!("errno {errno} must be Unsupported, got {other:?}"),
        }
    }
}

/// Other failures (e.g. `ENOBUFS`, `EINVAL`, `ENOENT` from
/// `tcp_md5_do_del`) are real errors, not "unsupported": a fallback policy
/// that tolerates a kernel without TCP MD5 must not also swallow these.
#[test]
fn other_errnos_are_os_errors() {
    for errno in [libc::ENOBUFS, libc::EINVAL, libc::ENOENT, libc::EBADF] {
        match classify(io::Error::from_raw_os_error(errno)) {
            TcpMd5Error::Os(e) => assert_eq!(e.raw_os_error(), Some(errno)),
            other @ TcpMd5Error::Unsupported(_) => {
                panic!("errno {errno} must be Os, got {other:?}")
            }
        }
    }
}

/// Code that only sees `io::Error` (e.g. a connect future) can still tell
/// "unsupported" apart and recover the reason.
#[test]
fn unsupported_converts_to_io_unsupported_with_reason() {
    let io_err = io::Error::from(TcpMd5Error::Unsupported(TcpMd5Unsupported::Platform));
    assert_eq!(io_err.kind(), io::ErrorKind::Unsupported);
    let inner = io_err
        .get_ref()
        .and_then(|e| e.downcast_ref::<TcpMd5Error>())
        .expect("inner TcpMd5Error");
    assert!(matches!(
        inner,
        TcpMd5Error::Unsupported(TcpMd5Unsupported::Platform)
    ));
}

// ── Platform behaviour ────────────────────────────────────────────────────

/// Issue #58: on non-Linux builds nothing is installed, so install and
/// remove must both report `Unsupported(Platform)`. The old API returned
/// `Ok(())` here.
#[cfg(not(target_os = "linux"))]
#[test]
fn non_linux_reports_platform_unsupported() {
    let l = loopback_listener();
    let key: TcpMd5Key = "k".parse().unwrap();
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert!(matches!(
        install_tcp_md5_key(l.as_fd(), peer, &key),
        Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Platform))
    ));
    assert!(matches!(
        remove_tcp_md5_key(l.as_fd(), peer),
        Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Platform))
    ));
    assert!(matches!(
        KernelTcpMd5.install(l.as_fd(), peer, &key),
        Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Platform))
    ));
}

/// IPv6 peers have no adapter yet. That must surface as `Unsupported`, not as
/// a silent success.
#[cfg(target_os = "linux")]
#[test]
fn ipv6_peer_reports_unsupported() {
    let l = std::net::TcpListener::bind("[::1]:0")
        .or_else(|_| std::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let key: TcpMd5Key = "k".parse().unwrap();
    let peer = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
    assert!(matches!(
        install_tcp_md5_key(l.as_fd(), peer, &key),
        Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Ipv6Peer))
    ));
    assert!(matches!(
        remove_tcp_md5_key(l.as_fd(), peer),
        Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Ipv6Peer))
    ));
}

/// On Linux a real `setsockopt` either installs the key or reports why it
/// cannot. It must never be any other error for a valid socket and key.
#[cfg(target_os = "linux")]
#[test]
fn linux_install_is_enforced_or_unsupported() {
    let l = loopback_listener();
    let key: TcpMd5Key = "k".parse().unwrap();
    match install_tcp_md5_key(l.as_fd(), IpAddr::V4(Ipv4Addr::LOCALHOST), &key) {
        Ok(()) | Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Kernel { .. })) => {}
        Err(e) => panic!("unexpected error: {e:?}"),
    }
}

#[test]
fn labels_are_stable() {
    assert_eq!(TcpMd5Unsupported::Kernel { errno: 92 }.label(), "kernel");
    assert_eq!(TcpMd5Unsupported::Platform.label(), "platform");
    assert_eq!(TcpMd5Unsupported::Ipv6Peer.label(), "ipv6_peer");
}
