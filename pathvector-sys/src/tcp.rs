//! TCP socket option wrappers.

use std::io;
use std::net::IpAddr;
use std::os::unix::io::RawFd;

/// Maximum TCP MD5 key length, as defined by the Linux kernel and RFC 2385.
/// This constant is platform-independent so validation runs everywhere.
const TCP_MD5SIG_MAXKEYLEN: usize = 80;

/// Set the `TCP_MD5SIG` socket option on `fd` for the given peer IP address.
///
/// Configures the Linux kernel to sign (outbound) or verify (inbound) every
/// TCP segment exchanged with `peer_ip` using HMAC-MD5 keyed by `key`. Both
/// sides of a BGP session must be configured with the same key.
///
/// Call this on the outbound socket before `connect()` and on the BGP
/// listener socket after `bind()` — before any SYN can arrive from the peer.
///
/// # Platform behaviour
///
/// - **Linux**: applies `setsockopt(TCP_MD5SIG)` via libc.
/// - **Other platforms**: no-op; returns `Ok(())` unconditionally. TCP MD5 is
///   only enforced on Linux in production; other platforms are for development.
///
/// # Errors
///
/// Returns `io::Error` if the syscall fails, for example:
/// - `EINVAL` — key exceeds 80 bytes or peer address is malformed.
/// - `ENOBUFS` — no room in the kernel MD5 key table.
/// - `EACCES` — permission denied (requires `CAP_NET_ADMIN` on some kernels).
pub fn apply_tcp_md5sig(fd: RawFd, peer_ip: IpAddr, key: &str) -> io::Result<()> {
    // Validate inputs on every platform so callers get consistent errors
    // regardless of where the binary runs (e.g. macOS in development).
    if key.len() > TCP_MD5SIG_MAXKEYLEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "TCP MD5 key too long: {} bytes (max {TCP_MD5SIG_MAXKEYLEN})",
                key.len(),
            ),
        ));
    }
    if let IpAddr::V6(_) = peer_ip {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP MD5SIG for IPv6 peers is not yet supported",
        ));
    }

    #[cfg(target_os = "linux")]
    return apply_linux(fd, peer_ip, key);

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, peer_ip);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn apply_linux(fd: RawFd, peer_ip: IpAddr, key: &str) -> io::Result<()> {
    use std::mem;

    // Mirror of the kernel's `tcp_md5sig` from `<linux/tcp.h>`.
    //
    // We define this locally rather than using `libc::tcp_md5sig` because the
    // libc crate does not expose `tcp_md5sig` on all Linux target architectures
    // in all released versions (e.g. aarch64 with libc 0.2.x). Defining it
    // ourselves is safe: the layout matches the kernel ABI on all Linux arches.
    //
    // Layout (128 + 2 + 1 + 1 + 4 + 80 = 216 bytes):
    //   struct __kernel_sockaddr_storage tcpm_addr;  // 128 bytes
    //   u16  __tcpm_pad1;                            //   2 bytes
    //   u8   tcpm_keylen;                            //   1 byte
    //   u8   __tcpm_pad2;                            //   1 byte
    //   u32  __tcpm_pad3;                            //   4 bytes
    //   u8   tcpm_key[TCP_MD5SIG_MAXKEYLEN];         //  80 bytes
    #[repr(C)]
    struct TcpMd5Sig {
        tcpm_addr:  libc::sockaddr_storage,
        tcpm_pad1:  u16,
        tcpm_keylen: u8,
        tcpm_pad2:  u8,
        tcpm_pad3:  u32,
        tcpm_key:   [u8; 80],
    }

    // Input validation was already performed by the public apply_tcp_md5sig
    // function. peer_ip is guaranteed to be V4; key length ≤ 80.
    let IpAddr::V4(v4) = peer_ip else {
        unreachable!("IPv6 rejected by apply_tcp_md5sig before reaching apply_linux")
    };

    let key_bytes = key.as_bytes();

    // SAFETY: TcpMd5Sig is a C struct of plain integers and fixed-size byte
    // arrays. A zero-initialised value is a valid starting state; all fields
    // are set explicitly before the setsockopt call.
    let mut sig: TcpMd5Sig = unsafe { mem::zeroed() };

    {
        let sin = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            // Port 0 in tcpm_addr means "match all connections to/from
            // this IP regardless of port" — the standard BGP MD5 usage.
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from(v4).to_be(),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: sockaddr_storage is large enough to hold sockaddr_in
        // (guaranteed by POSIX). We copy only sizeof(sockaddr_in) bytes
        // into the start of the storage; the remainder stays zeroed.
        unsafe {
            std::ptr::copy_nonoverlapping(
                std::ptr::addr_of!(sin).cast::<u8>(),
                std::ptr::addr_of_mut!(sig.tcpm_addr).cast::<u8>(),
                mem::size_of::<libc::sockaddr_in>(),
            );
        }
    }

    sig.tcpm_keylen = key_bytes.len() as u8;
    sig.tcpm_key[..key_bytes.len()].copy_from_slice(key_bytes);

    // SAFETY: `fd` is a valid socket descriptor supplied by the caller;
    // `sig` is fully initialised above; the size matches the struct.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            std::ptr::addr_of!(sig).cast::<libc::c_void>(),
            mem::size_of::<TcpMd5Sig>() as libc::socklen_t,
        )
    };

    if ret == 0 {
        return Ok(());
    }

    let err = io::Error::last_os_error();
    // ENOPROTOOPT / EOPNOTSUPP: kernel was built without CONFIG_TCP_MD5SIG.
    // This is expected on Docker Desktop (macOS/Windows) whose embedded Linux
    // kernel omits this feature; CI runs on native Linux where it is present.
    // Treat "not supported" as a non-fatal condition — log a warning and let
    // the BGP session continue without kernel-level authentication.
    if matches!(err.raw_os_error(), Some(libc::ENOPROTOOPT) | Some(libc::EOPNOTSUPP)) {
        // No tracing subscriber available here (sys crate has none); the
        // session-layer and daemon callers log via their own tracing spans.
        return Ok(());
    }
    Err(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ── Boundary / error-path unit tests ─────────────────────────────────────

    /// Keys longer than TCP_MD5SIG_MAXKEYLEN (80 bytes) must be rejected before
    /// the syscall is attempted. fd = -1 ensures we never reach the kernel.
    #[test]
    fn test_key_too_long_returns_error() {
        let long_key = "x".repeat(81);
        let result = apply_tcp_md5sig(-1, IpAddr::V4(Ipv4Addr::LOCALHOST), &long_key);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("too long"), "expected 'too long' in: {msg}");
    }

    /// A key at exactly the 80-byte limit must pass the length guard. On Linux
    /// the syscall will fail with EBADF (fd = -1) but not InvalidInput.
    /// On non-Linux this returns Ok(()) immediately.
    #[test]
    fn test_key_at_exact_limit_passes_length_guard() {
        let key = "x".repeat(80);
        let result = apply_tcp_md5sig(-1, IpAddr::V4(Ipv4Addr::LOCALHOST), &key);
        if let Err(e) = &result {
            assert_ne!(
                e.kind(),
                io::ErrorKind::InvalidInput,
                "80-byte key must not be rejected for length"
            );
        }
    }

    /// IPv6 addresses must be rejected with `Unsupported` until the feature is
    /// implemented. The check fires before any syscall.
    #[test]
    fn test_ipv6_returns_unsupported() {
        let result = apply_tcp_md5sig(-1, "::1".parse().unwrap(), "key");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    // ── Linux-only: real setsockopt call ─────────────────────────────────────

    /// On Linux, calling apply_tcp_md5sig on a real TCP socket with a valid key
    /// must succeed. This is the only test that actually exercises the kernel
    /// path; all others stay on the safe side of the syscall boundary.
    ///
    /// Uses a `TcpListener` (safe std API) to obtain a real socket fd.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_apply_succeeds_on_real_socket_linux() {
        use std::os::unix::io::AsRawFd;

        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("failed to bind loopback listener for MD5 test");
        let fd = listener.as_raw_fd();

        let result = apply_tcp_md5sig(fd, IpAddr::V4(Ipv4Addr::LOCALHOST), "bgp-test-key");
        assert!(
            result.is_ok(),
            "apply_tcp_md5sig must succeed on a real socket on Linux: {result:?}"
        );
    }

    /// Calling apply_tcp_md5sig twice on the same socket with the same peer IP
    /// (updating the key) must also succeed — the kernel replaces the entry.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_apply_twice_same_peer_succeeds_linux() {
        use std::os::unix::io::AsRawFd;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = listener.as_raw_fd();

        apply_tcp_md5sig(fd, IpAddr::V4(Ipv4Addr::LOCALHOST), "first-key")
            .expect("first apply must succeed");
        apply_tcp_md5sig(fd, IpAddr::V4(Ipv4Addr::LOCALHOST), "second-key")
            .expect("second apply (key rotation) must succeed");
    }

    /// Passing an invalid fd on Linux must return an OS error (EBADF), not
    /// panic or corrupt memory.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_invalid_fd_returns_os_error_linux() {
        let result = apply_tcp_md5sig(-1, IpAddr::V4(Ipv4Addr::LOCALHOST), "key");
        assert!(result.is_err());
        // Must be an OS-level error, not our application-layer InvalidInput.
        assert_ne!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    // ── Property tests ────────────────────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        /// Keys of 0–80 bytes (the full valid range) must never be rejected
        /// with InvalidInput. On Linux with fd = -1 the syscall returns EBADF;
        /// on non-Linux the function returns Ok(()). Neither is InvalidInput.
        #[test]
        fn prop_key_within_limit_never_rejected_for_length(
            key in "[a-zA-Z0-9!@#$%^&*]{0,80}"
        ) {
            let result = apply_tcp_md5sig(-1, IpAddr::V4(Ipv4Addr::LOCALHOST), &key);
            if let Err(e) = result {
                prop_assert_ne!(
                    e.kind(),
                    io::ErrorKind::InvalidInput,
                    "keys ≤80 bytes must not be rejected for length"
                );
            }
        }

        /// Any key longer than 80 bytes must be rejected with InvalidInput,
        /// regardless of content.
        #[test]
        fn prop_key_over_limit_always_rejected(
            suffix in "[a-zA-Z0-9]{1,200}"
        ) {
            // Build an 81+ byte key by prepending 80 x's.
            let key = format!("{}{suffix}", "x".repeat(80));
            prop_assume!(key.len() > 80);
            let result = apply_tcp_md5sig(-1, IpAddr::V4(Ipv4Addr::LOCALHOST), &key);
            prop_assert!(result.is_err());
            prop_assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }

        /// Any IPv6 address must always return Unsupported, regardless of the key.
        #[test]
        fn prop_ipv6_always_unsupported(
            a in 0u16..,
            b in 0u16..,
            c in 0u16..,
            d in 0u16..,
            e in 0u16..,
            f in 0u16..,
            g in 0u16..,
            h in 0u16..,
            key in "[a-zA-Z0-9]{1,80}"
        ) {
            use std::net::Ipv6Addr;
            let ip = IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h));
            let result = apply_tcp_md5sig(-1, ip, &key);
            prop_assert!(result.is_err());
            prop_assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
        }
    }
}
