//! TCP socket option wrappers.

use std::io;
use std::net::IpAddr;
use std::os::unix::io::RawFd;

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
    #[cfg(target_os = "linux")]
    return apply_linux(fd, peer_ip, key);

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, peer_ip, key);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn apply_linux(fd: RawFd, peer_ip: IpAddr, key: &str) -> io::Result<()> {
    use std::mem;

    let key_bytes = key.as_bytes();
    if key_bytes.len() > libc::TCP_MD5SIG_MAXKEYLEN as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "TCP MD5 key too long: {} bytes (max {})",
                key_bytes.len(),
                libc::TCP_MD5SIG_MAXKEYLEN,
            ),
        ));
    }

    // SAFETY: tcp_md5sig is a C struct of plain integers and fixed-size byte
    // arrays. A zero-initialised value is a valid starting state; all fields
    // are set explicitly before the setsockopt call.
    let mut sig: libc::tcp_md5sig = unsafe { mem::zeroed() };

    match peer_ip {
        IpAddr::V4(v4) => {
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
        IpAddr::V6(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TCP MD5SIG for IPv6 peers is not yet supported",
            ));
        }
    }

    sig.tcpm_keylen = key_bytes.len() as u16;
    sig.tcpm_key[..key_bytes.len()].copy_from_slice(key_bytes);

    // SAFETY: `fd` is a valid socket descriptor supplied by the caller;
    // `sig` is fully initialised above; the size matches the struct.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            std::ptr::addr_of!(sig).cast::<libc::c_void>(),
            mem::size_of::<libc::tcp_md5sig>() as libc::socklen_t,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_key_too_long_returns_error() {
        let long_key = "x".repeat(81);
        // Use an invalid fd (-1); the key-length check fires before the syscall.
        let result = apply_tcp_md5sig(-1, IpAddr::V4(Ipv4Addr::LOCALHOST), &long_key);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("too long"), "expected 'too long' in: {msg}");
    }

    #[test]
    fn test_ipv6_returns_unsupported() {
        let result = apply_tcp_md5sig(-1, "::1".parse().unwrap(), "key");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
    }
}
