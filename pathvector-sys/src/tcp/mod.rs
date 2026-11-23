//! TCP MD5 signature keys (RFC 2385) on sockets.
//!
//! This module is the OS adapter. It installs or removes a key on one socket
//! and says exactly what happened:
//!
//! - `Ok(())` from [`install_tcp_md5_key`] means the kernel accepted the key,
//!   so it signs every segment it sends to that peer and drops every segment
//!   from that peer that is unsigned or wrongly signed. It never means
//!   anything weaker.
//! - [`TcpMd5Error::Unsupported`] means no key was installed because this
//!   host cannot enforce one (kernel built without TCP MD5, a non-Linux
//!   build, or an IPv6 peer). Callers must treat this as "not protected".
//! - [`TcpMd5Error::Os`] is any other syscall failure.
//!
//! What to do when enforcement is unavailable (refuse the connection, or go
//! ahead unprotected and say so) is a policy decision. It belongs to the
//! caller, not to this module: see `pathvector_session::transport::tcp_md5`.
//! Callers that want to substitute a fake adapter in tests depend on the
//! [`TcpMd5Port`] trait; [`KernelTcpMd5`] is the real one.
//!
//! # Why "unsupported" is an error
//!
//! RFC 2385 §2.0: "the sending of signatures must be under the complete
//! control of the application, not at the mercy of the remote host not
//! understanding the option." RFC 5925 §8 (which obsoletes RFC 2385 but keeps
//! TCP MD5 for legacy peers): "When an endpoint is configured to require TCP
//! MD5 for a connection, it must be added to all outgoing segments and
//! validated on all incoming segments \[RFC2385\]." A socket on which the key
//! could not be installed does neither, so reporting it as success would
//! claim protection that does not exist.
//!
//! On Linux the option is only handled when the kernel is built with
//! `CONFIG_TCP_MD5SIG` (`net/ipv4/tcp.c`, `do_tcp_setsockopt`: the
//! `case TCP_MD5SIG:` arm sits inside `#ifdef CONFIG_TCP_MD5SIG`); otherwise
//! the call falls through to `default: err = -ENOPROTOOPT`. Docker Desktop's
//! `LinuxKit` kernel is built this way.
//!
//! # Deleting a key
//!
//! Linux treats a zero key length as "delete the key for this address"
//! (`net/ipv4/tcp_ipv4.c`, `tcp_v4_parse_md5_keys`:
//! `if (!cmd.tcpm_keylen) return tcp_md5_do_del(...)`). That is why
//! [`TcpMd5Key`] cannot be empty, and why deletion is its own function,
//! [`remove_tcp_md5_key`].

mod key;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(test)]
mod tests;

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::os::fd::BorrowedFd;

pub use key::{TCP_MD5SIG_MAXKEYLEN, TcpMd5Key, TcpMd5KeyError};

/// Why a TCP MD5 key could not be enforced on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpMd5Unsupported {
    /// The kernel rejected the option itself: `setsockopt(TCP_MD5SIG)` failed
    /// with `ENOPROTOOPT` or `EOPNOTSUPP`. Linux returns `ENOPROTOOPT` when
    /// built without `CONFIG_TCP_MD5SIG`.
    Kernel {
        /// The raw `errno` the kernel returned.
        errno: i32,
    },
    /// This build targets an OS other than Linux, where this crate has no
    /// TCP MD5 adapter.
    Platform,
    /// The peer is IPv6. This crate only builds the IPv4 (`sockaddr_in`)
    /// form of the option so far.
    Ipv6Peer,
}

impl TcpMd5Unsupported {
    /// A short, stable label for logs and metrics: `"kernel"`, `"platform"`
    /// or `"ipv6_peer"`.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Kernel { .. } => "kernel",
            Self::Platform => "platform",
            Self::Ipv6Peer => "ipv6_peer",
        }
    }
}

impl fmt::Display for TcpMd5Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kernel { errno } => write!(
                f,
                "the kernel does not support TCP_MD5SIG ({}); it was probably built \
                 without CONFIG_TCP_MD5SIG",
                io::Error::from_raw_os_error(*errno)
            ),
            Self::Platform => f.write_str("TCP MD5 is only implemented on Linux"),
            Self::Ipv6Peer => f.write_str("TCP MD5 for IPv6 peers is not implemented yet"),
        }
    }
}

/// Failure to install or remove a TCP MD5 key.
#[derive(Debug)]
pub enum TcpMd5Error {
    /// The host cannot enforce TCP MD5 for this peer. No key was installed.
    Unsupported(TcpMd5Unsupported),
    /// The syscall failed for another reason, for example `ENOBUFS` (no
    /// room for another key), `EINVAL`, or `ENOENT` when removing a key that
    /// is not installed.
    Os(io::Error),
}

impl fmt::Display for TcpMd5Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(why) => write!(f, "TCP MD5 cannot be enforced: {why}"),
            Self::Os(e) => write!(f, "TCP MD5 setsockopt failed: {e}"),
        }
    }
}

impl std::error::Error for TcpMd5Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unsupported(_) => None,
            Self::Os(e) => Some(e),
        }
    }
}

impl From<TcpMd5Error> for io::Error {
    /// [`TcpMd5Error::Unsupported`] becomes [`io::ErrorKind::Unsupported`]
    /// (with the `TcpMd5Error` as its inner error); [`TcpMd5Error::Os`]
    /// returns the original error.
    fn from(e: TcpMd5Error) -> Self {
        match e {
            TcpMd5Error::Unsupported(_) => io::Error::new(io::ErrorKind::Unsupported, e),
            TcpMd5Error::Os(e) => e,
        }
    }
}

/// Port for installing and removing TCP MD5 keys on a socket.
///
/// [`KernelTcpMd5`] is the production adapter. Tests can implement this
/// trait to drive callers through the unsupported and failure paths without
/// a kernel that has (or lacks) TCP MD5.
pub trait TcpMd5Port {
    /// Installs `key` for `peer` on `socket`. See [`install_tcp_md5_key`].
    ///
    /// # Errors
    ///
    /// As for [`install_tcp_md5_key`].
    fn install(
        &self,
        socket: BorrowedFd<'_>,
        peer: IpAddr,
        key: &TcpMd5Key,
    ) -> Result<(), TcpMd5Error>;

    /// Removes the key for `peer` from `socket`. See [`remove_tcp_md5_key`].
    ///
    /// # Errors
    ///
    /// As for [`remove_tcp_md5_key`].
    fn remove(&self, socket: BorrowedFd<'_>, peer: IpAddr) -> Result<(), TcpMd5Error>;
}

/// The kernel adapter for [`TcpMd5Port`]: calls [`install_tcp_md5_key`] and
/// [`remove_tcp_md5_key`].
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelTcpMd5;

impl TcpMd5Port for KernelTcpMd5 {
    fn install(
        &self,
        socket: BorrowedFd<'_>,
        peer: IpAddr,
        key: &TcpMd5Key,
    ) -> Result<(), TcpMd5Error> {
        install_tcp_md5_key(socket, peer, key)
    }

    fn remove(&self, socket: BorrowedFd<'_>, peer: IpAddr) -> Result<(), TcpMd5Error> {
        remove_tcp_md5_key(socket, peer)
    }
}

/// Installs `key` as the TCP MD5 key for `peer` on `socket`.
///
/// After `Ok(())` the kernel signs every segment this socket sends to `peer`
/// and drops, without reply, every segment from `peer` that is unsigned or
/// carries a wrong signature (RFC 2385 §2.0). The key applies to all ports of
/// `peer`. Installing a key for a peer that already has one replaces it.
///
/// Call it on an outbound socket before `connect()`, and on a listening
/// socket before the peer's SYN can arrive; accepted sockets inherit the
/// listener's keys.
///
/// # Errors
///
/// - [`TcpMd5Error::Unsupported`] if this host cannot enforce the key: a
///   non-Linux build, an IPv6 `peer`, or a kernel that rejects the option
///   with `ENOPROTOOPT`/`EOPNOTSUPP`. No key is installed.
/// - [`TcpMd5Error::Os`] for any other `setsockopt` failure.
pub fn install_tcp_md5_key(
    socket: BorrowedFd<'_>,
    peer: IpAddr,
    key: &TcpMd5Key,
) -> Result<(), TcpMd5Error> {
    set_md5sig(socket, peer, key.as_bytes())
}

/// Removes the TCP MD5 key for `peer` from `socket`.
///
/// This sends the kernel a zero-length key, which Linux reads as a delete
/// request (`tcp_v4_parse_md5_keys` → `tcp_md5_do_del`). After `Ok(())` the
/// socket neither signs segments to `peer` nor requires signatures from it.
///
/// # Errors
///
/// - [`TcpMd5Error::Unsupported`] in the same cases as
///   [`install_tcp_md5_key`].
/// - [`TcpMd5Error::Os`] with [`io::ErrorKind::NotFound`] (`ENOENT`) if no
///   key for `peer` is installed on `socket` (`tcp_md5_do_del` returns
///   `-ENOENT` when its exact lookup finds nothing), or another OS error.
pub fn remove_tcp_md5_key(socket: BorrowedFd<'_>, peer: IpAddr) -> Result<(), TcpMd5Error> {
    set_md5sig(socket, peer, &[])
}

/// Shared body of install and remove. An empty `key` is a delete request;
/// only [`remove_tcp_md5_key`] passes one.
fn set_md5sig(socket: BorrowedFd<'_>, peer: IpAddr, key: &[u8]) -> Result<(), TcpMd5Error> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (socket, peer, key);
        Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Platform))
    }

    #[cfg(target_os = "linux")]
    {
        let IpAddr::V4(peer) = peer else {
            return Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Ipv6Peer));
        };
        linux::set_md5sig_v4(socket, peer, key).map_err(classify)
    }
}

/// Sorts a failed `setsockopt` into "the kernel cannot do TCP MD5" and
/// everything else.
#[cfg(any(target_os = "linux", test))]
fn classify(err: io::Error) -> TcpMd5Error {
    match err.raw_os_error() {
        Some(errno) if errno == libc::ENOPROTOOPT || errno == libc::EOPNOTSUPP => {
            TcpMd5Error::Unsupported(TcpMd5Unsupported::Kernel { errno })
        }
        _ => TcpMd5Error::Os(err),
    }
}
