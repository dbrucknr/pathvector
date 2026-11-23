//! TCP MD5 (RFC 2385) policy for BGP sessions.
//!
//! [`pathvector_sys`] installs keys and reports, without judgement, whether
//! the host enforced them. This module decides what a session does with that
//! answer:
//!
//! - [`Md5Enforcement::Required`] (the default): if the key cannot be
//!   enforced, the connection is not attempted. RFC 5925 §8: "When an
//!   endpoint is configured to require TCP MD5 for a connection, it must be
//!   added to all outgoing segments and validated on all incoming segments."
//! - [`Md5Enforcement::BestEffort`]: an explicit opt-in for hosts that cannot
//!   enforce TCP MD5, such as development machines and Docker Desktop. The
//!   connection goes ahead **unauthenticated**, a warning is logged on every
//!   attempt, and [`protect_socket`] returns [`Md5Protection::Unenforced`]
//!   with the reason. Real failures (for example `ENOBUFS`) still fail.

use std::io;
use std::net::IpAddr;
use std::os::fd::BorrowedFd;

pub use pathvector_sys::tcp::{
    KernelTcpMd5, TCP_MD5SIG_MAXKEYLEN, TcpMd5Error, TcpMd5Key, TcpMd5KeyError, TcpMd5Port,
    TcpMd5Unsupported,
};

/// What to do when a configured TCP MD5 key cannot be enforced on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Md5Enforcement {
    /// Refuse to connect without enforcement. The default.
    #[default]
    Required,
    /// Connect without authentication, and log a warning, when the host
    /// cannot enforce the key. Development only.
    BestEffort,
}

/// A session's TCP MD5 configuration: the key and the enforcement policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpMd5Auth {
    key: TcpMd5Key,
    enforcement: Md5Enforcement,
}

impl TcpMd5Auth {
    /// Authentication with `key` that must be enforced
    /// ([`Md5Enforcement::Required`]).
    #[must_use]
    pub fn required(key: TcpMd5Key) -> Self {
        Self::new(key, Md5Enforcement::Required)
    }

    /// Authentication with `key` under an explicit `enforcement` policy.
    #[must_use]
    pub fn new(key: TcpMd5Key, enforcement: Md5Enforcement) -> Self {
        Self { key, enforcement }
    }

    /// The key.
    #[must_use]
    pub fn key(&self) -> &TcpMd5Key {
        &self.key
    }

    /// The enforcement policy.
    #[must_use]
    pub fn enforcement(&self) -> Md5Enforcement {
        self.enforcement
    }
}

/// Whether a socket is protected by TCP MD5 after [`protect_socket`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Md5Protection {
    /// The kernel signs and verifies every segment exchanged with the peer.
    Enforced,
    /// The host could not enforce the key and the policy is
    /// [`Md5Enforcement::BestEffort`]: the connection is **not**
    /// authenticated.
    Unenforced(TcpMd5Unsupported),
}

/// Installs `auth`'s key for `peer` on `socket` through `port`, then applies
/// the enforcement policy.
///
/// # Errors
///
/// - [`io::ErrorKind::Unsupported`] if the key cannot be enforced and the
///   policy is [`Md5Enforcement::Required`]. The inner error is
///   [`Md5NotEnforceable`].
/// - Any other `setsockopt` failure, whatever the policy.
///
/// Both errors are also logged at `error` level with the peer and reason,
/// because the session loop reports a failed connect only as `TcpFailed`.
pub fn protect_socket<P: TcpMd5Port + ?Sized>(
    port: &P,
    socket: BorrowedFd<'_>,
    peer: IpAddr,
    auth: &TcpMd5Auth,
) -> io::Result<Md5Protection> {
    match port.install(socket, peer, auth.key()) {
        Ok(()) => Ok(Md5Protection::Enforced),
        Err(TcpMd5Error::Unsupported(why)) if auth.enforcement == Md5Enforcement::BestEffort => {
            tracing::warn!(
                %peer,
                reason = why.label(),
                "TCP MD5 key configured but NOT enforced ({why}); connecting \
                 unauthenticated because tcp_md5_enforcement is best-effort"
            );
            Ok(Md5Protection::Unenforced(why))
        }
        Err(TcpMd5Error::Unsupported(reason)) => {
            let refusal = Md5NotEnforceable { peer, reason };
            // Logged here because the session loop folds every connect error
            // into `TcpFailed`; this is the only place that knows why.
            tracing::error!(%peer, reason = reason.label(), "{refusal}");
            Err(io::Error::new(io::ErrorKind::Unsupported, refusal))
        }
        Err(TcpMd5Error::Os(e)) => {
            tracing::error!(%peer, error = %e, "TCP MD5 key setup failed");
            Err(io::Error::new(
                e.kind(),
                format!("TCP MD5 key setup failed for {peer}: {e}"),
            ))
        }
    }
}

/// The inner error of the [`io::ErrorKind::Unsupported`] error that
/// [`protect_socket`] returns when a required key cannot be enforced.
/// Recover it with `io::Error::get_ref` and `downcast_ref`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Md5NotEnforceable {
    peer: IpAddr,
    reason: TcpMd5Unsupported,
}

impl Md5NotEnforceable {
    /// The peer whose key could not be enforced.
    #[must_use]
    pub fn peer(&self) -> IpAddr {
        self.peer
    }

    /// Why the host could not enforce it.
    #[must_use]
    pub fn reason(&self) -> TcpMd5Unsupported {
        self.reason
    }
}

impl std::fmt::Display for Md5NotEnforceable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "refusing to connect to {}: TCP MD5 is required but cannot be enforced: {}",
            self.peer, self.reason
        )
    }
}

impl std::error::Error for Md5NotEnforceable {}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::Ipv4Addr;
    use std::os::fd::AsFd;
    use std::sync::Mutex;

    use super::*;

    /// A [`TcpMd5Port`] that returns a scripted result and records calls.
    pub(crate) struct FakePort {
        outcome: fn() -> Result<(), TcpMd5Error>,
        pub(crate) installs: Mutex<Vec<IpAddr>>,
    }

    impl FakePort {
        pub(crate) fn new(outcome: fn() -> Result<(), TcpMd5Error>) -> Self {
            Self {
                outcome,
                installs: Mutex::new(Vec::new()),
            }
        }
    }

    impl TcpMd5Port for FakePort {
        fn install(
            &self,
            _socket: BorrowedFd<'_>,
            peer: IpAddr,
            _key: &TcpMd5Key,
        ) -> Result<(), TcpMd5Error> {
            self.installs.lock().unwrap().push(peer);
            (self.outcome)()
        }

        fn remove(&self, _socket: BorrowedFd<'_>, _peer: IpAddr) -> Result<(), TcpMd5Error> {
            unreachable!("sessions never remove keys")
        }
    }

    #[allow(clippy::unnecessary_wraps)] // must match the scripted-outcome fn type
    pub(crate) fn enforced() -> Result<(), TcpMd5Error> {
        Ok(())
    }
    pub(crate) fn kernel_unsupported() -> Result<(), TcpMd5Error> {
        Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Kernel {
            errno: 92,
        }))
    }
    fn platform_unsupported() -> Result<(), TcpMd5Error> {
        Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Platform))
    }
    fn ipv6_unsupported() -> Result<(), TcpMd5Error> {
        Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Ipv6Peer))
    }
    fn no_buffer_space() -> Result<(), TcpMd5Error> {
        Err(TcpMd5Error::Os(io::Error::from(io::ErrorKind::OutOfMemory)))
    }

    const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    fn auth(enforcement: Md5Enforcement) -> TcpMd5Auth {
        TcpMd5Auth::new("k".parse().unwrap(), enforcement)
    }

    fn socket() -> std::net::TcpListener {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap()
    }

    /// Fail closed unless the operator opts out.
    #[test]
    fn default_enforcement_is_required() {
        assert_eq!(Md5Enforcement::default(), Md5Enforcement::Required);
        assert_eq!(
            TcpMd5Auth::required("k".parse().unwrap()).enforcement(),
            Md5Enforcement::Required
        );
    }

    #[test]
    fn installed_key_is_enforced() {
        let port = FakePort::new(enforced);
        for policy in [Md5Enforcement::Required, Md5Enforcement::BestEffort] {
            let s = socket();
            let got = protect_socket(&port, s.as_fd(), PEER, &auth(policy)).unwrap();
            assert_eq!(got, Md5Protection::Enforced);
        }
        assert_eq!(*port.installs.lock().unwrap(), vec![PEER, PEER]);
    }

    /// RFC 5925 §8: an endpoint "configured to require TCP MD5" must sign
    /// and validate every segment. If the host cannot, the only conforming
    /// outcome under `Required` is an error, for every unsupported reason.
    #[test]
    fn required_key_that_cannot_be_enforced_is_an_error() {
        for (outcome, reason) in [
            (
                kernel_unsupported as fn() -> _,
                TcpMd5Unsupported::Kernel { errno: 92 },
            ),
            (platform_unsupported, TcpMd5Unsupported::Platform),
            (ipv6_unsupported, TcpMd5Unsupported::Ipv6Peer),
        ] {
            let s = socket();
            let err = protect_socket(
                &FakePort::new(outcome),
                s.as_fd(),
                PEER,
                &auth(Md5Enforcement::Required),
            )
            .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
            let inner = err
                .get_ref()
                .and_then(|e| e.downcast_ref::<Md5NotEnforceable>())
                .expect("Md5NotEnforceable inside");
            assert_eq!(inner.peer(), PEER);
            assert_eq!(inner.reason(), reason);
        }
    }

    /// Issue #58: a fallback must be an explicit choice and stay observable.
    /// Under `BestEffort` the outcome names the reason instead of claiming
    /// enforcement.
    #[test]
    fn best_effort_reports_unenforced_with_reason() {
        let s = socket();
        let got = protect_socket(
            &FakePort::new(platform_unsupported),
            s.as_fd(),
            PEER,
            &auth(Md5Enforcement::BestEffort),
        )
        .unwrap();
        assert_eq!(got, Md5Protection::Unenforced(TcpMd5Unsupported::Platform));
    }

    /// `BestEffort` only covers "this host cannot do TCP MD5". A real
    /// failure to install a key the host does support stays an error.
    #[test]
    fn best_effort_does_not_hide_os_errors() {
        let s = socket();
        let err = protect_socket(
            &FakePort::new(no_buffer_space),
            s.as_fd(),
            PEER,
            &auth(Md5Enforcement::BestEffort),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::OutOfMemory);
    }

    #[test]
    fn auth_debug_does_not_show_the_key() {
        let a = TcpMd5Auth::required("hunter2".parse().unwrap());
        assert!(!format!("{a:?}").contains("hunter2"));
    }
}
