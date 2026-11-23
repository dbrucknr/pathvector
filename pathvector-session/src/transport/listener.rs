//! The BGP listening socket and the TCP MD5 (RFC 2385) keys on it.
//!
//! RFC 4271 §8: "A BGP implementation MUST connect to and listen on TCP port
//! 179 for incoming connections in addition to trying to connect to peers."
//! When a peer has a TCP MD5 key, the listening socket needs that key as
//! well. A key installed on an outbound socket protects that socket only; a
//! listening socket without a key accepts unsigned connections from the
//! peer's address. RFC 5925 §8: "When an endpoint is configured to require
//! TCP MD5 for a connection, it must be added to all outgoing segments and
//! validated on all incoming segments \[RFC2385\]."
//!
//! [`ListenerKeys`] is the table of configured keys and their state on the
//! listening sockets. [`BgpListener`] is a listening socket that installs
//! those keys before it starts listening and screens every connection it
//! accepts against the table.
//!
//! # What Linux does with a key on a listening socket
//!
//! From `net/ipv4/tcp_ipv4.c` and `net/ipv4/tcp.c`:
//!
//! - `tcp_v4_rcv` runs `tcp_inbound_hash` on every segment for the listening
//!   socket before the handshake code sees it. An unsigned segment from an
//!   address the socket has a key for is dropped
//!   (`SKB_DROP_REASON_TCP_MD5NOTFOUND`). `tcp_inbound_md5_hash` drops a
//!   signed segment when there is no key (`TCP_MD5UNEXPECTED`) or the digest
//!   is wrong (`TCP_MD5FAILURE`). RFC 2385 §2.0: "A failing comparison must
//!   result in the segment being dropped and must not produce any response
//!   back to the sender", so such a client times out instead of being
//!   refused (§4.1).
//! - A key set with plain `TCP_MD5SIG` covers one address: in
//!   `tcp_v4_parse_md5_keys`, `prefixlen` is 32 unless `TCP_MD5SIG_EXT` with
//!   `TCP_MD5SIG_FLAG_PREFIX` says otherwise, and `__tcp_md5_do_lookup`
//!   matches keys by address prefix, not by port.
//! - When the handshake completes, `tcp_v4_syn_recv_sock` copies the
//!   listener's key for the peer into the new socket ("Copy over the MD5 key
//!   from the original socket", `tcp_md5_key_copy`). The accepted socket
//!   keeps that copy. Changing or removing the listener's key later has no
//!   effect on connections that already exist.
//!
//! # Key changes on a listening socket
//!
//! Since the key is copied when the handshake completes, a connection that
//! completed before the listener had the key carries no key, even if it is
//! accepted afterwards. Keys installed by [`BgpListener::bind`] go on the
//! socket before `listen()`, so for them no such connection can exist.
//!
//! A key added or changed later with [`ListenerKeys::set_peer`] goes on the
//! live socket at once, so new handshakes are checked against it. But
//! connections created before the change may already be queued, or may still
//! be on their way to the queue: the kernel copies the key into a new
//! connection (`tcp_v4_syn_recv_sock`) a moment before appending it to the
//! accept queue (`inet_csk_reqsk_queue_add`), and no amount of waiting proves
//! that every such append has happened. So after such a change [`BgpListener`]
//! **replaces its socket**:
//!
//! 1. It takes the queued connections off the old socket, rejecting those from
//!    the changed peer and keeping the others.
//! 2. It shuts the old socket down. `shutdown(SHUT_RD)` on a listening socket
//!    runs `tcp_disconnect` (`inet_shutdown`, `case TCP_LISTEN`), which sets
//!    `TCP_CLOSE` and then `inet_csk_listen_stop` discards every queued
//!    connection. A late `inet_csk_reqsk_queue_add` checks
//!    `sk->sk_state != TCP_LISTEN` under the queue lock and discards the
//!    connection, and a half-open handshake on a non-listening socket is
//!    dropped and looked up again (`tcp_v4_rcv`, `TCP_NEW_SYN_RECV`). The
//!    socket is never set listening again. Connections are not moved to
//!    another socket: `reuseport_migrate_sock` does that only for an
//!    `SO_REUSEPORT` group, which this socket never joins.
//! 3. It binds a new socket to the same address and installs every key
//!    before `listen()`, like [`BgpListener::bind`].
//!
//! Every connection from the new socket was created by a socket that had the
//! peer's current key from the start. Until the replacement is done,
//! connections from the changed peer are rejected; while it happens (well
//! under a millisecond on loopback), new handshakes get no answer and the
//! peer retries. Only a key that was actually installed after `listen()`
//! causes a replacement: added or rotated keys, not removals and not keys
//! that could not be installed.
//!
//! # Connections accepted around a key change
//!
//! Each connection [`BgpListener::accept`] returns carries an [`AuthStamp`]:
//! the state of the key table when the connection was screened. If the
//! peer's key is set again afterwards, [`ListenerKeys::is_current`] says the
//! connection predates it. The listener checks this before handing over a
//! connection it buffered, and the caller should check it again at the point
//! where it commits to using the connection: if the code that adds a peer
//! sets its key first and only then makes the peer reachable, a connection
//! that passes both the reachability check and `is_current` was screened
//! after the key was set.
//!
//! # When the key cannot be enforced
//!
//! The policy is the same as for outbound connections
//! ([`Md5Enforcement`]):
//!
//! - `Required`: the peer's connections are rejected after `accept()`, and
//!   [`ListenerKeys::set_peer`] returns an error. The kernel does not drop
//!   them, so the handshake completes, but no byte of BGP is read.
//! - `BestEffort`: the peer's connections are accepted unauthenticated, with
//!   a warning each time.
//!
//! # Address families
//!
//! One [`BgpListener`] per address family can be bound to a
//! [`ListenerKeys`]. IPv6 listeners are bound with `IPV6_V6ONLY`, so an IPv4
//! peer only ever reaches the IPv4 listener, which is the one that holds its
//! key. A connection whose address family differs from the listener's is
//! rejected.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

use super::tcp_md5::{
    KernelTcpMd5, Md5Enforcement, TcpMd5Auth, TcpMd5Error, TcpMd5Port, TcpMd5Unsupported,
};

/// Backlog passed to `listen()`.
const LISTEN_BACKLOG: i32 = 1024;

/// Most connections the accept queue can hold. Linux caps the backlog at
/// `net.core.somaxconn` (`__sys_listen_socket`) and stops creating
/// connections once the queue holds more than the backlog
/// (`sk_acceptq_is_full`: `sk_ack_backlog > sk_max_ack_backlog`, checked in
/// `tcp_v4_syn_recv_sock`). Taking at most this many before replacing the
/// socket keeps a connection flood from holding the replacement off.
const MAX_QUEUED: usize = LISTEN_BACKLOG.unsigned_abs() as usize + 1;

/// An IP address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

impl AddressFamily {
    /// The family of `ip`.
    #[must_use]
    pub const fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::V4 => 0,
            Self::V6 => 1,
        }
    }
}

/// What a listening socket does for a peer after [`ListenerKeys::set_peer`]
/// succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum ListenerProtection {
    /// The key is on the listening socket for the peer's address family. The
    /// kernel drops every unsigned or wrongly signed segment from the peer.
    Enforced,
    /// The host cannot enforce the key and the policy is
    /// [`Md5Enforcement::BestEffort`]: the peer's connections are accepted
    /// **unauthenticated**.
    Unenforced(TcpMd5Unsupported),
    /// No listening socket for the peer's address family is bound yet. The
    /// key is installed when one is, before it starts listening.
    Deferred,
}

/// Why a peer's key is not on the listening socket, so that its connections
/// are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRefusal {
    /// The host cannot enforce TCP MD5 for this peer and the policy is
    /// [`Md5Enforcement::Required`].
    NotEnforceable(TcpMd5Unsupported),
    /// `setsockopt` failed for another reason, for example `ENOMEM` when the
    /// socket's option memory (`net.core.optmem_max`) is used up.
    Os {
        /// The error kind.
        kind: io::ErrorKind,
        /// The raw `errno`, when there is one.
        errno: Option<i32>,
    },
}

impl KeyRefusal {
    fn os(e: &io::Error) -> Self {
        Self::Os {
            kind: e.kind(),
            errno: e.raw_os_error(),
        }
    }
}

impl fmt::Display for KeyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnforceable(why) => {
                write!(f, "TCP MD5 is required but cannot be enforced: {why}")
            }
            Self::Os {
                errno: Some(errno), ..
            } => write!(
                f,
                "installing the key failed: {}",
                io::Error::from_raw_os_error(*errno)
            ),
            Self::Os { kind, errno: None } => {
                write!(f, "installing the key failed: {}", io::Error::from(*kind))
            }
        }
    }
}

/// A peer's key could not be put on the listening socket. Connections from
/// the peer are rejected until a later [`ListenerKeys::set_peer`] succeeds or
/// the peer is removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerKeyError {
    peer: IpAddr,
    refusal: KeyRefusal,
}

impl ListenerKeyError {
    /// The peer.
    #[must_use]
    pub fn peer(&self) -> IpAddr {
        self.peer
    }

    /// Why its key is not installed.
    #[must_use]
    pub fn refusal(&self) -> KeyRefusal {
        self.refusal
    }
}

impl fmt::Display for ListenerKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "refusing inbound connections from {}: {}",
            self.peer, self.refusal
        )
    }
}

impl std::error::Error for ListenerKeyError {}

/// What the listener does with a connection from a given address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// No key is configured for the address; TCP MD5 does not apply.
    Unkeyed,
    /// The key is on the listening socket, so the kernel authenticated the
    /// handshake and the accepted socket carries the key.
    Authenticated,
    /// A key is configured but cannot be enforced, and the policy is
    /// [`Md5Enforcement::BestEffort`]. Accepted **unauthenticated**.
    Unauthenticated(TcpMd5Unsupported),
    /// The connection must not be used.
    Rejected(Rejection),
}

/// Why [`Admission::Rejected`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The configured key is not on the listening socket.
    KeyNotInstalled(KeyRefusal),
    /// The key was installed or changed after the socket started listening,
    /// and connections that completed before that may still be queued. See
    /// the [module documentation](self).
    KeyChangePending,
    /// No listening socket for the peer's address family is bound, so no
    /// connection from it can have been authenticated.
    NoListener,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyNotInstalled(refusal) => write!(f, "TCP MD5 key not installed: {refusal}"),
            Self::KeyChangePending => f.write_str(
                "TCP MD5 key changed; connections queued before the change are being discarded",
            ),
            Self::NoListener => f.write_str("no listening socket holds the TCP MD5 key"),
        }
    }
}

/// The state of a [`ListenerKeys`] table when a connection was screened.
/// See [`ListenerKeys::is_current`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthStamp(u64);

/// A connection [`BgpListener::accept`] admitted.
#[derive(Debug)]
pub struct Inbound {
    stream: TcpStream,
    peer: SocketAddr,
    stamp: AuthStamp,
}

impl Inbound {
    /// The remote address.
    #[must_use]
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// When the connection was screened. Check it with
    /// [`ListenerKeys::is_current`] or [`BgpListener::is_current`] before
    /// using the connection.
    #[must_use]
    pub fn stamp(&self) -> AuthStamp {
        self.stamp
    }

    /// The connection.
    #[must_use]
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}

/// A peer's key state on the listening socket of its address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyState {
    /// No listening socket for the family.
    Deferred,
    /// The key is on the socket. `settled` is false if it was installed after
    /// the socket started listening; the socket must then be replaced.
    Installed { settled: bool },
    /// Best-effort and not enforceable.
    Unenforced(TcpMd5Unsupported),
    /// Not installed; connections are rejected.
    Refused(KeyRefusal),
}

impl KeyState {
    const fn is_unsettled(self) -> bool {
        matches!(self, Self::Installed { settled: false })
    }
}

#[derive(Debug)]
struct PeerEntry {
    auth: TcpMd5Auth,
    state: KeyState,
    /// Whether the attached socket holds *some* key for this peer. Usually
    /// the same as `state` being `Installed`, but a failed key change
    /// leaves the previous key in place.
    on_socket: bool,
    /// The table's change counter when this peer's key was last set.
    changed: u64,
}

#[derive(Debug)]
struct Slot {
    /// A duplicate of the listening socket's descriptor, for `setsockopt`.
    fd: OwnedFd,
    /// Wakes the socket's [`BgpListener`] after a key change.
    notify: Arc<Notify>,
}

#[derive(Debug, Default)]
struct Inner {
    peers: HashMap<IpAddr, PeerEntry>,
    /// Indexed by [`AddressFamily::index`].
    slots: [Option<Slot>; 2],
    /// Number of unsettled keys per family, indexed like `slots`.
    unsettled: [usize; 2],
    /// Incremented by every [`ListenerKeys::set_peer`] that changes a peer.
    changes: u64,
}

impl Inner {
    /// Updates `family`'s unsettled count for a peer whose state changed
    /// from `before` to `after` (`None`: no entry).
    fn track(&mut self, family: AddressFamily, before: Option<KeyState>, after: Option<KeyState>) {
        let count = &mut self.unsettled[family.index()];
        if before.is_some_and(KeyState::is_unsettled) {
            *count -= 1;
        }
        if after.is_some_and(KeyState::is_unsettled) {
            *count += 1;
        }
    }
}

/// The TCP MD5 keys configured for inbound connections, and their state on
/// the listening sockets.
///
/// Shared (in an [`Arc`]) between whoever manages the peer set, which calls
/// [`set_peer`](Self::set_peer) and [`remove_peer`](Self::remove_peer), and
/// the [`BgpListener`]s, which install the keys when they bind and ask
/// [`admission`](Self::admission) for every connection they accept.
///
/// The OS calls go through `P`, a [`TcpMd5Port`]; tests substitute a fake.
pub struct ListenerKeys<P = KernelTcpMd5> {
    port: P,
    inner: Mutex<Inner>,
}

impl Default for ListenerKeys<KernelTcpMd5> {
    fn default() -> Self {
        Self::new(KernelTcpMd5)
    }
}

impl<P> fmt::Debug for ListenerKeys<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TcpMd5Auth's Debug redacts the key.
        f.debug_struct("ListenerKeys")
            .field("inner", &*self.lock())
            .finish_non_exhaustive()
    }
}

impl<P> ListenerKeys<P> {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        // Every critical section leaves `Inner` consistent before it can
        // panic, so a poisoned lock still holds valid state.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The OS adapter.
    #[must_use]
    pub fn port(&self) -> &P {
        &self.port
    }

    /// The configured authentication for `peer`, if any.
    #[must_use]
    pub fn configured(&self, peer: IpAddr) -> Option<TcpMd5Auth> {
        self.lock().peers.get(&peer).map(|e| e.auth.clone())
    }

    /// What a listener does with a connection from `peer`.
    #[must_use]
    pub fn admission(&self, peer: IpAddr) -> Admission {
        self.screen(peer).0
    }

    /// [`admission`](Self::admission) and the stamp it was read at.
    fn screen(&self, peer: IpAddr) -> (Admission, AuthStamp) {
        let inner = self.lock();
        let admission = match inner.peers.get(&peer).map(|e| e.state) {
            None => Admission::Unkeyed,
            Some(KeyState::Installed { settled: true }) => Admission::Authenticated,
            Some(KeyState::Installed { settled: false }) => {
                Admission::Rejected(Rejection::KeyChangePending)
            }
            Some(KeyState::Unenforced(why)) => Admission::Unauthenticated(why),
            Some(KeyState::Refused(refusal)) => {
                Admission::Rejected(Rejection::KeyNotInstalled(refusal))
            }
            Some(KeyState::Deferred) => Admission::Rejected(Rejection::NoListener),
        };
        (admission, AuthStamp(inner.changes))
    }

    /// Whether a connection from `peer` screened at `stamp` is still valid:
    /// `false` if `peer`'s key has been set since (added, rotated, or failed
    /// to install), so that the connection predates the current key.
    #[must_use]
    pub fn is_current(&self, peer: IpAddr, stamp: AuthStamp) -> bool {
        self.lock()
            .peers
            .get(&peer)
            .is_none_or(|e| e.changed <= stamp.0)
    }

    /// Whether any key of `family` was installed after its socket started
    /// listening, so that the socket must be replaced. Constant time.
    fn has_unsettled(&self, family: AddressFamily) -> bool {
        self.lock().unsettled[family.index()] > 0
    }

    /// Forgets `family`'s socket. Its keys go back to
    /// [`ListenerProtection::Deferred`].
    fn detach(&self, family: AddressFamily) {
        let mut inner = self.lock();
        inner.slots[family.index()] = None;
        inner.unsettled[family.index()] = 0;
        for (ip, e) in &mut inner.peers {
            if AddressFamily::of(*ip) == family {
                e.state = KeyState::Deferred;
                e.on_socket = false;
            }
        }
    }
}

impl<P: TcpMd5Port> ListenerKeys<P> {
    /// An empty table whose OS calls go through `port`.
    pub fn new(port: P) -> Self {
        Self {
            port,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Configures `auth` for connections from `peer`, replacing any earlier
    /// key for it (key rotation).
    ///
    /// If a listening socket for the peer's address family is bound, the key
    /// is installed on it now, and the [`BgpListener`] then replaces the
    /// socket (see the [module documentation](self)). Linux replaces an
    /// existing key for the same address in place (`__tcp_md5_do_add`:
    /// "Pre-existing entry - just update that one"); connections accepted
    /// earlier keep the key they were accepted with, and stop being
    /// [current](Self::is_current). Setting the key the peer already has
    /// changes nothing.
    ///
    /// # Errors
    ///
    /// [`ListenerKeyError`] if the key could not be installed and the peer's
    /// connections will be rejected: the host cannot enforce it and the
    /// policy is [`Md5Enforcement::Required`], or `setsockopt` failed. The
    /// configuration is still recorded, so [`remove_peer`](Self::remove_peer)
    /// is still needed to forget it.
    pub fn set_peer(
        &self,
        peer: IpAddr,
        auth: TcpMd5Auth,
    ) -> Result<ListenerProtection, ListenerKeyError> {
        let family = AddressFamily::of(peer);
        let mut inner = self.lock();
        let inner = &mut *inner;

        let previous = inner.peers.get(&peer);
        if let Some(e) = previous
            && e.auth == auth
            && matches!(e.state, KeyState::Installed { .. })
        {
            return Ok(ListenerProtection::Enforced);
        }
        let before = previous.map(|e| e.state);
        let previously_on_socket = previous.is_some_and(|e| e.on_socket);
        inner.changes += 1;
        let changed = inner.changes;

        let (state, on_socket, outcome) = match &inner.slots[family.index()] {
            None => (KeyState::Deferred, false, Ok(ListenerProtection::Deferred)),
            Some(slot) => match install(&self.port, slot, peer, &auth) {
                Ok(Installed::Enforced) => {
                    slot.notify.notify_one();
                    (
                        KeyState::Installed { settled: false },
                        true,
                        Ok(ListenerProtection::Enforced),
                    )
                }
                Ok(Installed::Unenforced(why)) => (
                    KeyState::Unenforced(why),
                    false,
                    Ok(ListenerProtection::Unenforced(why)),
                ),
                // A failed replacement leaves the previous key, if any, in place.
                Err(e) => (KeyState::Refused(e.refusal), previously_on_socket, Err(e)),
            },
        };
        inner.track(family, before, Some(state));
        inner.peers.insert(
            peer,
            PeerEntry {
                auth,
                state,
                on_socket,
                changed,
            },
        );
        outcome
    }

    /// Forgets `peer`'s key and removes it from the listening socket.
    ///
    /// Afterwards the listener treats `peer` as having no key
    /// ([`Admission::Unkeyed`]). Connections accepted earlier keep their own
    /// copy of the key. Returns whether a key was configured.
    ///
    /// # Errors
    ///
    /// The [`TcpMd5Error`] from removing the key from the socket. The entry
    /// is forgotten either way; if the key is still on the socket, the
    /// kernel keeps dropping the peer's unsigned segments, which fails
    /// closed.
    pub fn remove_peer(&self, peer: IpAddr) -> Result<bool, TcpMd5Error> {
        let family = AddressFamily::of(peer);
        let mut inner = self.lock();
        let Some(entry) = inner.peers.remove(&peer) else {
            return Ok(false);
        };
        inner.track(family, Some(entry.state), None);
        if entry.on_socket
            && let Some(slot) = &inner.slots[family.index()]
        {
            self.port.remove(slot.fd.as_fd(), peer)?;
        }
        Ok(true)
    }

    /// Takes `fd` as `family`'s listening socket and installs every key of
    /// that family on it. The socket must not be listening yet, so these
    /// keys are settled from the start. Returns the keys that could not be
    /// installed.
    fn attach(
        &self,
        family: AddressFamily,
        fd: OwnedFd,
        notify: Arc<Notify>,
    ) -> io::Result<Vec<ListenerKeyError>> {
        let mut inner = self.lock();
        let inner = &mut *inner;
        if inner.slots[family.index()].is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("a {family:?} listener is already bound to these keys"),
            ));
        }
        let slot = Slot { fd, notify };
        let mut failures = Vec::new();
        for (ip, e) in &mut inner.peers {
            if AddressFamily::of(*ip) != family {
                continue;
            }
            match install(&self.port, &slot, *ip, &e.auth) {
                Ok(Installed::Enforced) => {
                    e.state = KeyState::Installed { settled: true };
                    e.on_socket = true;
                }
                Ok(Installed::Unenforced(why)) => {
                    e.state = KeyState::Unenforced(why);
                    e.on_socket = false;
                }
                Err(err) => {
                    e.state = KeyState::Refused(err.refusal);
                    e.on_socket = false;
                    failures.push(err);
                }
            }
        }
        inner.unsettled[family.index()] = 0;
        inner.slots[family.index()] = Some(slot);
        Ok(failures)
    }
}

/// A key that [`install`] did not refuse.
enum Installed {
    Enforced,
    Unenforced(TcpMd5Unsupported),
}

/// Installs `auth`'s key for `peer` on `slot` and applies the policy.
fn install<P: TcpMd5Port>(
    port: &P,
    slot: &Slot,
    peer: IpAddr,
    auth: &TcpMd5Auth,
) -> Result<Installed, ListenerKeyError> {
    match port.install(slot.fd.as_fd(), peer, auth.key()) {
        Ok(()) => Ok(Installed::Enforced),
        Err(TcpMd5Error::Unsupported(why)) if auth.enforcement() == Md5Enforcement::BestEffort => {
            tracing::warn!(
                %peer,
                reason = why.label(),
                "TCP MD5 key configured but NOT enforced on the listener ({why}); inbound \
                 connections from this peer will be accepted unauthenticated because \
                 tcp_md5_enforcement is best-effort"
            );
            Ok(Installed::Unenforced(why))
        }
        Err(TcpMd5Error::Unsupported(why)) => Err(ListenerKeyError {
            peer,
            refusal: KeyRefusal::NotEnforceable(why),
        }),
        Err(TcpMd5Error::Os(e)) => Err(ListenerKeyError {
            peer,
            refusal: KeyRefusal::os(&e),
        }),
    }
}

/// A listening TCP socket for BGP whose connections are checked against a
/// [`ListenerKeys`] table.
///
/// [`bind`](Self::bind) installs the table's keys before the socket starts
/// listening. Later changes to the table reach the socket at once, and a key
/// installed while listening makes the listener replace its socket (see the
/// [module documentation](crate::transport::listener)).
/// [`accept`](Self::accept) only returns connections the table admits; it
/// closes the others.
pub struct BgpListener<P: TcpMd5Port = KernelTcpMd5> {
    /// `None` only if replacing the socket failed; the next
    /// [`accept`](Self::accept) tries again.
    listener: Option<TcpListener>,
    /// The bound address (with the actual port), for replacements.
    addr: SocketAddr,
    family: AddressFamily,
    keys: Arc<ListenerKeys<P>>,
    notify: Arc<Notify>,
    /// Admitted connections taken off the old socket while replacing it.
    ready: VecDeque<Inbound>,
}

impl<P: TcpMd5Port> fmt::Debug for BgpListener<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BgpListener")
            .field("addr", &self.addr)
            .field("family", &self.family)
            .finish_non_exhaustive()
    }
}

impl<P: TcpMd5Port> BgpListener<P> {
    /// Binds a listening socket to `addr` with `keys`' keys for `addr`'s
    /// address family installed before `listen()`.
    ///
    /// An IPv6 socket is set to `IPV6_V6ONLY`, so it never receives IPv4
    /// connections, which need the IPv4 socket's keys. `SO_REUSEADDR` is
    /// set; `SO_REUSEPORT` is not, so connections are never moved to another
    /// socket. Keys that cannot be installed are logged at error level, and
    /// their peers' connections are rejected; they do not make the bind
    /// fail.
    ///
    /// # Errors
    ///
    /// Any socket, bind or listen error, or [`io::ErrorKind::AlreadyExists`]
    /// if `keys` already has a listener for this address family.
    pub fn bind(addr: SocketAddr, keys: Arc<ListenerKeys<P>>) -> io::Result<Self> {
        let notify = Arc::new(Notify::new());
        let listener = bind_socket(addr, &keys, &notify)?;
        let addr = listener.local_addr()?;
        Ok(Self {
            listener: Some(listener),
            addr,
            family: AddressFamily::of(addr.ip()),
            keys,
            notify,
            ready: VecDeque::new(),
        })
    }

    /// The local address the socket is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Whether `inbound` is still valid: [`ListenerKeys::is_current`] for
    /// its peer and stamp.
    #[must_use]
    pub fn is_current(&self, inbound: &Inbound) -> bool {
        self.keys.is_current(inbound.peer.ip(), inbound.stamp)
    }

    /// The next connection that the key table admits.
    ///
    /// Connections it rejects are closed and logged. Connections from a
    /// best-effort peer whose key cannot be enforced are returned, with a
    /// warning. Cancel-safe: a connection taken off the queue is kept for
    /// the next call.
    ///
    /// # Errors
    ///
    /// An error from `accept()`, or from binding the replacement socket.
    /// After a failed replacement the next call tries again.
    pub async fn accept(&mut self) -> io::Result<Inbound> {
        loop {
            let mut replace_error = None;
            if self.listener.is_none() || self.keys.has_unsettled(self.family) {
                replace_error = self.replace_socket().err();
            }
            while let Some(inbound) = self.ready.pop_front() {
                if self.is_current(&inbound) {
                    return Ok(inbound);
                }
                tracing::warn!(
                    peer = %inbound.peer,
                    "rejecting inbound BGP connection: its TCP MD5 key changed after it was accepted"
                );
            }
            // Connections already taken off the old socket are served first,
            // even if its replacement could not be bound.
            if let Some(e) = replace_error {
                return Err(e);
            }
            let Some(listener) = &self.listener else {
                continue;
            };
            tokio::select! {
                biased;
                () = self.notify.notified() => {}
                accepted = listener.accept() => {
                    let (stream, addr) = accepted?;
                    if let Some(stamp) = self.admit(addr) {
                        return Ok(Inbound { stream, peer: addr, stamp });
                    }
                }
            }
        }
    }

    /// Replaces the listening socket after a key was installed on it while
    /// it was listening (see the [module documentation](crate::transport::listener)).
    ///
    /// # Errors
    ///
    /// Binding or listening on the new socket failed. The old socket is gone
    /// either way; `self.listener` stays `None` until a later call succeeds.
    fn replace_socket(&mut self) -> io::Result<()> {
        if let Some(old) = self.listener.take() {
            self.take_queued(&old);
            // The barrier: after this the old socket is not listening, its
            // queue is discarded, and any connection still on its way to the
            // queue is discarded too.
            if let Err(e) = socket2::SockRef::from(&old).shutdown(Shutdown::Read) {
                tracing::debug!(error = %e, "shutdown of replaced BGP listening socket");
            }
            drop(old);
        }
        // Drops the table's duplicate descriptor, so the old socket closes.
        self.keys.detach(self.family);
        let new = bind_socket(self.addr, &self.keys, &self.notify)?;
        tracing::debug!(addr = %self.addr, "replaced BGP listening socket after a TCP MD5 key change");
        self.listener = Some(new);
        Ok(())
    }

    /// Takes up to [`MAX_QUEUED`] connections off `old`'s queue, keeping the
    /// admitted ones in `ready`. Connections from a peer whose key changed
    /// are rejected, since they may predate the change.
    fn take_queued(&mut self, old: &TcpListener) {
        let socket = socket2::SockRef::from(old);
        for _ in 0..MAX_QUEUED {
            match socket.accept() {
                Ok((conn, addr)) => {
                    let Some(addr) = addr.as_socket() else {
                        continue;
                    };
                    let Some(stamp) = self.admit(addr) else {
                        continue;
                    };
                    let stream = std::net::TcpStream::from(conn);
                    match stream
                        .set_nonblocking(true)
                        .and_then(|()| TcpStream::from_std(stream))
                    {
                        Ok(stream) => self.ready.push_back(Inbound {
                            stream,
                            peer: addr,
                            stamp,
                        }),
                        Err(e) => tracing::warn!(peer = %addr, error = %e,
                            "dropping inbound BGP connection"),
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "BGP listener accept error before replacing the socket");
                    return;
                }
            }
        }
    }

    /// The stamp of a connection from `addr` that may be used, or `None`.
    /// Logs rejections.
    fn admit(&self, addr: SocketAddr) -> Option<AuthStamp> {
        if AddressFamily::of(addr.ip()) != self.family {
            tracing::warn!(peer = %addr, "rejecting inbound connection: wrong address family");
            return None;
        }
        let (admission, stamp) = self.keys.screen(addr.ip());
        match admission {
            Admission::Unkeyed | Admission::Authenticated => Some(stamp),
            Admission::Unauthenticated(why) => {
                tracing::warn!(
                    peer = %addr,
                    reason = why.label(),
                    "accepting inbound BGP connection WITHOUT TCP MD5 authentication \
                     (tcp_md5_enforcement is best-effort)"
                );
                Some(stamp)
            }
            Admission::Rejected(why) => {
                tracing::warn!(peer = %addr, "rejecting inbound BGP connection: {why}");
                None
            }
        }
    }
}

impl<P: TcpMd5Port> Drop for BgpListener<P> {
    fn drop(&mut self) {
        self.keys.detach(self.family);
    }
}

/// Creates a socket bound to `addr`, attaches it to `keys` (installing their
/// keys for its family), and only then starts listening.
fn bind_socket<P: TcpMd5Port>(
    addr: SocketAddr,
    keys: &ListenerKeys<P>,
    notify: &Arc<Notify>,
) -> io::Result<TcpListener> {
    let family = AddressFamily::of(addr.ip());
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if family == AddressFamily::V6 {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;

    let failures = keys.attach(family, socket.try_clone()?.into(), Arc::clone(notify))?;
    for e in &failures {
        tracing::error!(peer = %e.peer(), listen = %addr, "{e}");
    }

    // The keys are on the socket before it listens, so no handshake can
    // complete without them.
    let listener = socket
        .listen(LISTEN_BACKLOG)
        .and_then(|()| TcpListener::from_std(socket.into()));
    if listener.is_err() {
        keys.detach(family);
    }
    listener
}

#[cfg(test)]
mod tests;
