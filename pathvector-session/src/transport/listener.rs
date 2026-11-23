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
//! # Connections that completed before a key change
//!
//! Since the key is copied when the handshake completes, a connection that
//! completed before the listener had the key carries no key, even if the
//! application accepts it afterwards. Keys installed by [`BgpListener::bind`]
//! go on the socket before `listen()`, so for them no such connection can
//! exist. A key added or changed later, with [`ListenerKeys::set_peer`],
//! could be preceded by connections already waiting in the accept queue.
//! Until [`BgpListener`] has emptied its accept queue after the change, it
//! rejects every connection from that peer (the key is "unsettled"). The
//! cost is that a correctly signed connection that arrives in that short
//! window is also rejected, and the peer retries.
//!
//! # When the key cannot be enforced
//!
//! The policy is the same as for outbound connections
//! ([`Md5Enforcement`](super::tcp_md5::Md5Enforcement)):
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
use std::net::{IpAddr, SocketAddr};
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

/// A peer's key state on the listening socket of its address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyState {
    /// No listening socket for the family.
    Deferred,
    /// The key is on the socket. `settled` is false until the accept queue
    /// has been seen empty after install number `epoch`.
    Installed { epoch: u64, settled: bool },
    /// Best-effort and not enforceable.
    Unenforced(TcpMd5Unsupported),
    /// Not installed; connections are rejected.
    Refused(KeyRefusal),
}

#[derive(Debug)]
struct PeerEntry {
    auth: TcpMd5Auth,
    state: KeyState,
    /// Whether the attached socket holds *some* key for this peer. Usually
    /// the same as `state` being `Installed`, but a failed key change
    /// leaves the previous key in place.
    on_socket: bool,
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
    /// Incremented by every key installed after `listen()`.
    epoch: u64,
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

    /// The configured authentication for `peer`, if any.
    #[must_use]
    pub fn configured(&self, peer: IpAddr) -> Option<TcpMd5Auth> {
        self.lock().peers.get(&peer).map(|e| e.auth.clone())
    }

    /// What a listener does with a connection from `peer`.
    #[must_use]
    pub fn admission(&self, peer: IpAddr) -> Admission {
        match self.lock().peers.get(&peer).map(|e| e.state) {
            None => Admission::Unkeyed,
            Some(KeyState::Installed { settled: true, .. }) => Admission::Authenticated,
            Some(KeyState::Installed { settled: false, .. }) => {
                Admission::Rejected(Rejection::KeyChangePending)
            }
            Some(KeyState::Unenforced(why)) => Admission::Unauthenticated(why),
            Some(KeyState::Refused(refusal)) => {
                Admission::Rejected(Rejection::KeyNotInstalled(refusal))
            }
            Some(KeyState::Deferred) => Admission::Rejected(Rejection::NoListener),
        }
    }

    /// Whether any key of `family` is waiting for its accept queue to drain.
    fn has_unsettled(&self, family: AddressFamily) -> bool {
        self.lock().peers.iter().any(|(ip, e)| {
            AddressFamily::of(*ip) == family
                && matches!(e.state, KeyState::Installed { settled: false, .. })
        })
    }

    fn epoch(&self) -> u64 {
        self.lock().epoch
    }

    /// Marks every key of `family` installed at or before `epoch` as
    /// settled. Call only after the family's accept queue was seen empty
    /// after reading `epoch`.
    fn settle(&self, family: AddressFamily, epoch: u64) {
        for (ip, e) in &mut self.lock().peers {
            if AddressFamily::of(*ip) != family {
                continue;
            }
            if let KeyState::Installed {
                epoch: installed,
                settled,
            } = &mut e.state
                && *installed <= epoch
            {
                *settled = true;
            }
        }
    }

    /// Forgets `family`'s socket. Its keys go back to
    /// [`ListenerProtection::Deferred`].
    fn detach(&self, family: AddressFamily) {
        let mut inner = self.lock();
        inner.slots[family.index()] = None;
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
    /// is installed on it now. Linux replaces an existing key for the same
    /// address in place (`__tcp_md5_do_add`: "Pre-existing entry - just
    /// update that one"); connections accepted earlier keep the key they
    /// were accepted with. Connections from `peer` that completed before
    /// this call are rejected (see the [module documentation](self)).
    /// Setting the key the peer already has changes nothing.
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

        if let Some(e) = inner.peers.get(&peer)
            && e.auth == auth
            && matches!(e.state, KeyState::Installed { .. })
        {
            return Ok(ListenerProtection::Enforced);
        }

        let previously_on_socket = inner.peers.get(&peer).is_some_and(|e| e.on_socket);
        let Some(slot) = &inner.slots[family.index()] else {
            inner.peers.insert(
                peer,
                PeerEntry {
                    auth,
                    state: KeyState::Deferred,
                    on_socket: false,
                },
            );
            return Ok(ListenerProtection::Deferred);
        };

        let (state, on_socket, outcome) = match install(&self.port, slot, peer, &auth) {
            Ok(Installed::Enforced) => {
                inner.epoch += 1;
                slot.notify.notify_one();
                let state = KeyState::Installed {
                    epoch: inner.epoch,
                    settled: false,
                };
                (state, true, Ok(ListenerProtection::Enforced))
            }
            Ok(Installed::Unenforced(why)) => (
                KeyState::Unenforced(why),
                false,
                Ok(ListenerProtection::Unenforced(why)),
            ),
            // A failed replacement leaves the previous key, if any, in place.
            Err(e) => (KeyState::Refused(e.refusal), previously_on_socket, Err(e)),
        };
        inner.peers.insert(
            peer,
            PeerEntry {
                auth,
                state,
                on_socket,
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
        let mut inner = self.lock();
        let Some(entry) = inner.peers.remove(&peer) else {
            return Ok(false);
        };
        if entry.on_socket
            && let Some(slot) = &inner.slots[AddressFamily::of(peer).index()]
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
                    e.state = KeyState::Installed {
                        epoch: inner.epoch,
                        settled: true,
                    };
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
/// listening, and later changes to the table reach the socket without
/// rebinding it. [`accept`](Self::accept) only returns connections the table
/// admits; it closes the others.
pub struct BgpListener<P: TcpMd5Port = KernelTcpMd5> {
    listener: TcpListener,
    family: AddressFamily,
    keys: Arc<ListenerKeys<P>>,
    notify: Arc<Notify>,
    /// Admitted connections taken off the queue while draining it.
    ready: VecDeque<(TcpStream, SocketAddr)>,
}

impl<P: TcpMd5Port> fmt::Debug for BgpListener<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BgpListener")
            .field("listener", &self.listener)
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
    /// set. Keys that cannot be installed are logged at error level, and
    /// their peers' connections are rejected; they do not make the bind
    /// fail.
    ///
    /// # Errors
    ///
    /// Any socket, bind or listen error, or [`io::ErrorKind::AlreadyExists`]
    /// if `keys` already has a listener for this address family.
    pub fn bind(addr: SocketAddr, keys: Arc<ListenerKeys<P>>) -> io::Result<Self> {
        let family = AddressFamily::of(addr.ip());
        let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
        if family == AddressFamily::V6 {
            socket.set_only_v6(true)?;
        }
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;

        let notify = Arc::new(Notify::new());
        let failures = keys.attach(family, socket.try_clone()?.into(), Arc::clone(&notify))?;
        for e in &failures {
            tracing::error!(peer = %e.peer(), listen = %addr, "{e}");
        }

        // The keys are on the socket before it listens, so no handshake can
        // complete without them.
        let listener = socket
            .listen(LISTEN_BACKLOG)
            .and_then(|()| TcpListener::from_std(socket.into()));
        let listener = match listener {
            Ok(l) => l,
            Err(e) => {
                keys.detach(family);
                return Err(e);
            }
        };
        Ok(Self {
            listener,
            family,
            keys,
            notify,
            ready: VecDeque::new(),
        })
    }

    /// The local address the socket is bound to.
    ///
    /// # Errors
    ///
    /// As for [`TcpListener::local_addr`].
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
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
    /// An error from `accept()` on the listening socket.
    pub async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
        loop {
            if let Some(conn) = self.ready.pop_front() {
                return Ok(conn);
            }
            if self.keys.has_unsettled(self.family) {
                self.drain();
                if let Some(conn) = self.ready.pop_front() {
                    return Ok(conn);
                }
            }
            tokio::select! {
                biased;
                () = self.notify.notified() => {}
                accepted = self.listener.accept() => {
                    let (stream, addr) = accepted?;
                    if self.admit(addr) {
                        return Ok((stream, addr));
                    }
                }
            }
        }
    }

    /// Takes every connection off the accept queue, screening each, until
    /// the queue is empty, then settles the keys installed before the drain
    /// began. Any connection that completed before such a key was installed
    /// was in the queue when the drain began, and was rejected because its
    /// key was unsettled.
    fn drain(&mut self) {
        let epoch = self.keys.epoch();
        let socket = socket2::SockRef::from(&self.listener);
        loop {
            match socket.accept() {
                Ok((conn, addr)) => {
                    let Some(addr) = addr.as_socket() else {
                        continue;
                    };
                    if !self.admit(addr) {
                        continue;
                    }
                    let stream = std::net::TcpStream::from(conn);
                    match stream
                        .set_nonblocking(true)
                        .and_then(|()| TcpStream::from_std(stream))
                    {
                        Ok(stream) => self.ready.push_back((stream, addr)),
                        Err(e) => tracing::warn!(peer = %addr, error = %e,
                            "dropping inbound BGP connection"),
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.keys.settle(self.family, epoch);
                    return;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => {
                    // The queue was not seen empty, so nothing is settled;
                    // the next `accept` call tries again.
                    tracing::warn!(error = %e, "BGP listener accept error while draining");
                    return;
                }
            }
        }
    }

    /// Whether a connection from `addr` may be used. Logs rejections.
    fn admit(&self, addr: SocketAddr) -> bool {
        if AddressFamily::of(addr.ip()) != self.family {
            tracing::warn!(peer = %addr, "rejecting inbound connection: wrong address family");
            return false;
        }
        match self.keys.admission(addr.ip()) {
            Admission::Unkeyed | Admission::Authenticated => true,
            Admission::Unauthenticated(why) => {
                tracing::warn!(
                    peer = %addr,
                    reason = why.label(),
                    "accepting inbound BGP connection WITHOUT TCP MD5 authentication \
                     (tcp_md5_enforcement is best-effort)"
                );
                true
            }
            Admission::Rejected(why) => {
                tracing::warn!(peer = %addr, "rejecting inbound BGP connection: {why}");
                false
            }
        }
    }
}

impl<P: TcpMd5Port> Drop for BgpListener<P> {
    fn drop(&mut self) {
        self.keys.detach(self.family);
    }
}

#[cfg(test)]
mod tests;
