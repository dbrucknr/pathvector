// daemon/capabilities.rs — SpawnConfig and BGP capability advertisement.
#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) struct SpawnConfig {
    pub(super) local_as: u32,
    pub(super) local_bgp_id: Ipv4Addr,
    pub(super) hold_time: u16,
    /// RFC 4724: parameters for computing per-session capabilities.
    ///
    /// Capabilities are rebuilt at each session spawn (rather than once at
    /// startup) so that the R-bit correctly reflects the elapsed restart window:
    /// R=1 only while `startup_instant.elapsed() < graceful_restart_time`.
    pub(super) graceful_restart_time: u16,
    /// Whether the operator configured `restarting = true` in `[daemon]`.
    /// The actual R-bit in each OPEN is gated on this AND elapsed time.
    pub(super) configured_restarting: bool,
    /// Instant the daemon process started; used to expire the R-bit window.
    pub(super) startup_instant: std::time::Instant,
    /// RFC 5065 Confederation Identifier, if this daemon is a confederation
    /// Member-AS. Threaded into [`SessionConfig::confederation_member`]
    /// resolution at each session spawn via `effective_confederation_member`.
    pub(super) confederation_id: Option<u32>,
    /// `[daemon] tcp_md5_enforcement`, applied to every dynamically added
    /// peer that has an `md5_password`.
    pub(super) md5_enforcement: Md5Enforcement,
}

/// The TCP MD5 keys for inbound connections, shared between the peer-set
/// management (static setup, `AddPeer`, `RemovePeer`) and the BGP listeners,
/// which install them on the listening sockets. `P` is the OS adapter; tests
/// pass a fake.
pub(super) type Md5Keys<P = KernelTcpMd5> = Arc<ListenerKeys<P>>;

/// Configures `peer`'s key for inbound connections and logs the outcome.
///
/// Called before the peer is added to `incoming_senders`, so the listener
/// never hands over a connection from the peer before its key is on the
/// listening socket. A key that cannot be installed is logged at error
/// level; the listener then rejects the peer's inbound connections (see
/// [`ListenerKeys::set_peer`]). Outbound connections are governed
/// separately, by the session's own [`TcpMd5Auth`].
pub(super) fn set_listener_key<P: TcpMd5Port>(
    keys: &ListenerKeys<P>,
    peer: IpAddr,
    auth: TcpMd5Auth,
) {
    match keys.set_peer(peer, auth) {
        Ok(ListenerProtection::Enforced) => {
            tracing::debug!(%peer, "TCP MD5 key installed on the BGP listener");
        }
        Ok(ListenerProtection::Deferred) => {
            tracing::debug!(
                %peer,
                "TCP MD5 key will be installed when the BGP listener for its address family binds"
            );
        }
        // `ListenerKeys` has already logged a warning.
        Ok(ListenerProtection::Unenforced(_)) => {}
        Err(e) => tracing::error!(%peer, "{e}"),
    }
}

/// Removes `peer`'s key from the BGP listeners, logging a failure.
pub(super) fn remove_listener_key<P: TcpMd5Port>(keys: &ListenerKeys<P>, peer: IpAddr) {
    if let Err(e) = keys.remove_peer(peer) {
        tracing::warn!(%peer, error = %e, "failed to remove TCP MD5 key from the BGP listener");
    }
}

/// The session's TCP MD5 settings for `peer`, or `None` if it has no
/// `md5_password`.
pub(super) fn session_tcp_md5(
    peer: &config::PeerConfig,
    enforcement: Md5Enforcement,
) -> Option<TcpMd5Auth> {
    peer.md5_password
        .as_ref()
        .map(|p| TcpMd5Auth::new(p.key().clone(), enforcement))
}

/// Logs one warning at startup per peer whose MD5 key may go unenforced.
pub(super) fn warn_if_md5_best_effort(enforcement: Md5Enforcement, peers: &[config::PeerConfig]) {
    if enforcement != Md5Enforcement::BestEffort {
        return;
    }
    for peer in peers.iter().filter(|p| p.md5_password.is_some()) {
        tracing::warn!(
            peer = %peer.address,
            "tcp_md5_enforcement = \"best-effort\": if this host cannot enforce TCP MD5, \
             the session will connect WITHOUT authentication"
        );
    }
}

impl SpawnConfig {
    /// Build the capability list for a session being spawned right now.
    ///
    /// The R-bit is set only if the operator configured `restarting = true`
    /// AND the restart window (`graceful_restart_time` seconds) has not yet
    /// elapsed since daemon startup.  Once the window expires, R=0 — RFC 4724
    /// §3 requires the restarting speaker to clear the R-bit after completion.
    ///
    /// `role` is per-peer (not part of `SpawnConfig` itself, which is shared
    /// across every session) — pass `peer.role.map(Into::into)` from the
    /// `PeerConfig` being spawned. `None` omits the Role capability entirely,
    /// matching RFC 9234's own non-strict default.
    ///
    /// `advertised_as` is the AS number to place in the `FourByteAsn`
    /// capability for this specific peer — see
    /// [`super::effective_session_as`] (RFC 5065 §4: Confederation
    /// Identifier for `External` peers, Member-AS Number otherwise).
    pub(super) fn capabilities(&self, role: Option<Role>, advertised_as: u32) -> Vec<Capability> {
        let in_window = self.configured_restarting
            && self.graceful_restart_time > 0
            && self.startup_instant.elapsed()
                < std::time::Duration::from_secs(u64::from(self.graceful_restart_time));
        build_local_capabilities(advertised_as, self.graceful_restart_time, in_window, role)
    }
}

/// Returns the capability set advertised in every OPEN message pathvectord sends.
///
/// Called from both peer registration paths (static config and runtime AddPeer)
/// so they always advertise identical capabilities.
/// Build the capability list advertised in every OPEN message.
///
/// `restarting` controls the RFC 4724 §3 Restart State (R) bit.  Set it to
/// `true` during the post-restart window so peers know to preserve their
/// stale-route timers for us.  After the window elapses (or on normal startup)
/// pass `false`.
///
/// `role` is this peer's configured RFC 9234 BGP Role, if any. `None` omits
/// the Role capability — matching the RFC's own non-strict default of not
/// requiring Role negotiation at all.
pub(super) fn build_local_capabilities(
    local_as: u32,
    graceful_restart_time: u16,
    restarting: bool,
    role: Option<Role>,
) -> Vec<Capability> {
    // RFC 4724 §3: when restart_time > 0, advertise forwarding-preserved families
    // so peers hold our routes during our restart window.  When 0, advertise an
    // empty family list — peers still send EOR markers but withdraw our routes
    // immediately on session loss.
    // RFC 4724 §3: Restart State (R) bit (0x08) — set when we are the
    // restarting speaker within the restart window.
    // RFC 8538 §2: Notification (N) bit (0x04) — set whenever we advertise
    // a non-zero restart_time, signalling that we support the RFC 8538
    // notification mode (non-HardReset NOTIFICATIONs preserve GR windows).
    let restart_flags: u8 = if graceful_restart_time > 0 {
        let r_bit: u8 = if restarting { 0x08 } else { 0x00 };
        r_bit | 0x04 // N-bit always set when we participate in GR
    } else {
        0x00
    };
    // RFC 4724 §3: F-bit (forwarding_preserved) indicates our FIB is intact.
    // When we are restarting (R=1), run_with() has just deleted stale RTPROT_BGP
    // routes, so our FIB is NOT intact — F must be false.
    // When we are stable (R=0), kernel routes survive session loss, so F=true.
    let forwarding_preserved = !restarting || graceful_restart_time == 0;
    let gr_families = if graceful_restart_time > 0 {
        vec![
            GracefulRestartFamily {
                afi_safi: AfiSafi::IPV4_UNICAST,
                forwarding_preserved,
            },
            GracefulRestartFamily {
                afi_safi: AfiSafi::IPV6_UNICAST,
                forwarding_preserved,
            },
        ]
    } else {
        vec![]
    };
    let mut caps = vec![
        Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
        Capability::RouteRefresh,
        Capability::FourByteAsn(local_as),
        Capability::ExtendedMessage,
        Capability::GracefulRestart {
            restart_flags,
            restart_time: graceful_restart_time.min(4095),
            families: gr_families,
        },
    ];
    if let Some(role) = role {
        caps.push(Capability::Role(role));
    }
    caps
}
