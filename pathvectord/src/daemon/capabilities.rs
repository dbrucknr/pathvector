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
}

impl SpawnConfig {
    /// Build the capability list for a session being spawned right now.
    ///
    /// The R-bit is set only if the operator configured `restarting = true`
    /// AND the restart window (`graceful_restart_time` seconds) has not yet
    /// elapsed since daemon startup.  Once the window expires, R=0 — RFC 4724
    /// §3 requires the restarting speaker to clear the R-bit after completion.
    pub(super) fn capabilities(&self) -> Vec<Capability> {
        let in_window = self.configured_restarting
            && self.graceful_restart_time > 0
            && self.startup_instant.elapsed()
                < std::time::Duration::from_secs(u64::from(self.graceful_restart_time));
        build_local_capabilities(self.local_as, self.graceful_restart_time, in_window)
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
pub(super) fn build_local_capabilities(
    local_as: u32,
    graceful_restart_time: u16,
    restarting: bool,
) -> Vec<Capability> {
    // RFC 4724 §3: when restart_time > 0, advertise forwarding-preserved families
    // so peers hold our routes during our restart window.  When 0, advertise an
    // empty family list — peers still send EOR markers but withdraw our routes
    // immediately on session loss.
    // RFC 4724 §3: Restart State (R) bit is the high bit of restart_flags.
    // Set when we are the restarting speaker within the restart window so peers
    // know to stop their stale-route timers when our session re-establishes.
    // Only meaningful when graceful_restart_time > 0.
    let restart_flags: u8 = if restarting && graceful_restart_time > 0 {
        0x08
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
    vec![
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
    ]
}

