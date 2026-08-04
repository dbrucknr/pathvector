// daemon/deferral.rs — RFC 4724 §4.1 Restarting-Speaker Selection_Deferral_Timer.
#[allow(clippy::wildcard_imports)]
use super::*;
use std::time::Duration;

/// Tracks outbound-advertisement deferral for the Restarting-Speaker role
/// (RFC 4724 §4.1), independently per address family.
///
/// Scoped to **outbound advertisement only** — Loc-RIB/FIB computation is
/// unaffected — matching how BIRD implements graceful restart recovery
/// (`nest/proto.c`: "deferring export of routes to protocols until routing
/// tables are refilled") rather than the RFC's literal "defer route
/// selection" text. See `daemon/config.rs`'s `selection_deferral_time` doc
/// comment for the full rationale.
///
/// Each family releases — permanently, a one-way latch — as soon as either
/// (a) [`recompute`](Self::recompute) finds every configured, GR-capable,
/// non-restarting peer has sent that family's End-of-RIB marker, or (b)
/// [`force_release`](Self::force_release) is called (the
/// Selection_Deferral_Timer expiry path). Once released, a family never
/// re-defers even if a peer later disconnects.
pub(crate) struct SelectionDeferral {
    /// `None` once `selection_deferral_time == 0` (feature disabled) — no
    /// timer to wait for.
    deadline: Option<Instant>,
    v4_released: bool,
    v6_released: bool,
}

impl SelectionDeferral {
    /// Constructs armed state with both families deferred, deadline at
    /// `daemon_start + deferral_secs`. `deferral_secs == 0` constructs
    /// pre-released state instead — the feature is a true no-op when
    /// disabled, identical to [`disabled`](Self::disabled).
    pub(crate) fn new(daemon_start: Instant, deferral_secs: u16) -> Self {
        if deferral_secs == 0 {
            return Self::disabled();
        }
        Self {
            deadline: Some(daemon_start + Duration::from_secs(u64::from(deferral_secs))),
            v4_released: false,
            v6_released: false,
        }
    }

    /// Pre-released state used by `DaemonState::new()`, before `run_with`
    /// has a real `daemon_start`/config to build the armed version from.
    pub(crate) fn disabled() -> Self {
        Self {
            deadline: None,
            v4_released: true,
            v6_released: true,
        }
    }

    /// Deadline to sleep until, or `None` when there is nothing left to wait
    /// for (either both families already released, or the feature is
    /// disabled).
    pub(crate) fn pending_deadline(&self) -> Option<Instant> {
        if self.v4_released && self.v6_released {
            None
        } else {
            self.deadline
        }
    }

    /// Wait-set-conditional release check (RFC 4724 §4.1 path (a)).
    ///
    /// `configured_peers` MUST be the full *configured* peer set (e.g.
    /// `RibSnapshot::peer_remote_as`'s keys), not just currently-established
    /// peers — at daemon startup zero peers are established yet, so an
    /// established-peers-only wait-set would let one fast peer's EOR release
    /// the gate before a slower peer has even connected, defeating the
    /// feature in the ordinary multi-peer-restart case. An unestablished
    /// configured peer therefore blocks release conservatively (bounded by
    /// the deadline, see [`force_release`](Self::force_release)).
    ///
    /// A peer blocks a family's release only while all of the following
    /// hold: it is established, it advertised GracefulRestart with a
    /// non-zero `restart_time` (i.e. is present in `gr_capable_peers`), it
    /// is not itself restarting (`gr_peer_restarting`), and it has not yet
    /// sent that family's End-of-RIB marker. An established peer that is
    /// not GR-capable, or that set its own Restart State bit, never blocks —
    /// excluded per the RFC text. The v6 gate additionally excludes
    /// established peers that never negotiated the IPv6 unicast
    /// Multi-Protocol capability (`ipv6_capable_peers`).
    ///
    /// Idempotent and one-way: a family already released is left untouched
    /// and always contributes `false` to the returned tuple, regardless of
    /// what the current inputs would otherwise imply.
    ///
    /// Returns `(v4 newly released this call, v6 newly released this call)`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn recompute(
        &mut self,
        configured_peers: impl Iterator<Item = IpAddr>,
        peer_types: &HashMap<IpAddr, PeerType>,
        gr_capable_peers: &HashMap<IpAddr, u16>,
        gr_peer_restarting: &HashSet<IpAddr>,
        ipv6_capable_peers: &HashSet<IpAddr>,
        eor_received: &HashSet<IpAddr>,
        eor_received_v6: &HashSet<IpAddr>,
    ) -> (bool, bool) {
        if self.v4_released && self.v6_released {
            return (false, false);
        }

        let mut v4_blocked = self.v4_released; // already released ⇒ never "newly" blocks
        let mut v6_blocked = self.v6_released;

        for peer_ip in configured_peers {
            if !v4_blocked
                && family_blocks(
                    peer_ip,
                    false,
                    peer_types,
                    gr_capable_peers,
                    gr_peer_restarting,
                    ipv6_capable_peers,
                    eor_received,
                    eor_received_v6,
                )
            {
                v4_blocked = true;
            }
            if !v6_blocked
                && family_blocks(
                    peer_ip,
                    true,
                    peer_types,
                    gr_capable_peers,
                    gr_peer_restarting,
                    ipv6_capable_peers,
                    eor_received,
                    eor_received_v6,
                )
            {
                v6_blocked = true;
            }
            if v4_blocked && v6_blocked {
                break;
            }
        }

        let v4_transitioned = !self.v4_released && !v4_blocked;
        let v6_transitioned = !self.v6_released && !v6_blocked;
        if v4_transitioned {
            self.v4_released = true;
        }
        if v6_transitioned {
            self.v6_released = true;
        }
        (v4_transitioned, v6_transitioned)
    }

    /// Unconditional release — RFC 4724 §4.1 path (b), the
    /// Selection_Deferral_Timer expiry. Overrides an unsatisfied wait-set.
    ///
    /// Returns which families newly transitioned (already-released families
    /// contribute `false`).
    pub(crate) fn force_release(&mut self) -> (bool, bool) {
        let v4_transitioned = !self.v4_released;
        let v6_transitioned = !self.v6_released;
        self.v4_released = true;
        self.v6_released = true;
        (v4_transitioned, v6_transitioned)
    }

    pub(crate) fn v4_deferred(&self) -> bool {
        !self.v4_released
    }

    pub(crate) fn v6_deferred(&self) -> bool {
        !self.v6_released
    }
}

/// Whether `peer_ip` currently blocks release of one family (`is_v6`
/// selects v4 vs v6). See [`SelectionDeferral::recompute`]'s doc comment
/// for the membership rule this implements.
#[allow(clippy::too_many_arguments)]
fn family_blocks(
    peer_ip: IpAddr,
    is_v6: bool,
    peer_types: &HashMap<IpAddr, PeerType>,
    gr_capable_peers: &HashMap<IpAddr, u16>,
    gr_peer_restarting: &HashSet<IpAddr>,
    ipv6_capable_peers: &HashSet<IpAddr>,
    eor_received: &HashSet<IpAddr>,
    eor_received_v6: &HashSet<IpAddr>,
) -> bool {
    if !peer_types.contains_key(&peer_ip) {
        // Not yet established: unknown GR/EOR status — block conservatively,
        // bounded by the Selection_Deferral_Timer deadline.
        return true;
    }
    if is_v6 && !ipv6_capable_peers.contains(&peer_ip) {
        // Established but never negotiated IPv6 unicast — not part of the
        // v6 wait-set at all.
        return false;
    }
    if !gr_capable_peers.contains_key(&peer_ip) {
        // Established but not GR-capable — excluded per RFC 4724 §4.1.
        return false;
    }
    if gr_peer_restarting.contains(&peer_ip) {
        // Peer itself has the Restart State bit set — excluded per RFC 4724 §4.1.
        return false;
    }
    let eor_set = if is_v6 { eor_received_v6 } else { eor_received };
    !eor_set.contains(&peer_ip)
}

impl DaemonState {
    /// Recomputes the RFC 4724 §4.1 selection-deferral gate after any event
    /// that could satisfy it (EOR receipt, peer establishment, permanent
    /// peer removal). For each family that newly releases, immediately
    /// catches up every currently-established peer with a full-table dump
    /// and EOR for that family — the dump `on_established` would have done
    /// at connect time had the family not been deferred then.
    pub(super) fn recompute_selection_deferral(&mut self) {
        let configured: Vec<IpAddr> = self.rib.peer_remote_as.keys().copied().collect();
        let (v4_released, v6_released) = self.selection_deferral.recompute(
            configured.into_iter(),
            &self.rib.peer_types,
            &self.rib.gr_capable_peers,
            &self.rib.gr_peer_restarting,
            &self.ipv6_capable_peers,
            &self.rib.eor_received,
            &self.rib.eor_received_v6,
        );
        self.catch_up_released_families(v4_released, v6_released);
    }

    /// The Selection_Deferral_Timer expiry path (RFC 4724 §4.1 path (b)):
    /// unconditionally releases both families and runs the same gate-open
    /// catch-up as [`recompute_selection_deferral`](Self::recompute_selection_deferral).
    ///
    /// Deliberately separate from calling `force_release()` followed by
    /// `recompute_selection_deferral()`: `force_release` already flips both
    /// released flags, so a subsequent `recompute()` call would see nothing
    /// left to transition and skip the catch-up entirely. Driving the
    /// catch-up directly off `force_release`'s own return value avoids that
    /// trap.
    pub(super) fn force_release_selection_deferral(&mut self) {
        let (v4_released, v6_released) = self.selection_deferral.force_release();
        self.catch_up_released_families(v4_released, v6_released);
    }

    /// Runs the RFC 4724 §2 gate-open catch-up (full dump + EOR) for each
    /// family that just transitioned from deferred to released, across
    /// every currently-established peer. No-op for a family that didn't
    /// transition this call (already released, or still deferred).
    fn catch_up_released_families(&mut self, v4_released: bool, v6_released: bool) {
        if !v4_released && !v6_released {
            return;
        }
        let established: Vec<IpAddr> = self.rib.peer_types.keys().copied().collect();
        if v4_released {
            tracing::info!(
                "RFC 4724 §4.1: IPv4 selection-deferral gate opened — \
                 catching up established peers"
            );
            for peer_ip in &established {
                self.dump_family_v4(*peer_ip);
            }
        }
        if v6_released {
            tracing::info!(
                "RFC 4724 §4.1: IPv6 selection-deferral gate opened — \
                 catching up established peers"
            );
            for peer_ip in &established {
                self.dump_family_v6(*peer_ip);
            }
        }
    }

    /// Performs the RFC 4724 §2 initial full-table dump and End-of-RIB for
    /// IPv4 unicast to `peer_ip`, reading current state (peer type,
    /// negotiated max_len/four-byte, next-hop config) from `self`.
    ///
    /// Shared by `on_established` (dump at connect time, when not deferred)
    /// and `recompute_selection_deferral`'s gate-open catch-up. The two call
    /// sites are temporally exclusive by construction: a peer present in
    /// `peer_types` during the deferral window can only have gotten there by
    /// connecting during it, so it is dumped by exactly one of the two
    /// paths, never both, never neither.
    ///
    /// No-op (returns `false`) if any required per-peer state is missing —
    /// mirrors the defensive `let ... else` guards `on_established` used
    /// inline before this was extracted.
    pub(super) fn dump_family_v4(&mut self, peer_ip: IpAddr) -> bool {
        let Some(peer_type) = self.rib.peer_types.get(&peer_ip).copied() else {
            return false;
        };
        let Some(max_len) = self.negotiated_max_len.get(&peer_ip).copied() else {
            return false;
        };
        let Some(update_tx) = self.update_senders.get(&peer_ip).cloned() else {
            return false;
        };
        let Some(export_policy) = self.export_policies.get(&peer_ip) else {
            return false;
        };
        let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&peer_ip) else {
            return false;
        };
        let peer_four_byte = self.four_byte_peers.contains(&peer_ip);

        let all_nlris: Vec<Nlri<Ipv4Addr>> =
            self.rib.loc_rib.best_routes().map(|(n, _)| n).collect();
        let local_as = self.rib.local_as;
        let local_bgp_id = self.rib.local_bgp_id;
        let local_next_hop = self
            .rib
            .local_addrs
            .get(&peer_ip)
            .and_then(|a| match a {
                IpAddr::V4(v4) => Some(*v4),
                IpAddr::V6(_) => None,
            })
            .unwrap_or(local_bgp_id);
        let next_hop_self = self.rib.next_hop_self_peers.contains(&peer_ip);
        let is_rr = !self.rib.rr_clients.is_empty();
        let dest_is_client = self.rib.rr_clients.contains(&peer_ip);
        let rr_clients = &self.rib.rr_clients;
        let peer_types = &self.rib.peer_types;
        let loc_rib = &self.rib.loc_rib;

        let decisions: Vec<PrefixDecision> = all_nlris
            .into_iter()
            .map(|nlri| {
                // RFC 4456 §8 split-horizon: as an RR, a non-client iBGP peer
                // must not receive routes learned from other non-client iBGP
                // peers.
                if is_rr
                    && peer_type == PeerType::Internal
                    && let Some(src) = loc_rib.best_peer(&nlri)
                    && let IpAddr::V4(src_ip) = src.ip()
                {
                    let src_is_client = rr_clients.contains(&IpAddr::V4(src_ip));
                    let src_is_ibgp =
                        peer_types.get(&IpAddr::V4(src_ip)).copied() == Some(PeerType::Internal);
                    if src_is_ibgp && !src_is_client && !dest_is_client {
                        return PrefixDecision::NoChange;
                    }
                }
                propagate_prefix(
                    nlri,
                    loc_rib,
                    adj_rib_out,
                    export_policy,
                    peer_type,
                    local_as,
                    local_next_hop,
                    next_hop_self,
                    false, // never deferred inside the dump itself — the
                           // caller only invokes this once the gate is open.
                )
            })
            .collect();

        let mut stalled = !flush_updates(
            peer_ip,
            decisions,
            max_len,
            &update_tx,
            peer_type,
            peer_four_byte,
        );
        if !stalled && !send_eor_ipv4(&update_tx) {
            stalled = true;
        }
        if stalled {
            self.stalled_peers.push(peer_ip);
        }
        self.sync_advertised(peer_ip);
        stalled
    }

    /// IPv6 counterpart of [`dump_family_v4`](Self::dump_family_v4). No-op
    /// (returns `false`, no EOR sent) for a peer that never negotiated the
    /// IPv6 unicast Multi-Protocol capability. Still sends End-of-RIB (RFC
    /// 4724 §2) even when the IPv6 table is currently empty.
    pub(super) fn dump_family_v6(&mut self, peer_ip: IpAddr) -> bool {
        let Some(peer_type) = self.rib.peer_types.get(&peer_ip).copied() else {
            return false;
        };
        if !self.ipv6_capable_peers.contains(&peer_ip) {
            return false;
        }
        let Some(max_len) = self.negotiated_max_len.get(&peer_ip).copied() else {
            return false;
        };
        let Some(update_tx) = self.update_senders.get(&peer_ip).cloned() else {
            return false;
        };
        let peer_four_byte = self.four_byte_peers.contains(&peer_ip);

        let all_nlris_v6: Vec<Nlri<Ipv6Addr>> =
            self.rib.loc_rib_v6.best_routes().map(|(n, _)| n).collect();
        if all_nlris_v6.is_empty() {
            let stalled = !send_eor_ipv6(&update_tx);
            if stalled {
                self.stalled_peers.push(peer_ip);
            }
            return stalled;
        }

        let Some(export_policy_v6) = self.export_policies_v6.get(&peer_ip) else {
            return false;
        };
        let Some(adj_rib_out_v6) = self.adj_ribs_out_v6.get_mut(&peer_ip) else {
            return false;
        };

        let local_as = self.rib.local_as;
        let local_ipv6 = self.rib.local_ipv6;
        let next_hop_self = self.rib.next_hop_self_peers.contains(&peer_ip);
        let is_rr = !self.rib.rr_clients.is_empty();
        let dest_is_client = self.rib.rr_clients.contains(&peer_ip);
        let rr_clients = &self.rib.rr_clients;
        let peer_types = &self.rib.peer_types;
        let loc_rib_v6 = &self.rib.loc_rib_v6;

        let decisions_v6: Vec<PrefixDecisionV6> = all_nlris_v6
            .into_iter()
            .map(|nlri| {
                if is_rr
                    && peer_type == PeerType::Internal
                    && let Some(src) = loc_rib_v6.best_peer(&nlri)
                    && let IpAddr::V4(src_ip) = src.ip()
                {
                    let src_is_client = rr_clients.contains(&IpAddr::V4(src_ip));
                    let src_is_ibgp =
                        peer_types.get(&IpAddr::V4(src_ip)).copied() == Some(PeerType::Internal);
                    if src_is_ibgp && !src_is_client && !dest_is_client {
                        return PrefixDecisionV6::NoChange;
                    }
                }
                propagate_prefix_v6(
                    nlri,
                    loc_rib_v6,
                    adj_rib_out_v6,
                    export_policy_v6,
                    peer_type,
                    local_as,
                    local_ipv6,
                    next_hop_self,
                    false,
                )
            })
            .collect();

        let mut stalled = !flush_updates_v6(
            peer_ip,
            decisions_v6,
            max_len,
            &update_tx,
            peer_type,
            peer_four_byte,
        );
        if !stalled && !send_eor_ipv6(&update_tx) {
            stalled = true;
        }
        if stalled {
            self.stalled_peers.push(peer_ip);
        }
        self.sync_advertised(peer_ip);
        stalled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[allow(clippy::too_many_arguments)]
    struct Fixture {
        configured: Vec<IpAddr>,
        peer_types: HashMap<IpAddr, PeerType>,
        gr_capable_peers: HashMap<IpAddr, u16>,
        gr_peer_restarting: HashSet<IpAddr>,
        ipv6_capable_peers: HashSet<IpAddr>,
        eor_received: HashSet<IpAddr>,
        eor_received_v6: HashSet<IpAddr>,
    }

    impl Fixture {
        fn empty() -> Self {
            Self {
                configured: Vec::new(),
                peer_types: HashMap::new(),
                gr_capable_peers: HashMap::new(),
                gr_peer_restarting: HashSet::new(),
                ipv6_capable_peers: HashSet::new(),
                eor_received: HashSet::new(),
                eor_received_v6: HashSet::new(),
            }
        }

        fn recompute(&self, sd: &mut SelectionDeferral) -> (bool, bool) {
            sd.recompute(
                self.configured.iter().copied(),
                &self.peer_types,
                &self.gr_capable_peers,
                &self.gr_peer_restarting,
                &self.ipv6_capable_peers,
                &self.eor_received,
                &self.eor_received_v6,
            )
        }
    }

    #[test]
    fn empty_configured_peer_set_releases_immediately() {
        let mut sd = SelectionDeferral::new(Instant::now(), 120);
        let fx = Fixture::empty();
        assert_eq!(fx.recompute(&mut sd), (true, true));
        assert!(!sd.v4_deferred());
        assert!(!sd.v6_deferred());
    }

    #[test]
    fn unestablished_configured_peer_blocks_release() {
        let mut sd = SelectionDeferral::new(Instant::now(), 120);
        let mut fx = Fixture::empty();
        fx.configured.push(peer(1)); // never established
        assert_eq!(fx.recompute(&mut sd), (false, false));
        assert!(sd.v4_deferred());
        assert!(sd.v6_deferred());
    }

    #[test]
    fn established_non_gr_capable_peer_does_not_block() {
        let mut sd = SelectionDeferral::new(Instant::now(), 120);
        let mut fx = Fixture::empty();
        fx.configured.push(peer(1));
        fx.peer_types.insert(peer(1), PeerType::External); // established
        // Not in gr_capable_peers ⇒ excluded from the wait-set entirely.
        assert_eq!(fx.recompute(&mut sd), (true, true));
    }

    #[test]
    fn established_restarting_peer_does_not_block() {
        let mut sd = SelectionDeferral::new(Instant::now(), 120);
        let mut fx = Fixture::empty();
        fx.configured.push(peer(1));
        fx.peer_types.insert(peer(1), PeerType::External);
        fx.gr_capable_peers.insert(peer(1), 120);
        fx.gr_peer_restarting.insert(peer(1)); // peer itself is restarting
        assert_eq!(fx.recompute(&mut sd), (true, true));
    }

    #[test]
    fn established_gr_capable_peer_without_eor_blocks() {
        let mut sd = SelectionDeferral::new(Instant::now(), 120);
        let mut fx = Fixture::empty();
        fx.configured.push(peer(1));
        fx.peer_types.insert(peer(1), PeerType::External);
        fx.gr_capable_peers.insert(peer(1), 120);
        fx.ipv6_capable_peers.insert(peer(1)); // also part of the v6 wait-set
        // No EOR yet (either family).
        assert_eq!(fx.recompute(&mut sd), (false, false));
    }

    #[test]
    fn eor_receipt_satisfies_membership() {
        let mut sd = SelectionDeferral::new(Instant::now(), 120);
        let mut fx = Fixture::empty();
        fx.configured.push(peer(1));
        fx.peer_types.insert(peer(1), PeerType::External);
        fx.gr_capable_peers.insert(peer(1), 120);
        fx.ipv6_capable_peers.insert(peer(1)); // also part of the v6 wait-set
        assert_eq!(fx.recompute(&mut sd), (false, false));

        fx.eor_received.insert(peer(1));
        assert_eq!(fx.recompute(&mut sd), (true, false));
        assert!(!sd.v4_deferred());
        assert!(sd.v6_deferred());
    }

    #[test]
    fn v6_gate_excludes_peer_without_ipv6_capability() {
        let mut sd = SelectionDeferral::new(Instant::now(), 120);
        let mut fx = Fixture::empty();
        fx.configured.push(peer(1));
        fx.peer_types.insert(peer(1), PeerType::External);
        fx.gr_capable_peers.insert(peer(1), 120);
        fx.eor_received.insert(peer(1));
        // No v6 EOR and not ipv6-capable — still releases v6 since this peer
        // isn't part of the v6 wait-set at all.
        assert_eq!(fx.recompute(&mut sd), (true, true));
    }

    #[test]
    fn v6_gate_blocks_until_v6_eor_for_ipv6_capable_peer() {
        let mut sd = SelectionDeferral::new(Instant::now(), 120);
        let mut fx = Fixture::empty();
        fx.configured.push(peer(1));
        fx.peer_types.insert(peer(1), PeerType::External);
        fx.gr_capable_peers.insert(peer(1), 120);
        fx.ipv6_capable_peers.insert(peer(1));
        fx.eor_received.insert(peer(1));
        assert_eq!(fx.recompute(&mut sd), (true, false));
        fx.eor_received_v6.insert(peer(1));
        assert_eq!(fx.recompute(&mut sd), (false, true));
    }

    #[test]
    fn force_release_overrides_unsatisfied_wait_set() {
        let mut sd = SelectionDeferral::new(Instant::now(), 120);
        let mut fx = Fixture::empty();
        fx.configured.push(peer(1)); // never established, would block forever
        assert_eq!(fx.recompute(&mut sd), (false, false));
        assert_eq!(sd.force_release(), (true, true));
        assert!(!sd.v4_deferred());
        assert!(!sd.v6_deferred());
    }

    #[test]
    fn one_way_latch_survives_regressed_inputs() {
        let mut sd = SelectionDeferral::new(Instant::now(), 120);
        let fx_empty = Fixture::empty();
        assert_eq!(fx_empty.recompute(&mut sd), (true, true));

        // A later recompute with inputs that would otherwise block (an
        // unestablished configured peer appears) must NOT re-defer.
        let mut fx_blocking = Fixture::empty();
        fx_blocking.configured.push(peer(99));
        assert_eq!(fx_blocking.recompute(&mut sd), (false, false));
        assert!(!sd.v4_deferred());
        assert!(!sd.v6_deferred());
    }

    #[test]
    fn disabled_has_no_pending_deadline_and_is_released() {
        let sd = SelectionDeferral::disabled();
        assert_eq!(sd.pending_deadline(), None);
        assert!(!sd.v4_deferred());
        assert!(!sd.v6_deferred());
    }

    #[test]
    fn zero_deferral_secs_constructs_pre_released() {
        let sd = SelectionDeferral::new(Instant::now(), 0);
        assert_eq!(sd.pending_deadline(), None);
        assert!(!sd.v4_deferred());
        assert!(!sd.v6_deferred());
    }

    #[test]
    fn pending_deadline_present_while_either_family_deferred() {
        let start = Instant::now();
        let mut sd = SelectionDeferral::new(start, 120);
        assert!(sd.pending_deadline().is_some());
        sd.force_release();
        assert_eq!(sd.pending_deadline(), None);
    }
}
