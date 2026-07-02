// daemon/policy.rs — Import/export default policy management.
#[allow(clippy::wildcard_imports)]
use super::*;

impl DaemonState {
    pub(crate) fn set_import_default(&mut self, peer_ip: Ipv4Addr, action: DefaultAction) {
        if !self.import_policies.contains_key(&peer_ip) {
            tracing::warn!(peer = %peer_ip, "set_import_default: unknown peer — ignoring");
            return;
        }
        // `set_default` only, never `Policy::new(action)` — a full replacement
        // would silently discard any installed terms (RFC 9234 OTC leak
        // detection, RFC 6811 ROV reject) along with the default action.
        self.import_policies
            .get_mut(&peer_ip)
            .unwrap()
            .set_default(action);
        self.import_policies_v6
            .get_mut(&peer_ip)
            .unwrap()
            .set_default(action);

        self.reevaluate_import_for_peer(peer_ip);
        self.flush_pending();
    }

    /// Re-evaluates every configured peer's Adj-RIB-In against its
    /// **current, unchanged** import policy — everything `set_import_default`
    /// does, minus replacing the policy. Called whenever the RPKI ROA cache
    /// changes (see `pathvector_rpki::RtrHandle::subscribe`, wired up in
    /// `run_with`), so a route accepted while the cache was empty or stale
    /// gets correctly re-judged once the cache reflects it — this closes the
    /// "fail open until next session reset" window and reacts to a ROA
    /// changing after the fact, matching BIRD/FRR's ROA-table-triggered
    /// channel reload.
    pub(crate) fn reevaluate_all_import_policies(&mut self) {
        let peer_ips: Vec<Ipv4Addr> = self.import_policies.keys().copied().collect();
        for peer_ip in peer_ips {
            self.reevaluate_import_for_peer(peer_ip);
        }
        self.flush_pending();
    }

    /// Re-evaluates one peer's Adj-RIB-In (both address families) against
    /// its current import policy, updates Loc-RIB and the FIB, and
    /// propagates any resulting changes to other peers. Shared by
    /// `set_import_default` (policy replaced first) and
    /// `reevaluate_all_import_policies` (policy left as-is). Does **not**
    /// call `flush_pending` — callers do that once, after their own loop.
    fn reevaluate_import_for_peer(&mut self, peer_ip: Ipv4Addr) {
        // Collect affected NLRIs before the mutable borrow of loc_rib so the
        // borrow checker does not see two simultaneous borrows of `self`.
        let nlris: Vec<Nlri<Ipv4Addr>> = self
            .adj_ribs_in
            .get(&peer_ip)
            .map(|a| a.routes().map(|(n, _)| *n).collect())
            .unwrap_or_default();

        // Re-evaluate the peer's Adj-RIB-In against the current policy.
        // Clone oracle before the mutable borrow of rib so the borrow checker
        // sees oracle_v4 and rib as independent fields of self.
        let oracle = Arc::clone(&self.oracle_v4);
        let loc_rib = &mut Arc::make_mut(&mut self.rib).loc_rib;
        let fib_changes = reapply_import_policy(
            PeerId::from(peer_ip),
            &self.adj_ribs_in[&peer_ip],
            loc_rib,
            &self.import_policies[&peer_ip],
            &*oracle,
        );

        if let Some(fm) = &self.fib_manager {
            for change in fib_changes {
                fm.apply_v4(change);
            }
        }

        self.propagate_to_all_peers(&nlris);
        // propagate_to_all_peers fires PeerEvent::Changed (ADV); fire route
        // events too so the dashboard reflects the Loc-RIB change.
        self.emit_route_events(&nlris);

        // Re-evaluate IPv6 Adj-RIB-In against the same policy.
        let nlris_v6: Vec<Nlri<Ipv6Addr>> = self
            .adj_ribs_in_v6
            .get(&peer_ip)
            .map(|a| a.routes().map(|(n, _)| *n).collect())
            .unwrap_or_default();

        let oracle_v6 = Arc::clone(&self.oracle_v6);
        let loc_rib_v6 = &mut Arc::make_mut(&mut self.rib).loc_rib_v6;
        let fib_changes_v6 = reapply_import_policy_v6(
            PeerId::from(peer_ip),
            &self.adj_ribs_in_v6[&peer_ip],
            loc_rib_v6,
            &self.import_policies_v6[&peer_ip],
            &*oracle_v6,
        );

        if let Some(fm) = &self.fib_manager {
            for change in fib_changes_v6 {
                fm.apply_v6(change);
            }
        }

        self.propagate_to_all_peers_v6(&nlris_v6);
    }

    /// Replaces the export-policy default for `peer_ip` (leaving any
    /// installed terms — e.g. RFC 9234 OTC block/attach — untouched) and
    /// re-evaluates the entire Loc-RIB against the updated policy for that
    /// peer.  Newly accepted prefixes are sent as UPDATEs; newly rejected
    /// ones trigger WITHDRAWs.
    ///
    /// Has no effect on the wire if the peer is not currently established — the
    /// new policy will be applied on the next session's opening table dump.
    pub(crate) fn set_export_default(&mut self, peer_ip: Ipv4Addr, action: DefaultAction) {
        if !self.export_policies.contains_key(&peer_ip) {
            tracing::warn!(peer = %peer_ip, "set_export_default: unknown peer — ignoring");
            return;
        }
        self.export_policies
            .get_mut(&peer_ip)
            .unwrap()
            .set_default(action);

        if !self.rib.peer_types.contains_key(&peer_ip) {
            tracing::debug!(
                peer = %peer_ip,
                "set_export_default: peer not established — new policy applies on reconnect"
            );
            return;
        }

        let peer_type = self
            .rib
            .peer_types
            .get(&peer_ip)
            .copied()
            .unwrap_or(PeerType::External);

        // Collect all Loc-RIB NLRIs; the borrow is dropped after the collect.
        let nlris: Vec<Nlri<Ipv4Addr>> = self.rib.loc_rib.best_routes().map(|(n, _)| n).collect();

        let max_len = self
            .negotiated_max_len
            .get(&peer_ip)
            .copied()
            .unwrap_or(MAX_LEN);
        let local_as = self.rib.local_as;
        let local_bgp_id = self.rib.local_bgp_id;
        let Some(export_policy) = self.export_policies.get(&peer_ip) else {
            return;
        };
        let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&peer_ip) else {
            return;
        };
        let Some(update_tx) = self.update_senders.get(&peer_ip) else {
            return;
        };

        let next_hop_self = self.rib.next_hop_self_peers.contains(&peer_ip);
        let decisions: Vec<PrefixDecision> = nlris
            .into_iter()
            .map(|nlri| {
                propagate_prefix(
                    nlri,
                    &self.rib.loc_rib,
                    adj_rib_out,
                    export_policy,
                    peer_type,
                    local_as,
                    local_bgp_id,
                    next_hop_self,
                )
            })
            .collect();
        let peer_four_byte = self.four_byte_peers.contains(&peer_ip);
        if !flush_updates(decisions, max_len, update_tx, peer_type, peer_four_byte) {
            self.stalled_peers.push(peer_ip);
        }
        self.sync_advertised(peer_ip);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pathvector_policy::DefaultAction;
    use pathvector_rib::BestPathChange;
    use pathvector_session::message::{Capability, PathAttribute, UpdateMessage};
    use pathvector_types::{AsPath, Asn, Nlri, Origin, PeerType};

    use crate::daemon::tests::{make_state, with_recording_fib};

    const LOCAL_AS: u32 = 65001;
    const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const PEER_AS: u32 = 65002;

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn announce(prefix: &str) -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(PEER_AS)])),
                PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
            ],
            announced: vec![nlri(prefix)],
        }
    }

    /// `set_import_default` on an unknown peer must be silently ignored.
    #[test]
    fn set_import_default_unknown_peer_is_noop() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(PEER_IP, PEER_AS)]);
        let unknown: Ipv4Addr = "1.2.3.4".parse().unwrap();
        // Must not panic or alter state.
        state.set_import_default(unknown, DefaultAction::Accept);
    }

    /// `set_export_default` on an unknown peer must be silently ignored.
    #[test]
    fn set_export_default_unknown_peer_is_noop() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(PEER_IP, PEER_AS)]);
        let unknown: Ipv4Addr = "1.2.3.4".parse().unwrap();
        state.set_export_default(unknown, DefaultAction::Accept);
    }

    /// `set_export_default` when `adj_ribs_out` is missing must return without panic.
    /// Covers the defensive return at line 115.
    #[test]
    fn set_export_default_missing_adj_rib_out_returns_silently() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(PEER_IP, PEER_AS)]);
        state.on_established(PEER_IP, PEER_IP, PeerType::External, PEER_AS, 90, &[], None);
        state.adj_ribs_out.remove(&PEER_IP);
        // Must not panic.
        state.set_export_default(PEER_IP, DefaultAction::Accept);
    }

    /// `set_export_default` when `update_senders` is missing must return without panic.
    /// Covers the defensive return at line 118.
    #[test]
    fn set_export_default_missing_update_senders_returns_silently() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(PEER_IP, PEER_AS)]);
        state.on_established(PEER_IP, PEER_IP, PeerType::External, PEER_AS, 90, &[], None);
        state.update_senders.remove(&PEER_IP);
        // Must not panic.
        state.set_export_default(PEER_IP, DefaultAction::Accept);
    }

    /// `set_export_default` before `on_established` (peer not yet in `rib.peer_types`)
    /// must store the new policy without attempting to propagate (no crash, no output).
    #[test]
    fn set_export_default_not_established_is_stored_silently() {
        let (mut state, mut rxs) = make_state(LOCAL_AS, &[(PEER_IP, PEER_AS)]);
        // Peer exists in export_policies (added by make_state) but is NOT established.
        state.set_export_default(PEER_IP, DefaultAction::Reject);
        // No UPDATE must be sent.
        assert!(rxs.get_mut(&PEER_IP).unwrap().try_recv().is_err());
    }

    fn announce_v6(prefix: &str) -> UpdateMessage {
        use pathvector_session::message::{MpReachNlri, PathAttribute, Prefix};
        use pathvector_types::{AfiSafi, AsPath, Asn, NextHop, Origin};
        let nlri_v6: Nlri<Ipv6Addr> = prefix.parse().unwrap();
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(PEER_AS)])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                    prefixes: vec![Prefix::V6(nlri_v6)],
                }),
            ],
            announced: vec![],
        }
    }

    /// Changing import policy to Reject when a v6 route is present must trigger
    /// a FIB Withdrawn call via the v6 branch (covers lines 64-65).
    #[test]
    fn set_import_default_reject_v6_notifies_fib_manager() {
        use pathvector_types::{AfiSafi, PeerType};
        let (mut state, mut rxs) = make_state(LOCAL_AS, &[(PEER_IP, PEER_AS)]);
        let fib = with_recording_fib(&mut state);

        let v6_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &v6_caps,
            None,
        );
        while rxs.get_mut(&PEER_IP).unwrap().try_recv().is_ok() {}

        state.on_route_update(PEER_IP, announce_v6("2001:db8::/32"));
        fib.v6.lock().unwrap().clear();

        state.set_import_default(PEER_IP, DefaultAction::Reject);

        let v6_changes = fib.v6.lock().unwrap().clone();
        assert!(
            v6_changes
                .iter()
                .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
            "set_import_default(Reject) must push a v6 Withdrawn FIB change"
        );
    }

    /// Changing import policy to Reject when a route is present must trigger a FIB
    /// Withdrawn call (covers the `if let Some(fm)` branch in `set_import_default`).
    #[test]
    fn set_import_default_reject_notifies_fib_manager() {
        let (mut state, mut rxs) = make_state(LOCAL_AS, &[(PEER_IP, PEER_AS)]);
        let fib = with_recording_fib(&mut state);

        state.on_established(PEER_IP, PEER_IP, PeerType::External, PEER_AS, 90, &[], None);
        while rxs.get_mut(&PEER_IP).unwrap().try_recv().is_ok() {}

        state.on_route_update(PEER_IP, announce("10.0.0.0/8"));
        fib.v4.lock().unwrap().clear();

        state.set_import_default(PEER_IP, DefaultAction::Reject);

        let changes = fib.v4.lock().unwrap().clone();
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
            "set_import_default(Reject) must push a Withdrawn FIB change for the evicted route"
        );
    }
}
