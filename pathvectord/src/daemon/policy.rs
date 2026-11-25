// daemon/policy.rs — Import/export default policy management.
#[allow(clippy::wildcard_imports)]
use super::*;

impl DaemonState {
    pub(crate) fn set_import_default(&mut self, peer_ip: IpAddr, action: DefaultAction) {
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
        let peer_ips: Vec<IpAddr> = self.import_policies.keys().copied().collect();
        for peer_ip in peer_ips {
            self.reevaluate_import_for_peer(peer_ip);
        }
        self.flush_pending();
    }

    /// The pre-policy checks for announcements from `peer_ip` (issue #138):
    /// our AS, Confederation Identifier and addresses toward that peer.
    /// `on_route_update` and soft reconfiguration both use it, so arrival and
    /// re-evaluation reach the same verdict.
    pub(super) fn ingress_gate(&self, peer_ip: IpAddr) -> IngressGate {
        IngressGate::new(
            self.rib.local_as,
            self.rib.confederation_id,
            self.rib
                .local_addrs
                .get(&peer_ip)
                .and_then(|a| match a {
                    IpAddr::V4(v4) => Some(*v4),
                    IpAddr::V6(_) => None,
                })
                // The live session is gone but its routes may be retained (GR).
                .or_else(|| self.gr.retained_local_v4.get(&peer_ip).copied()),
            self.rib.local_ipv6,
        )
    }

    /// Re-imports `peer_ip`'s IPv4 Adj-RIB-In through the import pipeline
    /// ([`ImportPipeline`]: ingress gate, BLACKHOLE agreement, import policy)
    /// and reconciles the Loc-RIB and the null-route book with the result.
    ///
    /// The one re-evaluation entry point: policy changes, RPKI ROA changes,
    /// agreement changes and Graceful Restart stale marking all call it, so a
    /// retained route is judged exactly as arrival would judge it. Returns
    /// `None` for a peer with no policy (an unknown peer). The caller programs
    /// the effects ([`program_fib_v4`](Self::program_fib_v4)) and propagates.
    pub(super) fn reimport_peer_v4(
        &mut self,
        peer_ip: IpAddr,
        gate: &IngressGate,
    ) -> Option<RibEffects<Ipv4Addr>> {
        let policy = self.import_policies.get(&peer_ip)?;
        let adj_rib_in = self.adj_ribs_in.get(&peer_ip)?;
        let no_agreement = PeerBlackhole::denied();
        let blackhole = self
            .blackhole_sessions
            .get(&peer_ip)
            .unwrap_or(&no_agreement);
        let pipeline = ImportPipeline {
            policy,
            blackhole: &blackhole.v4,
        };
        // Clone the oracle Arc so the borrow checker sees `oracle_v4` and
        // `rib` as independent fields of `self`.
        let oracle = Arc::clone(&self.oracle_v4);
        Some(reapply_import_policy(
            PeerId::from(peer_ip),
            adj_rib_in,
            &mut Arc::make_mut(&mut self.rib).loc_rib,
            &mut self.blackholes.v4,
            &pipeline,
            gate,
            &*oracle,
        ))
    }

    /// IPv6 counterpart of [`reimport_peer_v4`](Self::reimport_peer_v4).
    pub(super) fn reimport_peer_v6(
        &mut self,
        peer_ip: IpAddr,
        gate: &IngressGate,
    ) -> Option<RibEffects<Ipv6Addr>> {
        let policy = self.import_policies_v6.get(&peer_ip)?;
        let adj_rib_in = self.adj_ribs_in_v6.get(&peer_ip)?;
        let no_agreement = PeerBlackhole::denied();
        let blackhole = self
            .blackhole_sessions
            .get(&peer_ip)
            .unwrap_or(&no_agreement);
        let pipeline = ImportPipeline {
            policy,
            blackhole: &blackhole.v6,
        };
        let oracle = Arc::clone(&self.oracle_v6);
        Some(reapply_import_policy(
            PeerId::from(peer_ip),
            adj_rib_in,
            &mut Arc::make_mut(&mut self.rib).loc_rib_v6,
            &mut self.blackholes.v6,
            &pipeline,
            gate,
            &*oracle,
        ))
    }

    /// Re-evaluates one peer's Adj-RIB-In (both address families) against
    /// its current import policy and BLACKHOLE agreement, updates Loc-RIB and
    /// the FIB, and propagates any resulting changes to other peers. Shared by
    /// `set_import_default` (policy replaced first) and
    /// `reevaluate_all_import_policies` (policy left as-is). Does **not**
    /// call `flush_pending` — callers do that once, after their own loop.
    fn reevaluate_import_for_peer(&mut self, peer_ip: IpAddr) {
        // The prefixes this peer's Adj-RIB-In holds: the only ones whose
        // state can change.
        let nlris: Vec<Nlri<Ipv4Addr>> = self
            .adj_ribs_in
            .get(&peer_ip)
            .map(super::gr::sorted_nlris)
            .unwrap_or_default();
        let gate = self.ingress_gate(peer_ip);

        if let Some(effects) = self.reimport_peer_v4(peer_ip, &gate) {
            self.program_fib_v4(effects);
        }
        self.propagate_to_all_peers(&nlris);
        // propagate_to_all_peers fires PeerEvent::Changed (ADV); fire route
        // events too so the dashboard reflects the Loc-RIB change.
        self.emit_route_events(&nlris);

        // IPv6 Adj-RIB-In, same pipeline.
        let nlris_v6: Vec<Nlri<Ipv6Addr>> = self
            .adj_ribs_in_v6
            .get(&peer_ip)
            .map(super::gr::sorted_nlris)
            .unwrap_or_default();
        if let Some(effects) = self.reimport_peer_v6(peer_ip, &gate) {
            self.program_fib_v6(effects);
        }
        self.propagate_to_all_peers_v6(&nlris_v6);
    }

    /// Replaces `peer_ip`'s RFC 7999 BLACKHOLE agreement (`None` revokes it)
    /// and re-evaluates the peer's Adj-RIB-In under it: newly authorized
    /// requests are programmed, revoked or out-of-scope ones have their null
    /// routes removed.
    ///
    /// There is no runtime configuration reload yet, so production sessions get
    /// their agreement from `add_peer`; this is the policy-change entry point
    /// the re-evaluation tests drive.
    #[cfg(test)]
    pub(crate) fn set_blackhole_scope(
        &mut self,
        peer_ip: IpAddr,
        scope: Option<&crate::blackhole::BlackholeScope>,
    ) {
        if !self.import_policies.contains_key(&peer_ip) {
            tracing::warn!(peer = %peer_ip, "set_blackhole_scope: unknown peer — ignoring");
            return;
        }
        let leak = self
            .rib
            .peer_roles
            .get(&peer_ip)
            .copied()
            .zip(self.rib.peer_remote_as.get(&peer_ip).copied())
            .map(|(role, asn)| (role, Asn::new(asn)));
        self.blackhole_sessions
            .insert(peer_ip, PeerBlackhole::from_config(scope, leak));
        self.reevaluate_import_for_peer(peer_ip);
        self.flush_pending();
    }

    /// Replaces the export-policy default for `peer_ip` — both address
    /// families, since there is no separate `export_default_v6` config knob
    /// (leaving any installed terms — e.g. RFC 9234 OTC block/attach —
    /// untouched in either) — and re-evaluates the entire Loc-RIB against
    /// the updated policy for that peer. Newly accepted prefixes are sent as
    /// UPDATEs; newly rejected ones trigger WITHDRAWs.
    ///
    /// Has no effect on the wire if the peer is not currently established — the
    /// new policy will be applied on the next session's opening table dump.
    pub(crate) fn set_export_default(&mut self, peer_ip: IpAddr, action: DefaultAction) {
        if !self.export_policies.contains_key(&peer_ip) {
            tracing::warn!(peer = %peer_ip, "set_export_default: unknown peer — ignoring");
            return;
        }
        self.export_policies
            .get_mut(&peer_ip)
            .unwrap()
            .set_default(action);
        self.export_policies_v6
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

        let local_as = self.rib.local_as;
        // RFC 5065: the AS number prepended for genuinely external peers —
        // the confederation identifier when confederations are configured,
        // or `local_as` again when they are not.
        let public_as = self.rib.confederation_id.unwrap_or(local_as);
        let local_bgp_id = self.rib.local_bgp_id;
        let next_hop_self = self.rib.next_hop_self_peers.contains(&peer_ip);
        let v4_deferred = self.selection_deferral.v4_deferred();
        let v6_deferred = self.selection_deferral.v6_deferred();

        if let (Some(export_policy), Some(adj_rib_out), true) = (
            self.export_policies.get(&peer_ip),
            self.adj_ribs_out.get_mut(&peer_ip),
            self.update_senders.contains_key(&peer_ip),
        ) {
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
                        public_as,
                        local_bgp_id,
                        next_hop_self,
                        v4_deferred,
                    )
                })
                .collect();
            self.send_decisions(peer_ip, decisions);
        }

        if self.ipv6_capable_peers.contains(&peer_ip) {
            let nlris_v6: Vec<Nlri<Ipv6Addr>> =
                self.rib.loc_rib_v6.best_routes().map(|(n, _)| n).collect();
            let local_ipv6 = self.rib.local_ipv6;
            if let (Some(export_policy_v6), Some(adj_rib_out_v6), true) = (
                self.export_policies_v6.get(&peer_ip),
                self.adj_ribs_out_v6.get_mut(&peer_ip),
                self.update_senders.contains_key(&peer_ip),
            ) {
                let decisions_v6: Vec<PrefixDecisionV6> = nlris_v6
                    .into_iter()
                    .map(|nlri| {
                        propagate_prefix_v6(
                            nlri,
                            &self.rib.loc_rib_v6,
                            adj_rib_out_v6,
                            export_policy_v6,
                            peer_type,
                            local_as,
                            public_as,
                            local_ipv6,
                            next_hop_self,
                            v6_deferred,
                        )
                    })
                    .collect();
                self.send_decisions_v6(peer_ip, decisions_v6);
            }
        }

        self.sync_advertised(peer_ip);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
        let unknown: Ipv4Addr = "1.2.3.4".parse().unwrap();
        // Must not panic or alter state.
        state.set_import_default(IpAddr::V4(unknown), DefaultAction::Accept);
    }

    /// `set_export_default` on an unknown peer must be silently ignored.
    #[test]
    fn set_export_default_unknown_peer_is_noop() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
        let unknown: Ipv4Addr = "1.2.3.4".parse().unwrap();
        state.set_export_default(IpAddr::V4(unknown), DefaultAction::Accept);
    }

    /// `set_export_default` when `adj_ribs_out` is missing must return without panic.
    /// Covers the defensive return at line 115.
    #[test]
    fn set_export_default_missing_adj_rib_out_returns_silently() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
        state.on_established(
            IpAddr::V4(PEER_IP),
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &[],
            None,
        );
        state.adj_ribs_out.remove(&IpAddr::V4(PEER_IP));
        // Must not panic.
        state.set_export_default(IpAddr::V4(PEER_IP), DefaultAction::Accept);
    }

    /// `set_export_default` when `update_senders` is missing must return without panic.
    /// Covers the defensive return at line 118.
    #[test]
    fn set_export_default_missing_update_senders_returns_silently() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
        state.on_established(
            IpAddr::V4(PEER_IP),
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &[],
            None,
        );
        state.update_senders.remove(&IpAddr::V4(PEER_IP));
        // Must not panic.
        state.set_export_default(IpAddr::V4(PEER_IP), DefaultAction::Accept);
    }

    /// `set_export_default` before `on_established` (peer not yet in `rib.peer_types`)
    /// must store the new policy without attempting to propagate (no crash, no output).
    #[test]
    fn set_export_default_not_established_is_stored_silently() {
        let (mut state, mut rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
        // Peer exists in export_policies (added by make_state) but is NOT established.
        state.set_export_default(IpAddr::V4(PEER_IP), DefaultAction::Reject);
        // No UPDATE must be sent.
        assert!(
            rxs.get_mut(&IpAddr::V4(PEER_IP))
                .unwrap()
                .try_recv()
                .is_err()
        );
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
        let (mut state, mut rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
        let fib = with_recording_fib(&mut state);

        let v6_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
        state.on_established(
            IpAddr::V4(PEER_IP),
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &v6_caps,
            None,
        );
        while rxs
            .get_mut(&IpAddr::V4(PEER_IP))
            .unwrap()
            .try_recv()
            .is_ok()
        {}

        state.on_route_update(IpAddr::V4(PEER_IP), announce_v6("2001:db8::/32"));
        fib.v6.lock().unwrap().clear();

        state.set_import_default(IpAddr::V4(PEER_IP), DefaultAction::Reject);

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
        let (mut state, mut rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
        let fib = with_recording_fib(&mut state);

        state.on_established(
            IpAddr::V4(PEER_IP),
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &[],
            None,
        );
        while rxs
            .get_mut(&IpAddr::V4(PEER_IP))
            .unwrap()
            .try_recv()
            .is_ok()
        {}

        state.on_route_update(IpAddr::V4(PEER_IP), announce("10.0.0.0/8"));
        fib.v4.lock().unwrap().clear();

        state.set_import_default(IpAddr::V4(PEER_IP), DefaultAction::Reject);

        let changes = fib.v4.lock().unwrap().clone();
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
            "set_import_default(Reject) must push a Withdrawn FIB change for the evicted route"
        );
    }
}
