// daemon/policy.rs — Import/export default policy management.
#[allow(clippy::wildcard_imports)]
use super::*;

impl DaemonState {
    pub(crate) fn set_import_default(&mut self, peer_ip: Ipv4Addr, action: DefaultAction) {
        if !self.import_policies.contains_key(&peer_ip) {
            tracing::warn!(peer = %peer_ip, "set_import_default: unknown peer — ignoring");
            return;
        }
        self.import_policies.insert(peer_ip, Policy::new(action));

        // Collect affected NLRIs before the mutable borrow of loc_rib so the
        // borrow checker does not see two simultaneous borrows of `self`.
        let nlris: Vec<Nlri<Ipv4Addr>> = self
            .adj_ribs_in
            .get(&peer_ip)
            .map(|a| a.routes().map(|(n, _)| *n).collect())
            .unwrap_or_default();

        // Re-evaluate the peer's Adj-RIB-In against the new policy.
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

        // Re-evaluate IPv6 Adj-RIB-In against the same policy change.
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
        self.flush_pending();
    }

    /// Replaces the export-policy default for `peer_ip` and re-evaluates the
    /// entire Loc-RIB against the new policy for that peer.  Newly accepted
    /// prefixes are sent as UPDATEs; newly rejected ones trigger WITHDRAWs.
    ///
    /// Has no effect on the wire if the peer is not currently established — the
    /// new policy will be applied on the next session's opening table dump.
    pub(crate) fn set_export_default(&mut self, peer_ip: Ipv4Addr, action: DefaultAction) {
        if !self.export_policies.contains_key(&peer_ip) {
            tracing::warn!(peer = %peer_ip, "set_export_default: unknown peer — ignoring");
            return;
        }
        self.export_policies.insert(peer_ip, Policy::new(action));

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
