// daemon/gr.rs — Graceful Restart: stale-route marking, repropagation, pruning, deadline handling.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Per-daemon GR state: active windows, stale-NLRI snapshots, and peer family info.
///
/// Consolidates four `DaemonState` fields that share a key type and lifecycle:
/// created together on unclean termination, read together on re-establishment,
/// and removed together on deadline expiry or peer removal.
pub(crate) struct GracefulRestartState {
    /// Active GR windows: `peer_ip → Instant` at which the window expires.
    ///
    /// Present while pathvectord holds stale routes from an uncleanly-terminated
    /// GR-capable peer.  Removed on re-establishment or deadline expiry.
    pub(crate) deadlines: HashMap<IpAddr, Instant>,
    /// NLRIs snapshotted from AdjRibIn at GR re-establishment time (IPv4).
    ///
    /// Routes that are not refreshed by the peer before its EOR are withdrawn on
    /// EOR receipt.  Cleared on EOR, deadline expiry, or peer removal.
    pub(crate) stale_nlri: HashMap<IpAddr, HashSet<Nlri<Ipv4Addr>>>,
    /// IPv6 counterpart of `stale_nlri` — same lifecycle, v6 NLRIs only.
    pub(crate) stale_nlri_v6: HashMap<IpAddr, HashSet<Nlri<Ipv6Addr>>>,
    /// Per-family GR info from the most-recent peer OPEN.
    ///
    /// Retained across termination so `on_terminated` knows which AFI/SAFIs the
    /// peer declared GR support for.  Cleared only on `remove_peer`.
    pub(crate) peer_families: HashMap<IpAddr, Vec<GracefulRestartFamily>>,
    /// Peers that advertised the RFC 8538 N-bit in their GracefulRestart capability.
    ///
    /// When a peer is in this set AND we advertise a non-zero `graceful_restart_time`
    /// (meaning we also have the N-bit set), a received NOTIFICATION other than
    /// `CEASE/HardReset` is treated as Unclean — the GR window opens rather than
    /// flushing routes immediately.
    pub(crate) notification_capable_peers: HashSet<IpAddr>,
}

impl GracefulRestartState {
    pub(crate) fn new() -> Self {
        Self {
            deadlines: HashMap::new(),
            stale_nlri: HashMap::new(),
            stale_nlri_v6: HashMap::new(),
            peer_families: HashMap::new(),
            notification_capable_peers: HashSet::new(),
        }
    }

    /// Remove all GR state for `peer_ip`.  Called from `remove_peer`.
    pub(crate) fn remove_peer(&mut self, peer_ip: IpAddr) {
        self.deadlines.remove(&peer_ip);
        self.stale_nlri.remove(&peer_ip);
        self.stale_nlri_v6.remove(&peer_ip);
        self.peer_families.remove(&peer_ip);
        self.notification_capable_peers.remove(&peer_ip);
    }

    /// Earliest deadline across all active GR windows, or `None` when empty.
    pub(crate) fn earliest_deadline(&self) -> Option<Instant> {
        self.deadlines.values().copied().min()
    }

    /// Drain all peers whose deadline has passed.  Returns their addresses.
    pub(crate) fn drain_expired(&mut self, now: Instant) -> Vec<IpAddr> {
        let mut expired = Vec::new();
        self.deadlines.retain(|ip, &mut d| {
            if d <= now {
                expired.push(*ip);
                false
            } else {
                true
            }
        });
        expired
    }
}

impl DaemonState {
    pub(super) fn mark_stale_and_repropagate(&mut self, peer_ip: IpAddr, do_v4: bool, do_v6: bool) {
        let stale_peer = PeerId::from(peer_ip);

        // v4 ─────────────────────────────────────────────────────────────────
        if do_v4 {
            let stale_v4: Vec<_> = self
                .adj_ribs_in
                .get_mut(&peer_ip)
                .map(AdjRibIn::mark_all_stale)
                .unwrap_or_default();

            if !stale_v4.is_empty() {
                let prev_prefixes: Vec<Nlri<Ipv4Addr>> =
                    self.rib.loc_rib.best_routes().map(|(n, _)| n).collect();
                let oracle = Arc::clone(&self.oracle_v4);
                let fib_changes: Vec<_> = stale_v4
                    .into_iter()
                    .map(|route| self.rib_mut().loc_rib.insert(stale_peer, route, &*oracle))
                    .collect();
                if let Some(fm) = &self.fib_manager {
                    for change in fib_changes {
                        fm.apply_v4(change);
                    }
                }
                self.repropagate_after_stale_mark_v4(peer_ip, &prev_prefixes);
                self.emit_route_events(&prev_prefixes);
            }
        }

        // v6 ─────────────────────────────────────────────────────────────────
        if do_v6 {
            let stale_v6: Vec<_> = self
                .adj_ribs_in_v6
                .get_mut(&peer_ip)
                .map(AdjRibIn::mark_all_stale)
                .unwrap_or_default();

            if !stale_v6.is_empty() {
                let oracle = Arc::clone(&self.oracle_v6);
                let fib_changes_v6: Vec<_> = stale_v6
                    .into_iter()
                    .map(|route| {
                        self.rib_mut()
                            .loc_rib_v6
                            .insert(stale_peer, route, &*oracle)
                    })
                    .collect();
                if let Some(fm) = &self.fib_manager {
                    for change in fib_changes_v6 {
                        fm.apply_v6(change);
                    }
                }
                self.repropagate_after_stale_mark_v6(peer_ip);
            }
        }
    }

    /// Propagates v4 best-path changes caused by stale marking to other peers.
    fn repropagate_after_stale_mark_v4(
        &mut self,
        peer_ip: IpAddr,
        prev_prefixes: &[Nlri<Ipv4Addr>],
    ) {
        // Use a HashSet for O(1) membership tests; the slice-based contains is O(n²).
        let prev_set: HashSet<Nlri<Ipv4Addr>> = prev_prefixes.iter().copied().collect();
        let affected: Vec<Nlri<Ipv4Addr>> = self
            .rib
            .loc_rib
            .best_routes()
            .filter_map(|(n, _)| if prev_set.contains(&n) { Some(n) } else { None })
            .chain(
                prev_prefixes
                    .iter()
                    .copied()
                    .filter(|n| self.rib.loc_rib.best(n).is_none()),
            )
            .collect();

        let other_peers: Vec<IpAddr> = self
            .rib
            .peer_types
            .keys()
            .copied()
            .filter(|&ip| ip != peer_ip)
            .collect();
        let local_as = self.rib.local_as;
        let local_bgp_id = self.rib.local_bgp_id;
        for other_ip in other_peers {
            let other_type = self
                .rib
                .peer_types
                .get(&other_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let max_len = self
                .negotiated_max_len
                .get(&other_ip)
                .copied()
                .unwrap_or(MAX_LEN);
            let Some(export_policy) = self.export_policies.get(&other_ip) else {
                continue;
            };
            let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&other_ip) else {
                continue;
            };
            let Some(update_tx) = self.update_senders.get(&other_ip) else {
                continue;
            };
            let local_next_hop = self
                .rib
                .local_addrs
                .get(&other_ip)
                .and_then(|a| match a {
                    IpAddr::V4(v4) => Some(*v4),
                    IpAddr::V6(_) => None,
                })
                .unwrap_or(local_bgp_id);
            let other_next_hop_self = self.rib.next_hop_self_peers.contains(&other_ip);
            let other_four_byte = self.four_byte_peers.contains(&other_ip);
            let decisions: Vec<PrefixDecision> = affected
                .iter()
                .map(|&nlri| {
                    propagate_prefix(
                        nlri,
                        &self.rib.loc_rib,
                        adj_rib_out,
                        export_policy,
                        other_type,
                        local_as,
                        local_next_hop,
                        other_next_hop_self,
                    )
                })
                .collect();
            if !flush_updates(
                other_ip,
                decisions,
                max_len,
                update_tx,
                other_type,
                other_four_byte,
            ) {
                self.stalled_peers.push(other_ip);
            }
            self.sync_advertised(other_ip);
        }
    }

    /// Propagates v6 best-path changes caused by stale marking to other peers.
    fn repropagate_after_stale_mark_v6(&mut self, peer_ip: IpAddr) {
        let affected: Vec<Nlri<Ipv6Addr>> =
            self.rib.loc_rib_v6.best_routes().map(|(n, _)| n).collect();

        let other_peers: Vec<IpAddr> = self
            .rib
            .peer_types
            .keys()
            .copied()
            .filter(|&ip| ip != peer_ip)
            .collect();
        let local_as = self.rib.local_as;
        let local_ipv6 = self.rib.local_ipv6;
        for other_ip in other_peers {
            if !self.ipv6_capable_peers.contains(&other_ip) {
                continue;
            }
            let other_type = self
                .rib
                .peer_types
                .get(&other_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let max_len = self
                .negotiated_max_len
                .get(&other_ip)
                .copied()
                .unwrap_or(MAX_LEN);
            let Some(export_policy_v6) = self.export_policies_v6.get(&other_ip) else {
                continue;
            };
            let Some(adj_rib_out_v6) = self.adj_ribs_out_v6.get_mut(&other_ip) else {
                continue;
            };
            let Some(update_tx) = self.update_senders.get(&other_ip) else {
                continue;
            };
            let other_next_hop_self = self.rib.next_hop_self_peers.contains(&other_ip);
            let other_four_byte = self.four_byte_peers.contains(&other_ip);
            let decisions_v6: Vec<PrefixDecisionV6> = affected
                .iter()
                .map(|&nlri| {
                    propagate_prefix_v6(
                        nlri,
                        &self.rib.loc_rib_v6,
                        adj_rib_out_v6,
                        export_policy_v6,
                        other_type,
                        local_as,
                        local_ipv6,
                        other_next_hop_self,
                    )
                })
                .collect();
            if !flush_updates_v6(
                other_ip,
                decisions_v6,
                max_len,
                update_tx,
                other_type,
                other_four_byte,
            ) {
                self.stalled_peers.push(other_ip);
            }
            self.sync_advertised(other_ip);
        }
    }

    /// Withdraw a set of NLRIs held as stale during a peer's GR window.
    ///
    /// Called either on EOR receipt (peer re-established and re-advertised its
    /// full table) or on GR deadline expiry (peer did not re-establish in time).
    /// Withdraws each NLRI from AdjRibIn and LocRib, then propagates the
    /// resulting best-path changes to all established peers.
    pub(super) fn prune_stale_nlri(&mut self, peer_ip: IpAddr, stale: &HashSet<Nlri<Ipv4Addr>>) {
        let stale_peer = PeerId::from(peer_ip);

        // Withdraw kernel null routes for any BLACKHOLE-tagged stale NLRIs before
        // removing them from AdjRibIn — they bypass LocRib and are invisible to
        // the normal FIB change path below.
        if let Some(fm) = &self.fib_manager
            && let Some(ari) = self.adj_ribs_in.get(&peer_ip)
        {
            for nlri in stale {
                if ari.get(nlri).is_some_and(|r| {
                    r.rare_or_default()
                        .communities
                        .iter()
                        .any(|c| c.is_blackhole())
                }) {
                    fm.withdraw_blackhole_v4(*nlri);
                }
            }
        }

        if let Some(ari) = self.adj_ribs_in.get_mut(&peer_ip) {
            for nlri in stale {
                ari.withdraw(nlri);
            }
        }

        let prev_prefixes: Vec<Nlri<Ipv4Addr>> =
            self.rib.loc_rib.best_routes().map(|(n, _)| n).collect();

        let oracle = Arc::clone(&self.oracle_v4);
        let fib_changes: Vec<_> = stale
            .iter()
            .map(|nlri| self.rib_mut().loc_rib.withdraw(&stale_peer, nlri, &*oracle))
            .collect();
        if let Some(fm) = &self.fib_manager {
            for change in fib_changes {
                fm.apply_v4(change);
            }
        }

        let other_peers: Vec<IpAddr> = self
            .rib
            .peer_types
            .keys()
            .copied()
            .filter(|&ip| ip != peer_ip)
            .collect();

        let local_as = self.rib.local_as;
        let local_bgp_id = self.rib.local_bgp_id;
        for other_ip in other_peers {
            let other_type = self
                .rib
                .peer_types
                .get(&other_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let max_len = self
                .negotiated_max_len
                .get(&other_ip)
                .copied()
                .unwrap_or(MAX_LEN);
            let Some(export_policy) = self.export_policies.get(&other_ip) else {
                continue;
            };
            let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&other_ip) else {
                continue;
            };
            let Some(update_tx) = self.update_senders.get(&other_ip) else {
                continue;
            };
            let local_next_hop = self
                .rib
                .local_addrs
                .get(&other_ip)
                .and_then(|a| match a {
                    IpAddr::V4(v4) => Some(*v4),
                    IpAddr::V6(_) => None,
                })
                .unwrap_or(local_bgp_id);
            let other_next_hop_self = self.rib.next_hop_self_peers.contains(&other_ip);
            let other_four_byte = self.four_byte_peers.contains(&other_ip);
            let decisions: Vec<PrefixDecision> = stale
                .iter()
                .map(|&nlri| {
                    propagate_prefix(
                        nlri,
                        &self.rib.loc_rib,
                        adj_rib_out,
                        export_policy,
                        other_type,
                        local_as,
                        local_next_hop,
                        other_next_hop_self,
                    )
                })
                .collect();
            if !flush_updates(
                other_ip,
                decisions,
                max_len,
                update_tx,
                other_type,
                other_four_byte,
            ) {
                self.stalled_peers.push(other_ip);
            }
            self.sync_advertised(other_ip);
        }
        self.emit_route_events(&prev_prefixes);
    }

    /// IPv6 counterpart of `prune_stale_nlri` — same semantics for IPv6 NLRIs.
    pub(super) fn prune_stale_nlri_v6(&mut self, peer_ip: IpAddr, stale: &HashSet<Nlri<Ipv6Addr>>) {
        let stale_peer = PeerId::from(peer_ip);

        // Same as prune_stale_nlri: check for BLACKHOLE routes before removal.
        if let Some(fm) = &self.fib_manager
            && let Some(ari) = self.adj_ribs_in_v6.get(&peer_ip)
        {
            for nlri in stale {
                if ari.get(nlri).is_some_and(|r| {
                    r.rare_or_default()
                        .communities
                        .iter()
                        .any(|c| c.is_blackhole())
                }) {
                    fm.withdraw_blackhole_v6(*nlri);
                }
            }
        }

        if let Some(ari) = self.adj_ribs_in_v6.get_mut(&peer_ip) {
            for nlri in stale {
                ari.withdraw(nlri);
            }
        }

        let oracle = Arc::clone(&self.oracle_v6);
        let fib_changes: Vec<_> = stale
            .iter()
            .map(|nlri| {
                self.rib_mut()
                    .loc_rib_v6
                    .withdraw(&stale_peer, nlri, &*oracle)
            })
            .collect();
        if let Some(fm) = &self.fib_manager {
            for change in fib_changes {
                fm.apply_v6(change);
            }
        }

        let other_peers: Vec<IpAddr> = self
            .rib
            .peer_types
            .keys()
            .copied()
            .filter(|&ip| ip != peer_ip)
            .collect();

        let local_as = self.rib.local_as;
        let local_ipv6 = self.rib.local_ipv6;
        for other_ip in other_peers {
            let other_type = self
                .rib
                .peer_types
                .get(&other_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let max_len = self
                .negotiated_max_len
                .get(&other_ip)
                .copied()
                .unwrap_or(MAX_LEN);
            if !self.ipv6_capable_peers.contains(&other_ip) {
                continue;
            }
            let Some(export_policy_v6) = self.export_policies_v6.get(&other_ip) else {
                continue;
            };
            let Some(adj_rib_out_v6) = self.adj_ribs_out_v6.get_mut(&other_ip) else {
                continue;
            };
            let Some(update_tx) = self.update_senders.get(&other_ip) else {
                continue;
            };
            let other_next_hop_self = self.rib.next_hop_self_peers.contains(&other_ip);
            let other_four_byte = self.four_byte_peers.contains(&other_ip);
            let decisions_v6: Vec<PrefixDecisionV6> = stale
                .iter()
                .map(|&nlri| {
                    propagate_prefix_v6(
                        nlri,
                        &self.rib.loc_rib_v6,
                        adj_rib_out_v6,
                        export_policy_v6,
                        other_type,
                        local_as,
                        local_ipv6,
                        other_next_hop_self,
                    )
                })
                .collect();
            if !flush_updates_v6(
                other_ip,
                decisions_v6,
                max_len,
                update_tx,
                other_type,
                other_four_byte,
            ) {
                self.stalled_peers.push(other_ip);
            }
            self.sync_advertised(other_ip);
        }
    }

    /// Flush stale routes held during GR deadline expiry.
    ///
    /// Called from the event loop when a peer's GR window expires without
    /// re-establishment.  Equivalent to a clean `on_terminated` flush for
    /// just the stale NLRIs.
    pub(crate) fn on_gr_deadline_expired(&mut self, peer_ip: IpAddr) {
        let expired_peer = PeerId::from(peer_ip);
        tracing::warn!(
            peer = %peer_ip,
            "GR restart window expired — flushing stale routes"
        );
        // Remove any stale tracking (re-establishment was not attempted).
        self.gr.stale_nlri.remove(&peer_ip);
        self.gr.stale_nlri_v6.remove(&peer_ip);
        // Remove kernel null routes for BLACKHOLE prefixes before clearing AdjRibIn.
        self.withdraw_peer_blackhole_kernel_routes(peer_ip);
        // Clear AdjRibIn and flush LocRib exactly as on_terminated does.
        if let Some(ari) = self.adj_ribs_in.get_mut(&peer_ip) {
            ari.clear();
        }
        if let Some(ari) = self.adj_ribs_in_v6.get_mut(&peer_ip) {
            ari.clear();
        }
        let prev_prefixes: Vec<Nlri<Ipv4Addr>> =
            self.rib.loc_rib.best_routes().map(|(n, _)| n).collect();
        let prev_prefixes_v6: Vec<Nlri<Ipv6Addr>> =
            self.rib.loc_rib_v6.best_routes().map(|(n, _)| n).collect();
        let fib_changes_v4 = self.rib_withdraw_peer_v4(&expired_peer);
        let fib_changes_v6 = self.rib_withdraw_peer_v6(&expired_peer);
        if let Some(fm) = &self.fib_manager {
            for change in fib_changes_v4 {
                fm.apply_v4(change);
            }
            for change in fib_changes_v6 {
                fm.apply_v6(change);
            }
        }
        // Reset AdjRibOut for a clean reconnect.
        let cfg_pt = self
            .peer_config_types
            .get(&peer_ip)
            .copied()
            .unwrap_or(PeerType::External);
        let is_rr = !self.rib.rr_clients.is_empty();
        let (new_aro, new_aro_v6) = make_adj_ribs_out_pair(expired_peer, cfg_pt, is_rr);
        if let Some(aro) = self.adj_ribs_out.get_mut(&peer_ip) {
            *aro = new_aro;
        }
        if let Some(aro) = self.adj_ribs_out_v6.get_mut(&peer_ip) {
            *aro = new_aro_v6;
        }
        // Propagate to established peers.
        let other_peers: Vec<IpAddr> = self
            .rib
            .peer_types
            .keys()
            .copied()
            .filter(|&ip| ip != peer_ip)
            .collect();
        let local_as = self.rib.local_as;
        let local_bgp_id = self.rib.local_bgp_id;
        for other_ip in other_peers {
            let other_type = self
                .rib
                .peer_types
                .get(&other_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let max_len = self
                .negotiated_max_len
                .get(&other_ip)
                .copied()
                .unwrap_or(MAX_LEN);
            let Some(export_policy) = self.export_policies.get(&other_ip) else {
                continue;
            };
            let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&other_ip) else {
                continue;
            };
            let Some(update_tx) = self.update_senders.get(&other_ip) else {
                continue;
            };
            let other_next_hop_self = self.rib.next_hop_self_peers.contains(&other_ip);
            let local_next_hop = self
                .rib
                .local_addrs
                .get(&other_ip)
                .and_then(|a| match a {
                    IpAddr::V4(v4) => Some(*v4),
                    IpAddr::V6(_) => None,
                })
                .unwrap_or(local_bgp_id);
            let other_four_byte = self.four_byte_peers.contains(&other_ip);
            let decisions: Vec<PrefixDecision> = prev_prefixes
                .iter()
                .map(|&nlri| {
                    propagate_prefix(
                        nlri,
                        &self.rib.loc_rib,
                        adj_rib_out,
                        export_policy,
                        other_type,
                        local_as,
                        local_next_hop,
                        other_next_hop_self,
                    )
                })
                .collect();
            if !flush_updates(
                other_ip,
                decisions,
                max_len,
                update_tx,
                other_type,
                other_four_byte,
            ) {
                self.stalled_peers.push(other_ip);
            }
            self.sync_advertised(other_ip);
        }

        // IPv6 counterpart of the v4 re-propagation loop above — mirrors
        // `prune_stale_nlri_v6`'s shape. Without this, other peers never
        // received a BGP WITHDRAW for IPv6 routes that were only reachable
        // via the expired peer, even though the kernel FIB and this
        // daemon's own Loc-RIB were already correct (see TODO.md item 6).
        let other_peers_v6: Vec<IpAddr> = self
            .rib
            .peer_types
            .keys()
            .copied()
            .filter(|&ip| ip != peer_ip)
            .collect();
        let local_ipv6 = self.rib.local_ipv6;
        for other_ip in other_peers_v6 {
            if !self.ipv6_capable_peers.contains(&other_ip) {
                continue;
            }
            let other_type = self
                .rib
                .peer_types
                .get(&other_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let max_len = self
                .negotiated_max_len
                .get(&other_ip)
                .copied()
                .unwrap_or(MAX_LEN);
            let Some(export_policy_v6) = self.export_policies_v6.get(&other_ip) else {
                continue;
            };
            let Some(adj_rib_out_v6) = self.adj_ribs_out_v6.get_mut(&other_ip) else {
                continue;
            };
            let Some(update_tx) = self.update_senders.get(&other_ip) else {
                continue;
            };
            let other_next_hop_self = self.rib.next_hop_self_peers.contains(&other_ip);
            let other_four_byte = self.four_byte_peers.contains(&other_ip);
            let decisions_v6: Vec<PrefixDecisionV6> = prev_prefixes_v6
                .iter()
                .map(|&nlri| {
                    propagate_prefix_v6(
                        nlri,
                        &self.rib.loc_rib_v6,
                        adj_rib_out_v6,
                        export_policy_v6,
                        other_type,
                        local_as,
                        local_ipv6,
                        other_next_hop_self,
                    )
                })
                .collect();
            if !flush_updates_v6(
                other_ip,
                decisions_v6,
                max_len,
                update_tx,
                other_type,
                other_four_byte,
            ) {
                self.stalled_peers.push(other_ip);
            }
            self.sync_advertised(other_ip);
        }

        self.emit_route_events(&prev_prefixes);
        let _ = self.peer_tx.send(proto::PeerEvent {
            r#type: proto::PeerEventType::Changed as i32,
            peer: None,
        });
    }
}
