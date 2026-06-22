// daemon/fib.rs — RIB/FIB operations: insert, withdraw, recompute, snapshot, FIB change handling.
#[allow(clippy::wildcard_imports)]
use super::*;

impl DaemonState {
    pub(crate) fn rib_insert_v4(
        &mut self,
        peer: PeerId,
        route: Route<Ipv4Addr>,
    ) -> BestPathChange<Ipv4Addr> {
        let oracle = Arc::clone(&self.oracle_v4);
        self.rib_mut().loc_rib.insert(peer, route, &*oracle)
    }

    pub(crate) fn rib_withdraw_v4(
        &mut self,
        peer: &PeerId,
        nlri: &Nlri<Ipv4Addr>,
    ) -> BestPathChange<Ipv4Addr> {
        let oracle = Arc::clone(&self.oracle_v4);
        self.rib_mut().loc_rib.withdraw(peer, nlri, &*oracle)
    }

    pub(crate) fn rib_withdraw_peer_v4(&mut self, peer: &PeerId) -> Vec<BestPathChange<Ipv4Addr>> {
        let oracle = Arc::clone(&self.oracle_v4);
        self.rib_mut().loc_rib.withdraw_peer(peer, &*oracle)
    }

    pub(crate) fn rib_insert_v6(
        &mut self,
        peer: PeerId,
        route: Route<Ipv6Addr>,
    ) -> BestPathChange<Ipv6Addr> {
        let oracle = Arc::clone(&self.oracle_v6);
        self.rib_mut().loc_rib_v6.insert(peer, route, &*oracle)
    }

    pub(crate) fn rib_withdraw_v6(
        &mut self,
        peer: &PeerId,
        nlri: &Nlri<Ipv6Addr>,
    ) -> BestPathChange<Ipv6Addr> {
        let oracle = Arc::clone(&self.oracle_v6);
        self.rib_mut().loc_rib_v6.withdraw(peer, nlri, &*oracle)
    }

    pub(crate) fn rib_withdraw_peer_v6(&mut self, peer: &PeerId) -> Vec<BestPathChange<Ipv6Addr>> {
        let oracle = Arc::clone(&self.oracle_v6);
        self.rib_mut().loc_rib_v6.withdraw_peer(peer, &*oracle)
    }

    /// Re-evaluates best-path for every IPv4 prefix in the Loc-RIB using the
    /// current oracle.  Returns only the prefixes whose best path changed.
    ///
    /// Called when the kernel FIB changes (next-hop gained / lost) so that
    /// routes whose next-hop became unreachable are withdrawn and routes that
    /// recovered are re-announced.
    pub(crate) fn rib_recompute_all_v4(&mut self) -> Vec<BestPathChange<Ipv4Addr>> {
        let oracle = Arc::clone(&self.oracle_v4);
        self.rib_mut().loc_rib.recompute_all(&*oracle)
    }

    /// Re-evaluates best-path for every IPv6 prefix in the Loc-RIB.
    pub(crate) fn rib_recompute_all_v6(&mut self) -> Vec<BestPathChange<Ipv6Addr>> {
        let oracle = Arc::clone(&self.oracle_v6);
        self.rib_mut().loc_rib_v6.recompute_all(&*oracle)
    }

    /// Returns a cheap clone of the snapshot Arc for lock-free gRPC reads.
    ///
    /// gRPC handlers call this while holding the outer `RwLock` read guard,
    /// then immediately release the lock. All subsequent work runs against
    /// the cloned Arc without holding any lock.
    pub(crate) fn snapshot(&self) -> Arc<RibSnapshot> {
        Arc::clone(&self.rib)
    }

    /// Returns a mutable reference to the snapshot.
    ///
    /// Uses copy-on-write semantics: free when no readers hold a clone (the
    /// common case during BGP convergence); allocates a fresh `RibSnapshot`
    /// only when a concurrent gRPC read is in flight.
    pub(crate) fn rib_mut(&mut self) -> &mut RibSnapshot {
        Arc::make_mut(&mut self.rib)
    }

    /// Syncs the derived `prefixes_received` count for `peer_ip` from the
    /// current `adj_ribs_in` length.
    pub(crate) fn on_fib_change(&mut self) {
        let fib_changes_v4 = self.rib_recompute_all_v4();
        let fib_changes_v6 = self.rib_recompute_all_v6();

        let changed_nlris_v4: Vec<Nlri<Ipv4Addr>> = fib_changes_v4
            .iter()
            .filter_map(|c| match c {
                BestPathChange::Announced(n, _) | BestPathChange::Withdrawn(n) => Some(*n),
                BestPathChange::Unchanged => None,
            })
            .collect();

        let changed_nlris_v6: Vec<Nlri<Ipv6Addr>> = fib_changes_v6
            .iter()
            .filter_map(|c| match c {
                BestPathChange::Announced(n, _) | BestPathChange::Withdrawn(n) => Some(*n),
                BestPathChange::Unchanged => None,
            })
            .collect();

        if !changed_nlris_v4.is_empty() || !changed_nlris_v6.is_empty() {
            tracing::debug!(
                changed_v4 = changed_nlris_v4.len(),
                changed_v6 = changed_nlris_v6.len(),
                "FIB change triggered best-path re-evaluation"
            );
        }

        if let Some(fm) = &self.fib_manager {
            for change in fib_changes_v4 {
                fm.apply_v4(change);
            }
            for change in fib_changes_v6 {
                fm.apply_v6(change);
            }
        }

        if !changed_nlris_v4.is_empty() {
            self.propagate_to_all_peers(&changed_nlris_v4);
            self.emit_route_events(&changed_nlris_v4);
        }
        if !changed_nlris_v6.is_empty() {
            self.propagate_to_all_peers_v6(&changed_nlris_v6);
        }
    }
}

pub(crate) async fn withdraw_stale_bgp_routes<W: pathvector_sys::FibWrite>(
    stale_v4: Vec<(std::net::Ipv4Addr, u8)>,
    stale_v6: Vec<(std::net::Ipv6Addr, u8)>,
    writer: &W,
) {
    for (dst, prefix_len) in stale_v4 {
        if let Err(e) = writer.withdraw_v4(dst, prefix_len).await {
            tracing::warn!(%dst, prefix_len, "stale BGP route removal failed: {e}");
        }
    }
    for (dst, prefix_len) in stale_v6 {
        if let Err(e) = writer.withdraw_v6(dst, prefix_len).await {
            tracing::warn!(%dst, prefix_len, "stale BGP v6 route removal failed: {e}");
        }
    }
}

