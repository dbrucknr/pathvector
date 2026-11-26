// daemon/fib.rs — RIB/FIB operations: insert, withdraw, recompute, snapshot, FIB change handling.
#[allow(clippy::wildcard_imports)]
use super::*;
use pathvector_types::IpAddress;

/// Which port calls a batch of [`RibEffects`] translates to.
///
/// The kernel route for a prefix is either the Loc-RIB's forwarding route or an
/// RFC 7999 null route, never both:
///
/// - a best-path change for a prefix that currently holds an authorized
///   blackhole is **not** programmed — the null route owns the kernel entry
///   (it is the more specific, locally authorized intent) and the Loc-RIB's
///   candidate stays in the Loc-RIB, ready for when the blackhole goes;
/// - when the last blackhole for a prefix is withdrawn, the null route is
///   removed and, if the Loc-RIB has a best route for it, that route is
///   programmed again (a blackhole bypasses the Loc-RIB, so no best-path
///   change announces it).
///
/// Pure: only calls the closures it is given.
fn program_effects<A: IpAddress>(
    effects: RibEffects<A>,
    book: &BlackholeBook<A>,
    loc_rib: &LocRib<A>,
    apply: impl Fn(BestPathChange<A>),
    install_blackhole: impl Fn(Nlri<A>),
    withdraw_blackhole: impl Fn(Nlri<A>),
) {
    for change in effects.best {
        let nlri = match &change {
            BestPathChange::Announced(n, _) | BestPathChange::Withdrawn(n) => *n,
            BestPathChange::Unchanged => continue,
        };
        if !book.is_blackholed(&nlri) {
            apply(change);
        }
    }
    for change in effects.blackhole {
        match change {
            BlackholeChange::Install(n) => install_blackhole(n),
            BlackholeChange::Withdraw(n) => {
                withdraw_blackhole(n);
                if !book.is_blackholed(&n)
                    && let Some(route) = loc_rib.best(&n)
                {
                    apply(BestPathChange::Announced(n, route.clone()));
                }
            }
        }
    }
}

/// The prefixes whose best path a batch of Loc-RIB mutations removed or
/// replaced.
pub(super) fn changed_nlris<A: IpAddress>(changes: &[BestPathChange<A>]) -> Vec<Nlri<A>> {
    changes
        .iter()
        .filter_map(|c| match c {
            BestPathChange::Announced(n, _) | BestPathChange::Withdrawn(n) => Some(*n),
            BestPathChange::Unchanged => None,
        })
        .collect()
}

impl DaemonState {
    /// Programs one IPv4 batch of RIB effects into the FIB port, if there is one.
    pub(super) fn program_fib_v4(&self, effects: RibEffects<Ipv4Addr>) {
        if let Some(fm) = &self.fib_manager {
            program_effects(
                effects,
                &self.blackholes.v4,
                &self.rib.loc_rib,
                |c| fm.apply_v4(c),
                |n| fm.apply_blackhole_v4(n),
                |n| fm.withdraw_blackhole_v4(n),
            );
        }
    }

    /// IPv6 counterpart of [`program_fib_v4`](Self::program_fib_v4).
    pub(super) fn program_fib_v6(&self, effects: RibEffects<Ipv6Addr>) {
        if let Some(fm) = &self.fib_manager {
            program_effects(
                effects,
                &self.blackholes.v6,
                &self.rib.loc_rib_v6,
                |c| fm.apply_v6(c),
                |n| fm.apply_blackhole_v6(n),
                |n| fm.withdraw_blackhole_v6(n),
            );
        }
    }

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

        let changed_nlris_v4 = changed_nlris(&fib_changes_v4);
        let changed_nlris_v6 = changed_nlris(&fib_changes_v6);

        if !changed_nlris_v4.is_empty() || !changed_nlris_v6.is_empty() {
            tracing::debug!(
                changed_v4 = changed_nlris_v4.len(),
                changed_v6 = changed_nlris_v6.len(),
                "FIB change triggered best-path re-evaluation"
            );
        }

        // Through the blackhole-aware path: a next hop that becomes resolvable
        // must not replace a null route the book still holds for the prefix.
        self.program_fib_v4(RibEffects::from_best(fib_changes_v4));
        self.program_fib_v6(RibEffects::from_best(fib_changes_v6));

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
