use std::collections::HashMap;

use ipnetx::interfaces::IpAddress;
use pathvector_types::Nlri;
use routemap::RouteMap;

use crate::{
    best_path::select_best_with_oracle, oracle::NextHopOracle, peer::PeerId, route::Route,
};

/// Describes how the best path for a prefix changed after a `LocRib` mutation.
///
/// Returned by [`LocRib::insert`], [`LocRib::withdraw`], and
/// [`LocRib::withdraw_peer`] so callers can react without re-querying the RIB.
///
/// The common consumer is a `FibManager` that installs or removes kernel
/// routes on best-path changes, and the outbound advertisement pipeline that
/// sends UPDATE messages to peers.
// `Announced` carries a full `Route<A>` so the FibManager can act on it
// immediately without a second RIB lookup. `Route<A>` is large (~207 bytes),
// but these values are consumed immediately at each call site — they are never
// stored in a long-lived collection — so boxing would add allocation in the
// common (Announced) case for no benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum BestPathChange<A: IpAddress> {
    /// A new or replacement best path was selected for this prefix.
    ///
    /// The caller should install/update the route in the FIB and advertise
    /// it to eligible peers.
    Announced(Nlri<A>, Route<A>),
    /// The best path was removed and no candidates remain for this prefix.
    ///
    /// The caller should withdraw the route from the FIB and send a BGP
    /// WITHDRAW to all peers that were receiving it.
    Withdrawn(Nlri<A>),
    /// The best path is unchanged — the insert or withdraw touched a
    /// non-winning candidate.
    ///
    /// No FIB update or BGP advertisement is required.
    Unchanged,
}

/// The local routing table — best-path selected, post-import-policy.
///
/// `LocRib` holds two parallel data structures per prefix:
///
/// - **Candidates** — every route for that prefix that passed import policy,
///   keyed by the peer that announced it. A prefix may have one candidate per
///   peer.
/// - **Best** — the single winning route chosen by `select_best_with_oracle`, recomputed
///   every time the candidate set changes.
///
/// # Policy is applied externally
///
/// `LocRib` does not apply import or export policy. The caller runs import
/// policy on routes from `AdjRibIn` and inserts only the accepted ones here.
/// Export policy is applied by the caller after reading best routes for
/// `AdjRibOut`. This separation keeps the RIB as a pure data structure and
/// allows policy to be changed and re-applied at runtime.
///
/// # Examples
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr};
/// use pathvector_rib::{LocRib, PeerId, RouteBuilder};
/// use pathvector_rib::oracle::AlwaysReachable;
/// use pathvector_types::{AsPath, LocalPref, Nlri, Origin};
///
/// let peer_a = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
/// let peer_b = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
/// let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
///
/// let mut rib = LocRib::new();
///
/// rib.insert(peer_a, RouteBuilder::new(nlri, Origin::Igp, AsPath::new())
///     .local_pref(LocalPref::new(200))
///     .build(), &AlwaysReachable);
/// rib.insert(peer_b, RouteBuilder::new(nlri, Origin::Igp, AsPath::new())
///     .local_pref(LocalPref::new(100))
///     .build(), &AlwaysReachable);
///
/// // peer_a wins — higher LOCAL_PREF
/// assert_eq!(rib.best_peer(&nlri), Some(peer_a));
/// assert_eq!(rib.best(&nlri).unwrap().local_pref, Some(LocalPref::new(200)));
/// ```
/// Read-only view into the Loc-RIB needed by the outbound advertisement path.
///
/// Abstracting over this boundary lets the Update-Send Process (`propagate_prefix`)
/// be tested without constructing a full [`LocRib`] with real route data.
pub trait RibView<A: IpAddress> {
    /// Returns the current best route for `nlri`, or `None` if no route exists.
    fn best(&self, nlri: &Nlri<A>) -> Option<&Route<A>>;

    /// Returns the peer whose route is currently best for `nlri`.
    ///
    /// Implementations that cannot track the source peer (e.g. test stubs)
    /// return `None`, which disables the source-peer split-horizon check in
    /// the outbound pipeline.
    fn best_peer(&self, nlri: &Nlri<A>) -> Option<PeerId> {
        let _ = nlri;
        None
    }
}

impl<A: IpAddress> RibView<A> for LocRib<A> {
    fn best(&self, nlri: &Nlri<A>) -> Option<&Route<A>> {
        self.best.get(nlri.prefix()).map(|pair| &pair.1)
    }

    fn best_peer(&self, nlri: &Nlri<A>) -> Option<PeerId> {
        LocRib::best_peer(self, nlri)
    }
}

#[derive(Clone)]
pub struct LocRib<A: IpAddress> {
    candidates: HashMap<Nlri<A>, HashMap<PeerId, Route<A>>>,
    best: RouteMap<A, (PeerId, Route<A>)>,
}

impl<A: IpAddress> LocRib<A> {
    /// Creates an empty `LocRib`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            candidates: HashMap::new(),
            best: RouteMap::new(),
        }
    }

    /// Inserts a route from `peer` into the candidate set and recomputes the
    /// best route for that prefix.
    ///
    /// If this peer previously had a route for this prefix, it is replaced.
    /// Best-path selection runs after every insert, so `best()` always
    /// reflects the current winner.
    ///
    /// Returns a [`BestPathChange`] describing whether and how the best path
    /// changed as a result of this insert.
    pub fn insert(
        &mut self,
        peer: PeerId,
        route: Route<A>,
        oracle: &dyn NextHopOracle,
    ) -> BestPathChange<A> {
        let nlri = route.nlri;
        let old = self.best.get(nlri.prefix()).map(|(p, r)| (*p, r.clone()));
        self.candidates.entry(nlri).or_default().insert(peer, route);
        self.recompute_best(nlri, oracle);
        match self.best.get(nlri.prefix()) {
            None => BestPathChange::Unchanged,
            Some((new_peer, new_route)) => match old {
                Some((old_peer, ref old_route))
                    if old_peer == *new_peer && old_route == new_route =>
                {
                    BestPathChange::Unchanged
                }
                _ => BestPathChange::Announced(nlri, new_route.clone()),
            },
        }
    }

    /// Removes a specific prefix from a peer's contribution and recomputes
    /// best-path selection for that prefix.
    ///
    /// Called when a peer withdraws a specific route. If no candidates remain
    /// for the prefix, the prefix is removed from the `LocRib` entirely.
    ///
    /// Returns a [`BestPathChange`] describing whether and how the best path
    /// changed as a result of this withdrawal.
    pub fn withdraw(
        &mut self,
        peer: &PeerId,
        nlri: &Nlri<A>,
        oracle: &dyn NextHopOracle,
    ) -> BestPathChange<A> {
        let old = self.best.get(nlri.prefix()).map(|(p, r)| (*p, r.clone()));
        if let Some(peer_map) = self.candidates.get_mut(nlri) {
            peer_map.remove(peer);
            if peer_map.is_empty() {
                self.candidates.remove(nlri);
                self.best.remove(nlri.prefix());
                if old.is_some() {
                    return BestPathChange::Withdrawn(*nlri);
                }
            } else {
                self.recompute_best(*nlri, oracle);
                return match self.best.get(nlri.prefix()) {
                    None => BestPathChange::Withdrawn(*nlri),
                    Some((new_peer, new_route)) => match old {
                        Some((old_peer, ref old_route))
                            if old_peer == *new_peer && old_route == new_route =>
                        {
                            BestPathChange::Unchanged
                        }
                        _ => BestPathChange::Announced(*nlri, new_route.clone()),
                    },
                };
            }
        }
        BestPathChange::Unchanged
    }

    /// Removes all routes contributed by `peer` and recomputes best-path
    /// for every affected prefix.
    ///
    /// Called when a BGP session goes down. Any prefix for which this was the
    /// only candidate is removed from the `LocRib`.
    ///
    /// Returns one [`BestPathChange`] per prefix that had a candidate from
    /// this peer. Prefixes unaffected by this peer are omitted.
    pub fn withdraw_peer(
        &mut self,
        peer: &PeerId,
        oracle: &dyn NextHopOracle,
    ) -> Vec<BestPathChange<A>> {
        let affected: Vec<Nlri<A>> = self
            .candidates
            .iter()
            .filter(|(_, pm)| pm.contains_key(peer))
            .map(|(n, _)| *n)
            .collect();

        affected
            .into_iter()
            .map(|nlri| self.withdraw(peer, &nlri, oracle))
            .collect()
    }

    /// Returns the current best route for `nlri`, if any.
    ///
    /// This is the route that passed import policy and won best-path selection
    /// from among all peers that announced this prefix.
    #[must_use]
    pub fn best(&self, nlri: &Nlri<A>) -> Option<&Route<A>> {
        self.best.get(nlri.prefix()).map(|pair| &pair.1)
    }

    /// Returns the peer whose route is currently best for `nlri`.
    #[must_use]
    pub fn best_peer(&self, nlri: &Nlri<A>) -> Option<PeerId> {
        self.best.get(nlri.prefix()).map(|pair| pair.0)
    }

    /// Iterates over all `(prefix, best_route)` pairs.
    ///
    /// Useful for building `AdjRibOut` — iterate this, apply export policy,
    /// and insert accepted routes into the peer's outbound table.
    pub fn best_routes(&self) -> impl Iterator<Item = (Nlri<A>, &Route<A>)> {
        self.best
            .iter()
            .map(|(prefix, pair)| (Nlri::from_prefix(prefix), &pair.1))
    }

    /// Returns the best route whose prefix most specifically covers `addr`.
    ///
    /// This is the forwarding lookup — the same route the data plane would use
    /// to forward a packet destined for `addr`.
    #[must_use]
    pub fn longest_match(&self, addr: A) -> Option<&Route<A>> {
        self.best.longest_match(addr).map(|pair| &pair.1)
    }

    /// Returns all candidate routes for `nlri`, keyed by peer.
    ///
    /// Useful for diagnostics and "show bgp detail" output.
    #[must_use]
    pub fn candidates(&self, nlri: &Nlri<A>) -> Option<&HashMap<PeerId, Route<A>>> {
        self.candidates.get(nlri)
    }

    /// Returns the number of unique prefixes with at least one candidate.
    #[must_use]
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Returns `true` if the `LocRib` contains no routes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    fn recompute_best(&mut self, nlri: Nlri<A>, oracle: &dyn NextHopOracle) {
        if let Some(peer_map) = self.candidates.get(&nlri) {
            if let Some((peer, route)) = select_best_with_oracle(peer_map, oracle) {
                self.best.insert(nlri.prefix(), (peer, route.clone()));
            } else {
                self.best.remove(nlri.prefix());
            }
        }
    }
}

impl<A: IpAddress> Default for LocRib<A> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RouteBuilder, oracle::AlwaysReachable};
    use pathvector_types::{AsPath, LocalPref, Origin};
    use std::net::{IpAddr, Ipv4Addr};

    fn peer(n: u8) -> PeerId {
        PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
    }

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn route_with_lp(prefix: &str, lp: u32) -> Route<Ipv4Addr> {
        RouteBuilder::new(nlri(prefix), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(lp))
            .build()
    }

    fn route(prefix: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(nlri(prefix), Origin::Igp, AsPath::new()).build()
    }

    #[test]
    fn test_loc_rib_new_is_empty() {
        let rib: LocRib<Ipv4Addr> = LocRib::new();
        assert!(rib.is_empty());
        assert_eq!(rib.len(), 0);
    }

    #[test]
    fn test_loc_rib_insert_single() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");
        rib.insert(peer(1), route("10.0.0.0/8"), &AlwaysReachable);
        assert_eq!(rib.len(), 1);
        assert!(rib.best(&n).is_some());
        assert_eq!(rib.best_peer(&n), Some(peer(1)));
    }

    #[test]
    fn test_loc_rib_best_path_selects_higher_local_pref() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");
        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 100), &AlwaysReachable);
        rib.insert(peer(2), route_with_lp("10.0.0.0/8", 200), &AlwaysReachable);
        assert_eq!(rib.best_peer(&n), Some(peer(2))); // higher LOCAL_PREF
    }

    #[test]
    fn test_loc_rib_best_updated_on_insert() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 100), &AlwaysReachable);
        assert_eq!(rib.best_peer(&n), Some(peer(1)));

        // New peer with better LOCAL_PREF takes over
        rib.insert(peer(2), route_with_lp("10.0.0.0/8", 200), &AlwaysReachable);
        assert_eq!(rib.best_peer(&n), Some(peer(2)));
    }

    #[test]
    fn test_loc_rib_withdraw_route() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 200), &AlwaysReachable);
        rib.insert(peer(2), route_with_lp("10.0.0.0/8", 100), &AlwaysReachable);

        // Remove the winning peer — peer(2) should take over
        rib.withdraw(&peer(1), &n, &AlwaysReachable);
        assert_eq!(rib.best_peer(&n), Some(peer(2)));
        assert_eq!(rib.len(), 1);
    }

    #[test]
    fn test_loc_rib_withdraw_last_candidate_removes_prefix() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(peer(1), route("10.0.0.0/8"), &AlwaysReachable);
        rib.withdraw(&peer(1), &n, &AlwaysReachable);

        assert!(rib.is_empty());
        assert!(rib.best(&n).is_none());
    }

    #[test]
    fn test_loc_rib_withdraw_peer_removes_all_prefixes() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();

        rib.insert(peer(1), route("10.0.0.0/8"), &AlwaysReachable);
        rib.insert(peer(1), route("192.168.0.0/16"), &AlwaysReachable);
        rib.insert(peer(2), route("172.16.0.0/12"), &AlwaysReachable); // different peer

        rib.withdraw_peer(&peer(1), &AlwaysReachable);

        assert_eq!(rib.len(), 1); // only peer(2)'s prefix remains
        assert!(rib.best(&nlri("172.16.0.0/12")).is_some());
        assert!(rib.best(&nlri("10.0.0.0/8")).is_none());
    }

    #[test]
    fn test_loc_rib_withdraw_peer_promotes_remaining_candidate() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 200), &AlwaysReachable); // winning
        rib.insert(peer(2), route_with_lp("10.0.0.0/8", 100), &AlwaysReachable); // losing

        rib.withdraw_peer(&peer(1), &AlwaysReachable);

        // peer(2)'s route should now be best
        assert_eq!(rib.best_peer(&n), Some(peer(2)));
    }

    #[test]
    fn test_loc_rib_multiple_prefixes() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.insert(peer(1), route("10.0.0.0/8"), &AlwaysReachable);
        rib.insert(peer(1), route("192.168.0.0/16"), &AlwaysReachable);
        rib.insert(peer(2), route("172.16.0.0/12"), &AlwaysReachable);
        assert_eq!(rib.len(), 3);
    }

    #[test]
    fn test_loc_rib_candidates() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");
        rib.insert(peer(1), route("10.0.0.0/8"), &AlwaysReachable);
        rib.insert(peer(2), route("10.0.0.0/8"), &AlwaysReachable);
        let candidates = rib.candidates(&n).unwrap();
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn test_loc_rib_best_routes_iterator() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.insert(peer(1), route("10.0.0.0/8"), &AlwaysReachable);
        rib.insert(peer(1), route("192.168.0.0/16"), &AlwaysReachable);
        assert_eq!(rib.best_routes().count(), 2);
    }

    #[test]
    fn test_loc_rib_withdraw_nonexistent_prefix_is_noop() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.withdraw(&peer(1), &nlri("10.0.0.0/8"), &AlwaysReachable);
        assert!(rib.is_empty());
    }

    #[test]
    fn test_loc_rib_default() {
        let rib: LocRib<Ipv4Addr> = LocRib::default();
        assert!(rib.is_empty());
        assert_eq!(rib.len(), 0);
    }

    #[test]
    fn test_recompute_best_clears_best_when_candidates_empty() {
        // Covers the defensive else-branch in recompute_best where select_best
        // returns None. Unreachable through the public API, so we reach it by
        // injecting an empty peer map directly into the private candidates field.
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(peer(1), route("10.0.0.0/8"), &AlwaysReachable);
        assert!(rib.best(&n).is_some());

        rib.candidates.insert(n, std::collections::HashMap::new());
        rib.recompute_best(n, &AlwaysReachable);

        assert!(rib.best(&n).is_none());
    }

    #[test]
    fn test_recompute_best_noop_for_unknown_prefix() {
        // Calls recompute_best directly with a prefix that is not in candidates.
        // Covers the implicit else-fallthrough of `if let Some(peer_map)`.
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.recompute_best(nlri("10.0.0.0/8"), &AlwaysReachable);
        assert!(rib.is_empty());
    }

    #[test]
    fn test_loc_rib_longest_match() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.insert(peer(1), route("10.0.0.0/8"), &AlwaysReachable);
        rib.insert(peer(2), route("10.20.0.0/16"), &AlwaysReachable);

        // /16 is more specific than /8
        assert!(rib.longest_match(Ipv4Addr::new(10, 20, 5, 1)).is_some());
        // falls back to /8
        assert!(rib.longest_match(Ipv4Addr::new(10, 99, 0, 1)).is_some());
        // no match
        assert!(rib.longest_match(Ipv4Addr::new(192, 168, 1, 1)).is_none());
    }

    #[test]
    fn test_rib_view_best_via_trait_object() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");
        rib.insert(peer(1), route("10.0.0.0/8"), &AlwaysReachable);

        let view: &dyn RibView<Ipv4Addr> = &rib;
        assert!(view.best(&n).is_some());
        assert!(view.best(&nlri("192.168.0.0/16")).is_none());
    }

    #[test]
    fn test_loc_rib_same_peer_update_replaces_candidate() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 100), &AlwaysReachable);
        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 200), &AlwaysReachable); // same peer, better route

        let candidates = rib.candidates(&n).unwrap();
        assert_eq!(candidates.len(), 1); // still only one candidate for peer(1)
        assert_eq!(rib.best(&n).unwrap().local_pref, Some(LocalPref::new(200)));
    }

    // BestPathChange tests — verify the return-value contract that FibManager
    // depends on for deciding when to install/remove kernel routes.

    #[test]
    fn test_insert_first_route_is_announced() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");
        let change = rib.insert(peer(1), route("10.0.0.0/8"), &AlwaysReachable);
        assert!(matches!(change, BestPathChange::Announced(nlri, _) if nlri == n));
    }

    #[test]
    fn test_insert_inferior_route_is_unchanged() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 200), &AlwaysReachable);
        // peer(2) loses best-path — best stays with peer(1)
        let change = rib.insert(peer(2), route_with_lp("10.0.0.0/8", 100), &AlwaysReachable);
        assert_eq!(change, BestPathChange::Unchanged);
    }

    #[test]
    fn test_insert_superior_route_is_announced() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 100), &AlwaysReachable);
        let n = nlri("10.0.0.0/8");
        // peer(2) wins with higher LOCAL_PREF
        let change = rib.insert(peer(2), route_with_lp("10.0.0.0/8", 200), &AlwaysReachable);
        assert!(matches!(change, BestPathChange::Announced(nlri, _) if nlri == n));
    }

    #[test]
    fn test_withdraw_sole_candidate_is_withdrawn() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");
        rib.insert(peer(1), route("10.0.0.0/8"), &AlwaysReachable);
        let change = rib.withdraw(&peer(1), &n, &AlwaysReachable);
        assert_eq!(change, BestPathChange::Withdrawn(n));
    }

    #[test]
    fn test_withdraw_losing_candidate_is_unchanged() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");
        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 200), &AlwaysReachable);
        rib.insert(peer(2), route_with_lp("10.0.0.0/8", 100), &AlwaysReachable);
        // withdrawing the loser changes nothing
        let change = rib.withdraw(&peer(2), &n, &AlwaysReachable);
        assert_eq!(change, BestPathChange::Unchanged);
    }

    #[test]
    fn test_withdraw_winning_candidate_announces_new_best() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");
        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 200), &AlwaysReachable);
        rib.insert(peer(2), route_with_lp("10.0.0.0/8", 100), &AlwaysReachable);
        // withdrawing the winner promotes peer(2) → Announced
        let change = rib.withdraw(&peer(1), &n, &AlwaysReachable);
        assert!(matches!(change, BestPathChange::Announced(nlri, _) if nlri == n));
    }

    #[test]
    fn test_withdraw_nonexistent_peer_is_unchanged() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");
        rib.insert(peer(1), route("10.0.0.0/8"), &AlwaysReachable);
        let change = rib.withdraw(&peer(99), &n, &AlwaysReachable);
        assert_eq!(change, BestPathChange::Unchanged);
    }

    #[test]
    fn test_withdraw_nonexistent_prefix_is_unchanged() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let change = rib.withdraw(&peer(1), &nlri("10.0.0.0/8"), &AlwaysReachable);
        assert_eq!(change, BestPathChange::Unchanged);
    }

    #[test]
    fn test_withdraw_peer_returns_withdrawn_for_sole_owner() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.insert(peer(1), route("10.0.0.0/8"), &AlwaysReachable);
        rib.insert(peer(1), route("192.168.0.0/16"), &AlwaysReachable);
        let changes = rib.withdraw_peer(&peer(1), &AlwaysReachable);
        assert_eq!(changes.len(), 2);
        assert!(
            changes
                .iter()
                .all(|c| matches!(c, BestPathChange::Withdrawn(_)))
        );
    }

    #[test]
    fn test_withdraw_peer_returns_announced_for_promoted_candidate() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 200), &AlwaysReachable);
        rib.insert(peer(2), route_with_lp("10.0.0.0/8", 100), &AlwaysReachable);
        // removing peer(1) promotes peer(2)
        let changes = rib.withdraw_peer(&peer(1), &AlwaysReachable);
        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0], BestPathChange::Announced(_, _)));
    }
}
