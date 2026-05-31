use std::collections::HashMap;

use ipnetx::interfaces::IpAddress;
use pathvector_types::Nlri;
use routemap::RouteMap;

use crate::{best_path::select_best, peer::PeerId, route::Route};

/// The local routing table — best-path selected, post-import-policy.
///
/// `LocRib` holds two parallel data structures per prefix:
///
/// - **Candidates** — every route for that prefix that passed import policy,
///   keyed by the peer that announced it. A prefix may have one candidate per
///   peer.
/// - **Best** — the single winning route chosen by [`select_best`], recomputed
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
///     .build());
/// rib.insert(peer_b, RouteBuilder::new(nlri, Origin::Igp, AsPath::new())
///     .local_pref(LocalPref::new(100))
///     .build());
///
/// // peer_a wins — higher LOCAL_PREF
/// assert_eq!(rib.best_peer(&nlri), Some(peer_a));
/// assert_eq!(rib.best(&nlri).unwrap().local_pref, Some(LocalPref::new(200)));
/// ```
pub struct LocRib<A: IpAddress> {
    candidates: HashMap<Nlri<A>, HashMap<PeerId, Route<A>>>,
    best: RouteMap<A, (PeerId, Route<A>)>,
}

impl<A: IpAddress> LocRib<A> {
    /// Creates an empty `LocRib`.
    #[must_use]
    pub fn new() -> Self {
        Self { candidates: HashMap::new(), best: RouteMap::new() }
    }

    /// Inserts a route from `peer` into the candidate set and recomputes the
    /// best route for that prefix.
    ///
    /// If this peer previously had a route for this prefix, it is replaced.
    /// Best-path selection runs after every insert, so `best()` always
    /// reflects the current winner.
    pub fn insert(&mut self, peer: PeerId, route: Route<A>) {
        let nlri = route.nlri;
        self.candidates
            .entry(nlri)
            .or_default()
            .insert(peer, route);
        self.recompute_best(nlri);
    }

    /// Removes a specific prefix from a peer's contribution and recomputes
    /// best-path selection for that prefix.
    ///
    /// Called when a peer withdraws a specific route. If no candidates remain
    /// for the prefix, the prefix is removed from the `LocRib` entirely.
    pub fn withdraw(&mut self, peer: &PeerId, nlri: &Nlri<A>) {
        if let Some(peer_map) = self.candidates.get_mut(nlri) {
            peer_map.remove(peer);
            if peer_map.is_empty() {
                self.candidates.remove(nlri);
                self.best.remove(nlri.prefix());
            } else {
                self.recompute_best(*nlri);
            }
        }
    }

    /// Removes all routes contributed by `peer` and recomputes best-path
    /// for every affected prefix.
    ///
    /// Called when a BGP session goes down. Any prefix for which this was the
    /// only candidate is removed from the `LocRib`.
    pub fn withdraw_peer(&mut self, peer: &PeerId) {
        let affected: Vec<Nlri<A>> = self
            .candidates
            .iter()
            .filter(|(_, pm)| pm.contains_key(peer))
            .map(|(n, _)| *n)
            .collect();

        for nlri in affected {
            self.withdraw(peer, &nlri);
        }
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
        self.best.iter().map(|(prefix, pair)| (Nlri::from_prefix(prefix), &pair.1))
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

    fn recompute_best(&mut self, nlri: Nlri<A>) {
        if let Some(peer_map) = self.candidates.get(&nlri) {
            if let Some((peer, route)) = select_best(peer_map) {
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
    use std::net::{IpAddr, Ipv4Addr};
    use pathvector_types::{AsPath, LocalPref, Origin};
    use crate::RouteBuilder;

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
        rib.insert(peer(1), route("10.0.0.0/8"));
        assert_eq!(rib.len(), 1);
        assert!(rib.best(&n).is_some());
        assert_eq!(rib.best_peer(&n), Some(peer(1)));
    }

    #[test]
    fn test_loc_rib_best_path_selects_higher_local_pref() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");
        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 100));
        rib.insert(peer(2), route_with_lp("10.0.0.0/8", 200));
        assert_eq!(rib.best_peer(&n), Some(peer(2))); // higher LOCAL_PREF
    }

    #[test]
    fn test_loc_rib_best_updated_on_insert() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 100));
        assert_eq!(rib.best_peer(&n), Some(peer(1)));

        // New peer with better LOCAL_PREF takes over
        rib.insert(peer(2), route_with_lp("10.0.0.0/8", 200));
        assert_eq!(rib.best_peer(&n), Some(peer(2)));
    }

    #[test]
    fn test_loc_rib_withdraw_route() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 200));
        rib.insert(peer(2), route_with_lp("10.0.0.0/8", 100));

        // Remove the winning peer — peer(2) should take over
        rib.withdraw(&peer(1), &n);
        assert_eq!(rib.best_peer(&n), Some(peer(2)));
        assert_eq!(rib.len(), 1);
    }

    #[test]
    fn test_loc_rib_withdraw_last_candidate_removes_prefix() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(peer(1), route("10.0.0.0/8"));
        rib.withdraw(&peer(1), &n);

        assert!(rib.is_empty());
        assert!(rib.best(&n).is_none());
    }

    #[test]
    fn test_loc_rib_withdraw_peer_removes_all_prefixes() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();

        rib.insert(peer(1), route("10.0.0.0/8"));
        rib.insert(peer(1), route("192.168.0.0/16"));
        rib.insert(peer(2), route("172.16.0.0/12")); // different peer

        rib.withdraw_peer(&peer(1));

        assert_eq!(rib.len(), 1); // only peer(2)'s prefix remains
        assert!(rib.best(&nlri("172.16.0.0/12")).is_some());
        assert!(rib.best(&nlri("10.0.0.0/8")).is_none());
    }

    #[test]
    fn test_loc_rib_withdraw_peer_promotes_remaining_candidate() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 200)); // winning
        rib.insert(peer(2), route_with_lp("10.0.0.0/8", 100)); // losing

        rib.withdraw_peer(&peer(1));

        // peer(2)'s route should now be best
        assert_eq!(rib.best_peer(&n), Some(peer(2)));
    }

    #[test]
    fn test_loc_rib_multiple_prefixes() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.insert(peer(1), route("10.0.0.0/8"));
        rib.insert(peer(1), route("192.168.0.0/16"));
        rib.insert(peer(2), route("172.16.0.0/12"));
        assert_eq!(rib.len(), 3);
    }

    #[test]
    fn test_loc_rib_candidates() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");
        rib.insert(peer(1), route("10.0.0.0/8"));
        rib.insert(peer(2), route("10.0.0.0/8"));
        let candidates = rib.candidates(&n).unwrap();
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn test_loc_rib_best_routes_iterator() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.insert(peer(1), route("10.0.0.0/8"));
        rib.insert(peer(1), route("192.168.0.0/16"));
        assert_eq!(rib.best_routes().count(), 2);
    }

    #[test]
    fn test_loc_rib_withdraw_nonexistent_prefix_is_noop() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.withdraw(&peer(1), &nlri("10.0.0.0/8"));
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

        rib.insert(peer(1), route("10.0.0.0/8"));
        assert!(rib.best(&n).is_some());

        rib.candidates.insert(n, std::collections::HashMap::new());
        rib.recompute_best(n);

        assert!(rib.best(&n).is_none());
    }

    #[test]
    fn test_recompute_best_noop_for_unknown_prefix() {
        // Calls recompute_best directly with a prefix that is not in candidates.
        // Covers the implicit else-fallthrough of `if let Some(peer_map)`.
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.recompute_best(nlri("10.0.0.0/8"));
        assert!(rib.is_empty());
    }

    #[test]
    fn test_loc_rib_longest_match() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.insert(peer(1), route("10.0.0.0/8"));
        rib.insert(peer(2), route("10.20.0.0/16"));

        // /16 is more specific than /8
        assert!(rib.longest_match(Ipv4Addr::new(10, 20, 5, 1)).is_some());
        // falls back to /8
        assert!(rib.longest_match(Ipv4Addr::new(10, 99, 0, 1)).is_some());
        // no match
        assert!(rib.longest_match(Ipv4Addr::new(192, 168, 1, 1)).is_none());
    }

    #[test]
    fn test_loc_rib_same_peer_update_replaces_candidate() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 100));
        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 200)); // same peer, better route

        let candidates = rib.candidates(&n).unwrap();
        assert_eq!(candidates.len(), 1); // still only one candidate for peer(1)
        assert_eq!(rib.best(&n).unwrap().local_pref, Some(LocalPref::new(200)));
    }
}
