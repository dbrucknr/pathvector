use ahash::AHashMap;
use ipnetx::interfaces::IpAddress;
use pathvector_types::Nlri;
use smallvec::SmallVec;

use crate::{
    best_path::select_best_with_oracle, best_table::BestTable, canonical::CanonicalNlri,
    oracle::NextHopOracle, peer::PeerId, route::Route,
};

/// Describes how the best path for a prefix changed after a `LocRib` mutation.
///
/// Returned by [`LocRib::insert`], [`LocRib::withdraw`],
/// [`LocRib::withdraw_peer`], and [`LocRib::recompute_all`] so callers can
/// react without re-querying the RIB.
///
/// The common consumer is a `FibManager` that installs or removes kernel
/// routes on best-path changes, and the outbound advertisement pipeline that
/// sends UPDATE messages to peers.
///
/// # Delta contract
///
/// The values are a *complete and minimal delta* of the Loc-RIB's best-path
/// table: a consumer that starts from an empty map and applies every change
/// it is handed (`Announced` → insert, `Withdrawn` → remove) always holds
/// exactly [`LocRib::best_routes`].
///
/// - **Complete** — every prefix that had a selected route before a mutation
///   and has none after it yields `Withdrawn`, *whatever* the mutation was:
///   an explicit withdrawal, a replacement route whose `NEXT_HOP` is
///   unresolvable (RFC 4271 §9 implicit withdrawal + §9.1.2 "Unresolvable
///   routes SHALL be removed from the Loc-RIB and the routing table"), a
///   session going down, or a reachability change.
/// - **Minimal** — `Withdrawn` is never emitted for a prefix that had no
///   selected route before the mutation (e.g. one whose candidates were all
///   unresolvable), so a FIB writer never deletes a route BGP did not
///   install.
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
    /// The prefix had a selected best path and now has none: every remaining
    /// candidate (if any) is infeasible, or no candidates remain.
    ///
    /// RFC 4271 §9.2: "all newly unfeasible routes for which there is no
    /// replacement route SHALL be advertised to its peers by means of an
    /// UPDATE message." The caller should withdraw the route from the FIB and
    /// send a BGP WITHDRAW to all peers that were receiving it.
    Withdrawn(Nlri<A>),
    /// The best path is unchanged — the mutation touched a non-winning
    /// candidate, or the prefix had no feasible route before or after it.
    ///
    /// No FIB update or BGP advertisement is required.
    Unchanged,
}

/// How the selected peer for one prefix moved across a single Loc-RIB
/// mutation.
///
/// Built only by [`BestTransition::between`], which matches exhaustively on
/// `(previous, next)`. Every mutating `LocRib` method derives its
/// [`BestPathChange`] through this type, so no code path can forget the
/// `Some → None` (withdraw) case or invent a `None → None` withdrawal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BestTransition {
    /// No feasible route before or after: nothing was installed or
    /// advertised, so nothing needs withdrawing.
    NeverSelected,
    /// The same peer's unmodified route is still selected.
    Kept,
    /// A selected route existed and none does now (RFC 4271 §9.2 "newly
    /// unfeasible routes for which there is no replacement route").
    Lost,
    /// `PeerId`'s route is now selected and differs from what was selected
    /// before — a new winner, or the same winner with replaced attributes.
    Selected(PeerId),
}

impl BestTransition {
    /// Classifies the move from `previous` to `next` selected peer.
    ///
    /// `replaced` is the peer whose candidate route was overwritten by this
    /// mutation, if any. When it is also the (unchanged) winner, its route
    /// content changed (RFC 4271 §3.1: "Changing the attribute(s) of a route
    /// is accomplished by advertising a replacement route"), so the
    /// transition is `Selected`, not `Kept`.
    fn between(previous: Option<PeerId>, next: Option<PeerId>, replaced: Option<PeerId>) -> Self {
        match (previous, next) {
            (None, None) => Self::NeverSelected,
            (Some(_), None) => Self::Lost,
            (None, Some(winner)) => Self::Selected(winner),
            (Some(before), Some(winner)) if before != winner || replaced == Some(winner) => {
                Self::Selected(winner)
            }
            (Some(_), Some(_)) => Self::Kept,
        }
    }
}

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
        LocRib::best(self, nlri)
    }

    fn best_peer(&self, nlri: &Nlri<A>) -> Option<PeerId> {
        LocRib::best_peer(self, nlri)
    }
}

/// Flat route table: `(prefix, peer) → Route`.
///
/// Uses `AHashMap` (non-cryptographic hasher) — ~15–20% faster than std's
/// `SipHash` for internal keys that are not attacker-controlled.
type CandidateMap<A> = AHashMap<(CanonicalNlri<A>, PeerId), Route<A>>;

/// Reverse index: prefix → list of peers that have a candidate for it.
///
/// `SmallVec<[PeerId; 4]>` stores up to 4 peers inline (no heap allocation)
/// which covers the vast majority of real-world prefixes (1–8 eBGP peers).
/// Kept in sync with `candidates` so `recompute_best` is O(k) per prefix.
type PeerIndex<A> = AHashMap<CanonicalNlri<A>, SmallVec<[PeerId; 4]>>;

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
/// # Prefix identity
///
/// A destination is its prefix: bits beyond the prefix length are irrelevant
/// (RFC 4271 §4.3, RFC 4760 §5). Every method accepts any spelling of an NLRI,
/// so `10.1.2.3/8` and `10.0.0.0/8` insert, find and withdraw the same entry.
/// Everything handed back — `Route::nlri`, [`best_routes`](LocRib::best_routes),
/// [`BestPathChange`] — carries the canonical form, with those bits zero.
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
#[derive(Clone)]
pub struct LocRib<A: IpAddress> {
    /// All candidate routes, keyed by `(prefix, peer)`.
    candidates: CandidateMap<A>,
    /// Which peers have a candidate for each prefix.
    peer_index: PeerIndex<A>,
    /// Winning peer per prefix.  Stores only the `PeerId` — the actual Route
    /// is always available via `candidates[(prefix, peer)]`.  This avoids
    /// keeping a second full clone of every best route in memory.
    ///
    /// Also counts, per peer, how many prefixes it wins ([`BestTable`]), so
    /// [`LocRib::best_win_count`] is O(1).
    best: BestTable<A>,
}

impl<A: IpAddress> LocRib<A> {
    /// Creates an empty `LocRib`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            candidates: AHashMap::new(),
            peer_index: AHashMap::new(),
            best: BestTable::new(),
        }
    }

    /// Inserts a route from `peer` into the candidate set and recomputes the
    /// best route for that prefix.
    ///
    /// The route is stored with its NLRI in canonical form (see [prefix
    /// identity](LocRib#prefix-identity)).
    ///
    /// If this peer previously had a route for this prefix, it is replaced —
    /// RFC 4271 §9: the new route "SHALL replace the older route [...] thus
    /// implicitly withdrawing the older route from service." Best-path
    /// selection runs after every insert, so `best()` always reflects the
    /// current winner.
    ///
    /// A route whose `NEXT_HOP` `oracle` reports unresolvable is still stored as
    /// a candidate (RFC 4271 §9.1.2: such routes "SHOULD be kept in the
    /// Adj-RIBs-In (in case they become resolvable)") but is excluded from
    /// selection.
    ///
    /// # Returns
    ///
    /// - [`BestPathChange::Announced`] when the inserted route, or another
    ///   candidate, becomes the new best, or when the current winner's route
    ///   was replaced.
    /// - [`BestPathChange::Withdrawn`] when the prefix had a best route and
    ///   the replacement left it with no feasible candidate — e.g. the sole
    ///   selected route is replaced by one whose `NEXT_HOP` is unresolvable.
    /// - [`BestPathChange::Unchanged`] otherwise, including when the prefix
    ///   had no feasible route before the insert and still has none.
    pub fn insert(
        &mut self,
        peer: PeerId,
        mut route: Route<A>,
        oracle: &dyn NextHopOracle,
    ) -> BestPathChange<A> {
        let key = CanonicalNlri::new(route.nlri);
        route.nlri = key.nlri();
        let previous = self.best.get(key);

        self.candidates.insert((key, peer), route);
        let peers = self.peer_index.entry(key).or_default();
        if !peers.contains(&peer) {
            peers.push(peer);
        }
        self.recompute_best(key, previous, oracle);

        let next = self.best.get(key);
        self.change_for(key, BestTransition::between(previous, next, Some(peer)))
    }

    /// Removes a specific prefix from a peer's contribution and recomputes
    /// best-path selection for that prefix.
    ///
    /// Called when a peer withdraws a specific route (WITHDRAWN ROUTES,
    /// `MP_UNREACH_NLRI`, or RFC 7606 "treat-as-withdraw"). If no candidates
    /// remain for the prefix, the prefix is removed from the `LocRib`
    /// entirely.
    ///
    /// Returns a [`BestPathChange`] describing whether and how the best path
    /// changed as a result of this withdrawal: `Withdrawn` exactly when the
    /// prefix had a best route and no feasible candidate remains, `Announced`
    /// when another candidate takes over, `Unchanged` otherwise (including
    /// when `peer` had no route for `nlri`).
    pub fn withdraw(
        &mut self,
        peer: &PeerId,
        nlri: &Nlri<A>,
        oracle: &dyn NextHopOracle,
    ) -> BestPathChange<A> {
        self.withdraw_key(*peer, CanonicalNlri::new(*nlri), oracle)
    }

    /// [`withdraw`](Self::withdraw) for a caller that already holds a key.
    fn withdraw_key(
        &mut self,
        peer: PeerId,
        key: CanonicalNlri<A>,
        oracle: &dyn NextHopOracle,
    ) -> BestPathChange<A> {
        let previous = self.best.get(key);

        if self.candidates.remove(&(key, peer)).is_none() {
            return BestPathChange::Unchanged;
        }

        let has_remaining = if let Some(peers) = self.peer_index.get_mut(&key) {
            peers.retain(|p| *p != peer);
            !peers.is_empty()
        } else {
            false
        };
        if has_remaining {
            self.recompute_best(key, previous, oracle);
        } else {
            self.peer_index.remove(&key);
            self.best.set(key, previous, None);
        }

        // `peer`'s candidate is gone, so it cannot be the next winner: no
        // route was replaced in place.
        let next = self.best.get(key);
        self.change_for(key, BestTransition::between(previous, next, None))
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
        let affected: Vec<CanonicalNlri<A>> = self
            .peer_index
            .iter()
            .filter(|(_, peers)| peers.contains(peer))
            .map(|(key, _)| *key)
            .collect();

        affected
            .into_iter()
            .map(|key| self.withdraw_key(*peer, key, oracle))
            .collect()
    }

    /// Returns the current best route for `nlri`, if any.
    #[must_use]
    pub fn best(&self, nlri: &Nlri<A>) -> Option<&Route<A>> {
        let key = CanonicalNlri::new(*nlri);
        let peer = self.best.get(key)?;
        self.candidates.get(&(key, peer))
    }

    /// Returns the peer whose route is currently best for `nlri`.
    #[must_use]
    pub fn best_peer(&self, nlri: &Nlri<A>) -> Option<PeerId> {
        self.best.get(CanonicalNlri::new(*nlri))
    }

    /// Returns how many prefixes currently have `peer` as their best-path
    /// winner.
    ///
    /// O(1): the count is maintained at the single point where the winner of
    /// a prefix changes, so it is always equal to
    /// `best_routes().filter(|(n, _)| best_peer(n) == Some(peer)).count()`
    /// without scanning the table. Management reads (`list_peers`,
    /// `get_peer`) use this instead of walking a full table per peer.
    #[must_use]
    pub fn best_win_count(&self, peer: &PeerId) -> usize {
        self.best.win_count(*peer)
    }

    /// Audits the incremental win counts against a full recount.
    ///
    /// O(table). For tests and debug assertions only; the counts cannot
    /// drift through the public API, and this is how that is verified.
    #[must_use]
    pub fn best_win_counts_consistent(&self) -> bool {
        self.best.counts_consistent()
    }

    /// Iterates over all `(prefix, best_route)` pairs.
    ///
    /// Useful for building `AdjRibOut` — iterate this, apply export policy,
    /// and insert accepted routes into the peer's outbound table.
    pub fn best_routes(&self) -> impl Iterator<Item = (Nlri<A>, &Route<A>)> {
        self.best.iter().filter_map(|(key, peer)| {
            let route = self.candidates.get(&(key, *peer))?;
            Some((key.nlri(), route))
        })
    }

    /// Returns the best route whose prefix most specifically covers `addr`.
    ///
    /// This is the forwarding lookup — the same route the data plane would use
    /// to forward a packet destined for `addr`.
    #[must_use]
    pub fn longest_match(&self, addr: A) -> Option<&Route<A>> {
        let (key, peer) = self.best.longest_match_entry(addr)?;
        self.candidates.get(&(key, *peer))
    }

    /// Returns all candidate routes for `nlri`, keyed by peer.
    ///
    /// Useful for diagnostics and "show bgp detail" output.
    #[must_use]
    pub fn candidates(&self, nlri: &Nlri<A>) -> Option<AHashMap<PeerId, &Route<A>>> {
        let key = CanonicalNlri::new(*nlri);
        let peers = self.peer_index.get(&key)?;
        let routes: AHashMap<PeerId, &Route<A>> = peers
            .iter()
            .filter_map(|p| Some((*p, self.candidates.get(&(key, *p))?)))
            .collect();
        if routes.is_empty() {
            None
        } else {
            Some(routes)
        }
    }

    /// Returns the number of unique prefixes with at least one candidate.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peer_index.len()
    }

    /// Returns `true` if the `LocRib` contains no routes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peer_index.is_empty()
    }

    /// Re-evaluates best-path selection for every prefix currently in the RIB.
    ///
    /// Called when the next-hop oracle's view of the world changes — for example,
    /// when the kernel FIB gains or loses a route that a BGP next-hop depends on.
    /// Only prefixes whose best path actually changed are included in the result;
    /// unchanged prefixes are silently skipped.
    pub fn recompute_all(&mut self, oracle: &dyn NextHopOracle) -> Vec<BestPathChange<A>> {
        let keys: Vec<CanonicalNlri<A>> = self.peer_index.keys().copied().collect();

        keys.into_iter()
            .filter_map(|key| {
                let previous = self.best.get(key);
                self.recompute_best(key, previous, oracle);
                let next = self.best.get(key);
                match self.change_for(key, BestTransition::between(previous, next, None)) {
                    BestPathChange::Unchanged => None,
                    change => Some(change),
                }
            })
            .collect()
    }

    /// Maps a [`BestTransition`] for `key` to the public [`BestPathChange`].
    ///
    /// The only place a `Route` is cloned for a change, and only for
    /// `Selected` — the same single clone the insert/withdraw paths have
    /// always paid for an announcement.
    fn change_for(&self, key: CanonicalNlri<A>, transition: BestTransition) -> BestPathChange<A> {
        match transition {
            BestTransition::NeverSelected | BestTransition::Kept => BestPathChange::Unchanged,
            BestTransition::Lost => BestPathChange::Withdrawn(key.nlri()),
            BestTransition::Selected(winner) => {
                BestPathChange::Announced(key.nlri(), self.candidates[&(key, winner)].clone())
            }
        }
    }

    /// `previous` is the prefix's winner as the caller just read it.
    fn recompute_best(
        &mut self,
        key: CanonicalNlri<A>,
        previous: Option<PeerId>,
        oracle: &dyn NextHopOracle,
    ) {
        // Use peer_index for O(k) lookup instead of scanning the full flat map.
        // Clone routes into a temp AHashMap — k is typically 1–8, negligible cost.
        let peer_map: AHashMap<PeerId, Route<A>> = self
            .peer_index
            .get(&key)
            .into_iter()
            .flatten()
            .filter_map(|p| Some((*p, self.candidates.get(&(key, *p))?.clone())))
            .collect();

        if let Some((peer, _)) = select_best_with_oracle(&peer_map, oracle) {
            self.best.set(key, previous, Some(peer));
        } else {
            self.best.set(key, previous, None);
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
    use std::{
        cell::Cell,
        net::{IpAddr, Ipv4Addr},
    };

    use pathvector_types::{AsPath, LocalPref, NextHop, Origin};

    use super::*;
    use crate::{RouteBuilder, oracle::AlwaysReachable};

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

    fn route_with_nh(prefix: &str, nh: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(nlri(prefix), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(nh.parse().unwrap()))
            .build()
    }

    /// Oracle whose reachability verdict can be toggled during a test.
    struct ToggleOracle(Cell<bool>);

    impl ToggleOracle {
        fn reachable() -> Self {
            Self(Cell::new(true))
        }

        fn set(&self, reachable: bool) {
            self.0.set(reachable);
        }
    }

    impl NextHopOracle for ToggleOracle {
        fn is_reachable(&self, _: &NextHop) -> bool {
            self.0.get()
        }

        fn igp_metric(&self, _: &NextHop) -> Option<u32> {
            None
        }
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
        // returns None. With the flat map we trigger this by removing the only
        // candidate and calling recompute_best directly.
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(peer(1), route("10.0.0.0/8"), &AlwaysReachable);
        assert!(rib.best(&n).is_some());

        let key = CanonicalNlri::new(n);
        rib.candidates.remove(&(key, peer(1)));
        rib.peer_index
            .get_mut(&key)
            .unwrap()
            .retain(|p| *p != peer(1));
        rib.recompute_best(key, rib.best_peer(&n), &AlwaysReachable);

        assert!(rib.best(&n).is_none());
    }

    #[test]
    fn test_recompute_best_noop_for_unknown_prefix() {
        // Calls recompute_best directly with a prefix that is not in candidates.
        // Covers the implicit else-fallthrough of `if let Some(peer_map)`.
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.recompute_best(
            CanonicalNlri::new(nlri("10.0.0.0/8")),
            None,
            &AlwaysReachable,
        );
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

    // ── recompute_all ─────────────────────────────────────────────────────────

    #[test]
    fn test_recompute_all_empty_rib_returns_nothing() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        assert!(rib.recompute_all(&AlwaysReachable).is_empty());
    }

    #[test]
    fn test_recompute_all_no_change_returns_nothing() {
        // Oracle says reachable before and after — no change.
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let oracle = ToggleOracle::reachable();
        rib.insert(peer(1), route_with_nh("10.0.0.0/8", "192.0.2.1"), &oracle);
        let changes = rib.recompute_all(&oracle);
        assert!(
            changes.is_empty(),
            "no FIB change expected when reachability is stable"
        );
    }

    #[test]
    fn test_recompute_all_next_hop_goes_down_withdraws_prefix() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let oracle = ToggleOracle::reachable();
        rib.insert(peer(1), route_with_nh("10.0.0.0/8", "192.0.2.1"), &oracle);
        assert!(rib.best(&nlri("10.0.0.0/8")).is_some());

        oracle.set(false); // next-hop goes down
        let changes = rib.recompute_all(&oracle);

        assert_eq!(changes.len(), 1);
        assert!(
            matches!(changes[0], BestPathChange::Withdrawn(n) if n == nlri("10.0.0.0/8")),
            "prefix must be withdrawn when the only candidate's next-hop is unreachable"
        );
        assert!(rib.best(&nlri("10.0.0.0/8")).is_none());
    }

    #[test]
    fn test_recompute_all_next_hop_recovers_announces_prefix() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let oracle = ToggleOracle::reachable();
        oracle.set(false); // insert while unreachable — no best selected
        rib.insert(peer(1), route_with_nh("10.0.0.0/8", "192.0.2.1"), &oracle);
        assert!(rib.best(&nlri("10.0.0.0/8")).is_none());

        oracle.set(true); // next-hop recovers
        let changes = rib.recompute_all(&oracle);

        assert_eq!(changes.len(), 1);
        assert!(
            matches!(changes[0], BestPathChange::Announced(n, _) if n == nlri("10.0.0.0/8")),
            "prefix must be announced when the candidate's next-hop becomes reachable"
        );
        assert!(rib.best(&nlri("10.0.0.0/8")).is_some());
    }

    #[test]
    fn test_recompute_all_only_returns_changed_prefixes() {
        struct NeverReachable;
        impl NextHopOracle for NeverReachable {
            fn is_reachable(&self, _: &NextHop) -> bool {
                false
            }
            fn igp_metric(&self, _: &NextHop) -> Option<u32> {
                None
            }
        }

        // Three prefixes; only the one whose next-hop changes should appear.
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.insert(
            peer(1),
            route_with_nh("10.0.0.0/8", "192.0.2.1"),
            &AlwaysReachable,
        );
        rib.insert(
            peer(1),
            route_with_nh("172.16.0.0/12", "192.0.2.1"),
            &AlwaysReachable,
        );
        rib.insert(
            peer(1),
            route_with_nh("192.168.0.0/16", "192.0.2.1"),
            &AlwaysReachable,
        );

        // NeverReachable oracle makes all three drop.
        let changes = rib.recompute_all(&NeverReachable);
        assert_eq!(changes.len(), 3, "all three prefixes must be withdrawn");
        assert!(
            changes
                .iter()
                .all(|c| matches!(c, BestPathChange::Withdrawn(_)))
        );
    }

    #[test]
    fn test_recompute_all_alternate_candidate_promoted_on_reachability_change() {
        // peer(1) has higher LOCAL_PREF but unreachable next-hop.
        // peer(2) has lower LOCAL_PREF but reachable next-hop.
        // Initially peer(1) wins (oracle says all reachable).
        // After oracle flips peer(1)'s next-hop unreachable, peer(2) should win.
        use std::sync::atomic::{AtomicBool, Ordering};

        struct SelectiveOracle {
            block: AtomicBool,
            blocked_nh: Ipv4Addr,
        }
        impl SelectiveOracle {
            fn new(blocked_nh: Ipv4Addr) -> Self {
                Self {
                    block: AtomicBool::new(false),
                    blocked_nh,
                }
            }
            fn block(&self) {
                self.block.store(true, Ordering::Relaxed);
            }
        }
        impl NextHopOracle for SelectiveOracle {
            fn is_reachable(&self, nh: &NextHop) -> bool {
                if let NextHop::V4(a) = nh {
                    !self.block.load(Ordering::Relaxed) || *a != self.blocked_nh
                } else {
                    true
                }
            }
            fn igp_metric(&self, _: &NextHop) -> Option<u32> {
                None
            }
        }

        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let oracle = SelectiveOracle::new("192.0.2.1".parse().unwrap());

        // peer(1): LP=200, next-hop 192.0.2.1 (will be blocked)
        let r1 = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(200))
            .next_hop(NextHop::V4("192.0.2.1".parse().unwrap()))
            .build();
        // peer(2): LP=100, next-hop 192.0.2.2 (always reachable)
        let r2 = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(100))
            .next_hop(NextHop::V4("192.0.2.2".parse().unwrap()))
            .build();

        rib.insert(peer(1), r1, &oracle);
        rib.insert(peer(2), r2, &oracle);
        assert_eq!(rib.best_peer(&nlri("10.0.0.0/8")), Some(peer(1)));

        oracle.block();
        let changes = rib.recompute_all(&oracle);

        assert_eq!(changes.len(), 1);
        assert!(
            matches!(&changes[0], BestPathChange::Announced(n, _) if *n == nlri("10.0.0.0/8")),
            "best-path change expected when winner's next-hop goes down and runner-up is reachable"
        );
        assert_eq!(rib.best_peer(&nlri("10.0.0.0/8")), Some(peer(2)));
    }

    // ── Issue #67: an UPDATE that removes the last feasible path ─────────────
    //
    // RFC 4271 §9 (UPDATE Message Handling): "if the NLRI of the new route is
    // identical to the one the route currently has stored in the Adj-RIB-In,
    // then the new route SHALL replace the older route in the Adj-RIB-In, thus
    // implicitly withdrawing the older route from service."
    //
    // RFC 4271 §9.1.2: "If the NEXT_HOP attribute of a BGP route depicts an
    // address that is not resolvable [...] the BGP route MUST be excluded from
    // the Phase 2 decision function." and "Unresolvable routes SHALL be removed
    // from the Loc-RIB and the routing table.  However, corresponding
    // unresolvable routes SHOULD be kept in the Adj-RIBs-In (in case they
    // become resolvable)."
    //
    // RFC 4271 §9.2: "All newly installed routes and all newly unfeasible
    // routes for which there is no replacement route SHALL be advertised to
    // its peers by means of an UPDATE message."
    //
    // So a replacement whose NEXT_HOP is unresolvable, arriving when it (or
    // every remaining candidate) is the last feasible route, must surface as
    // `Withdrawn` — exactly as an explicit WITHDRAWN ROUTES entry would. Every
    // oracle below is fixed for the whole test: the transition is caused by
    // the UPDATE, never by a change in reachability.

    /// Oracle with a fixed verdict per next-hop: everything is resolvable
    /// except the addresses in `unresolvable`.
    struct FixedOracle(Vec<NextHop>);

    impl FixedOracle {
        fn rejecting(unresolvable: &[&str]) -> Self {
            Self(
                unresolvable
                    .iter()
                    .map(|a| match a.parse::<IpAddr>().unwrap() {
                        IpAddr::V4(v4) => NextHop::V4(v4),
                        IpAddr::V6(v6) => NextHop::V6(v6),
                    })
                    .collect(),
            )
        }
    }

    impl NextHopOracle for FixedOracle {
        fn is_reachable(&self, nh: &NextHop) -> bool {
            !self.0.contains(nh)
        }

        fn igp_metric(&self, _: &NextHop) -> Option<u32> {
            None
        }
    }

    const UNRESOLVABLE_V4: &str = "198.51.100.99";
    const UNRESOLVABLE_V6: &str = "2001:db8:ffff::99";

    fn route_lp_nh(prefix: &str, lp: u32, nh: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(nlri(prefix), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(lp))
            .next_hop(NextHop::V4(nh.parse().unwrap()))
            .build()
    }

    /// RFC 4271 §9 + §9.1.2 + §9.2: replacing the sole selected route with one
    /// whose `NEXT_HOP` is unresolvable is an implicit withdrawal of the only
    /// feasible route, so the change must be `Withdrawn` and no best remains.
    #[test]
    fn test_insert_replacing_sole_best_with_unresolvable_next_hop_is_withdrawn() {
        let oracle = FixedOracle::rejecting(&[UNRESOLVABLE_V4]);
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        let first = rib.insert(peer(1), route_with_nh("10.0.0.0/8", "192.0.2.1"), &oracle);
        assert!(matches!(first, BestPathChange::Announced(p, _) if p == n));

        let change = rib.insert(
            peer(1),
            route_with_nh("10.0.0.0/8", UNRESOLVABLE_V4),
            &oracle,
        );

        assert_eq!(change, BestPathChange::Withdrawn(n));
        assert!(rib.best(&n).is_none());
        assert_eq!(rib.best_peer(&n), None);
        assert_eq!(rib.best_routes().count(), 0);
        assert!(rib.longest_match("10.1.2.3".parse().unwrap()).is_none());
    }

    /// RFC 4271 §9.1.2: "corresponding unresolvable routes SHOULD be kept in
    /// the Adj-RIBs-In (in case they become resolvable)". The withdrawn
    /// replacement must stay a candidate so a later reachability change can
    /// re-select it.
    #[test]
    fn test_insert_unresolvable_replacement_is_kept_as_candidate() {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");
        let rejecting = FixedOracle::rejecting(&[UNRESOLVABLE_V4]);

        rib.insert(
            peer(1),
            route_with_nh("10.0.0.0/8", "192.0.2.1"),
            &rejecting,
        );
        rib.insert(
            peer(1),
            route_with_nh("10.0.0.0/8", UNRESOLVABLE_V4),
            &rejecting,
        );
        assert!(rib.best(&n).is_none());
        assert_eq!(rib.candidates(&n).map(|c| c.len()), Some(1));

        let changes = rib.recompute_all(&AlwaysReachable);
        assert_eq!(changes.len(), 1);
        assert!(matches!(
            &changes[0],
            BestPathChange::Announced(p, r)
                if *p == n && r.next_hop == Some(NextHop::V4(UNRESOLVABLE_V4.parse().unwrap()))
        ));
    }

    /// RFC 4271 §9.1.2 / §9.2, both address families: the same transition on
    /// an IPv6 Loc-RIB must also yield `Withdrawn`.
    #[test]
    fn test_insert_replacing_sole_best_with_unresolvable_next_hop_is_withdrawn_v6() {
        use std::net::Ipv6Addr;

        let oracle = FixedOracle::rejecting(&[UNRESOLVABLE_V6]);
        let mut rib: LocRib<Ipv6Addr> = LocRib::new();
        let n: Nlri<Ipv6Addr> = "2001:db8:1::/48".parse().unwrap();
        let v6_route = |nh: &str| {
            RouteBuilder::new(n, Origin::Igp, AsPath::new())
                .next_hop(NextHop::V6(nh.parse().unwrap()))
                .build()
        };

        let first = rib.insert(peer(1), v6_route("2001:db8::1"), &oracle);
        assert!(matches!(first, BestPathChange::Announced(p, _) if p == n));

        let change = rib.insert(peer(1), v6_route(UNRESOLVABLE_V6), &oracle);

        assert_eq!(change, BestPathChange::Withdrawn(n));
        assert!(rib.best(&n).is_none());
        assert_eq!(rib.best_routes().count(), 0);
    }

    /// RFC 4271 §9.2 "newly unfeasible routes for which there is no
    /// replacement route": with several candidates, a prefix is withdrawn
    /// only when the replacement removes the *last* feasible one. Here the
    /// runner-up is already unresolvable, so replacing the winner leaves no
    /// feasible route.
    #[test]
    fn test_insert_last_feasible_of_several_candidates_is_withdrawn() {
        let oracle = FixedOracle::rejecting(&[UNRESOLVABLE_V4]);
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(
            peer(1),
            route_lp_nh("10.0.0.0/8", 200, "192.0.2.1"),
            &oracle,
        );
        // Infeasible from the start: never selected, nothing to announce.
        let infeasible = rib.insert(
            peer(2),
            route_lp_nh("10.0.0.0/8", 300, UNRESOLVABLE_V4),
            &oracle,
        );
        assert_eq!(infeasible, BestPathChange::Unchanged);
        assert_eq!(rib.best_peer(&n), Some(peer(1)));

        let change = rib.insert(
            peer(1),
            route_lp_nh("10.0.0.0/8", 200, UNRESOLVABLE_V4),
            &oracle,
        );

        assert_eq!(change, BestPathChange::Withdrawn(n));
        assert!(rib.best(&n).is_none());
        assert_eq!(rib.candidates(&n).map(|c| c.len()), Some(2));
    }

    /// Same as above, but every candidate starts feasible and is replaced by
    /// an infeasible route one UPDATE at a time: the losing candidate going
    /// infeasible is `Unchanged`; the winner going infeasible afterwards is
    /// `Withdrawn`.
    #[test]
    fn test_insert_all_candidates_become_infeasible_one_by_one() {
        let oracle = FixedOracle::rejecting(&[UNRESOLVABLE_V4]);
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(
            peer(1),
            route_lp_nh("10.0.0.0/8", 200, "192.0.2.1"),
            &oracle,
        );
        rib.insert(
            peer(2),
            route_lp_nh("10.0.0.0/8", 100, "192.0.2.2"),
            &oracle,
        );
        assert_eq!(rib.best_peer(&n), Some(peer(1)));

        let loser = rib.insert(
            peer(2),
            route_lp_nh("10.0.0.0/8", 100, UNRESOLVABLE_V4),
            &oracle,
        );
        assert_eq!(loser, BestPathChange::Unchanged);
        assert_eq!(rib.best_peer(&n), Some(peer(1)));

        let winner = rib.insert(
            peer(1),
            route_lp_nh("10.0.0.0/8", 200, UNRESOLVABLE_V4),
            &oracle,
        );
        assert_eq!(winner, BestPathChange::Withdrawn(n));
        assert!(rib.best(&n).is_none());
    }

    /// RFC 4271 §9.1.2: "install that route in the Loc-RIB, replacing any
    /// route to the same destination". When the winner's replacement is
    /// unresolvable but a feasible alternative exists, the alternative is
    /// selected and must be announced — not withdrawn.
    #[test]
    fn test_insert_unresolvable_replacement_promotes_feasible_alternative() {
        let oracle = FixedOracle::rejecting(&[UNRESOLVABLE_V4]);
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(
            peer(1),
            route_lp_nh("10.0.0.0/8", 200, "192.0.2.1"),
            &oracle,
        );
        let runner_up = route_lp_nh("10.0.0.0/8", 100, "192.0.2.2");
        rib.insert(peer(2), runner_up.clone(), &oracle);

        let change = rib.insert(
            peer(1),
            route_lp_nh("10.0.0.0/8", 200, UNRESOLVABLE_V4),
            &oracle,
        );

        assert_eq!(change, BestPathChange::Announced(n, runner_up));
        assert_eq!(rib.best_peer(&n), Some(peer(2)));
    }

    /// A winner's replacement that stays resolvable carries changed attributes
    /// (RFC 4271 §3.1: "Changing the attribute(s) of a route is accomplished
    /// by advertising a replacement route"), so it must be re-announced with
    /// the new content.
    #[test]
    fn test_insert_feasible_replacement_of_winner_is_announced_with_new_content() {
        let oracle = FixedOracle::rejecting(&[UNRESOLVABLE_V4]);
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(peer(1), route_with_nh("10.0.0.0/8", "192.0.2.1"), &oracle);
        let replacement = route_with_nh("10.0.0.0/8", "192.0.2.7");

        let change = rib.insert(peer(1), replacement.clone(), &oracle);

        assert_eq!(change, BestPathChange::Announced(n, replacement));
    }

    /// An infeasible route for a prefix that has never had a feasible best
    /// route must not emit a spurious `Withdrawn` — nothing was ever installed
    /// or advertised, so §9.2 has nothing to withdraw.
    #[test]
    fn test_insert_infeasible_into_prefix_without_best_is_unchanged() {
        let oracle = FixedOracle::rejecting(&[UNRESOLVABLE_V4]);
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        let first = rib.insert(
            peer(1),
            route_with_nh("10.0.0.0/8", UNRESOLVABLE_V4),
            &oracle,
        );
        assert_eq!(first, BestPathChange::Unchanged);
        let replaced = rib.insert(
            peer(1),
            route_with_nh("10.0.0.0/8", UNRESOLVABLE_V4),
            &oracle,
        );
        assert_eq!(replaced, BestPathChange::Unchanged);
        let second_peer = rib.insert(
            peer(2),
            route_with_nh("10.0.0.0/8", UNRESOLVABLE_V4),
            &oracle,
        );
        assert_eq!(second_peer, BestPathChange::Unchanged);
        assert!(rib.best(&n).is_none());
    }

    /// RFC 7606 §2 "treat-as-withdraw" removes routes "just as if they had
    /// been listed in the WITHDRAWN ROUTES field", i.e. via `withdraw`. An
    /// explicit withdrawal of the only *feasible* candidate, leaving only an
    /// infeasible one, must also report `Withdrawn`.
    #[test]
    fn test_withdraw_last_feasible_leaving_infeasible_candidate_is_withdrawn() {
        let oracle = FixedOracle::rejecting(&[UNRESOLVABLE_V4]);
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(peer(1), route_with_nh("10.0.0.0/8", "192.0.2.1"), &oracle);
        rib.insert(
            peer(2),
            route_with_nh("10.0.0.0/8", UNRESOLVABLE_V4),
            &oracle,
        );

        assert_eq!(
            rib.withdraw(&peer(1), &n, &oracle),
            BestPathChange::Withdrawn(n)
        );
        assert!(rib.best(&n).is_none());
        // Withdrawing the remaining infeasible candidate is not a second withdrawal.
        assert_eq!(
            rib.withdraw(&peer(2), &n, &oracle),
            BestPathChange::Unchanged
        );
        assert!(rib.is_empty());
    }

    /// Mirror image of issue #67, found by the replay property test: removing
    /// one of several candidates that are *all* infeasible leaves the prefix
    /// without a best route, but there was none before either. Emitting
    /// `Withdrawn` here would make the FIB writer delete a kernel route BGP
    /// never installed (possibly a static or connected route for the same
    /// prefix). RFC 4271 §9.2 only requires withdrawing "newly unfeasible
    /// routes", so the change must be `Unchanged`.
    #[test]
    fn test_withdraw_infeasible_candidate_when_no_best_is_unchanged() {
        let oracle = FixedOracle::rejecting(&[UNRESOLVABLE_V4]);
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let n = nlri("10.0.0.0/8");

        rib.insert(
            peer(1),
            route_with_nh("10.0.0.0/8", UNRESOLVABLE_V4),
            &oracle,
        );
        rib.insert(
            peer(2),
            route_with_nh("10.0.0.0/8", UNRESOLVABLE_V4),
            &oracle,
        );
        assert!(rib.best(&n).is_none());

        assert_eq!(
            rib.withdraw(&peer(1), &n, &oracle),
            BestPathChange::Unchanged
        );
        assert_eq!(
            rib.withdraw_peer(&peer(2), &oracle),
            vec![BestPathChange::Unchanged]
        );
        assert!(rib.is_empty());
    }

    /// Exhaustive truth table for [`BestTransition::between`], derived from
    /// RFC 4271 §9.1.2 (install the selected route, "replacing any route to
    /// the same destination") and §9.2 ("newly unfeasible routes for which
    /// there is no replacement route SHALL be advertised").
    struct NothingReachable;
    impl NextHopOracle for NothingReachable {
        fn is_reachable(&self, _: &NextHop) -> bool {
            false
        }
        fn igp_metric(&self, _: &NextHop) -> Option<u32> {
            None
        }
    }

    // ── best_win_count (issue #106) ──────────────────────────────────────────

    #[test]
    fn test_best_win_count_empty_rib_is_zero() {
        let rib: LocRib<Ipv4Addr> = LocRib::new();
        assert_eq!(rib.best_win_count(&peer(1)), 0);
        assert!(rib.best_win_counts_consistent());
    }

    #[test]
    fn test_best_win_count_tracks_winner_changes() {
        let mut rib = LocRib::new();
        // peer 1 wins both prefixes at first.
        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 100), &AlwaysReachable);
        rib.insert(peer(1), route_with_lp("11.0.0.0/8", 100), &AlwaysReachable);
        assert_eq!(rib.best_win_count(&peer(1)), 2);
        assert_eq!(rib.best_win_count(&peer(2)), 0);

        // peer 2 takes over one prefix: the count moves, the total does not.
        rib.insert(peer(2), route_with_lp("10.0.0.0/8", 200), &AlwaysReachable);
        assert_eq!(rib.best_win_count(&peer(1)), 1);
        assert_eq!(rib.best_win_count(&peer(2)), 1);

        // A losing candidate changes nothing.
        rib.insert(peer(3), route_with_lp("10.0.0.0/8", 50), &AlwaysReachable);
        assert_eq!(rib.best_win_count(&peer(3)), 0);

        // The winner replacing its own route keeps a single count.
        rib.insert(peer(2), route_with_lp("10.0.0.0/8", 300), &AlwaysReachable);
        assert_eq!(rib.best_win_count(&peer(2)), 1);

        // Withdrawing the winner promotes the next candidate (peer 1).
        rib.withdraw(&peer(2), &nlri("10.0.0.0/8"), &AlwaysReachable);
        assert_eq!(rib.best_win_count(&peer(1)), 2);
        assert_eq!(rib.best_win_count(&peer(2)), 0);
        assert!(rib.best_win_counts_consistent());
    }

    #[test]
    fn test_best_win_count_teardown_zeroes_the_peer() {
        let mut rib = LocRib::new();
        for p in ["10.0.0.0/8", "11.0.0.0/8", "12.0.0.0/8"] {
            rib.insert(peer(1), route_with_lp(p, 200), &AlwaysReachable);
            rib.insert(peer(2), route_with_lp(p, 100), &AlwaysReachable);
        }
        assert_eq!(rib.best_win_count(&peer(1)), 3);
        rib.withdraw_peer(&peer(1), &AlwaysReachable);
        assert_eq!(rib.best_win_count(&peer(1)), 0);
        assert_eq!(rib.best_win_count(&peer(2)), 3);
        rib.withdraw_peer(&peer(2), &AlwaysReachable);
        assert_eq!(rib.best_win_count(&peer(2)), 0);
        assert!(rib.is_empty());
        assert!(rib.best_win_counts_consistent());
    }

    #[test]
    fn test_best_win_count_unresolvable_winner_is_not_counted() {
        // RFC 4271 §9.1.2: a route with an unresolvable NEXT_HOP is excluded
        // from selection, so it must not count as a best-path win.
        let mut rib = LocRib::new();
        rib.insert(
            peer(1),
            route_with_nh("10.0.0.0/8", "192.0.2.1"),
            &AlwaysReachable,
        );
        assert_eq!(rib.best_win_count(&peer(1)), 1);

        rib.recompute_all(&NothingReachable);
        assert_eq!(rib.best_win_count(&peer(1)), 0, "no selected route");
        assert_eq!(rib.len(), 1, "the candidate is retained");

        rib.recompute_all(&AlwaysReachable);
        assert_eq!(rib.best_win_count(&peer(1)), 1);
        assert!(rib.best_win_counts_consistent());
    }

    #[test]
    fn test_best_transition_truth_table() {
        let (a, b) = (peer(1), peer(2));
        let cases = [
            // previous, next, replaced => expected
            (None, None, None, BestTransition::NeverSelected),
            (None, None, Some(a), BestTransition::NeverSelected),
            (Some(a), None, None, BestTransition::Lost),
            (Some(a), None, Some(a), BestTransition::Lost),
            (Some(a), None, Some(b), BestTransition::Lost),
            (None, Some(a), None, BestTransition::Selected(a)),
            (None, Some(a), Some(a), BestTransition::Selected(a)),
            (None, Some(a), Some(b), BestTransition::Selected(a)),
            (Some(a), Some(b), None, BestTransition::Selected(b)),
            (Some(a), Some(b), Some(a), BestTransition::Selected(b)),
            (Some(a), Some(b), Some(b), BestTransition::Selected(b)),
            (Some(a), Some(a), Some(a), BestTransition::Selected(a)),
            (Some(a), Some(a), None, BestTransition::Kept),
            (Some(a), Some(a), Some(b), BestTransition::Kept),
        ];
        for (previous, next, replaced, expected) in cases {
            assert_eq!(
                BestTransition::between(previous, next, replaced),
                expected,
                "between({previous:?}, {next:?}, {replaced:?})"
            );
        }
    }
}
