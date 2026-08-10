use ahash::AHashMap;
use ipnetx::interfaces::IpAddress;
use pathvector_types::Nlri;
use smallvec::SmallVec;

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

    /// Returns the current best route together with its source peer, in one
    /// call.
    ///
    /// The peer is nested in its own `Option` — deliberately independent of
    /// whether a route exists — because an implementor with no source-peer
    /// tracking (e.g. a test stub) legitimately returns a route from
    /// `best()` while `best_peer()` returns `None`; that must still count
    /// as "route present, peer unknown," not "no route." Default
    /// implementation composes `best()` and `best_peer()` (two lookups) for
    /// implementors with no cheaper option. `LocRib` overrides this with a
    /// genuine single-lookup implementation — see `LocRib::best_with_peer`,
    /// whose own signature is the simpler, non-nested `Option<(PeerId,
    /// &Route<A>)>` since a real `LocRib` never has a route without a known
    /// peer.
    fn best_with_peer(&self, nlri: &Nlri<A>) -> Option<(Option<PeerId>, &Route<A>)> {
        self.best(nlri).map(|route| (self.best_peer(nlri), route))
    }
}

impl<A: IpAddress> RibView<A> for LocRib<A> {
    fn best(&self, nlri: &Nlri<A>) -> Option<&Route<A>> {
        LocRib::best(self, nlri)
    }

    fn best_peer(&self, nlri: &Nlri<A>) -> Option<PeerId> {
        LocRib::best_peer(self, nlri)
    }

    fn best_with_peer(&self, nlri: &Nlri<A>) -> Option<(Option<PeerId>, &Route<A>)> {
        LocRib::best_with_peer(self, nlri).map(|(peer, route)| (Some(peer), route))
    }
}

/// Flat route table: `(prefix, peer) → Route`.
///
/// Uses `AHashMap` (non-cryptographic hasher) — ~15–20% faster than std's
/// `SipHash` for internal keys that are not attacker-controlled.
type CandidateMap<A> = AHashMap<(Nlri<A>, PeerId), Route<A>>;

/// Reverse index: prefix → list of peers that have a candidate for it.
///
/// `SmallVec<[PeerId; 4]>` stores up to 4 peers inline (no heap allocation)
/// which covers the vast majority of real-world prefixes (1–8 eBGP peers).
/// Kept in sync with `candidates` so `recompute_best` is O(k) per prefix.
type PeerIndex<A> = AHashMap<Nlri<A>, SmallVec<[PeerId; 4]>>;

/// Best-path index: prefix → winning peer.
///
/// `AHashMap` rather than `routemap::RouteMap` — every real caller
/// (`insert`/`withdraw`/`best`/`best_peer`) does exact lookups; the only
/// consumer of `RouteMap`'s longest-prefix-match capability was
/// `LocRib::longest_match`, which has no production call site and is now
/// implemented as a bounded sequence of exact probes instead (see
/// `longest_match`). Benchmarked ~16-48% faster than `RouteMap` for exact
/// insert/get/remove under both a `/32`-heavy and a mixed-prefix-length
/// shape — see `plans/blocking-arbiter-performance.md`, Item 2.
/// `pathvector-rpki`'s own `RouteMap` usage (genuine LPM-heavy coverage
/// queries) is unaffected.
type BestIndex<A> = AHashMap<Nlri<A>, PeerId>;

#[derive(Clone)]
pub struct LocRib<A: IpAddress> {
    /// All candidate routes, keyed by `(prefix, peer)`.
    candidates: CandidateMap<A>,
    /// Which peers have a candidate for each prefix.
    peer_index: PeerIndex<A>,
    /// Winning peer per prefix.  Stores only the `PeerId` — the actual Route
    /// is always available via `candidates[(prefix, peer)]`.  This avoids
    /// keeping a second full clone of every best route in memory.  Keys are
    /// always canonicalized with [`Nlri::masked`] on insert/query.
    best: BestIndex<A>,
}

impl<A: IpAddress> LocRib<A> {
    /// Creates an empty `LocRib`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            candidates: AHashMap::new(),
            peer_index: AHashMap::new(),
            best: AHashMap::new(),
        }
    }

    /// Creates an empty `LocRib` with capacity pre-allocated for `n`
    /// candidate entries and `n` distinct prefixes.
    ///
    /// Use when a batch's exact size is known upfront (e.g. a benchmark
    /// harness building a fixed-size table) to avoid incremental rehashing.
    /// See [`LocRib::reserve`] for the equivalent operation on an existing,
    /// already-populated `LocRib`.
    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Self {
            candidates: AHashMap::with_capacity(n),
            peer_index: AHashMap::with_capacity(n),
            best: AHashMap::with_capacity(n),
        }
    }

    /// Reserves capacity for at least `additional` more candidate entries
    /// and distinct prefixes, without changing the current length.
    ///
    /// Call before inserting a batch of known size (e.g.
    /// `OriginateRoutes`'s route list) to avoid incremental rehashing as the
    /// batch is inserted one route at a time.
    pub fn reserve(&mut self, additional: usize) {
        self.candidates.reserve(additional);
        self.peer_index.reserve(additional);
        self.best.reserve(additional);
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

        // Snapshot old best peer before mutation so we can detect Unchanged.
        let old_best_peer = self.best.get(&nlri.masked()).copied();

        self.candidates.insert((nlri, peer), route);
        let peers = self.peer_index.entry(nlri).or_default();
        if !peers.contains(&peer) {
            peers.push(peer);
        }
        self.recompute_best(nlri, oracle);

        match self.best.get(&nlri.masked()).copied() {
            None => BestPathChange::Unchanged,
            Some(new_peer) => {
                let new_route = &self.candidates[&(nlri, new_peer)];
                match old_best_peer {
                    Some(old_peer) if old_peer == new_peer => {
                        // Same winning peer — unchanged unless its route content changed.
                        // We only need to check content when the inserting peer is the
                        // current winner (otherwise its route didn't change this round).
                        //
                        // Deliberately conservative: we no longer have the old
                        // route's content to compare against here (it was just
                        // overwritten above), so a same-peer update always
                        // reports Announced. An earlier version added a
                        // content-comparison gate directly in this function to
                        // avoid that — reverted (see
                        // plans/blocking-arbiter-performance.md, Item 5): it
                        // didn't skip the recompute_best call above (the actual
                        // cost for the multi-candidate path), and the one real
                        // caller of this — local origination — discarded the
                        // BestPathChange result anyway, so it bought nothing in
                        // production while adding a real cost to every
                        // multi-candidate BGP-learned-route update. Suppressing
                        // a genuinely idempotent re-origination now happens one
                        // layer up, before this function is even called — see
                        // `pathvectord::daemon::origination`.
                        if peer == new_peer {
                            BestPathChange::Announced(nlri, new_route.clone())
                        } else {
                            BestPathChange::Unchanged
                        }
                    }
                    _ => BestPathChange::Announced(nlri, new_route.clone()),
                }
            }
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
        let had_best = self.best.get(&nlri.masked()).is_some();

        if self.candidates.remove(&(*nlri, *peer)).is_none() {
            return BestPathChange::Unchanged;
        }

        let has_remaining = if let Some(peers) = self.peer_index.get_mut(nlri) {
            peers.retain(|p| p != peer);
            !peers.is_empty()
        } else {
            false
        };
        if !has_remaining {
            self.peer_index.remove(nlri);
            self.best.remove(&nlri.masked());
            return if had_best {
                BestPathChange::Withdrawn(*nlri)
            } else {
                BestPathChange::Unchanged
            };
        }

        let old_best_peer = self.best.get(&nlri.masked()).copied();
        self.recompute_best(*nlri, oracle);

        match self.best.get(&nlri.masked()).copied() {
            None => BestPathChange::Withdrawn(*nlri),
            Some(new_peer) => {
                if old_best_peer == Some(new_peer) && old_best_peer != Some(*peer) {
                    // Same winner and it wasn't the peer we just withdrew — no change.
                    BestPathChange::Unchanged
                } else {
                    BestPathChange::Announced(*nlri, self.candidates[&(*nlri, new_peer)].clone())
                }
            }
        }
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
            .peer_index
            .iter()
            .filter(|(_, peers)| peers.contains(peer))
            .map(|(n, _)| *n)
            .collect();

        affected
            .into_iter()
            .map(|nlri| self.withdraw(peer, &nlri, oracle))
            .collect()
    }

    /// Returns the current best route for `nlri`, if any.
    #[must_use]
    pub fn best(&self, nlri: &Nlri<A>) -> Option<&Route<A>> {
        let peer = *self.best.get(&nlri.masked())?;
        self.candidates.get(&(*nlri, peer))
    }

    /// Returns the peer whose route is currently best for `nlri`.
    #[must_use]
    pub fn best_peer(&self, nlri: &Nlri<A>) -> Option<PeerId> {
        self.best.get(&nlri.masked()).copied()
    }

    /// Returns both the winning peer and its route for `nlri` in one
    /// lookup, instead of two.
    ///
    /// Outbound propagation (`pathvectord::outbound::propagate_prefix`)
    /// previously called `best_peer()` then `best()` separately for every
    /// prefix, for every peer — two `best`-index reads per prefix per peer,
    /// which scales with peer count the way `insert`/`withdraw`'s O(1)
    /// per-prefix cost doesn't. This collapses that to one.
    #[must_use]
    pub fn best_with_peer(&self, nlri: &Nlri<A>) -> Option<(PeerId, &Route<A>)> {
        let peer = *self.best.get(&nlri.masked())?;
        self.candidates
            .get(&(*nlri, peer))
            .map(|route| (peer, route))
    }

    /// Iterates over all `(prefix, best_route)` pairs.
    ///
    /// Useful for building `AdjRibOut` — iterate this, apply export policy,
    /// and insert accepted routes into the peer's outbound table.
    pub fn best_routes(&self) -> impl Iterator<Item = (Nlri<A>, &Route<A>)> {
        self.best.iter().filter_map(|(&nlri, peer)| {
            let route = self.candidates.get(&(nlri, *peer))?;
            Some((nlri, route))
        })
    }

    /// Returns the best route whose prefix most specifically covers `addr`.
    ///
    /// This is the forwarding lookup — the same route the data plane would use
    /// to forward a packet destined for `addr`. Implemented as a bounded
    /// sequence of exact-masked probes from most-specific (`A::BITS`) down to
    /// least-specific (`0`) — up to 33 lookups for IPv4, 129 for IPv6. This
    /// has no production call site today (confirmed via workspace-wide grep),
    /// so a rare O(bits) scan is the right trade for keeping `best` a plain
    /// exact-match `AHashMap` — see Item 2 in
    /// `plans/blocking-arbiter-performance.md`.
    ///
    /// # Panics
    ///
    /// Never in practice: `len` ranges over `0..=A::BITS` by construction,
    /// which is always a valid prefix length for `A`.
    #[must_use]
    pub fn longest_match(&self, addr: A) -> Option<&Route<A>> {
        for len in (0..=A::BITS).rev() {
            let candidate = Nlri::new(addr, len)
                .expect("len is in [0, A::BITS] by loop construction")
                .masked();
            if let Some(peer) = self.best.get(&candidate) {
                return self.candidates.get(&(candidate, *peer));
            }
        }
        None
    }

    /// Returns all candidate routes for `nlri`, keyed by peer.
    ///
    /// Returns the single candidate route contributed by `peer` for `nlri`,
    /// if any — an exact `(nlri, peer)` lookup, not best-path selection.
    ///
    /// Useful for callers that need to compare an incoming route against
    /// what a specific peer previously contributed (e.g. local origination
    /// checking whether a re-announced route is content-identical to what's
    /// already stored) without paying for the full `candidates()` map.
    #[must_use]
    pub fn candidate(&self, nlri: &Nlri<A>, peer: PeerId) -> Option<&Route<A>> {
        self.candidates.get(&(*nlri, peer))
    }

    /// Useful for diagnostics and "show bgp detail" output.
    #[must_use]
    pub fn candidates(&self, nlri: &Nlri<A>) -> Option<AHashMap<PeerId, &Route<A>>> {
        let peers = self.peer_index.get(nlri)?;
        let routes: AHashMap<PeerId, &Route<A>> = peers
            .iter()
            .filter_map(|p| Some((*p, self.candidates.get(&(*nlri, *p))?)))
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
        let nlris: Vec<Nlri<A>> = self.peer_index.keys().copied().collect();

        nlris
            .into_iter()
            .filter_map(|nlri| {
                let old_peer = self.best.get(&nlri.masked()).copied();
                self.recompute_best(nlri, oracle);
                let new_peer = self.best.get(&nlri.masked()).copied();
                match (old_peer, new_peer) {
                    (None, None) => None,
                    (Some(_), None) => Some(BestPathChange::Withdrawn(nlri)),
                    (Some(op), Some(np)) if op == np => None,
                    (_, Some(np)) => Some(BestPathChange::Announced(
                        nlri,
                        self.candidates[&(nlri, np)].clone(),
                    )),
                }
            })
            .collect()
    }

    fn recompute_best(&mut self, nlri: Nlri<A>, oracle: &dyn NextHopOracle) {
        let masked = nlri.masked();
        match self.peer_index.get(&nlri).map(SmallVec::as_slice) {
            None | Some([]) => {
                self.best.remove(&masked);
            }
            Some([only_peer]) => {
                // Fast path: exactly one candidate — the dominant case for a
                // locally-originated host-route workload (see
                // plans/blocking-arbiter-performance.md, Item 1). Skips the
                // AHashMap clone below and `select_best_with_oracle`'s
                // Vec/HashMap allocations entirely.
                //
                // For a single candidate, `select_best_with_oracle` reduces
                // to exactly this: reachable → wins unconditionally (nothing
                // to compare `prefer()` against — `max_by` on a one-element
                // iterator never calls the comparator, so LOCAL_PREF/`stale`/
                // everything else is irrelevant); unreachable → no winner.
                // Reuses the same `next_hop.as_ref().is_none_or(...)`
                // expression `best_path.rs`'s Step 1 filter uses, rather than
                // reimplementing it, to avoid the two copies drifting apart.
                // Proven equivalent to the general path by
                // `prop_tests::prop_single_candidate_fast_path_matches_general_path`.
                let reachable = self
                    .candidates
                    .get(&(nlri, *only_peer))
                    .is_some_and(|route| {
                        route
                            .next_hop
                            .as_ref()
                            .is_none_or(|nh| oracle.is_reachable(nh))
                    });
                if reachable {
                    self.best.insert(masked, *only_peer);
                } else {
                    self.best.remove(&masked);
                }
            }
            Some(_) => {
                // 2+ candidates — general path, unchanged. Clone routes into a
                // temp AHashMap — k is typically 1–8, negligible cost.
                let peer_map: AHashMap<PeerId, Route<A>> = self
                    .peer_index
                    .get(&nlri)
                    .into_iter()
                    .flatten()
                    .filter_map(|p| Some((*p, self.candidates.get(&(nlri, *p))?.clone())))
                    .collect();

                if let Some((peer, _)) = select_best_with_oracle(&peer_map, oracle) {
                    self.best.insert(masked, peer);
                } else {
                    self.best.remove(&masked);
                }
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

        rib.candidates.remove(&(n, peer(1)));
        rib.peer_index
            .get_mut(&n)
            .unwrap()
            .retain(|p| *p != peer(1));
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
    fn test_insert_identical_content_by_winner_is_conservatively_announced() {
        // Deliberately reverted from an earlier version that special-cased
        // byte-identical re-insertion as Unchanged: that gate didn't skip
        // the recompute_best cost it was meant to avoid (the general
        // multi-candidate path still ran unconditionally), and the one real
        // caller — local origination — never even looked at this return
        // value. Suppression of a genuinely idempotent re-origination now
        // happens before LocRib::insert is called at all — see
        // pathvectord::daemon::origination. This function stays
        // conservative: any same-peer update is Announced.
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        rib.insert(peer(1), route_with_lp("10.0.0.0/8", 200), &AlwaysReachable);
        let n = nlri("10.0.0.0/8");
        let change = rib.insert(peer(1), route_with_lp("10.0.0.0/8", 200), &AlwaysReachable);
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
}

/// Differential proof that `recompute_best`'s single-candidate fast path
/// (see the `Some([only_peer])` arm) is behaviorally identical to the
/// general `select_best_with_oracle` path for every single-candidate input —
/// see `plans/blocking-arbiter-performance.md`, Item 1.
#[cfg(test)]
mod prop_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use pathvector_types::{AsPath, LocalPref, NextHop, Origin};
    use proptest::prelude::*;

    use super::*;
    use crate::{RouteBuilder, best_path::select_best_with_oracle, oracle::NextHopOracle};

    fn peer_at(n: u8) -> PeerId {
        PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
    }

    fn nlri() -> Nlri<Ipv4Addr> {
        "10.0.0.0/8".parse().unwrap()
    }

    struct ToggleOracle(bool);

    impl NextHopOracle for ToggleOracle {
        fn is_reachable(&self, _: &NextHop) -> bool {
            self.0
        }

        fn igp_metric(&self, _: &NextHop) -> Option<u32> {
            None
        }
    }

    proptest! {
        #[test]
        fn prop_single_candidate_fast_path_matches_general_path(
            has_next_hop in any::<bool>(),
            reachable in any::<bool>(),
            lp in 0u32..=500u32,
            stale in any::<bool>(),
        ) {
            let n = nlri();
            let mut route = RouteBuilder::new(n, Origin::Igp, AsPath::new())
                .local_pref(LocalPref::new(lp))
                .build();
            route.stale = stale;
            if has_next_hop {
                route.next_hop = Some(NextHop::V4(Ipv4Addr::new(192, 0, 2, 1)));
            }
            let oracle = ToggleOracle(reachable);

            // Via the real LocRib — exercises whichever code path is
            // actually wired in (the fast path, as of this commit).
            let mut rib: LocRib<Ipv4Addr> = LocRib::new();
            rib.insert(peer_at(1), route.clone(), &oracle);
            let via_loc_rib = rib.best_peer(&n);

            // Via the general path directly, on an equivalent one-entry map.
            let mut candidates = std::collections::HashMap::new();
            candidates.insert(peer_at(1), route);
            let via_general_path = select_best_with_oracle(&candidates, &oracle).map(|(p, _)| p);

            prop_assert_eq!(via_loc_rib, via_general_path);
        }
    }

    // Differential proof that `LocRib::longest_match`'s bounded exact-probe
    // implementation (Item 2 of `plans/blocking-arbiter-performance.md`)
    // agrees with `routemap::RouteMap`'s genuine treebitmap LPM — used here
    // only as a test oracle, not swapped into production (`LocRib::best`'s
    // new `AHashMap` is the one under test).
    proptest! {
        #[test]
        fn prop_longest_match_matches_routemap_oracle(
            prefixes in proptest::collection::vec(
                (any::<[u8; 4]>(), 0u8..=32u8, 1u8..=250u8),
                0..30usize,
            ),
            query in any::<[u8; 4]>(),
        ) {
            let mut rib: LocRib<Ipv4Addr> = LocRib::new();
            let mut oracle: routemap::RouteMap<Ipv4Addr, PeerId> = routemap::RouteMap::new();
            let mut inserted_addrs: Vec<Ipv4Addr> = Vec::new();

            for (addr_bytes, len, peer_last_octet) in &prefixes {
                let candidate = Nlri::new(Ipv4Addr::from(*addr_bytes), *len)
                    .expect("len is in [0, 32] by the strategy's range")
                    .masked();
                let p = peer_at(*peer_last_octet);
                rib.insert(
                    p,
                    RouteBuilder::new(candidate, Origin::Igp, AsPath::new()).build(),
                    &crate::oracle::AlwaysReachable,
                );
                oracle.insert(candidate.prefix(), p);
                inserted_addrs.push(Ipv4Addr::from(*addr_bytes));
            }

            // A fully random query exercises the general case; each inserted
            // prefix's own (unmasked) address is also queried directly so an
            // exact-boundary regression (e.g. an off-by-one in the probe
            // range that skips checking `/32`) is caught deterministically —
            // a purely random query almost never coincides exactly with a
            // stored prefix's address, which let an earlier, deliberately
            // broken version of this probe range pass unnoticed.
            let mut queries = vec![Ipv4Addr::from(query)];
            queries.extend(inserted_addrs);

            for addr in queries {
                let rib_hit = rib.longest_match(addr).is_some();
                let oracle_hit = oracle.longest_match_entry(addr).is_some();
                prop_assert_eq!(rib_hit, oracle_hit, "mismatch for query {}", addr);
            }
        }
    }
}
