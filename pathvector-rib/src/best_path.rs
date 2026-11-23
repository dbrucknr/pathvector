use std::{cmp::Ordering, collections::HashMap};

use ipnetx::interfaces::IpAddress;
use pathvector_types::{Asn, LocalPref, PeerType};

use crate::{
    oracle::{AlwaysReachable, NextHopOracle},
    peer::PeerId,
    route::{EffectiveRouterId, Route},
};

/// Selects the best route from a set of candidates using the BGP decision
/// process (RFC 4271 §9.1).
///
/// Returns the winning `(PeerId, &Route)` pair, or `None` if the map is empty.
///
/// # Decision steps implemented
///
/// | Step | Criterion | Winner |
/// |---|---|---|
/// | 2 | `LOCAL_PREF` | higher (missing → 100) |
/// | 3/7 | Source type | `Local` > `External` > `Internal` |
/// | 4 | AS path length | shorter |
/// | 5 | `ORIGIN` | lower (`IGP=0` best) |
/// | 6 | `MED` (same neighboring AS only) | lower (missing → `0`) |
/// | 9 | Route age (eBGP only) | older |
/// | 10 | BGP Identifier (RFC 4271 §9.1.2.2 (f)); `ORIGINATOR_ID` replaces it on reflected routes (RFC 4456 §9); unknown ranks last | lower |
/// | 10a | `CLUSTER_LIST` length (RFC 4456 §9, inserted between (f) and (g)); absent → 0 | shorter |
/// | 11 | Peer IP address (RFC 4271 §9.1.2.2 (g), final tie-breaker) | lower |
///
/// Steps 1 and 8 require IGP reachability information not available at the
/// RIB layer. See `TODO.md`.
///
/// # Route reflection
///
/// RFC 4456 §9 amends the tie-breakers: "If a route carries the
/// `ORIGINATOR_ID` attribute, then in Step f) the `ORIGINATOR_ID` SHOULD be
/// treated as the BGP Identifier of the BGP speaker that has advertised the
/// route", and "a BGP Speaker SHOULD prefer a route with the shorter
/// `CLUSTER_LIST` length" before step (g). Both are read from the route
/// itself ([`Route::effective_router_id`], [`Route::cluster_list_len`]); the
/// caller only has to store the attributes as received.
///
/// An unknown identifier (a route with neither `ORIGINATOR_ID` nor
/// [`Route::peer_bgp_id`]) ranks after every known one at step (f) rather
/// than skipping the step, which would not be transitive — see
/// [`EffectiveRouterId`].
///
/// # Graceful Restart
///
/// A route retained during conventional Graceful Restart
/// ([`Staleness::GrStale`](crate::Staleness::GrStale)) is not a separate
/// step: it competes on its attributes exactly like a fresh route (RFC 4724
/// §4.2, RFC 9494 §1). It is removed — not depreferenced — when the peer
/// replaces it, sends End-of-RIB, or fails to return within its Restart Time.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use std::net::{IpAddr, Ipv4Addr};
/// use pathvector_rib::{PeerId, Route, RouteBuilder, best_path::select_best};
/// use pathvector_types::{AsPath, Asn, LocalPref, Nlri, Origin};
///
/// let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
/// let peer_a = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
/// let peer_b = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
///
/// let mut candidates = HashMap::new();
/// candidates.insert(peer_a, RouteBuilder::new(nlri, Origin::Igp, AsPath::new())
///     .local_pref(LocalPref::new(200))
///     .build());
/// candidates.insert(peer_b, RouteBuilder::new(nlri, Origin::Igp, AsPath::new())
///     .local_pref(LocalPref::new(100))
///     .build());
///
/// let (winner, _) = select_best(&candidates).unwrap();
/// assert_eq!(winner, peer_a); // higher LOCAL_PREF wins
/// ```
#[must_use]
pub fn select_best<A: IpAddress, S: std::hash::BuildHasher>(
    candidates: &HashMap<PeerId, Route<A>, S>,
) -> Option<(PeerId, &Route<A>)> {
    select_best_with_oracle(candidates, &AlwaysReachable)
}

/// Like [`select_best`] but honours RFC 4271 §9.1 steps 1 and 8 via `oracle`.
///
/// Step 1: routes whose `NEXT_HOP` the oracle marks unreachable are excluded
/// from the candidate set before comparison begins.
///
/// Step 8: when all higher-priority criteria tie, the route whose `NEXT_HOP`
/// has the lower IGP metric (as reported by the oracle) is preferred. If the
/// oracle returns `None` for either route the step is skipped.
///
/// Passing [`AlwaysReachable`] produces identical results to [`select_best`].
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use std::net::{IpAddr, Ipv4Addr};
/// use pathvector_rib::{PeerId, RouteBuilder, best_path::select_best_with_oracle};
/// use pathvector_rib::oracle::{AlwaysReachable, NextHopOracle};
/// use pathvector_types::{AsPath, Nlri, NextHop, Origin};
///
/// let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
/// let peer = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
///
/// let mut candidates = HashMap::new();
/// candidates.insert(peer, RouteBuilder::new(nlri, Origin::Igp, AsPath::new())
///     .next_hop(NextHop::V4(Ipv4Addr::new(192, 0, 2, 1)))
///     .build());
///
/// // With AlwaysReachable the route is kept.
/// assert!(select_best_with_oracle(&candidates, &AlwaysReachable).is_some());
/// ```
#[must_use]
pub fn select_best_with_oracle<'a, A: IpAddress, S: std::hash::BuildHasher>(
    candidates: &'a HashMap<PeerId, Route<A>, S>,
    oracle: &dyn NextHopOracle,
) -> Option<(PeerId, &'a Route<A>)> {
    // Step 1: exclude routes with unreachable next-hops.
    let reachable: Vec<_> = candidates
        .iter()
        .filter(|(_, route)| {
            route
                .next_hop
                .as_ref()
                .is_none_or(|nh| oracle.is_reachable(nh))
        })
        .collect();

    if reachable.is_empty() {
        return None;
    }

    // RFC 4271 §9.1.2.2 step 6: MED is only comparable within routes from the
    // same neighboring AS. A naive pairwise max_by comparator that conditionally
    // applies MED is non-transitive for 3+ routes across multiple ASes, producing
    // unspecified results. The correct algorithm:
    //
    //   1. Group routes by neighboring AS (first AS in the path).
    //   2. Select the best within each group — prefer() applies MED because all
    //      routes in a group share the same neighboring_as().
    //   3. Compare group winners — prefer() skips MED because winners come from
    //      different ASes, guaranteeing a total order for the final comparison.
    let mut groups: HashMap<Option<Asn>, Vec<(&PeerId, &Route<A>)>> = HashMap::new();
    for (peer, route) in &reachable {
        groups
            .entry(route.as_path.neighboring_as())
            .or_default()
            .push((peer, route));
    }

    let group_winners: Vec<_> = groups
        .into_values()
        .filter_map(|group| {
            group
                .into_iter()
                .max_by(|(pa, ra), (pb, rb)| prefer(pa, ra, pb, rb, oracle))
        })
        .collect();

    group_winners
        .into_iter()
        .max_by(|(pa, ra), (pb, rb)| prefer(pa, ra, pb, rb, oracle))
        .map(|(peer, route)| (*peer, route))
}

/// Best-path preference rank for RFC 4271 §9.1 steps 3/7, extended by RFC
/// 5065 §5.3.
///
/// `Local` beats `External`, which beats `Internal`/`ConfedMember` — the
/// latter two are a deliberate tie (RFC 5065 §5.3 requires confederation
/// Member-AS routes to be treated exactly like iBGP routes here). Do not
/// replace this with `PeerType`'s derived `Ord`: that comparison has no
/// concept of ties and only exists to support unrelated uses (e.g. sorting
/// for display).
fn peer_type_rank(pt: PeerType) -> u8 {
    match pt {
        PeerType::Internal | PeerType::ConfedMember => 0,
        PeerType::External => 1,
        PeerType::Local => 2,
    }
}

/// Compares two (peer, route) pairs and returns the ordering from the
/// perspective of route preference — `Ordering::Greater` means the first
/// pair is preferred.
///
/// [`Route::staleness`](crate::Route::staleness) is deliberately not read.
/// The only staleness this crate represents is conventional Graceful Restart
/// ([`Staleness::GrStale`](crate::Staleness::GrStale)), and RFC 9494 §1 says
/// of it: "in conventional GR, route preference is not affected" (RFC 4724
/// §4.2: "MUST NOT differentiate between stale and other routing information
/// during forwarding"). The least-preferred rule of RFC 9494 §4.4 belongs to
/// Long-Lived GR, which is not implemented; see
/// [`Staleness`](crate::Staleness).
fn prefer<A: IpAddress>(
    peer_a: &PeerId,
    a: &Route<A>,
    peer_b: &PeerId,
    b: &Route<A>,
    oracle: &dyn NextHopOracle,
) -> Ordering {
    // Step 2: Highest LOCAL_PREF (missing treated as the conventional default of 100).
    let lp = a
        .local_pref
        .unwrap_or(LocalPref::DEFAULT)
        .cmp(&b.local_pref.unwrap_or(LocalPref::DEFAULT));
    if lp != Ordering::Equal {
        return lp; // higher LOCAL_PREF → Greater → preferred
    }

    // Step 4: Shortest AS path length.
    let path_len = b.as_path.path_length().cmp(&a.as_path.path_length());
    if path_len != Ordering::Equal {
        return path_len; // reverse: shorter path_len(a) → Greater → preferred
    }

    // Step 5: Lowest ORIGIN value.
    let origin = b.origin.cmp(&a.origin);
    if origin != Ordering::Equal {
        return origin; // reverse: lower origin → Greater → preferred
    }

    // Step 6: Lowest MED (Multi-Exit Discriminator).
    // RFC 4271 §9.1.2.2: compare MED only between routes from the same
    // neighboring AS (first AS in path). Routes from different ASes skip
    // this step — MED is not a meaningful cross-AS metric.
    let neighbor_a = a.as_path.neighboring_as();
    let neighbor_b = b.as_path.neighboring_as();
    if neighbor_a.is_some() && neighbor_a == neighbor_b {
        let med_a = a.med.map_or(0, pathvector_types::Med::as_u32);
        let med_b = b.med.map_or(0, pathvector_types::Med::as_u32);
        let med = med_b.cmp(&med_a);
        if med != Ordering::Equal {
            return med; // reverse: lower MED → Greater → preferred
        }
    }

    // Steps 3/7: Prefer locally originated routes, then eBGP over iBGP
    // (RFC 4271 §9.1 steps 3 and 7). RFC 5065 §5.3: a confederation
    // Member-AS peer "MUST follow the same rules used for information
    // received from members inside the same autonomous system" — it ties
    // with Internal here, which `PeerType`'s derived `Ord` cannot express
    // (it has its own, unrelated discriminant). Use an explicit rank
    // instead of comparing the enum directly.
    let session = peer_type_rank(a.peer_type).cmp(&peer_type_rank(b.peer_type));
    if session != Ordering::Equal {
        return session;
    }

    // Step 8: Lowest IGP metric to NEXT_HOP (RFC 4271 §9.1.2.2 step 8).
    // Skipped when the oracle returns None for either route (AlwaysReachable,
    // or no FIB entry for the next-hop).
    let metric_a = a.next_hop.as_ref().and_then(|nh| oracle.igp_metric(nh));
    let metric_b = b.next_hop.as_ref().and_then(|nh| oracle.igp_metric(nh));
    if let (Some(ma), Some(mb)) = (metric_a, metric_b) {
        let metric = mb.cmp(&ma); // reverse: lower metric → Greater → preferred
        if metric != Ordering::Equal {
            return metric;
        }
    }

    // Step 9: Oldest eBGP route (RFC 4271 §9.1 step 9).
    // Only applies when both routes are eBGP — iBGP and local routes were
    // resolved at step 3/7.
    if a.peer_type == PeerType::External {
        let age = b.received_at.cmp(&a.received_at); // older (smaller u32) → Greater
        if age != Ordering::Equal {
            return age;
        }
    }

    // Step 10 (RFC 4271 §9.1.2.2 (f), amended by RFC 4456 §9): lowest
    // effective BGP Identifier — ORIGINATOR_ID if carried, else the peer's
    // BGP Identifier; unknown ranks last — then, the step RFC 4456 §9
    // inserts "between Steps f) and g)", shortest CLUSTER_LIST.
    let tie_break = TieBreakKey::of(b).cmp(&TieBreakKey::of(a));
    if tie_break != Ordering::Equal {
        return tie_break; // reverse: smaller key → Greater → preferred
    }

    // Step 11 (RFC 4271 §9.1.2.2 (g)): lowest peer address (final tie-breaker).
    peer_b.cmp(peer_a) // reverse: lower peer IP → Greater → preferred
}

/// The route-reflection-aware tie-breakers that precede RFC 4271 §9.1.2.2
/// (g), in decision order. The derived `Ord` is lexicographic over the
/// fields in declaration order, so a smaller key is preferred:
///
/// 1. `router_id` — step (f), with `ORIGINATOR_ID` substituted for the
///    advertising peer's BGP Identifier (RFC 4456 §9). See
///    [`EffectiveRouterId`] for the ordering, including unknown identifiers.
/// 2. `cluster_list_len` — RFC 4456 §9: "the following rule SHOULD be
///    inserted between Steps f) and g): a BGP Speaker SHOULD prefer a route
///    with the shorter `CLUSTER_LIST` length."
///
/// Each field is a total order, so the key — and with (g) a total order on
/// peer addresses, `prefer`'s tie-breaking tail — is transitive.
///
/// Only built when every earlier step has tied, so it is off the common
/// path; building it reads `Route::rare` without allocating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TieBreakKey {
    router_id: EffectiveRouterId,
    cluster_list_len: usize,
}

impl TieBreakKey {
    /// Equivalent to `(route.effective_router_id(), route.cluster_list_len())`
    /// (checked by `reflection_tests::prop_tie_break_key_matches_route_accessors`),
    /// but dereferences the boxed rare attributes once instead of twice.
    #[inline]
    fn of<A: IpAddress>(route: &Route<A>) -> Self {
        let (originator_id, cluster_list_len) = route
            .rare
            .as_deref()
            .map_or((None, 0), |r| (r.originator_id, r.cluster_list.len()));
        Self {
            router_id: EffectiveRouterId::for_route(route.peer_bgp_id, originator_id),
            cluster_list_len,
        }
    }
}

// ── Property tests ────────────────────────────────────────────────────────────
//
// Each proptest targets a specific RFC 4271 §9.1 decision step in isolation.
// Higher-priority criteria are held constant so the step under test is the
// only discriminator, giving us confidence the implementation is correct for
// *all* valid inputs, not just the hand-crafted cases in the unit tests below.

#[cfg(test)]
mod prop_tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    use std::cmp::Ordering;

    use pathvector_types::{AsPath, Asn, LocalPref, Med, Nlri, Origin, PeerType};
    use proptest::prelude::*;

    use super::{prefer, select_best};
    use crate::{PeerId, Route, RouteBuilder, Staleness, oracle::AlwaysReachable};

    // ── Shared helpers ────────────────────────────────────────────────────────

    fn nlri() -> Nlri<Ipv4Addr> {
        "10.0.0.0/8".parse().unwrap()
    }

    fn peer(last_octet: u8) -> PeerId {
        PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)))
    }

    fn make_path(len: usize) -> AsPath {
        if len == 0 {
            AsPath::new()
        } else {
            let asns: Vec<Asn> = (1..=u32::try_from(len).unwrap()).map(Asn::new).collect();
            AsPath::from_sequence(asns)
        }
    }

    fn arb_origin() -> impl Strategy<Value = Origin> {
        prop_oneof![
            Just(Origin::Igp),
            Just(Origin::Egp),
            Just(Origin::Incomplete),
        ]
    }

    // ── Structural invariants ─────────────────────────────────────────────────

    // A non-empty candidate set always yields Some.
    proptest! {
        #[test]
        fn prop_select_best_non_empty_returns_some(
            lp  in 0u32..=500u32,
            len in 0usize..=8usize,
            origin in arb_origin(),
        ) {
            let mut candidates = HashMap::new();
            candidates.insert(
                peer(1),
                RouteBuilder::new(nlri(), origin, make_path(len))
                    .local_pref(LocalPref::new(lp))
                    .build(),
            );
            prop_assert!(select_best(&candidates).is_some());
        }
    }

    // The winner is always one of the input candidates (no phantom routes).
    proptest! {
        #[test]
        fn prop_select_best_winner_is_in_candidates(
            lp_a in 0u32..=500u32,
            lp_b in 0u32..=500u32,
        ) {
            let mut candidates = HashMap::new();
            candidates.insert(peer(1), RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
                .local_pref(LocalPref::new(lp_a)).build());
            candidates.insert(peer(2), RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
                .local_pref(LocalPref::new(lp_b)).build());

            let (winner, _) = select_best(&candidates).unwrap();
            prop_assert!(candidates.contains_key(&winner));
        }
    }

    // ── Step 2: LOCAL_PREF (RFC 4271 §9.1.2) ─────────────────────────────────

    // Winner's effective LOCAL_PREF is always >= every other candidate's.
    // All other attributes are equal so LOCAL_PREF is the only discriminator.
    proptest! {
        #[test]
        fn prop_select_best_winner_has_highest_local_pref(
            lp_a in 0u32..=500u32,
            lp_b in 0u32..=500u32,
        ) {
            let mut candidates = HashMap::new();
            candidates.insert(peer(1), RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
                .local_pref(LocalPref::new(lp_a)).build());
            candidates.insert(peer(2), RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
                .local_pref(LocalPref::new(lp_b)).build());

            let (winner, winning_route) = select_best(&candidates).unwrap();
            let winning_lp = winning_route.local_pref.unwrap().as_u32();

            prop_assert!(winning_lp >= lp_a, "winner LP {} < lp_a {}", winning_lp, lp_a);
            prop_assert!(winning_lp >= lp_b, "winner LP {} < lp_b {}", winning_lp, lp_b);

            match lp_a.cmp(&lp_b) {
                std::cmp::Ordering::Greater => {
                    prop_assert_eq!(winner, peer(1), "peer(1) has higher LP");
                }
                std::cmp::Ordering::Less => {
                    prop_assert_eq!(winner, peer(2), "peer(2) has higher LP");
                }
                // Equal LP: falls through to tiebreaker — verified by the invariant above.
                std::cmp::Ordering::Equal => {}
            }
        }
    }

    // Absent LOCAL_PREF is treated as the conventional default (100).
    proptest! {
        #[test]
        fn prop_select_best_missing_local_pref_treated_as_100(
            explicit in 0u32..=500u32,
        ) {
            let with_lp = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
                .local_pref(LocalPref::new(explicit))
                .build();
            let without_lp = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
                .build(); // no LOCAL_PREF → treated as 100

            let mut candidates = HashMap::new();
            candidates.insert(peer(1), with_lp);
            candidates.insert(peer(2), without_lp);

            let (winner, _) = select_best(&candidates).unwrap();
            match explicit.cmp(&100) {
                std::cmp::Ordering::Greater => { prop_assert_eq!(winner, peer(1),
                    "explicit {} > default 100 — peer(1) should win", explicit); }
                std::cmp::Ordering::Less => { prop_assert_eq!(winner, peer(2),
                    "default 100 > explicit {} — peer(2) should win", explicit); }
                std::cmp::Ordering::Equal => {}
            }
            // explicit == 100: tie, falls to tiebreaker.
        }
    }

    // ── Step 4: AS path length (RFC 4271 §9.1.2.2) ───────────────────────────

    // Winner's AS path length is always <= every other candidate's.
    // LOCAL_PREF is identical so AS path length is the first discriminator.
    proptest! {
        #[test]
        fn prop_select_best_winner_has_shortest_as_path(
            len_a in 0usize..=8usize,
            len_b in 0usize..=8usize,
        ) {
            let mut candidates = HashMap::new();
            candidates.insert(peer(1), RouteBuilder::new(nlri(), Origin::Igp, make_path(len_a))
                .local_pref(LocalPref::new(100)).build());
            candidates.insert(peer(2), RouteBuilder::new(nlri(), Origin::Igp, make_path(len_b))
                .local_pref(LocalPref::new(100)).build());

            let (winner, winning_route) = select_best(&candidates).unwrap();
            let winning_len = winning_route.as_path.path_length();

            prop_assert!(winning_len <= len_a,
                "winner path len {} > len_a {}", winning_len, len_a);
            prop_assert!(winning_len <= len_b,
                "winner path len {} > len_b {}", winning_len, len_b);

            match len_a.cmp(&len_b) {
                std::cmp::Ordering::Less => { prop_assert_eq!(winner, peer(1), "peer(1) has shorter path"); }
                std::cmp::Ordering::Greater => { prop_assert_eq!(winner, peer(2), "peer(2) has shorter path"); }
                std::cmp::Ordering::Equal => {}
            }
        }
    }

    // ── Step 5: ORIGIN (RFC 4271 §9.1.2.2) ───────────────────────────────────

    // Winner's ORIGIN is always <= (lower = more preferred) every candidate's.
    // LOCAL_PREF and AS path are equal so ORIGIN is the first discriminator.
    proptest! {
        #[test]
        fn prop_select_best_winner_has_lowest_origin(
            origin_a in arb_origin(),
            origin_b in arb_origin(),
        ) {
            let mut candidates = HashMap::new();
            candidates.insert(peer(1), RouteBuilder::new(nlri(), origin_a, AsPath::new())
                .local_pref(LocalPref::new(100)).build());
            candidates.insert(peer(2), RouteBuilder::new(nlri(), origin_b, AsPath::new())
                .local_pref(LocalPref::new(100)).build());

            let (winner, winning_route) = select_best(&candidates).unwrap();

            prop_assert!(winning_route.origin <= origin_a,
                "winner origin {:?} > origin_a {:?}", winning_route.origin, origin_a);
            prop_assert!(winning_route.origin <= origin_b,
                "winner origin {:?} > origin_b {:?}", winning_route.origin, origin_b);

            match origin_a.cmp(&origin_b) {
                std::cmp::Ordering::Less => { prop_assert_eq!(winner, peer(1), "peer(1) has lower origin"); }
                std::cmp::Ordering::Greater => { prop_assert_eq!(winner, peer(2), "peer(2) has lower origin"); }
                std::cmp::Ordering::Equal => {}
            }
        }
    }

    // ── Step 6: MED (RFC 4271 §9.1.2.2) ─────────────────────────────────────

    // Winner's effective MED (None = 0) is always <= every candidate's.
    // LOCAL_PREF, AS path, and ORIGIN are equal so MED is the first discriminator.
    proptest! {
        #[test]
        fn prop_select_best_winner_has_lowest_med(
            med_a in proptest::option::of(0u32..=1_000u32),
            med_b in proptest::option::of(0u32..=1_000u32),
        ) {
            let eff_a = med_a.unwrap_or(0);
            let eff_b = med_b.unwrap_or(0);
            // Shared neighboring AS so MED comparison fires (RFC 4271 §9.1.2.2).
            let neighbor = AsPath::from_sequence(vec![Asn::new(65001)]);

            let mut ra = RouteBuilder::new(nlri(), Origin::Igp, neighbor.clone())
                .local_pref(LocalPref::new(100));
            if let Some(m) = med_a { ra = ra.med(Med::new(m)); }

            let mut rb = RouteBuilder::new(nlri(), Origin::Igp, neighbor)
                .local_pref(LocalPref::new(100));
            if let Some(m) = med_b { rb = rb.med(Med::new(m)); }

            let mut candidates = HashMap::new();
            candidates.insert(peer(1), ra.build());
            candidates.insert(peer(2), rb.build());

            let (winner, winning_route) = select_best(&candidates).unwrap();
            let winning_med = winning_route.med.map_or(0, Med::as_u32);

            prop_assert!(winning_med <= eff_a,
                "winner MED {} > eff_a {}", winning_med, eff_a);
            prop_assert!(winning_med <= eff_b,
                "winner MED {} > eff_b {}", winning_med, eff_b);

            match eff_a.cmp(&eff_b) {
                std::cmp::Ordering::Less => {
                    prop_assert_eq!(winner, peer(1), "peer(1) has lower MED");
                }
                std::cmp::Ordering::Greater => {
                    prop_assert_eq!(winner, peer(2), "peer(2) has lower MED");
                }
                std::cmp::Ordering::Equal => {}
            }
        }
    }

    // ── Step 7: eBGP preferred over iBGP (RFC 4271 §9.1.2.2) ────────────────

    // eBGP always beats iBGP when all higher steps tie.
    // The iBGP route is given the lower peer IP to confirm step 7 overrides
    // the IP tiebreaker at step 10.
    proptest! {
        #[test]
        fn prop_select_best_ebgp_beats_ibgp(
            lp  in 0u32..=300u32,
            len in 0usize..=5usize,
            origin in arb_origin(),
        ) {
            let ebgp = RouteBuilder::new(nlri(), origin, make_path(len))
                .local_pref(LocalPref::new(lp))
                .peer_type(PeerType::External)
                .build();
            let ibgp = RouteBuilder::new(nlri(), origin, make_path(len))
                .local_pref(LocalPref::new(lp))
                .peer_type(PeerType::Internal)
                .build();

            // iBGP gets the lower peer IP — if step 7 were skipped it would win.
            let mut candidates = HashMap::new();
            candidates.insert(peer(1), ibgp);  // lower IP, iBGP
            candidates.insert(peer(2), ebgp);  // higher IP, eBGP

            let (winner, _) = select_best(&candidates).unwrap();
            prop_assert_eq!(winner, peer(2), "eBGP must beat iBGP regardless of peer IP");
        }
    }

    // ── Step 10: tiebreaker — lowest peer IP (RFC 4271 §9.1.2.2) ────────────

    // When every attribute is identical, the numerically lowest peer IP wins.
    // ip_a (1..=127) is always < ip_b (128..=254) by construction.
    proptest! {
        #[test]
        fn prop_select_best_lower_peer_ip_wins_on_full_tie(
            ip_a in 1u8..=127u8,
            ip_b in 128u8..=254u8,
        ) {
            let route = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
                .local_pref(LocalPref::new(100))
                .build();

            let mut candidates = HashMap::new();
            candidates.insert(peer(ip_a), route.clone());
            candidates.insert(peer(ip_b), route);

            let (winner, _) = select_best(&candidates).unwrap();
            prop_assert_eq!(winner, peer(ip_a),
                "peer ...{} should beat ...{}", ip_a, ip_b);
        }
    }

    // ── Step (f): lowest BGP Identifier, before (g) peer IP (RFC 4271 §9.1.2.2) ──

    // Every candidate's peer IP is deliberately given the *opposite* order
    // from its BGP Identifier — id_a (1..=127) is always < id_b (128..=254),
    // but peer_a's session IP is always > peer_b's. If (f) were skipped
    // (the pre-fix bug), (g) would pick peer_b; (f) must pick peer_a instead.
    proptest! {
        #[test]
        fn prop_select_best_lower_bgp_identifier_wins_on_full_tie(
            id_a in 1u8..=127u8,
            id_b in 128u8..=254u8,
        ) {
            let route_a = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
                .local_pref(LocalPref::new(100))
                .peer_bgp_id(Ipv4Addr::new(id_a, id_a, id_a, id_a))
                .build();
            let route_b = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
                .local_pref(LocalPref::new(100))
                .peer_bgp_id(Ipv4Addr::new(id_b, id_b, id_b, id_b))
                .build();

            let mut candidates = HashMap::new();
            candidates.insert(peer(200), route_a); // higher peer IP, lower BGP Identifier
            candidates.insert(peer(50), route_b);  // lower peer IP, higher BGP Identifier

            let (winner, _) = select_best(&candidates).unwrap();
            prop_assert_eq!(winner, peer(200),
                "BGP Identifier {}...{} should beat {}...{} regardless of peer IP order",
                id_a, id_a, id_b, id_b);
        }
    }

    // ── Step 3: locally originated beats peer-learned (RFC 4271 §9.1) ────────

    proptest! {
        #[test]
        fn prop_select_best_locally_originated_beats_peer_learned(
            lp  in 0u32..=300u32,
            len in 0usize..=5usize,
            origin in arb_origin(),
        ) {
            let local = RouteBuilder::new(nlri(), origin, make_path(len))
                .local_pref(LocalPref::new(lp))
                .peer_type(PeerType::Local)
                .build();
            let ebgp = RouteBuilder::new(nlri(), origin, make_path(len))
                .local_pref(LocalPref::new(lp))
                .peer_type(PeerType::External)
                .build();

            // eBGP gets the lower peer IP — step 3 must override step 10.
            let mut candidates = HashMap::new();
            candidates.insert(peer(1), ebgp);   // lower IP, eBGP
            candidates.insert(peer(2), local);  // higher IP, Local

            let (winner, _) = select_best(&candidates).unwrap();
            prop_assert_eq!(winner, peer(2), "Local must beat eBGP regardless of peer IP");
        }
    }

    // ── Conventional GR staleness (RFC 4724 §4.2, RFC 9494 §1) ───────────────
    //
    // Arbitrary candidates over every attribute `prefer` reads, drawn from
    // deliberately narrow ranges so that ties — and therefore the later
    // decision steps — are common.

    /// Everything `prefer` reads from one candidate, plus its staleness.
    ///
    /// `bgp_id: None` is a route whose advertising peer's BGP Identifier is
    /// unknown; `originator_id`/`cluster_len` are the RFC 4456 attributes
    /// (`None`/`0` = not carried). The identifier ranges overlap so that
    /// `ORIGINATOR_ID` substitution (RFC 4456 §9) both ties and reorders.
    #[derive(Debug, Clone)]
    struct Candidate {
        local_pref: Option<u32>,
        neighbor_as: u32,
        path_len: usize,
        origin: Origin,
        med: Option<u32>,
        peer_type: PeerType,
        received_at: u32,
        bgp_id: Option<u8>,
        originator_id: Option<u8>,
        cluster_len: usize,
        staleness: Staleness,
    }

    fn arb_candidate() -> impl Strategy<Value = Candidate> {
        (
            prop::option::of(99u32..=101),
            1u32..=3,
            1usize..=3,
            arb_origin(),
            prop::option::of(0u32..=2),
            prop_oneof![
                Just(PeerType::Internal),
                Just(PeerType::ConfedMember),
                Just(PeerType::External),
                Just(PeerType::Local),
            ],
            0u32..=2,
            (
                prop::option::of(1u8..=3),
                prop::option::of(1u8..=3),
                0usize..=2,
            ),
            prop_oneof![Just(Staleness::Fresh), Just(Staleness::GrStale)],
        )
            .prop_map(
                |(
                    local_pref,
                    neighbor_as,
                    path_len,
                    origin,
                    med,
                    peer_type,
                    received_at,
                    (bgp_id, originator_id, cluster_len),
                    staleness,
                )| Candidate {
                    local_pref,
                    neighbor_as,
                    path_len,
                    origin,
                    med,
                    peer_type,
                    received_at,
                    bgp_id,
                    originator_id,
                    cluster_len,
                    staleness,
                },
            )
    }

    fn build(c: &Candidate) -> Route<Ipv4Addr> {
        let mut asns = vec![Asn::new(65_000 + c.neighbor_as)];
        asns.extend((1..c.path_len).map(|i| Asn::new(64_512 + u32::try_from(i).unwrap())));
        let mut b =
            RouteBuilder::new(nlri(), c.origin, AsPath::from_sequence(asns)).peer_type(c.peer_type);
        if let Some(lp) = c.local_pref {
            b = b.local_pref(LocalPref::new(lp));
        }
        if let Some(med) = c.med {
            b = b.med(Med::new(med));
        }
        let mut route = b.build();
        route.received_at = c.received_at;
        route.peer_bgp_id = c.bgp_id.map(|d| Ipv4Addr::new(10, 255, 0, d));
        if c.originator_id.is_some() || c.cluster_len > 0 {
            let rare = route.rare_mut();
            rare.originator_id = c.originator_id.map(|d| Ipv4Addr::new(10, 255, 0, d));
            rare.cluster_list = (1..=u32::try_from(c.cluster_len).unwrap()).collect();
        }
        route.staleness = c.staleness;
        route
    }

    proptest! {
        /// RFC 9494 §1: "in conventional GR, route preference is not
        /// affected"; RFC 4724 §4.2: "MUST NOT differentiate between stale
        /// and other routing information during forwarding". Marking any
        /// subset of the candidates `GrStale` must leave the selected peer
        /// exactly where it was with every candidate fresh.
        #[test]
        fn prop_conventional_gr_staleness_never_changes_the_winner(
            specs in prop::collection::vec(arb_candidate(), 1..=6),
        ) {
            let with_staleness: HashMap<_, _> = specs
                .iter()
                .enumerate()
                .map(|(i, c)| (peer(u8::try_from(i + 1).unwrap()), build(c)))
                .collect();
            let all_fresh: HashMap<_, _> = with_staleness
                .iter()
                .map(|(p, r)| {
                    let mut r = r.clone();
                    r.staleness = Staleness::Fresh;
                    (*p, r)
                })
                .collect();

            prop_assert_eq!(
                select_best(&with_staleness).map(|(p, _)| p),
                select_best(&all_fresh).map(|(p, _)| p),
            );
        }

        /// `prefer` must be a strict weak ordering — here, because every
        /// candidate has a distinct peer address and step (g) never ties,
        /// a strict total order — with staleness in the mix: irreflexive,
        /// asymmetric, total over distinct peers, and transitive over every
        /// ordered triple of 3–6 candidates. `max_by` over a relation that
        /// is not transitive returns an iteration-order-dependent winner.
        ///
        /// Two domains are checked, matching how `select_best_with_oracle`
        /// calls `prefer`: within one neighboring-AS group (MED compared),
        /// and across groups with MED absent (MED never decides). Across
        /// groups *with* MED, RFC 4271 §9.1.2.2 (c) is not transitive by
        /// design — that is why selection groups by neighboring AS first.
        ///
        /// Sets mix known and unknown BGP Identifiers, reflected and direct
        /// routes, and CLUSTER_LISTs of length 0–2. Before issue #69, step
        /// (f) was skipped when only one side's identifier was known, which
        /// is not transitive for such a mix; this property is the proof
        /// that the RFC 4456 §9 tie-breakers (effective identifier, then
        /// `CLUSTER_LIST` length, then peer address) keep the order total.
        /// The selected winner must also be the order's maximum.
        #[test]
        fn prop_prefer_is_a_strict_total_order(
            mut specs in prop::collection::vec(arb_candidate(), 3..=6),
            one_neighbor_group in any::<bool>(),
        ) {
            for c in &mut specs {
                if one_neighbor_group {
                    c.neighbor_as = 1;
                } else {
                    c.med = None;
                }
            }
            let cands: Vec<(PeerId, Route<Ipv4Addr>)> = specs
                .iter()
                .enumerate()
                .map(|(i, c)| (peer(u8::try_from(i + 1).unwrap()), build(c)))
                .collect();
            let cmp = |i: usize, j: usize| {
                prefer(&cands[i].0, &cands[i].1, &cands[j].0, &cands[j].1, &AlwaysReachable)
            };
            let n = cands.len();
            for i in 0..n {
                prop_assert_eq!(cmp(i, i), Ordering::Equal, "irreflexive");
                for j in 0..n {
                    if i == j {
                        continue;
                    }
                    prop_assert_ne!(cmp(i, j), Ordering::Equal, "total over distinct peers");
                    prop_assert_eq!(cmp(i, j), cmp(j, i).reverse(), "asymmetric");
                    for k in 0..n {
                        if k == i || k == j {
                            continue;
                        }
                        if cmp(i, j) == Ordering::Greater && cmp(j, k) == Ordering::Greater {
                            prop_assert_eq!(
                                cmp(i, k),
                                Ordering::Greater,
                                "transitive: {} > {} > {}", i, j, k
                            );
                        }
                    }
                }
            }
            if one_neighbor_group {
                let map: HashMap<_, _> = cands.iter().cloned().collect();
                let (best, _) = select_best(&map).unwrap();
                let w = cands.iter().position(|(p, _)| *p == best).unwrap();
                for j in (0..n).filter(|&j| j != w) {
                    prop_assert_eq!(cmp(w, j), Ordering::Greater, "winner is the maximum");
                }
            }
        }

        /// The pairwise form of the invariance property: flipping either
        /// side's staleness never changes the outcome of a comparison.
        #[test]
        fn prop_prefer_ignores_conventional_gr_staleness(
            a in arb_candidate(),
            b in arb_candidate(),
        ) {
            let (pa, pb) = (peer(1), peer(2));
            let ra = build(&a);
            let rb = build(&b);
            let expected = prefer(&pa, &ra, &pb, &rb, &AlwaysReachable);
            for sa in [Staleness::Fresh, Staleness::GrStale] {
                for sb in [Staleness::Fresh, Staleness::GrStale] {
                    let mut ra = ra.clone();
                    let mut rb = rb.clone();
                    ra.staleness = sa;
                    rb.staleness = sb;
                    prop_assert_eq!(prefer(&pa, &ra, &pb, &rb, &AlwaysReachable), expected);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use pathvector_types::{AsPath, Asn, LocalPref, Med, Nlri, Origin, PeerType};

    use crate::{RouteBuilder, Staleness};

    fn peer(last_octet: u8) -> PeerId {
        PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)))
    }

    fn nlri() -> Nlri<Ipv4Addr> {
        "10.0.0.0/8".parse().unwrap()
    }

    fn basic(
        origin: Origin,
        path_len: usize,
        lp: Option<u32>,
        med: Option<u32>,
    ) -> Route<Ipv4Addr> {
        let asns: Vec<_> = (1..=u32::try_from(path_len).unwrap())
            .map(Asn::new)
            .collect();
        let mut b = RouteBuilder::new(
            nlri(),
            origin,
            if asns.is_empty() {
                AsPath::new()
            } else {
                AsPath::from_sequence(asns)
            },
        );
        if let Some(v) = lp {
            b = b.local_pref(LocalPref::new(v));
        }
        if let Some(v) = med {
            b = b.med(Med::new(v));
        }
        b.build()
    }

    #[test]
    fn test_select_best_empty() {
        let candidates: HashMap<PeerId, Route<Ipv4Addr>> = HashMap::new();
        assert!(select_best(&candidates).is_none());
    }

    /// `basic` with `path_len = 0` takes the `asns.is_empty()` branch and builds
    /// a route with an empty `AS_PATH`. Exercises the otherwise-uncovered branch.
    #[test]
    fn test_select_best_with_empty_as_path() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 0, None, None));
        let result = select_best(&candidates);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, peer(1));
    }

    #[test]
    fn test_select_best_single_candidate() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(100), None));
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1));
    }

    #[test]
    fn test_select_best_prefers_higher_local_pref() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(200), None));
        candidates.insert(peer(2), basic(Origin::Igp, 2, Some(100), None));
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // LOCAL_PREF 200 > 100
    }

    #[test]
    fn test_select_best_missing_local_pref_treated_as_100() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, None, None)); // missing → 100
        candidates.insert(peer(2), basic(Origin::Igp, 2, Some(150), None)); // 150 wins
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(2));
    }

    #[test]
    fn test_select_best_prefers_shorter_as_path() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(100), None));
        candidates.insert(peer(2), basic(Origin::Igp, 5, Some(100), None));
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // AS path length 2 < 5
    }

    #[test]
    fn test_select_best_prefers_lower_origin() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(100), None));
        candidates.insert(peer(2), basic(Origin::Incomplete, 2, Some(100), None));
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // IGP=0 < INCOMPLETE=2
    }

    #[test]
    fn test_select_best_prefers_lower_med() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(100), Some(10)));
        candidates.insert(peer(2), basic(Origin::Igp, 2, Some(100), Some(100)));
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // MED 10 < 100
    }

    #[test]
    fn test_select_best_missing_med_treated_as_zero() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(100), None)); // MED → 0
        candidates.insert(peer(2), basic(Origin::Igp, 2, Some(100), Some(1))); // MED = 1
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // MED 0 < 1
    }

    #[test]
    fn test_med_ignored_for_different_neighboring_as() {
        // Routes from AS 65001 and AS 65002 — MED must not be compared across ASes.
        // The lower MED from AS 65002 must NOT win just because its MED is lower.
        // Tiebreaker falls through to step 10 (lower peer IP wins).
        let mut candidates = HashMap::new();
        candidates.insert(
            peer(1),
            RouteBuilder::new(
                nlri(),
                Origin::Igp,
                AsPath::from_sequence(vec![Asn::new(65001)]),
            )
            .local_pref(LocalPref::new(100))
            .med(Med::new(500))
            .build(),
        );
        candidates.insert(
            peer(2),
            RouteBuilder::new(
                nlri(),
                Origin::Igp,
                AsPath::from_sequence(vec![Asn::new(65002)]),
            )
            .local_pref(LocalPref::new(100))
            .med(Med::new(1))
            .build(),
        );
        let (winner, _) = select_best(&candidates).unwrap();
        // MED skipped — peer(1) wins on lower peer IP (step 10)
        assert_eq!(winner, peer(1));
    }

    #[test]
    fn test_med_compared_within_same_neighboring_as() {
        // Two routes both from AS 65001 — MED comparison applies.
        let mut candidates = HashMap::new();
        candidates.insert(
            peer(1),
            RouteBuilder::new(
                nlri(),
                Origin::Igp,
                AsPath::from_sequence(vec![Asn::new(65001)]),
            )
            .local_pref(LocalPref::new(100))
            .med(Med::new(200))
            .build(),
        );
        candidates.insert(
            peer(2),
            RouteBuilder::new(
                nlri(),
                Origin::Igp,
                AsPath::from_sequence(vec![Asn::new(65001)]),
            )
            .local_pref(LocalPref::new(100))
            .med(Med::new(50))
            .build(),
        );
        let (winner, _) = select_best(&candidates).unwrap();
        // MED 50 < 200 → peer(2) wins
        assert_eq!(winner, peer(2));
    }

    #[test]
    fn test_select_best_tiebreak_lower_peer_ip() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(100), None));
        candidates.insert(peer(2), basic(Origin::Igp, 2, Some(100), None));
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // lower peer IP wins
    }

    // ── Step (f)/(g): BGP Identifier before peer IP (RFC 4271 §9.1.2.2) ─────

    #[test]
    fn test_select_best_bgp_identifier_overrides_peer_ip_tiebreak() {
        // RFC 4271 §9.1.2.2 (f): the route from the peer with the *lowest
        // BGP Identifier* wins, evaluated before (g)'s peer-IP tiebreak.
        // peer(1) has the lower session IP but the higher BGP Identifier;
        // peer(2) has the higher session IP but the lower BGP Identifier.
        // (f) must decide this in favor of peer(2) — a peer-IP-only
        // comparator (the pre-fix behavior) would incorrectly pick peer(1).
        let route_a = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .peer_bgp_id(Ipv4Addr::new(9, 9, 9, 9))
            .build();
        let route_b = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .peer_bgp_id(Ipv4Addr::new(1, 1, 1, 1))
            .build();
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), route_a); // lower peer IP, higher BGP Identifier
        candidates.insert(peer(2), route_b); // higher peer IP, lower BGP Identifier
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(2)); // lower BGP Identifier wins despite higher peer IP
    }

    #[test]
    fn test_select_best_falls_back_to_peer_ip_when_bgp_identifier_unknown() {
        // When neither candidate has a known peer_bgp_id, step (f) has
        // nothing to compare and (g) peer-IP decides — the pre-fix
        // behavior, preserved for routes where the BGP Identifier isn't
        // tracked (e.g. built without going through the daemon's ingest
        // path that populates it).
        let route = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .build();
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), route.clone());
        candidates.insert(peer(2), route);
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // step (g): lower peer IP
    }

    #[test]
    fn test_select_best_known_bgp_identifier_beats_unknown() {
        // Corrected for issue #69. This test used to assert that (f) is
        // *skipped* when only one side's identifier is known, letting (g)
        // decide. That rule is not transitive (see
        // `reflection_tests::unknown_identifier_ranks_after_every_known_identifier_transitively`
        // for the three-route cycle it produces), and RFC 4271 §9.1.2.2 has
        // no "skip" clause for (f). An unknown identifier now ranks after
        // every known one, so the route with the known identifier wins even
        // from the higher peer address.
        let with_id = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .peer_bgp_id(Ipv4Addr::new(1, 1, 1, 1))
            .build();
        let without_id = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .build();
        let mut with_id = with_id;
        let mut without_id = without_id;
        // Same received_at so step 9 (oldest eBGP route) cannot decide.
        with_id.received_at = 0;
        without_id.received_at = 0;
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), without_id); // lower peer IP, no known BGP Identifier
        candidates.insert(peer(2), with_id); // higher peer IP, known BGP Identifier
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(2)); // (f): known identifier ranks first
    }

    #[test]
    fn test_select_best_local_pref_beats_path_length() {
        // A route with higher LOCAL_PREF wins even if its AS path is longer.
        // LOCAL_PREF is evaluated before AS path length in the decision process.
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 10, Some(200), None)); // long path, high LP
        candidates.insert(peer(2), basic(Origin::Igp, 1, Some(100), None)); // short path, low LP
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1));
    }

    #[test]
    fn test_select_best_returns_correct_route_reference() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(200), None));
        candidates.insert(peer(2), basic(Origin::Igp, 2, Some(100), None));
        let (_, route) = select_best(&candidates).unwrap();
        assert_eq!(route.local_pref, Some(LocalPref::new(200)));
    }

    // ── Step 7: eBGP preferred over iBGP (RFC 4271 §9.1) ─────────────────────

    #[test]
    fn test_select_best_prefers_ebgp_over_ibgp() {
        // All attributes equal — eBGP route wins over iBGP route at step 7.
        let ebgp = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(100))
            .peer_type(PeerType::External)
            .build();
        let ibgp = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(100))
            .peer_type(PeerType::Internal)
            .build();
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), ibgp);
        candidates.insert(peer(2), ebgp);
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(2)); // eBGP peer wins
    }

    #[test]
    fn test_local_pref_beats_ebgp_preference() {
        // A higher LOCAL_PREF on an iBGP route overrules the eBGP preference at
        // step 7 — LOCAL_PREF is evaluated first at step 2.
        let ebgp = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(100))
            .peer_type(PeerType::External)
            .build();
        let ibgp = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(200))
            .peer_type(PeerType::Internal)
            .build();
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), ibgp);
        candidates.insert(peer(2), ebgp);
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // higher LOCAL_PREF on iBGP route wins
    }

    #[test]
    fn test_two_ebgp_routes_fall_through_to_tiebreak() {
        // When both routes are eBGP the step-7 comparison is Equal and
        // resolution continues to step 10 (lower peer IP).
        let route = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .build();
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), route.clone());
        candidates.insert(peer(2), route);
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // step 10: lower peer IP
    }

    // ── RFC 5065 §5.3: ConfedMember ties with Internal ───────────────────────

    #[test]
    fn test_confed_member_ties_with_internal_falls_through_to_tiebreak() {
        // RFC 5065 §5.3: a confederation Member-AS peer's routes "MUST
        // follow the same rules used for information received from members
        // inside the same autonomous system" — ConfedMember must NOT win
        // outright at step 3/7 the way External does; it ties with
        // Internal and falls through to a later tiebreak (step 10: BGP ID).
        let confed = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(100))
            .peer_type(PeerType::ConfedMember)
            .peer_bgp_id(Ipv4Addr::new(9, 9, 9, 9))
            .build();
        let ibgp = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(100))
            .peer_type(PeerType::Internal)
            .peer_bgp_id(Ipv4Addr::new(1, 1, 1, 1))
            .build();
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), confed);
        candidates.insert(peer(2), ibgp);
        let (winner, _) = select_best(&candidates).unwrap();
        // Lower BGP ID wins at step 10, proving step 3/7 was a tie.
        assert_eq!(winner, peer(2));
    }

    #[test]
    fn test_confed_member_beaten_by_external() {
        // Step 7 preference (eBGP over iBGP) still holds against
        // ConfedMember specifically — only Internal ties with it.
        let confed = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(100))
            .peer_type(PeerType::ConfedMember)
            .build();
        let ebgp = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(100))
            .peer_type(PeerType::External)
            .build();
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), confed);
        candidates.insert(peer(2), ebgp);
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(2)); // eBGP peer wins
    }

    #[test]
    fn test_confed_member_beaten_by_local() {
        let confed = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(100))
            .peer_type(PeerType::ConfedMember)
            .build();
        let local = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(100))
            .peer_type(PeerType::Local)
            .build();
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), confed);
        candidates.insert(peer(2), local);
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(2)); // locally originated wins
    }

    // ── Step 3: locally originated (RFC 4271 §9.1 step 3) ───────────────────

    #[test]
    fn test_locally_originated_beats_ebgp() {
        let local = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(100))
            .peer_type(PeerType::Local)
            .build();
        let ebgp = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(100))
            .peer_type(PeerType::External)
            .build();
        // eBGP gets the lower peer IP — step 3 must override step 10.
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), ebgp);
        candidates.insert(peer(2), local);
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(2)); // Local beats eBGP
    }

    #[test]
    fn test_locally_originated_beats_ibgp() {
        let local = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .peer_type(PeerType::Local)
            .build();
        let ibgp = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .peer_type(PeerType::Internal)
            .build();
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), ibgp);
        candidates.insert(peer(2), local);
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(2)); // Local beats iBGP
    }

    #[test]
    fn test_local_pref_still_overrides_local_origin() {
        // LOCAL_PREF (step 2) is evaluated before source type (step 3).
        // An iBGP route with a very high LOCAL_PREF beats a locally
        // originated route with a low LOCAL_PREF.
        let local = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(50))
            .peer_type(PeerType::Local)
            .build();
        let ibgp = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(200))
            .peer_type(PeerType::Internal)
            .build();
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), ibgp);
        candidates.insert(peer(2), local);
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // higher LOCAL_PREF wins over Local origin
    }

    // ── Step 9: oldest eBGP route (RFC 4271 §9.1 step 9) ────────────────────

    #[test]
    fn test_select_best_prefers_older_ebgp_route() {
        let older = {
            let mut r = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
                .peer_type(PeerType::External)
                .build();
            r.received_at = r.received_at.saturating_sub(60);
            r
        };
        let newer = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .build();

        // newer gets the lower peer IP — step 9 must override step 10.
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), newer);
        candidates.insert(peer(2), older);
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(2)); // older route preferred
    }

    #[test]
    fn test_step9_only_applies_to_ebgp() {
        // iBGP route that is very old — should NOT win over a newer eBGP route
        // because step 3/7 resolves in favour of eBGP first.
        let old_ibgp = {
            let mut r = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
                .peer_type(PeerType::Internal)
                .build();
            r.received_at = r.received_at.saturating_sub(3600);
            r
        };
        let new_ebgp = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .build();

        let mut candidates = HashMap::new();
        candidates.insert(peer(1), old_ibgp);
        candidates.insert(peer(2), new_ebgp);
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(2)); // eBGP wins at step 3/7 before step 9 fires
    }

    // ── Conventional Graceful Restart staleness (RFC 4724 §4.2) ──────────────
    //
    // RFC 4724 §4.2: the Receiving Speaker "MUST retain the routes received
    // from the peer [...] and MUST mark them as stale routing information
    // [...] The router MUST NOT differentiate between stale and other
    // routing information during forwarding." RFC 8538 §4.1 restates that
    // sentence unchanged. RFC 9494 §1: "in conventional GR, route preference
    // is not affected." Only Long-Lived GR depreferences retained routes
    // (RFC 9494 §4.3/§4.4), and only for a speaker that advertised the LLGR
    // Capability, which pathvectord does not. Every expectation below follows
    // from that: a `GrStale` route is compared exactly as if it were fresh.

    fn gr_stale(mut route: Route<Ipv4Addr>) -> Route<Ipv4Addr> {
        route.staleness = Staleness::GrStale;
        route
    }

    /// Issue #68 acceptance case: the selected `LOCAL_PREF` 300 route is
    /// marked stale while a fresh `LOCAL_PREF` 100 alternative exists. RFC
    /// 9494 §1 ("route preference is not affected") plus RFC 4271 §9.1.1
    /// (`LOCAL_PREF` is the degree of preference) → the stale route keeps
    /// winning. The stale route is on the *higher* peer address so the
    /// final tie-breaker (§9.1.2.2 (g)) cannot be what decides it.
    #[test]
    fn conventional_gr_stale_route_keeps_its_higher_local_pref_preference() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(2), gr_stale(basic(Origin::Igp, 1, Some(300), None)));
        candidates.insert(peer(1), basic(Origin::Igp, 1, Some(100), None));

        let (winner, route) = select_best(&candidates).unwrap();
        assert_eq!(
            winner,
            peer(2),
            "RFC 9494 §1: a conventional-GR stale route keeps its LOCAL_PREF preference"
        );
        assert_eq!(route.staleness, Staleness::GrStale);
    }

    /// The reverse direction: a stale route with *lower* preference still
    /// loses to a fresh, more-preferred route — staleness neither helps nor
    /// hurts.
    #[test]
    fn conventional_gr_stale_route_with_lower_local_pref_still_loses() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), gr_stale(basic(Origin::Igp, 1, Some(100), None)));
        candidates.insert(peer(2), basic(Origin::Igp, 1, Some(300), None));

        assert_eq!(select_best(&candidates).unwrap().0, peer(2));
    }

    /// Each later decision step still decides between a stale and a fresh
    /// route: AS path length (§9.1.2.2 (a)), ORIGIN (b), MED (c). In every
    /// case the stale route holds the advantage and must win.
    #[test]
    fn conventional_gr_stale_route_wins_on_every_later_decision_step() {
        let cases = [
            (
                "AS_PATH length",
                basic(Origin::Igp, 1, None, None),
                basic(Origin::Igp, 3, None, None),
            ),
            (
                "ORIGIN",
                basic(Origin::Igp, 1, None, None),
                basic(Origin::Incomplete, 1, None, None),
            ),
            (
                "MED",
                basic(Origin::Igp, 1, None, Some(10)),
                basic(Origin::Igp, 1, None, Some(20)),
            ),
        ];
        for (step, better, worse) in cases {
            let mut candidates = HashMap::new();
            // Stale route on the higher address so (g) would pick the fresh one.
            candidates.insert(peer(9), gr_stale(better));
            candidates.insert(peer(1), worse);
            assert_eq!(
                select_best(&candidates).unwrap().0,
                peer(9),
                "{step}: the stale route's better attribute must decide, not its staleness"
            );
        }
    }

    /// With every attribute equal, ordinary RFC 4271 §9.1.2.2 tie-breaking
    /// applies: (f) lowest BGP Identifier, else (g) lowest peer address.
    /// Staleness is not an extra tie-breaker in either direction.
    #[test]
    fn conventional_gr_staleness_is_not_a_tie_breaker() {
        // (g) lowest peer address: the stale route on peer(1) wins.
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), gr_stale(basic(Origin::Igp, 1, Some(100), None)));
        candidates.insert(peer(2), basic(Origin::Igp, 1, Some(100), None));
        assert_eq!(
            select_best(&candidates).unwrap().0,
            peer(1),
            "§9.1.2.2 (g): lower peer address wins even though it is stale"
        );

        // Swap which side is stale: the answer must not move.
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 1, Some(100), None));
        candidates.insert(peer(2), gr_stale(basic(Origin::Igp, 1, Some(100), None)));
        assert_eq!(select_best(&candidates).unwrap().0, peer(1));

        // (f) lowest BGP Identifier: the stale route on the higher peer
        // address but with the lower router-id wins.
        let mut stale = gr_stale(basic(Origin::Igp, 1, Some(100), None));
        stale.peer_bgp_id = Some(Ipv4Addr::new(1, 1, 1, 1));
        let mut fresh = basic(Origin::Igp, 1, Some(100), None);
        fresh.peer_bgp_id = Some(Ipv4Addr::new(9, 9, 9, 9));
        let mut candidates = HashMap::new();
        candidates.insert(peer(2), stale);
        candidates.insert(peer(1), fresh);
        assert_eq!(
            select_best(&candidates).unwrap().0,
            peer(2),
            "§9.1.2.2 (f): lower BGP Identifier wins even though it is stale"
        );
    }

    /// RFC 4724 §4.2: retained routes remain usable, so a stale route is
    /// selected when it is the only candidate.
    #[test]
    fn stale_route_wins_when_only_candidate() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), gr_stale(basic(Origin::Igp, 1, Some(100), None)));
        assert!(
            select_best(&candidates).is_some(),
            "stale-only RIB must still yield a winner"
        );
    }

    /// Two stale candidates are compared by the ordinary criteria
    /// (`LOCAL_PREF` here).
    #[test]
    fn two_stale_routes_compared_normally() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), gr_stale(basic(Origin::Igp, 1, Some(200), None)));
        candidates.insert(peer(2), gr_stale(basic(Origin::Igp, 1, Some(100), None)));
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(
            winner,
            peer(1),
            "among stale routes, higher LOCAL_PREF still wins"
        );
    }
}

// ── NextHopOracle tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod oracle_tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    use pathvector_types::{AsPath, NextHop, Nlri, Origin};

    use crate::{PeerId, RouteBuilder, best_path::select_best_with_oracle, oracle::NextHopOracle};

    fn peer(last_octet: u8) -> PeerId {
        PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)))
    }

    fn nlri() -> Nlri<Ipv4Addr> {
        "10.0.0.0/24".parse().unwrap()
    }

    fn nh(a: u8, b: u8, c: u8, d: u8) -> NextHop {
        NextHop::V4(Ipv4Addr::new(a, b, c, d))
    }

    // Oracle that rejects a single specific next-hop address.
    struct RejectOracle(Ipv4Addr);

    impl NextHopOracle for RejectOracle {
        fn is_reachable(&self, next_hop: &NextHop) -> bool {
            match next_hop {
                NextHop::V4(ip) => *ip != self.0,
                _ => true,
            }
        }
        fn igp_metric(&self, _: &NextHop) -> Option<u32> {
            None
        }
    }

    // Oracle that assigns a fixed metric to next-hops by last octet.
    struct MetricOracle;

    impl NextHopOracle for MetricOracle {
        fn is_reachable(&self, _: &NextHop) -> bool {
            true
        }
        fn igp_metric(&self, next_hop: &NextHop) -> Option<u32> {
            match next_hop {
                NextHop::V4(ip) => Some(u32::from(ip.octets()[3])),
                _ => None,
            }
        }
    }

    /// Step 1: a route whose `NEXT_HOP` the oracle rejects is excluded from
    /// best-path selection even if it would otherwise win on all other criteria.
    #[test]
    fn test_unreachable_next_hop_excluded_from_selection() {
        let unreachable_nh = Ipv4Addr::new(192, 0, 2, 1);
        let reachable_nh = Ipv4Addr::new(192, 0, 2, 2);

        // peer(1) has a higher-metric LOCAL_PREF (would win step 2) but an
        // unreachable NEXT_HOP, so it should be filtered out at step 1.
        let winner_route = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(unreachable_nh))
            .build();
        let loser_route = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(reachable_nh))
            .build();

        let mut candidates = HashMap::new();
        candidates.insert(peer(1), winner_route); // unreachable next-hop
        candidates.insert(peer(2), loser_route); // reachable next-hop

        let oracle = RejectOracle(unreachable_nh);
        let (winner, _) = select_best_with_oracle(&candidates, &oracle).unwrap();
        assert_eq!(winner, peer(2), "reachable route must win over unreachable");
    }

    /// Step 1: when all candidates have unreachable next-hops, no route is
    /// selected (no best path).
    #[test]
    fn test_all_unreachable_returns_none() {
        let bad = Ipv4Addr::new(192, 0, 2, 1);
        let route = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(bad))
            .build();

        let mut candidates = HashMap::new();
        candidates.insert(peer(1), route);

        let oracle = RejectOracle(bad);
        assert!(
            select_best_with_oracle(&candidates, &oracle).is_none(),
            "no reachable candidates → no best path"
        );
    }

    /// Step 8: when all other criteria tie, the route with the lower IGP
    /// metric to its `NEXT_HOP` is preferred.
    #[test]
    fn test_step8_lower_igp_metric_preferred() {
        // Both routes are otherwise identical; peer(1) has metric 10
        // (next-hop last octet = 10), peer(2) has metric 20.
        let route_low_metric = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .next_hop(nh(192, 0, 2, 10)) // metric = 10
            .build();
        let route_high_metric = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .next_hop(nh(192, 0, 2, 20)) // metric = 20
            .build();

        // Give the high-metric route the lower peer IP so step 10 would pick
        // it without the oracle — step 8 must fire first.
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), route_high_metric); // lower IP, higher metric
        candidates.insert(peer(2), route_low_metric); // higher IP, lower metric

        let (winner, _) = select_best_with_oracle(&candidates, &MetricOracle).unwrap();
        assert_eq!(winner, peer(2), "lower IGP metric must win before step 10");
    }

    /// Step 8 is skipped when oracle returns None — falls through to step 10.
    #[test]
    fn test_step8_skipped_when_oracle_returns_none() {
        use crate::oracle::AlwaysReachable;

        let route_a = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .next_hop(nh(192, 0, 2, 1))
            .build();
        let route_b = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .next_hop(nh(192, 0, 2, 2))
            .build();

        let mut candidates = HashMap::new();
        candidates.insert(peer(1), route_a); // lower IP
        candidates.insert(peer(2), route_b);

        // AlwaysReachable returns None for igp_metric → step 8 skipped → step 10 picks peer(1).
        let (winner, _) = select_best_with_oracle(&candidates, &AlwaysReachable).unwrap();
        assert_eq!(
            winner,
            peer(1),
            "step 10 (lower peer IP) should win when step 8 is skipped"
        );
    }
}

// ── RFC 4456 §9: reflected-route tie-breakers ────────────────────────────────
//
// RFC 4456 §9 ("Impact on Route Selection") modifies RFC 4271 §9.1.2.2:
//
//   "If a route carries the ORIGINATOR_ID attribute, then in Step f) the
//    ORIGINATOR_ID SHOULD be treated as the BGP Identifier of the BGP
//    speaker that has advertised the route.
//
//    In addition, the following rule SHOULD be inserted between Steps f)
//    and g): a BGP Speaker SHOULD prefer a route with the shorter
//    CLUSTER_LIST length.  The CLUSTER_LIST length is zero if a route does
//    not carry the CLUSTER_LIST attribute."
//
// RFC 4271 §9.1.2.2: "The criteria MUST be applied in the order specified."
// (f) "Remove from consideration all routes other than the route that was
// advertised by the BGP speaker with the lowest BGP Identifier value."
// (g) "Prefer the route received from the lowest peer address."
//
// Every expectation below is derived from those clauses, not from the
// implementation. Each candidate is an iBGP route tied with the other through
// (e) — same LOCAL_PREF, AS_PATH, ORIGIN, MED, and source type, and no IGP
// metric (`AlwaysReachable`) — so only (f), the inserted CLUSTER_LIST step,
// and (g) can separate them.

#[cfg(test)]
mod reflection_tests {
    use std::cmp::Ordering;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    use pathvector_types::{AsPath, Asn, LocalPref, Nlri, Origin, PeerType};

    use super::{prefer, select_best};
    use crate::{PeerId, Route, RouteBuilder, oracle::AlwaysReachable};

    fn peer(last_octet: u8) -> PeerId {
        PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)))
    }

    fn id(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    /// An iBGP route tied with every other route from this helper through
    /// RFC 4271 §9.1.2.2 (e). `peer_bgp_id` is the advertising neighbor's
    /// OPEN identifier; `originator_id`/`cluster_list` are the RFC 4456
    /// attributes the route carries (`None`/empty = not carried).
    fn ibgp(
        peer_bgp_id: Option<Ipv4Addr>,
        originator_id: Option<Ipv4Addr>,
        cluster_list: &[u32],
    ) -> Route<Ipv4Addr> {
        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let mut route = RouteBuilder::new(
            nlri,
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65100)]),
        )
        .local_pref(LocalPref::new(100))
        .peer_type(PeerType::Internal)
        .build();
        route.received_at = 0;
        route.peer_bgp_id = peer_bgp_id;
        if originator_id.is_some() || !cluster_list.is_empty() {
            let rare = route.rare_mut();
            rare.originator_id = originator_id;
            rare.cluster_list = cluster_list.to_vec();
        }
        route
    }

    fn winner(candidates: Vec<(PeerId, Route<Ipv4Addr>)>) -> PeerId {
        let map: HashMap<_, _> = candidates.into_iter().collect();
        select_best(&map).expect("non-empty").0
    }

    fn cmp(pa: PeerId, a: &Route<Ipv4Addr>, pb: PeerId, b: &Route<Ipv4Addr>) -> Ordering {
        prefer(&pa, a, &pb, b, &AlwaysReachable)
    }

    /// Issue #69 acceptance case 1. Reflector A (BGP Identifier 1.1.1.1)
    /// carries `ORIGINATOR_ID` 9.9.9.9; reflector B (2.2.2.2) carries
    /// 3.3.3.3. RFC 4456 §9: step (f) compares the `ORIGINATOR_ID`s, so B's
    /// 3.3.3.3 beats A's 9.9.9.9 — although A's reflector identifier is
    /// lower and A sits on the lower peer address ((g) would pick A too).
    #[test]
    fn rfc4456_originator_id_replaces_reflector_bgp_identifier_in_step_f() {
        let a = ibgp(Some(id(1, 1, 1, 1)), Some(id(9, 9, 9, 9)), &[100]);
        let b = ibgp(Some(id(2, 2, 2, 2)), Some(id(3, 3, 3, 3)), &[200]);
        assert_eq!(
            winner(vec![(peer(1), a.clone()), (peer(2), b.clone())]),
            peer(2),
            "RFC 4456 §9: ORIGINATOR_ID 3.3.3.3 < 9.9.9.9 decides step (f)"
        );
        assert_eq!(cmp(peer(2), &b, peer(1), &a), Ordering::Greater);
        assert_eq!(cmp(peer(1), &a, peer(2), &b), Ordering::Less);
    }

    /// Issue #69 acceptance case 2. Both routes were originated by 9.9.9.9 and
    /// reached us through different reflectors, so their step-(f)
    /// identifiers tie. RFC 4456 §9 inserts "prefer a route with the shorter
    /// `CLUSTER_LIST` length" before (g): B's one-entry list beats A's
    /// two-entry list although A has both the lower reflector identifier and
    /// the lower peer address.
    #[test]
    fn rfc4456_shorter_cluster_list_wins_when_originator_ids_tie() {
        let a = ibgp(Some(id(1, 1, 1, 1)), Some(id(9, 9, 9, 9)), &[100, 300]);
        let b = ibgp(Some(id(2, 2, 2, 2)), Some(id(9, 9, 9, 9)), &[200]);
        assert_eq!(
            winner(vec![(peer(1), a), (peer(2), b)]),
            peer(2),
            "RFC 4456 §9: one-entry CLUSTER_LIST beats two-entry when (f) ties"
        );
    }

    /// The `CLUSTER_LIST` step sits *between* (f) and (g): with the identifier
    /// tied and no `ORIGINATOR_ID` on either side (two sessions to the same
    /// speaker), the shorter list wins over the lower peer address.
    #[test]
    fn rfc4456_cluster_list_length_is_compared_before_peer_address() {
        let a = ibgp(Some(id(5, 5, 5, 5)), None, &[100, 300]);
        let b = ibgp(Some(id(5, 5, 5, 5)), None, &[200]);
        assert_eq!(
            winner(vec![(peer(1), a), (peer(2), b)]),
            peer(2),
            "RFC 4456 §9: CLUSTER_LIST length is decided before (g) peer address"
        );
    }

    /// "The `CLUSTER_LIST` length is zero if a route does not carry the
    /// `CLUSTER_LIST` attribute." A route without the attribute beats one
    /// with a one-entry list when (f) ties, despite the higher peer address.
    #[test]
    fn rfc4456_absent_cluster_list_counts_as_length_zero() {
        let reflected = ibgp(Some(id(5, 5, 5, 5)), Some(id(5, 5, 5, 5)), &[100]);
        let direct = ibgp(Some(id(5, 5, 5, 5)), None, &[]);
        assert_eq!(
            winner(vec![(peer(1), reflected), (peer(2), direct)]),
            peer(2),
            "absent CLUSTER_LIST = length 0 < 1"
        );
    }

    /// The `CLUSTER_LIST` rule is inserted *after* (f): a lower effective
    /// identifier wins even with the longer `CLUSTER_LIST`.
    #[test]
    fn rfc4456_step_f_is_decided_before_cluster_list_length() {
        let a = ibgp(Some(id(8, 8, 8, 8)), Some(id(1, 1, 1, 1)), &[100, 200, 300]);
        let b = ibgp(Some(id(7, 7, 7, 7)), Some(id(2, 2, 2, 2)), &[400]);
        assert_eq!(
            winner(vec![(peer(2), a), (peer(1), b)]),
            peer(2),
            "(f): ORIGINATOR_ID 1.1.1.1 wins before the CLUSTER_LIST step"
        );
    }

    /// Neither route carries `ORIGINATOR_ID`: RFC 4271 §9.1.2.2 (f) applies
    /// unchanged and compares the advertising peers' BGP Identifiers.
    #[test]
    fn non_reflected_routes_compare_peer_bgp_identifiers() {
        let a = ibgp(Some(id(9, 9, 9, 9)), None, &[]);
        let b = ibgp(Some(id(1, 1, 1, 1)), None, &[]);
        assert_eq!(
            winner(vec![(peer(1), a), (peer(2), b)]),
            peer(2),
            "(f): lower BGP Identifier wins over lower peer address"
        );
    }

    /// A route learned directly from its originator (no `ORIGINATOR_ID`) and a
    /// reflected one are compared on the same footing: the direct route's
    /// (f) identifier is its peer's BGP Identifier, the reflected route's is
    /// its `ORIGINATOR_ID`. Here the direct speaker 5.5.5.5 beats the reflected
    /// route's originator 7.7.7.7 even though the reflector's own identifier
    /// (1.1.1.1) is lower — the pre-fix comparator picked the reflected route.
    #[test]
    fn mixed_direct_and_reflected_compare_peer_id_against_originator_id() {
        let direct = ibgp(Some(id(5, 5, 5, 5)), None, &[]);
        let reflected = ibgp(Some(id(1, 1, 1, 1)), Some(id(7, 7, 7, 7)), &[100]);
        assert_eq!(
            winner(vec![
                (peer(2), direct.clone()),
                (peer(1), reflected.clone())
            ]),
            peer(2),
            "(f): 5.5.5.5 (direct peer) < 7.7.7.7 (ORIGINATOR_ID)"
        );

        // And the other way round: the reflected route's originator is lower.
        let direct = ibgp(Some(id(5, 5, 5, 5)), None, &[]);
        let reflected = ibgp(Some(id(9, 9, 9, 9)), Some(id(3, 3, 3, 3)), &[100]);
        assert_eq!(
            winner(vec![(peer(1), direct), (peer(2), reflected)]),
            peer(2),
            "(f): 3.3.3.3 (ORIGINATOR_ID) < 5.5.5.5 (direct peer)"
        );
    }

    /// RFC 4456 §9 keys the substitution on the route *carrying*
    /// `ORIGINATOR_ID`, not on the peer's identifier being known: a route
    /// with `ORIGINATOR_ID` but no recorded peer BGP Identifier still has a
    /// step-(f) identifier.
    #[test]
    fn originator_id_supplies_the_identifier_when_peer_bgp_id_is_unknown() {
        let reflected = ibgp(None, Some(id(1, 1, 1, 1)), &[100]);
        let direct = ibgp(Some(id(2, 2, 2, 2)), None, &[]);
        assert_eq!(
            winner(vec![(peer(2), reflected), (peer(1), direct)]),
            peer(2),
            "(f): ORIGINATOR_ID 1.1.1.1 < 2.2.2.2"
        );
    }

    /// The tie-breakers never override an earlier step: a reflected route
    /// with a better `ORIGINATOR_ID` and shorter `CLUSTER_LIST` still loses on
    /// `LOCAL_PREF` and on `AS_PATH` length.
    #[test]
    fn rfc4456_tie_breakers_never_override_earlier_steps() {
        let better_ids = ibgp(Some(id(1, 1, 1, 1)), Some(id(1, 1, 1, 1)), &[]);
        let mut higher_lp = ibgp(Some(id(9, 9, 9, 9)), Some(id(9, 9, 9, 9)), &[1, 2, 3]);
        higher_lp.local_pref = Some(LocalPref::new(200));
        assert_eq!(
            winner(vec![(peer(1), better_ids.clone()), (peer(2), higher_lp)]),
            peer(2),
            "LOCAL_PREF decides before any tie-breaker"
        );

        let mut shorter_path = ibgp(Some(id(9, 9, 9, 9)), Some(id(9, 9, 9, 9)), &[1, 2, 3]);
        shorter_path.as_path = std::sync::Arc::new(AsPath::new());
        assert_eq!(
            winner(vec![(peer(1), better_ids), (peer(2), shorter_path)]),
            peer(2),
            "(a) AS_PATH length decides before any tie-breaker"
        );
    }

    /// Missing-identifier policy, and the transitivity it buys. RFC 4271
    /// gives no rule for a route whose step-(f) identifier is unknown (only
    /// a route from outside a session — e.g. one built without
    /// `peer_bgp_id` — can lack one). Skipping (f) whenever *either* side
    /// is unknown is not transitive: with a = 1.1.1.1 on .3, b = unknown on
    /// .2, c = 1.1.1.2 on .1 it gives a ≻ c by (f), c ≻ b and b ≻ a by (g) —
    /// a cycle, so `max_by` returns an iteration-order-dependent winner.
    /// pathvector instead ranks an unknown identifier after every known one
    /// (a route never wins (f) on missing data), which makes (f) a total
    /// order: a ≻ c ≻ b.
    #[test]
    fn unknown_identifier_ranks_after_every_known_identifier_transitively() {
        let (pa, a) = (peer(3), ibgp(Some(id(1, 1, 1, 1)), None, &[]));
        let (pb, b) = (peer(2), ibgp(None, None, &[]));
        let (pc, c) = (peer(1), ibgp(Some(id(1, 1, 1, 2)), None, &[]));

        assert_eq!(cmp(pa, &a, pc, &c), Ordering::Greater, "a ≻ c: (f)");
        assert_eq!(
            cmp(pc, &c, pb, &b),
            Ordering::Greater,
            "c ≻ b: known beats unknown"
        );
        assert_eq!(
            cmp(pa, &a, pb, &b),
            Ordering::Greater,
            "a ≻ b: known beats unknown"
        );
        assert_eq!(
            winner(vec![(pa, a), (pb, b), (pc, c)]),
            pa,
            "the maximum of a total order"
        );
    }

    /// Both identifiers unknown: (f) ties, the `CLUSTER_LIST` step and then (g)
    /// decide.
    #[test]
    fn both_identifiers_unknown_fall_through_to_cluster_list_then_peer_address() {
        let a = ibgp(None, None, &[]);
        let b = ibgp(None, None, &[]);
        assert_eq!(winner(vec![(peer(1), a), (peer(2), b)]), peer(1), "(g)");

        let longer = ibgp(None, None, &[]);
        let mut longer = longer;
        longer.rare_mut().cluster_list = vec![1];
        let shorter = ibgp(None, None, &[]);
        assert_eq!(
            winner(vec![(peer(1), longer), (peer(2), shorter)]),
            peer(2),
            "CLUSTER_LIST step before (g)"
        );
    }

    proptest::proptest! {
        /// Reference model written straight from the RFC text, independent
        /// of `prefer`. For two routes tied through (e):
        ///   (f)  identifier = `ORIGINATOR_ID` if carried, else the peer's BGP
        ///        Identifier (RFC 4456 §9); lower wins; unknown ranks last
        ///        (pathvector's documented missing-identifier policy);
        ///   (f') shorter `CLUSTER_LIST`, absent = 0 (RFC 4456 §9);
        ///   (g)  lower peer address (RFC 4271 §9.1.2.2).
        /// Identifier values are drawn from a tiny range so every step is
        /// exercised, including equal identifiers from different sources.
        #[test]
        fn prop_reflected_tie_break_matches_rfc_reference(
            a_peer_id in proptest::option::of(1u8..=3),
            a_orig in proptest::option::of(1u8..=3),
            a_len in 0usize..=2,
            b_peer_id in proptest::option::of(1u8..=3),
            b_orig in proptest::option::of(1u8..=3),
            b_len in 0usize..=2,
            a_has_lower_address in proptest::bool::ANY,
        ) {
            let ip = |d: u8| id(10, 255, 0, d);
            let clusters = |n: usize| (1..=u32::try_from(n).unwrap()).collect::<Vec<_>>();
            let a = ibgp(a_peer_id.map(ip), a_orig.map(ip), &clusters(a_len));
            let b = ibgp(b_peer_id.map(ip), b_orig.map(ip), &clusters(b_len));
            let (pa, pb) = if a_has_lower_address {
                (peer(1), peer(2))
            } else {
                (peer(2), peer(1))
            };

            // Smaller key = preferred.
            let key = |peer_id: Option<u8>, orig: Option<u8>, len: usize, p: PeerId| {
                let effective = orig.or(peer_id);
                (effective.is_none(), effective, len, p)
            };
            let expected = if key(a_peer_id, a_orig, a_len, pa) < key(b_peer_id, b_orig, b_len, pb) {
                pa
            } else {
                pb
            };

            proptest::prop_assert_eq!(winner(vec![(pa, a.clone()), (pb, b.clone())]), expected);
            proptest::prop_assert_eq!(
                cmp(pa, &a, pb, &b),
                if expected == pa { Ordering::Greater } else { Ordering::Less }
            );
        }
    }

    proptest::proptest! {
        /// `prefer` restricted to the tie-breakers is a strict total order
        /// (irreflexive, asymmetric, total over distinct peers, transitive
        /// over every triple), for 3–6 routes tied through (e) that mix
        /// known/unknown peer identifiers, reflected/direct routes, and
        /// `CLUSTER_LIST` lengths. This is the focused form of
        /// `prop_tests::prop_prefer_is_a_strict_total_order`: with every
        /// earlier step tied, it finds the pre-fix (f) cycle within the
        /// default case count.
        #[test]
        fn prop_tie_breakers_are_a_strict_total_order(
            specs in proptest::collection::vec(
                (
                    proptest::option::of(1u8..=3),
                    proptest::option::of(1u8..=3),
                    0usize..=2,
                ),
                3..=6,
            ),
        ) {
            let ip = |d: u8| id(10, 255, 0, d);
            let cands: Vec<(PeerId, Route<Ipv4Addr>)> = specs
                .iter()
                .enumerate()
                .map(|(i, &(peer_id, orig, len))| {
                    let clusters: Vec<u32> = (1..=u32::try_from(len).unwrap()).collect();
                    (
                        peer(u8::try_from(i + 1).unwrap()),
                        ibgp(peer_id.map(ip), orig.map(ip), &clusters),
                    )
                })
                .collect();
            let c = |i: usize, j: usize| cmp(cands[i].0, &cands[i].1, cands[j].0, &cands[j].1);
            let n = cands.len();
            for i in 0..n {
                proptest::prop_assert_eq!(c(i, i), Ordering::Equal);
                for j in (0..n).filter(|&j| j != i) {
                    proptest::prop_assert_ne!(c(i, j), Ordering::Equal);
                    proptest::prop_assert_eq!(c(i, j), c(j, i).reverse());
                    for k in (0..n).filter(|&k| k != i && k != j) {
                        if c(i, j) == Ordering::Greater && c(j, k) == Ordering::Greater {
                            proptest::prop_assert_eq!(c(i, k), Ordering::Greater, "{} > {} > {}", i, j, k);
                        }
                    }
                }
            }
        }
    }

    proptest::proptest! {
        /// `TieBreakKey::of` reads the rare attributes directly for speed;
        /// it must agree with the public accessors that document the rule.
        #[test]
        fn prop_tie_break_key_matches_route_accessors(
            peer_id in proptest::option::of(proptest::num::u32::ANY),
            orig in proptest::option::of(proptest::num::u32::ANY),
            len in 0usize..=3,
            allocate_rare in proptest::bool::ANY,
        ) {
            let clusters: Vec<u32> = (1..=u32::try_from(len).unwrap()).collect();
            let mut route = ibgp(peer_id.map(Ipv4Addr::from), orig.map(Ipv4Addr::from), &clusters);
            if allocate_rare {
                let _ = route.rare_mut(); // allocated but possibly all-default
            }
            let key = super::TieBreakKey::of(&route);
            proptest::prop_assert_eq!(key.router_id, route.effective_router_id());
            proptest::prop_assert_eq!(key.cluster_list_len, route.cluster_list_len());
        }
    }

    /// Ties all the way to (g): equal effective identifier and equal
    /// `CLUSTER_LIST` length — the lower peer address wins, and the
    /// comparison is antisymmetric.
    #[test]
    fn full_tie_through_cluster_list_falls_to_peer_address() {
        let a = ibgp(Some(id(4, 4, 4, 4)), Some(id(9, 9, 9, 9)), &[1, 2]);
        let b = ibgp(Some(id(3, 3, 3, 3)), Some(id(9, 9, 9, 9)), &[3, 4]);
        assert_eq!(cmp(peer(1), &a, peer(2), &b), Ordering::Greater);
        assert_eq!(cmp(peer(2), &b, peer(1), &a), Ordering::Less);
        assert_eq!(cmp(peer(1), &a, peer(1), &a), Ordering::Equal);
    }
}
