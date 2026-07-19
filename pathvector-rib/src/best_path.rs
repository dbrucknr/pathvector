use std::{cmp::Ordering, collections::HashMap};

use ipnetx::interfaces::IpAddress;
use pathvector_types::{Asn, LocalPref, PeerType};

use crate::{
    oracle::{AlwaysReachable, NextHopOracle},
    peer::PeerId,
    route::Route,
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
/// | 10 | BGP Identifier (RFC 4271 §9.1.2.2 (f); skipped if either side unknown) | lower |
/// | 11 | Peer IP address (RFC 4271 §9.1.2.2 (g), final tie-breaker) | lower |
///
/// Steps 1 and 8 require IGP reachability information not available at the
/// RIB layer. See `TODO.md`.
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

/// Compares two (peer, route) pairs and returns the ordering from the
/// perspective of route preference — `Ordering::Greater` means the first
/// pair is preferred.
fn prefer<A: IpAddress>(
    peer_a: &PeerId,
    a: &Route<A>,
    peer_b: &PeerId,
    b: &Route<A>,
    oracle: &dyn NextHopOracle,
) -> Ordering {
    // Step 0 (RFC 4724 §4.2): non-stale beats stale before all other criteria.
    // Mirrors FRR's BGP_PATH_STALE and BIRD's RS_STALE handling: a fresh route
    // from any peer immediately wins over a GR-retained stale route.
    match (a.stale, b.stale) {
        (false, true) => return Ordering::Greater,
        (true, false) => return Ordering::Less,
        _ => {}
    }

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
    // (RFC 4271 §9.1 steps 3 and 7).
    // PeerType discriminants encode the preference order:
    // Local (2) > External (1) > Internal (0).
    let session = a.peer_type.cmp(&b.peer_type);
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

    // Step 10 (RFC 4271 §9.1.2.2 (f)): lowest BGP Identifier.
    // Only compared when both routes have a known peer_bgp_id — if either
    // is None (e.g. the identifier isn't tracked for that route), this step
    // is skipped and step 11 decides instead, mirroring how step 8's
    // IGP-metric comparison is skipped when either side's metric is None.
    if let (Some(id_a), Some(id_b)) = (a.peer_bgp_id, b.peer_bgp_id) {
        let bgp_id = id_b.cmp(&id_a);
        if bgp_id != Ordering::Equal {
            return bgp_id; // reverse: lower BGP Identifier → Greater → preferred
        }
    }

    // Step 11 (RFC 4271 §9.1.2.2 (g)): lowest peer address (final tie-breaker).
    peer_b.cmp(peer_a) // reverse: lower peer IP → Greater → preferred
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

    use pathvector_types::{AsPath, Asn, LocalPref, Med, Nlri, Origin, PeerType};
    use proptest::prelude::*;

    use super::select_best;
    use crate::{PeerId, RouteBuilder};

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use pathvector_types::{AsPath, Asn, LocalPref, Med, Nlri, Origin, PeerType};

    use crate::RouteBuilder;

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
    fn test_select_best_falls_back_to_peer_ip_when_bgp_identifier_known_on_only_one_side() {
        // (f) requires a known BGP Identifier on *both* candidates to
        // compare; if only one side has it, the comparison is skipped
        // (mirrors the IGP-metric step's None-on-either-side skip) and (g)
        // peer-IP decides instead.
        let with_id = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .peer_bgp_id(Ipv4Addr::new(1, 1, 1, 1))
            .build();
        let without_id = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .build();
        // Give the peer *without* a known BGP Identifier the lower peer IP,
        // so if (f) were incorrectly applied one-sided it would still have
        // to fall through to (g) and agree — construct the disagreeing case
        // instead: the known-ID peer gets the higher peer IP, so a
        // one-sided (f) bug (e.g. treating missing-as-lowest) would pick a
        // different winner than the correct skip-to-(g) behavior.
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), without_id); // lower peer IP, no known BGP Identifier
        candidates.insert(peer(2), with_id); // higher peer IP, known BGP Identifier
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // (f) skipped entirely; (g): lower peer IP wins
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

    /// RFC 4724 §4.2 — a non-stale route beats a stale route regardless of
    /// all other attributes (higher `LOCAL_PREF`, shorter AS path, etc.).
    #[test]
    fn stale_loses_to_non_stale_before_all_other_criteria() {
        // Stale peer has every other advantage: higher LOCAL_PREF (300 vs 100),
        // shorter AS path (0 vs 2), better origin (IGP vs Incomplete).
        let mut stale = basic(Origin::Igp, 0, Some(300), None);
        stale.stale = true;
        let fresh = basic(Origin::Incomplete, 2, Some(100), None);

        let mut candidates = HashMap::new();
        candidates.insert(peer(1), stale);
        candidates.insert(peer(2), fresh);
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(
            winner,
            peer(2),
            "fresh route must win over stale regardless of attributes"
        );
    }

    /// A stale route wins when it is the only candidate — it still provides
    /// reachability until the GR window expires or the peer re-announces.
    #[test]
    fn stale_route_wins_when_only_candidate() {
        let mut only = basic(Origin::Igp, 1, Some(100), None);
        only.stale = true;
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), only);
        assert!(
            select_best(&candidates).is_some(),
            "stale-only RIB must still yield a winner"
        );
    }

    /// Two stale candidates fall through to normal criteria (`LOCAL_PREF` wins).
    #[test]
    fn two_stale_routes_compared_normally() {
        let mut high_lp = basic(Origin::Igp, 1, Some(200), None);
        high_lp.stale = true;
        let mut low_lp = basic(Origin::Igp, 1, Some(100), None);
        low_lp.stale = true;
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), high_lp);
        candidates.insert(peer(2), low_lp);
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
