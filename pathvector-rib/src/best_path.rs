use std::{cmp::Ordering, collections::HashMap};

use ipnetx::interfaces::IpAddress;
use pathvector_types::{LocalPref, PeerType};

use crate::{peer::PeerId, route::Route};

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
/// | 6 | `MED` | lower (missing → `0`) |
/// | 9 | Route age (eBGP only) | older |
/// | 10 | Peer IP address | lower |
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
    candidates
        .iter()
        .max_by(|(peer_a, route_a), (peer_b, route_b)| prefer(peer_a, route_a, peer_b, route_b))
        .map(|(peer, route)| (*peer, route))
}

/// Compares two (peer, route) pairs and returns the ordering from the
/// perspective of route preference — `Ordering::Greater` means the first
/// pair is preferred.
///
/// This function encodes the partial BGP decision process. Steps that require
/// external information (IGP metrics, session type) are not implemented here;
/// the caller may wrap this with additional logic.
fn prefer<A: IpAddress>(peer_a: &PeerId, a: &Route<A>, peer_b: &PeerId, b: &Route<A>) -> Ordering {
    // Step 2: Highest LOCAL_PREF (missing treated as the conventional default of 100).
    // LOCAL_PREF is the most powerful inbound policy lever — an operator can
    // force any route to win by setting this high enough.
    let lp = a
        .local_pref
        .unwrap_or(LocalPref::DEFAULT)
        .cmp(&b.local_pref.unwrap_or(LocalPref::DEFAULT));
    if lp != Ordering::Equal {
        return lp; // higher LOCAL_PREF → Greater → preferred
    }

    // Step 4: Shortest AS path length.
    // Shorter paths are generally closer to the destination. This is the
    // main tool for influencing inbound traffic from eBGP peers.
    let path_len = b.as_path.path_length().cmp(&a.as_path.path_length());
    if path_len != Ordering::Equal {
        return path_len; // reverse: shorter path_len(a) → Greater → preferred
    }

    // Step 5: Lowest ORIGIN value.
    // IGP (0) > EGP (1) > INCOMPLETE (2) in preference, so a lower numeric
    // value is better. We reverse the comparison to make Greater mean preferred.
    let origin = b.origin.cmp(&a.origin);
    if origin != Ordering::Equal {
        return origin; // reverse: lower origin → Greater → preferred
    }

    // Step 6: Lowest MED (Multi-Exit Discriminator).
    // MED is a hint from a neighboring AS about which of their entry points
    // to prefer. Lower is better. Missing MED is treated as 0 (prefer routes
    // that explicitly set MED=0 equally with routes that omit it).
    //
    // Note: Strictly speaking, MED should only be compared between routes
    // from the same neighboring AS. This implementation compares MED
    // globally. See TODO.md (deterministic-med, always-compare-med).
    let med_a = a.med.map_or(0, pathvector_types::Med::as_u32);
    let med_b = b.med.map_or(0, pathvector_types::Med::as_u32);
    let med = med_b.cmp(&med_a);
    if med != Ordering::Equal {
        return med; // reverse: lower MED → Greater → preferred
    }

    // Step 3/7: Prefer locally originated routes, then eBGP over iBGP
    // (RFC 4271 §9.1 steps 3 and 7).
    // PeerType discriminants encode the preference order:
    // Local (2) > External (1) > Internal (0).
    let session = a.peer_type.cmp(&b.peer_type);
    if session != Ordering::Equal {
        return session;
    }

    // Step 9: Oldest eBGP route (RFC 4271 §9.1 step 9).
    // Only applies when both routes are eBGP — iBGP and local routes were
    // resolved at step 3/7. Prefer the older, more stable route to reduce
    // churn when all policy-relevant attributes are equal.
    // Step 8 (IGP metric) is skipped — requires FIB integration.
    if a.peer_type == PeerType::External {
        let age = b.received_at.cmp(&a.received_at); // older (smaller Instant) → Greater
        if age != Ordering::Equal {
            return age;
        }
    }

    // Step 10: Lowest peer IP address (final tie-breaker).
    // When all policy-relevant attributes are equal, prefer the route from
    // the numerically lower peer address. This is deterministic and stable
    // across policy changes.
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

            if lp_a > lp_b {
                prop_assert_eq!(winner, peer(1), "peer(1) has higher LP");
            } else if lp_b > lp_a {
                prop_assert_eq!(winner, peer(2), "peer(2) has higher LP");
            }
            // Equal LP: falls through to tiebreaker — verified by the invariant above.
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
            if explicit > 100 {
                prop_assert_eq!(winner, peer(1),
                    "explicit {} > default 100 — peer(1) should win", explicit);
            } else if explicit < 100 {
                prop_assert_eq!(winner, peer(2),
                    "default 100 > explicit {} — peer(2) should win", explicit);
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

            if len_a < len_b {
                prop_assert_eq!(winner, peer(1), "peer(1) has shorter path");
            } else if len_b < len_a {
                prop_assert_eq!(winner, peer(2), "peer(2) has shorter path");
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

            if origin_a < origin_b {
                prop_assert_eq!(winner, peer(1), "peer(1) has lower origin");
            } else if origin_b < origin_a {
                prop_assert_eq!(winner, peer(2), "peer(2) has lower origin");
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

            let mut ra = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
                .local_pref(LocalPref::new(100));
            if let Some(m) = med_a { ra = ra.med(Med::new(m)); }

            let mut rb = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
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

            if eff_a < eff_b {
                prop_assert_eq!(winner, peer(1), "peer(1) has lower MED");
            } else if eff_b < eff_a {
                prop_assert_eq!(winner, peer(2), "peer(2) has lower MED");
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
    fn test_select_best_tiebreak_lower_peer_ip() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(100), None));
        candidates.insert(peer(2), basic(Origin::Igp, 2, Some(100), None));
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // lower peer IP wins
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
        use std::time::{Duration, Instant};

        let older = {
            let mut r = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
                .peer_type(PeerType::External)
                .build();
            // Backdate received_at to simulate an older route.
            r.received_at = Instant::now().checked_sub(Duration::from_secs(60)).unwrap();
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
        use std::time::{Duration, Instant};

        // iBGP route that is very old — should NOT win over a newer eBGP route
        // because step 3/7 resolves in favour of eBGP first.
        let old_ibgp = {
            let mut r = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
                .peer_type(PeerType::Internal)
                .build();
            r.received_at = Instant::now()
                .checked_sub(Duration::from_secs(3600))
                .unwrap();
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
}
