use std::{collections::HashMap, net::Ipv4Addr};

use pathvector_types::{AsPath, Asn, LocalPref, Med, Nlri, Origin};
use proptest::prelude::*;

use crate::{
    AdjRibIn, AdjRibOut, LocRib, PeerId, Route, RouteBuilder,
    best_path::select_best,
};

// ── Strategies ───────────────────────────────────────────────────────────────

// Four distinct peers drawn from a small pool to encourage multi-peer
// interactions (e.g., two peers competing for the same prefix).
prop_compose! {
    fn arb_peer_id()(octet in 1u8..=4u8) -> PeerId {
        PeerId::from(Ipv4Addr::new(10, 0, 0, octet))
    }
}

// Masked IPv4 NLRI from a narrow address space so prefix collisions —
// multiple peers announcing the same prefix — occur frequently.
prop_compose! {
    fn arb_nlri()(
        a    in 0u8..=3u8,
        b    in 0u8..=3u8,
        mask in 8u8..=24u8,
    ) -> Nlri<Ipv4Addr> {
        Nlri::new(Ipv4Addr::new(a, b, 0, 0), mask).unwrap().masked()
    }
}

fn arb_origin() -> impl Strategy<Value = Origin> {
    prop_oneof![
        Just(Origin::Igp),
        Just(Origin::Egp),
        Just(Origin::Incomplete),
    ]
}

/// A route for a specific NLRI with randomly chosen BGP path attributes.
fn arb_route_for(nlri: Nlri<Ipv4Addr>) -> impl Strategy<Value = Route<Ipv4Addr>> {
    (
        arb_origin(),
        proptest::collection::vec(1u32..=65535u32, 0..=6usize),
        proptest::option::of(0u32..=300u32),
        proptest::option::of(0u32..=1000u32),
    )
    .prop_map(move |(origin, asns, lp, med)| {
        let as_path = if asns.is_empty() {
            AsPath::new()
        } else {
            AsPath::from_sequence(asns.into_iter().map(Asn::new).collect())
        };
        let mut b = RouteBuilder::new(nlri, origin, as_path);
        if let Some(v) = lp { b = b.local_pref(LocalPref::new(v)); }
        if let Some(v) = med { b = b.med(Med::new(v)); }
        b.build()
    })
}

/// Non-empty candidate map (1–4 peers, all routes for 10.0.0.0/8).
fn arb_candidates() -> impl Strategy<Value = HashMap<PeerId, Route<Ipv4Addr>>> {
    let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
    proptest::collection::hash_map(arb_peer_id(), arb_route_for(nlri), 1..=4usize)
}

/// A (peer, route) pair for LocRib insertion with a varying NLRI.
fn arb_peer_route() -> impl Strategy<Value = (PeerId, Route<Ipv4Addr>)> {
    (arb_peer_id(), arb_nlri()).prop_flat_map(|(peer, nlri)| {
        arb_route_for(nlri).prop_map(move |route| (peer, route))
    })
}

// ── best_path::select_best ───────────────────────────────────────────────────

proptest! {
    /// The winner is always a key that was in the input candidate map.
    ///
    /// A phantom peer winning best-path would silently install a route from a
    /// peer unknown to the RIB, corrupting subsequent withdrawal tracking.
    #[test]
    fn prop_select_best_winner_is_in_candidates(candidates in arb_candidates()) {
        let (winner, _) = select_best(&candidates).unwrap();
        prop_assert!(candidates.contains_key(&winner));
    }

    /// A non-empty candidate set always produces a winner.
    ///
    /// A spurious None from a populated map would silently drop a valid prefix
    /// from the Loc-RIB, making it unreachable without any operator-visible
    /// signal.
    #[test]
    fn prop_select_best_non_empty_returns_some(candidates in arb_candidates()) {
        prop_assert!(select_best(&candidates).is_some());
    }

    /// Calling select_best twice on the same map always elects the same peer.
    ///
    /// Flapping best-path selection would cause oscillating FIB installs for
    /// a stable set of candidates — a serious operational problem.
    #[test]
    fn prop_select_best_deterministic(candidates in arb_candidates()) {
        let first  = select_best(&candidates).map(|(p, _)| p);
        let second = select_best(&candidates).map(|(p, _)| p);
        prop_assert_eq!(first, second);
    }

    /// When all candidates carry distinct LOCAL_PREF values, the winner is
    /// always the one with the highest value.
    ///
    /// LOCAL_PREF is the most powerful inbound policy lever (step 2 of the
    /// decision process). An incorrect winner here means an operator's import
    /// filter is effectively ignored.
    #[test]
    fn prop_select_best_winner_has_highest_local_pref(
        lp_values in proptest::collection::hash_set(0u32..=300u32, 1..=4usize),
    ) {
        // Fixed array avoids a cast from usize to u8.
        let peers = [
            PeerId::from(Ipv4Addr::new(10, 0, 0, 1)),
            PeerId::from(Ipv4Addr::new(10, 0, 0, 2)),
            PeerId::from(Ipv4Addr::new(10, 0, 0, 3)),
            PeerId::from(Ipv4Addr::new(10, 0, 0, 4)),
        ];
        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let lp_vec: Vec<u32> = lp_values.into_iter().collect();
        let max_lp = lp_vec.iter().copied().max().unwrap();

        let mut candidates: HashMap<PeerId, Route<Ipv4Addr>> = HashMap::new();
        for (i, &lp) in lp_vec.iter().enumerate() {
            candidates.insert(
                peers[i],
                RouteBuilder::new(nlri, Origin::Igp, AsPath::new())
                    .local_pref(LocalPref::new(lp))
                    .build(),
            );
        }

        let (_, winner) = select_best(&candidates).unwrap();
        prop_assert_eq!(winner.local_pref, Some(LocalPref::new(max_lp)));
    }
}

// ── LocRib ────────────────────────────────────────────────────────────────────

proptest! {
    /// `is_empty()` and `len() == 0` always agree after any combination of
    /// inserts.
    #[test]
    fn prop_loc_rib_is_empty_consistent_with_len(
        inserts in proptest::collection::vec(arb_peer_route(), 0..=12usize),
    ) {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        for (peer, route) in inserts { rib.insert(peer, route); }
        prop_assert_eq!(rib.is_empty(), rib.len() == 0);
    }

    /// `best_routes().count()` always equals `len()`.
    ///
    /// A divergence means some prefix has candidates but no installed best
    /// route, or has a stale best entry with no remaining candidates — both
    /// would result in incorrect "show bgp" output and FIB inconsistencies.
    #[test]
    fn prop_loc_rib_best_routes_count_equals_len(
        inserts in proptest::collection::vec(arb_peer_route(), 1..=12usize),
    ) {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        for (peer, route) in inserts { rib.insert(peer, route); }
        prop_assert_eq!(rib.best_routes().count(), rib.len());
    }

    /// After any insert, `best()` for that prefix is Some.
    ///
    /// A missing best route after an insert would silently black-hole traffic
    /// for a newly advertised prefix with no operator-visible error.
    #[test]
    fn prop_loc_rib_insert_makes_best_some(
        (peer, route) in arb_peer_route(),
    ) {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let nlri = route.nlri;
        rib.insert(peer, route);
        prop_assert!(rib.best(&nlri).is_some());
    }

    /// For every prefix, `best_peer()` is always a key present in
    /// `candidates()` for that prefix.
    ///
    /// A stale best-peer pointer — one whose route was already withdrawn —
    /// would keep forwarding traffic toward an unreachable next-hop.
    #[test]
    fn prop_loc_rib_best_peer_is_valid_candidate(
        inserts in proptest::collection::vec(arb_peer_route(), 1..=12usize),
    ) {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let nlris: Vec<Nlri<Ipv4Addr>> = inserts.iter().map(|(_, r)| r.nlri).collect();

        for (peer, route) in inserts { rib.insert(peer, route); }

        for nlri in nlris {
            if let Some(winner) = rib.best_peer(&nlri) {
                prop_assert!(rib.candidates(&nlri).unwrap().contains_key(&winner));
            }
        }
    }

    /// After `withdraw_peer`, every prefix for which that peer was the sole
    /// candidate has no remaining best route.
    ///
    /// A stale best route after session teardown would continue forwarding
    /// traffic toward a now-down peer — incorrect BGP behavior.
    #[test]
    fn prop_loc_rib_withdraw_peer_removes_sole_owner_prefixes(
        inserts in proptest::collection::vec(arb_peer_route(), 1..=8usize),
        target_octet in 1u8..=4u8,
    ) {
        let target = PeerId::from(Ipv4Addr::new(10, 0, 0, target_octet));
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();

        for (peer, route) in &inserts {
            rib.insert(*peer, route.clone());
        }

        // Snapshot which NLRIs the target exclusively owns before the withdraw.
        let exclusive: Vec<Nlri<Ipv4Addr>> = inserts
            .iter()
            .map(|(_, r)| r.nlri)
            .filter(|nlri| {
                rib.candidates(nlri)
                    .map(|c| c.len() == 1 && c.contains_key(&target))
                    .unwrap_or(false)
            })
            .collect();

        rib.withdraw_peer(&target);

        for nlri in exclusive {
            prop_assert!(rib.best(&nlri).is_none());
        }
    }
}

// ── AdjRibIn ────────────────────────────────────────────────────────────────

proptest! {
    /// After inserting a route, `get()` returns that exact route.
    ///
    /// A lossy insert would corrupt the pre-policy store used for soft
    /// reconfiguration: re-applying import policy after a change would produce
    /// different results than the original evaluation.
    #[test]
    fn prop_adj_rib_in_insert_then_get(
        route in arb_nlri().prop_flat_map(arb_route_for),
    ) {
        let peer = PeerId::from(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib: AdjRibIn<Ipv4Addr> = AdjRibIn::new(peer);
        let nlri = route.nlri;
        rib.insert(route.clone());
        prop_assert_eq!(rib.get(&nlri), Some(&route));
    }

    /// A second insert for the same NLRI returns the displaced route and
    /// leaves `get()` pointing at the new one.
    ///
    /// If the old route were silently discarded, the session layer would lose
    /// the ability to detect attribute changes needed to build WITHDRAWN /
    /// re-advertised UPDATE messages.
    #[test]
    fn prop_adj_rib_in_second_insert_replaces_old(
        (route1, route2) in arb_nlri().prop_flat_map(|nlri| {
            (arb_route_for(nlri), arb_route_for(nlri))
        }),
    ) {
        let peer = PeerId::from(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib: AdjRibIn<Ipv4Addr> = AdjRibIn::new(peer);
        let nlri = route1.nlri;
        rib.insert(route1.clone());
        let old = rib.insert(route2.clone());
        prop_assert_eq!(old, Some(route1));
        prop_assert_eq!(rib.get(&nlri), Some(&route2));
    }

    /// After `withdraw`, `get()` returns None for that prefix.
    ///
    /// A failed withdraw leaves a stale pre-policy entry; soft reconfiguration
    /// would re-install a route the peer has already retracted.
    #[test]
    fn prop_adj_rib_in_withdraw_clears_route(
        route in arb_nlri().prop_flat_map(arb_route_for),
    ) {
        let peer = PeerId::from(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib: AdjRibIn<Ipv4Addr> = AdjRibIn::new(peer);
        let nlri = route.nlri;
        rib.insert(route);
        rib.withdraw(&nlri);
        prop_assert!(rib.get(&nlri).is_none());
    }
}

// ── AdjRibOut ────────────────────────────────────────────────────────────────

proptest! {
    /// After inserting a route, `get()` returns that exact route.
    ///
    /// A lossy insert would cause a different UPDATE to be sent to the peer
    /// than the one export policy produced.
    #[test]
    fn prop_adj_rib_out_insert_then_get(
        route in arb_nlri().prop_flat_map(arb_route_for),
    ) {
        let peer = PeerId::from(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(peer);
        let nlri = route.nlri;
        rib.insert(route.clone());
        prop_assert_eq!(rib.get(&nlri), Some(&route));
    }

    /// After `withdraw`, `get()` returns None for that prefix.
    ///
    /// A stale AdjRibOut entry would suppress the WITHDRAW message that should
    /// be sent to the peer, leaving them with a route they must no longer use.
    #[test]
    fn prop_adj_rib_out_withdraw_clears_route(
        route in arb_nlri().prop_flat_map(arb_route_for),
    ) {
        let peer = PeerId::from(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(peer);
        let nlri = route.nlri;
        rib.insert(route);
        rib.withdraw(&nlri);
        prop_assert!(rib.get(&nlri).is_none());
    }
}
