use std::{collections::HashMap, net::Ipv4Addr};

use pathvector_types::{AsPath, Asn, LocalPref, Med, NextHop, Nlri, Origin, PeerType};
use proptest::prelude::*;

use crate::{
    AdjRibIn, AdjRibOut, BestPathChange, LocRib, PeerId, Route, RouteBuilder,
    best_path::select_best,
    oracle::{AlwaysReachable, NextHopOracle},
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
            if let Some(v) = lp {
                b = b.local_pref(LocalPref::new(v));
            }
            if let Some(v) = med {
                b = b.med(Med::new(v));
            }
            b.build()
        })
}

/// Non-empty candidate map (1–4 peers, all routes for 10.0.0.0/8).
fn arb_candidates() -> impl Strategy<Value = HashMap<PeerId, Route<Ipv4Addr>>> {
    let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
    proptest::collection::hash_map(arb_peer_id(), arb_route_for(nlri), 1..=4usize)
}

/// A (peer, route) pair for [`LocRib`] insertion with a varying NLRI.
fn arb_peer_route() -> impl Strategy<Value = (PeerId, Route<Ipv4Addr>)> {
    (arb_peer_id(), arb_nlri())
        .prop_flat_map(|(peer, nlri)| arb_route_for(nlri).prop_map(move |route| (peer, route)))
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

// ── best_path: step-by-step isolation ────────────────────────────────────────

proptest! {
    /// When all candidates share the same LOCAL_PREF and distinct AS_PATH
    /// lengths, the winner always has the shortest path.
    ///
    /// AS_PATH length is step 4 of the decision process. An incorrect winner
    /// here means traffic takes a longer route than necessary, violating the
    /// operator's intended topology.
    #[test]
    fn prop_select_best_winner_has_shortest_as_path(
        path_lengths in proptest::collection::hash_set(1usize..=6usize, 1..=4usize),
    ) {
        let peers = [
            PeerId::from(Ipv4Addr::new(10, 0, 0, 1)),
            PeerId::from(Ipv4Addr::new(10, 0, 0, 2)),
            PeerId::from(Ipv4Addr::new(10, 0, 0, 3)),
            PeerId::from(Ipv4Addr::new(10, 0, 0, 4)),
        ];
        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let len_vec: Vec<usize> = path_lengths.into_iter().collect();
        let min_len = *len_vec.iter().min().unwrap();

        let mut candidates: HashMap<PeerId, Route<Ipv4Addr>> = HashMap::new();
        for (i, &len) in len_vec.iter().enumerate() {
            let asns: Vec<_> = (1..=u32::try_from(len).unwrap()).map(Asn::new).collect();
            candidates.insert(
                peers[i],
                RouteBuilder::new(nlri, Origin::Igp, AsPath::from_sequence(asns))
                    .local_pref(LocalPref::new(100))
                    .build(),
            );
        }

        let (_, winner) = select_best(&candidates).unwrap();
        prop_assert_eq!(winner.as_path.path_length(), min_len);
    }

    /// When all candidates share the same LOCAL_PREF and AS_PATH length but
    /// have distinct ORIGIN values, the winner always has the lowest ORIGIN.
    ///
    /// ORIGIN is step 5: IGP (0) < EGP (1) < INCOMPLETE (2). An incorrect
    /// winner here means a route learned from an external source is preferred
    /// over one with complete internal provenance.
    #[test]
    fn prop_select_best_winner_has_lowest_origin(
        include_egp        in any::<bool>(),
        include_incomplete in any::<bool>(),
    ) {
        let peers = [
            PeerId::from(Ipv4Addr::new(10, 0, 0, 1)),
            PeerId::from(Ipv4Addr::new(10, 0, 0, 2)),
            PeerId::from(Ipv4Addr::new(10, 0, 0, 3)),
        ];
        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();

        let mut origins = vec![Origin::Igp];
        if include_egp        { origins.push(Origin::Egp); }
        if include_incomplete { origins.push(Origin::Incomplete); }
        let min_origin = *origins.iter().min().unwrap();

        let mut candidates: HashMap<PeerId, Route<Ipv4Addr>> = HashMap::new();
        for (i, &origin) in origins.iter().enumerate() {
            candidates.insert(
                peers[i],
                RouteBuilder::new(nlri, origin, AsPath::new())
                    .local_pref(LocalPref::new(100))
                    .build(),
            );
        }

        let (_, winner) = select_best(&candidates).unwrap();
        prop_assert_eq!(winner.origin, min_origin);
    }

    /// When all candidates share LOCAL_PREF, AS_PATH length, and ORIGIN but
    /// have distinct MED values, the winner always has the lowest MED.
    ///
    /// MED is step 6. An incorrect winner here means traffic exits via a
    /// higher-cost link than the neighboring AS advertised.
    #[test]
    fn prop_select_best_winner_has_lowest_med(
        med_values in proptest::collection::hash_set(0u32..=1000u32, 1..=4usize),
    ) {
        let peers = [
            PeerId::from(Ipv4Addr::new(10, 0, 0, 1)),
            PeerId::from(Ipv4Addr::new(10, 0, 0, 2)),
            PeerId::from(Ipv4Addr::new(10, 0, 0, 3)),
            PeerId::from(Ipv4Addr::new(10, 0, 0, 4)),
        ];
        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let med_vec: Vec<u32> = med_values.into_iter().collect();
        let min_med = *med_vec.iter().min().unwrap();
        // All routes share the same neighboring AS so MED comparison applies
        // (RFC 4271 §9.1.2.2: MED only compared within same neighboring AS).
        let shared_neighbor = AsPath::from_sequence(vec![Asn::new(65001)]);

        let mut candidates: HashMap<PeerId, Route<Ipv4Addr>> = HashMap::new();
        for (i, &med) in med_vec.iter().enumerate() {
            candidates.insert(
                peers[i],
                RouteBuilder::new(nlri, Origin::Igp, shared_neighbor.clone())
                    .local_pref(LocalPref::new(100))
                    .med(Med::new(med))
                    .build(),
            );
        }

        let (_, winner) = select_best(&candidates).unwrap();
        prop_assert_eq!(winner.med, Some(Med::new(min_med)));
    }

    /// The winner is the same regardless of the order routes are inserted into
    /// the candidate map.
    ///
    /// A pairwise MED comparator that conditionally skips MED for cross-AS pairs
    /// is non-transitive for 3+ routes across multiple ASes, causing `max_by` to
    /// return different winners depending on HashMap iteration order. The group-
    /// based implementation must be stable under all permutations.
    #[test]
    fn prop_med_winner_is_insertion_order_independent(
        med_as1_a in 0u32..=1000u32,
        med_as1_b in 0u32..=1000u32,
        med_as2   in 0u32..=1000u32,
        peer1_ip  in 1u8..=50u8,
        peer2_ip  in 51u8..=100u8,
        peer3_ip  in 101u8..=150u8,
    ) {
        // Three routes: two from AS 65001 (MED comparable), one from AS 65002 (MED skipped).
        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let as1 = AsPath::from_sequence(vec![Asn::new(65001)]);
        let as2 = AsPath::from_sequence(vec![Asn::new(65002)]);

        let make = |path: AsPath, med: u32, _ip: u8| -> Route<Ipv4Addr> {
            RouteBuilder::new(nlri, Origin::Igp, path)
                .local_pref(LocalPref::new(100))
                .med(Med::new(med))
                .build()
        };

        let p1 = PeerId::from(Ipv4Addr::new(10, 0, 0, peer1_ip));
        let p2 = PeerId::from(Ipv4Addr::new(10, 0, 0, peer2_ip));
        let p3 = PeerId::from(Ipv4Addr::new(10, 0, 0, peer3_ip));

        let r1 = make(as1.clone(), med_as1_a, peer1_ip);
        let r2 = make(as1.clone(), med_as1_b, peer2_ip);
        let r3 = make(as2.clone(), med_as2,   peer3_ip);

        // All six insertion orders must produce the same winner.
        let orders: [&[(&PeerId, &Route<Ipv4Addr>)]; 6] = [
            &[(&p1, &r1), (&p2, &r2), (&p3, &r3)],
            &[(&p1, &r1), (&p3, &r3), (&p2, &r2)],
            &[(&p2, &r2), (&p1, &r1), (&p3, &r3)],
            &[(&p2, &r2), (&p3, &r3), (&p1, &r1)],
            &[(&p3, &r3), (&p1, &r1), (&p2, &r2)],
            &[(&p3, &r3), (&p2, &r2), (&p1, &r1)],
        ];

        let results: Vec<PeerId> = orders
            .iter()
            .map(|order| {
                let mut candidates = HashMap::new();
                for (peer, route) in *order {
                    candidates.insert(**peer, (*route).clone());
                }
                select_best(&candidates).unwrap().0
            })
            .collect();

        let first = results[0];
        for (i, &winner) in results.iter().enumerate().skip(1) {
            prop_assert_eq!(
                winner, first,
                "insertion order {} produced different winner {:?} vs {:?}",
                i, winner, first
            );
        }
    }

    /// When there is at least one eBGP candidate and all routes share the same
    /// LOCAL_PREF, AS_PATH length, ORIGIN, and MED, the winner is always eBGP.
    ///
    /// eBGP preference is step 7. Returning an iBGP winner in a mixed set
    /// would violate the fundamental BGP rule that external routes are
    /// preferred over internal ones.
    #[test]
    fn prop_select_best_ebgp_beats_ibgp(
        is_external in proptest::collection::vec(any::<bool>(), 1..=4usize),
    ) {
        let peers = [
            PeerId::from(Ipv4Addr::new(10, 0, 0, 1)),
            PeerId::from(Ipv4Addr::new(10, 0, 0, 2)),
            PeerId::from(Ipv4Addr::new(10, 0, 0, 3)),
            PeerId::from(Ipv4Addr::new(10, 0, 0, 4)),
        ];
        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let has_ebgp = is_external.iter().any(|&ext| ext);

        let mut candidates: HashMap<PeerId, Route<Ipv4Addr>> = HashMap::new();
        for (i, &ext) in is_external.iter().enumerate() {
            let pt = if ext { PeerType::External } else { PeerType::Internal };
            candidates.insert(
                peers[i],
                RouteBuilder::new(nlri, Origin::Igp, AsPath::new())
                    .local_pref(LocalPref::new(100))
                    .peer_type(pt)
                    .build(),
            );
        }

        let (_, winner) = select_best(&candidates).unwrap();
        if has_ebgp {
            prop_assert_eq!(winner.peer_type, PeerType::External);
        }
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
        for (peer, route) in inserts { rib.insert(peer, route, &AlwaysReachable); }
        #[allow(clippy::len_zero)]
        let len_is_zero = rib.len() == 0;
        prop_assert_eq!(rib.is_empty(), len_is_zero);
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
        for (peer, route) in inserts { rib.insert(peer, route, &AlwaysReachable); }
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
        rib.insert(peer, route, &AlwaysReachable);
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

        for (peer, route) in inserts { rib.insert(peer, route, &AlwaysReachable); }

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
            rib.insert(*peer, route.clone(), &AlwaysReachable);
        }

        // Snapshot which NLRIs the target exclusively owns before the withdraw.
        let exclusive: Vec<Nlri<Ipv4Addr>> = inserts
            .iter()
            .map(|(_, r)| r.nlri)
            .filter(|nlri| {
                rib.candidates(nlri)
                    .is_some_and(|c| c.len() == 1 && c.contains_key(&target))
            })
            .collect();

        rib.withdraw_peer(&target, &AlwaysReachable);

        for nlri in exclusive {
            prop_assert!(rib.best(&nlri).is_none());
        }
    }
}

// ── LocRib: BestPathChange stream is a faithful delta (issue #67) ───────────
//
// Every consumer of `BestPathChange` (FIB writer, Adj-RIB-Out propagation,
// route-event streams) maintains its own copy of "the selected route per
// prefix" by applying the changes it is handed. RFC 4271 §9.1.2 requires that
// "Unresolvable routes SHALL be removed from the Loc-RIB and the routing
// table", and §9.2 that "all newly unfeasible routes for which there is no
// replacement route SHALL be advertised" — both are only possible if the
// change stream never drops a transition. This model test drives a Loc-RIB
// through arbitrary insert / withdraw / peer-down / reachability operations
// and checks after every step that replaying the emitted changes onto an
// empty map reproduces the Loc-RIB's own best-path table exactly.

/// Next-hop pool. `NH_POOL[i]` is resolvable iff `ReachabilityOracle.0[i]`.
const NH_POOL: [Ipv4Addr; 3] = [
    Ipv4Addr::new(192, 0, 2, 1),
    Ipv4Addr::new(192, 0, 2, 2),
    Ipv4Addr::new(192, 0, 2, 3),
];

/// Prefix pool, kept tiny so operations collide on the same destination.
const PREFIX_POOL: [&str; 3] = ["10.0.0.0/8", "10.1.0.0/16", "192.168.0.0/24"];

#[derive(Debug, Clone, Copy)]
struct ReachabilityOracle([bool; 3]);

impl NextHopOracle for ReachabilityOracle {
    fn is_reachable(&self, next_hop: &NextHop) -> bool {
        match next_hop {
            NextHop::V4(addr) => NH_POOL
                .iter()
                .position(|nh| nh == addr)
                .is_none_or(|i| self.0[i]),
            _ => true,
        }
    }

    fn igp_metric(&self, _: &NextHop) -> Option<u32> {
        None
    }
}

#[derive(Debug, Clone)]
enum RibOp {
    /// UPDATE announcing (or replacing) `peer`'s route.
    Insert(PeerId, Route<Ipv4Addr>),
    /// UPDATE listing the prefix in WITHDRAWN ROUTES (or treat-as-withdraw).
    Withdraw(PeerId, Nlri<Ipv4Addr>),
    /// Session down: every route from `peer` is withdrawn.
    WithdrawPeer(PeerId),
    /// Next-hop `NH_POOL[i]` becomes (un)resolvable; the caller then runs
    /// `recompute_all` (RFC 4271 §9.1.2: "Phase 2 Route Selection MUST be
    /// performed again").
    SetReachable(usize, bool),
}

fn arb_pool_nlri() -> impl Strategy<Value = Nlri<Ipv4Addr>> {
    (0..PREFIX_POOL.len()).prop_map(|i| PREFIX_POOL[i].parse().unwrap())
}

fn arb_rib_op() -> impl Strategy<Value = RibOp> {
    let insert = (
        arb_peer_id(),
        arb_pool_nlri(),
        proptest::option::of(0..NH_POOL.len()),
    )
        .prop_flat_map(|(peer, nlri, nh)| {
            arb_route_for(nlri).prop_map(move |mut route| {
                route.next_hop = nh.map(|i| NextHop::V4(NH_POOL[i]));
                RibOp::Insert(peer, route)
            })
        });
    prop_oneof![
        5 => insert,
        2 => (arb_peer_id(), arb_pool_nlri()).prop_map(|(p, n)| RibOp::Withdraw(p, n)),
        1 => arb_peer_id().prop_map(RibOp::WithdrawPeer),
        2 => (0..NH_POOL.len(), any::<bool>()).prop_map(|(i, r)| RibOp::SetReachable(i, r)),
    ]
}

/// Applies `change` to the consumer-side replay map, failing on a
/// `Withdrawn` for a prefix the consumer was never told about (a spurious
/// withdrawal would make the FIB writer delete a route it never installed).
fn replay(
    map: &mut HashMap<Nlri<Ipv4Addr>, Route<Ipv4Addr>>,
    change: BestPathChange<Ipv4Addr>,
) -> Result<(), TestCaseError> {
    match change {
        BestPathChange::Announced(nlri, route) => {
            prop_assert_eq!(nlri, route.nlri, "Announced NLRI must match its route");
            map.insert(nlri, route);
        }
        BestPathChange::Withdrawn(nlri) => {
            prop_assert!(
                map.remove(&nlri).is_some(),
                "Withdrawn({:?}) emitted for a prefix that was never announced",
                nlri
            );
        }
        BestPathChange::Unchanged => {}
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Replaying the `BestPathChange` stream onto an empty map always equals
    /// the Loc-RIB's best-path table, and the Loc-RIB selects a route for a
    /// prefix iff at least one of its candidates is feasible (RFC 4271
    /// §9.1.2: unresolvable routes "MUST be excluded from the Phase 2
    /// decision function"; a feasible route, if one exists, is installed).
    #[test]
    fn prop_loc_rib_change_stream_replays_to_best_table(
        ops in proptest::collection::vec(arb_rib_op(), 1..=40usize),
    ) {
        let mut rib: LocRib<Ipv4Addr> = LocRib::new();
        let mut oracle = ReachabilityOracle([true; 3]);
        let mut replayed: HashMap<Nlri<Ipv4Addr>, Route<Ipv4Addr>> = HashMap::new();
        // Independent model of the candidate set: (prefix, peer) -> route.
        let mut model: HashMap<(Nlri<Ipv4Addr>, PeerId), Route<Ipv4Addr>> = HashMap::new();

        for op in ops {
            let changes = match op {
                RibOp::Insert(peer, route) => {
                    model.insert((route.nlri, peer), route.clone());
                    vec![rib.insert(peer, route, &oracle)]
                }
                RibOp::Withdraw(peer, nlri) => {
                    model.remove(&(nlri, peer));
                    vec![rib.withdraw(&peer, &nlri, &oracle)]
                }
                RibOp::WithdrawPeer(peer) => {
                    model.retain(|(_, p), _| *p != peer);
                    rib.withdraw_peer(&peer, &oracle)
                }
                RibOp::SetReachable(i, reachable) => {
                    oracle.0[i] = reachable;
                    rib.recompute_all(&oracle)
                }
            };
            for change in changes {
                replay(&mut replayed, change)?;
            }

            let actual: HashMap<Nlri<Ipv4Addr>, Route<Ipv4Addr>> = rib
                .best_routes()
                .map(|(nlri, route)| (nlri, route.clone()))
                .collect();
            prop_assert_eq!(&replayed, &actual);

            for nlri in PREFIX_POOL.iter().map(|p| p.parse::<Nlri<Ipv4Addr>>().unwrap()) {
                let feasible: Vec<(&PeerId, &Route<Ipv4Addr>)> = model
                    .iter()
                    .filter(|((n, _), r)| {
                        *n == nlri && r.next_hop.as_ref().is_none_or(|nh| oracle.is_reachable(nh))
                    })
                    .map(|((_, p), r)| (p, r))
                    .collect();
                match rib.best_peer(&nlri) {
                    None => prop_assert!(
                        feasible.is_empty(),
                        "{:?} has feasible candidates but no best route", nlri
                    ),
                    Some(winner) => {
                        let selected = feasible.iter().find(|(p, _)| **p == winner);
                        prop_assert!(
                            selected.is_some_and(|(_, r)| Some(*r) == rib.best(&nlri)),
                            "{:?}: best route is not a feasible candidate", nlri
                        );
                    }
                }
            }
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
        use pathvector_types::PeerType;
        let peer = PeerId::from(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(peer, PeerType::External);
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
        use pathvector_types::PeerType;
        let peer = PeerId::from(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(peer, PeerType::External);
        let nlri = route.nlri;
        rib.insert(route);
        rib.withdraw(&nlri);
        prop_assert!(rib.get(&nlri).is_none());
    }
}
