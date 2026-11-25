//! Every RIB identifies a destination by its prefix, not by the bits a caller
//! happened to supply beyond the prefix length (issue #71).
//!
//! RFC 4271 §4.3, of the NLRI field: "The Prefix field contains an IP address
//! prefix, followed by enough trailing bits to make the end of the field fall
//! on an octet boundary. Note that the value of the trailing bits is
//! irrelevant." Its Withdrawn Routes field says the same. So does RFC 4760 §5
//! for `MP_REACH_NLRI` / `MP_UNREACH_NLRI`: "Note that the value of trailing
//! bits is irrelevant."
//!
//! So `10.1.2.3/8` and `10.0.0.0/8` name one destination. Consequently:
//!
//! - RFC 4271 §9: a new route whose NLRI is identical to a stored one "SHALL
//!   replace the older route".
//! - RFC 4271 §9: withdrawn destinations "(expressed as IP prefixes)" "SHALL
//!   be removed".
//! - RFC 4271 §9.1: the Decision Process chooses among *all* feasible routes
//!   to the same destination.
//!
//! The expected values here come from those clauses. The tests mask addresses
//! with their own bit-by-bit [`network`] function, never with the library's.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use pathvector_rib::{
    AdjRibIn, AdjRibOut, BestPathChange, InsertOutcome, LocRib, PeerId, Route, RouteBuilder,
    oracle::AlwaysReachable,
};
use pathvector_types::{AsPath, IpAddress, LocalPref, Nlri, Origin, PeerType};
use proptest::prelude::*;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn peer(n: u8) -> PeerId {
    PeerId::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, n)))
}

fn v4(s: &str) -> Nlri<Ipv4Addr> {
    s.parse().unwrap()
}

fn v6(s: &str) -> Nlri<Ipv6Addr> {
    s.parse().unwrap()
}

fn route<A: IpAddress>(nlri: Nlri<A>, local_pref: u32) -> Route<A> {
    RouteBuilder::new(nlri, Origin::Igp, AsPath::new())
        .local_pref(LocalPref::new(local_pref))
        .peer_type(PeerType::External)
        .build()
}

/// The first `len` bits of `bits`, in an address `A::BITS` wide; the rest
/// zero. Deliberately bit by bit so it shares no code with the library's mask.
fn network<A: IpAddress>(bits: u128, len: u8) -> u128 {
    let width = u32::from(A::BITS);
    (0..u32::from(len))
        .map(|i| bits & (1u128 << (width - 1 - i)))
        .fold(0, |acc, bit| acc | bit)
}

/// A destination, identified the way the RFC identifies it.
type Dest = (u128, u8);

fn dest<A: IpAddress>(nlri: Nlri<A>) -> Dest {
    let len = nlri.prefix_len();
    (network::<A>(nlri.prefix().ip().to_u128(), len), len)
}

/// Asserts that `nlri` carries no bits beyond its length — the form every RIB
/// hands back to its callers.
fn assert_canonical<A: IpAddress>(nlri: Nlri<A>) {
    let bits = nlri.prefix().ip().to_u128();
    assert_eq!(
        bits,
        network::<A>(bits, nlri.prefix_len()),
        "{nlri} carries host bits"
    );
}

// ── Reported reproductions ───────────────────────────────────────────────────

/// Issue #71: "Inserting a route for `10.1.2.3/8` leaves
/// `longest_match(10.9.8.7)` returning `None` even though the table contains a
/// candidate covering the address."
#[test]
fn issue_71_longest_match_finds_a_route_inserted_with_host_bits() {
    let mut rib = LocRib::new();
    rib.insert(peer(1), route(v4("10.1.2.3/8"), 100), &AlwaysReachable);

    let found = rib
        .longest_match(Ipv4Addr::new(10, 9, 8, 7))
        .expect("10.0.0.0/8 covers 10.9.8.7");
    assert_eq!(found.nlri, v4("10.0.0.0/8"));
}

/// The follow-up comment on issue #71: `192.0.2.129/24` was reported as
/// `len=1 best(raw)=true best_routes=0 longest_match=false`.
#[test]
fn issue_71_comment_best_routes_and_longest_match_see_the_candidate() {
    let mut rib = LocRib::new();
    let supplied = v4("192.0.2.129/24");
    rib.insert(peer(1), route(supplied, 100), &AlwaysReachable);

    assert_eq!(rib.len(), 1);
    assert!(rib.best(&supplied).is_some());
    assert!(rib.best(&v4("192.0.2.0/24")).is_some());
    assert_eq!(rib.best_routes().count(), 1);
    assert!(rib.longest_match(Ipv4Addr::new(192, 0, 2, 1)).is_some());
}

// ── Loc-RIB: one destination, whatever form it arrives in ────────────────────

/// Two host-bit variants of one prefix, and its canonical form, driven through
/// every `LocRib` entry point.
fn loc_rib_treats_variants_as_one_destination<A: IpAddress>(
    canonical: Nlri<A>,
    variant_a: Nlri<A>,
    variant_b: Nlri<A>,
    covered: A,
) {
    assert_canonical(canonical);
    assert_ne!(variant_a, canonical);
    assert_ne!(variant_b, canonical);
    assert_eq!(dest(variant_a), dest(canonical));
    assert_eq!(dest(variant_b), dest(canonical));
    let forms = [canonical, variant_a, variant_b];

    let mut rib = LocRib::new();

    // First announcement.
    let change = rib.insert(peer(1), route(variant_a, 100), &AlwaysReachable);
    assert_eq!(
        change,
        BestPathChange::Announced(canonical, route(canonical, 100))
    );

    // RFC 4271 §9: the same destination in another form replaces the route.
    let change = rib.insert(peer(1), route(variant_b, 150), &AlwaysReachable);
    assert_eq!(
        change,
        BestPathChange::Announced(canonical, route(canonical, 150))
    );
    assert_eq!(rib.len(), 1, "one destination, one entry");

    // RFC 4271 §9.1: a second peer's route to it competes with the first.
    let change = rib.insert(peer(2), route(canonical, 200), &AlwaysReachable);
    assert_eq!(
        change,
        BestPathChange::Announced(canonical, route(canonical, 200))
    );
    assert_eq!(rib.len(), 1);

    // Every read, through every form.
    for form in forms {
        assert_eq!(rib.best_peer(&form), Some(peer(2)), "best_peer({form})");
        assert_eq!(
            rib.best(&form),
            Some(&route(canonical, 200)),
            "best({form})"
        );
        let candidates = rib.candidates(&form).expect("candidates");
        assert_eq!(candidates.len(), 2, "candidates({form})");
        assert!(candidates.values().all(|r| r.nlri == canonical));
    }
    let best: Vec<_> = rib.best_routes().map(|(n, r)| (n, r.nlri)).collect();
    assert_eq!(best, vec![(canonical, canonical)]);
    assert_eq!(rib.longest_match(covered), Some(&route(canonical, 200)));
    assert_eq!(rib.best_win_count(&peer(2)), 1);

    // Withdrawal through a non-canonical form: the other candidate takes over.
    let change = rib.withdraw(&peer(2), &variant_a, &AlwaysReachable);
    assert_eq!(
        change,
        BestPathChange::Announced(canonical, route(canonical, 150))
    );

    // ...and the last one through the canonical form, although it was inserted
    // with host bits.
    let change = rib.withdraw(&peer(1), &canonical, &AlwaysReachable);
    assert_eq!(change, BestPathChange::Withdrawn(canonical));

    // Nothing stale in any index.
    assert!(rib.is_empty());
    assert_eq!(rib.len(), 0);
    assert_eq!(rib.best_routes().count(), 0);
    assert_eq!(rib.longest_match(covered), None);
    for form in forms {
        assert_eq!(rib.best(&form), None);
        assert_eq!(rib.best_peer(&form), None);
        assert!(rib.candidates(&form).is_none());
    }
    assert_eq!(rib.best_win_count(&peer(1)), 0);
    assert_eq!(rib.best_win_count(&peer(2)), 0);
    assert!(rib.best_win_counts_consistent());
}

#[test]
fn loc_rib_ipv4_non_octet_aligned_lengths() {
    // /23: bit 8 of the third octet onwards is host.
    loc_rib_treats_variants_as_one_destination(
        v4("172.16.2.0/23"),
        v4("172.16.3.255/23"),
        v4("172.16.2.1/23"),
        Ipv4Addr::new(172, 16, 3, 9),
    );
    // /13.
    loc_rib_treats_variants_as_one_destination(
        v4("10.8.0.0/13"),
        v4("10.15.255.255/13"),
        v4("10.9.0.0/13"),
        Ipv4Addr::new(10, 11, 1, 1),
    );
    // /31 (RFC 3021): a single host bit.
    loc_rib_treats_variants_as_one_destination(
        v4("192.0.2.6/31"),
        v4("192.0.2.7/31"),
        // /31 has only one non-canonical spelling.
        v4("192.0.2.7/31"),
        Ipv4Addr::new(192, 0, 2, 7),
    );
}

#[test]
fn loc_rib_ipv4_default_route() {
    loc_rib_treats_variants_as_one_destination(
        v4("0.0.0.0/0"),
        v4("203.0.113.7/0"),
        v4("255.255.255.255/0"),
        Ipv4Addr::new(8, 8, 8, 8),
    );
}

#[test]
fn loc_rib_ipv6_non_octet_aligned_lengths() {
    loc_rib_treats_variants_as_one_destination(
        v6("2001:db8:8::/45"),
        v6("2001:db8:f:ffff::1/45"),
        v6("2001:db8:9::/45"),
        "2001:db8:a::42".parse().unwrap(),
    );
    loc_rib_treats_variants_as_one_destination(
        v6("2001:db8:8000::/33"),
        v6("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff/33"),
        v6("2001:db8:8000::1/33"),
        "2001:db8:abcd::".parse().unwrap(),
    );
}

#[test]
fn loc_rib_ipv6_default_route() {
    loc_rib_treats_variants_as_one_destination(
        v6("::/0"),
        v6("2001:db8::1/0"),
        v6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0"),
        "2001:db8::5".parse().unwrap(),
    );
}

/// A full-length prefix has no trailing bits: neighbouring host routes stay
/// distinct destinations.
#[test]
fn host_routes_are_not_merged() {
    let mut rib = LocRib::new();
    rib.insert(peer(1), route(v4("192.0.2.1/32"), 100), &AlwaysReachable);
    rib.insert(peer(1), route(v4("192.0.2.2/32"), 100), &AlwaysReachable);
    assert_eq!(rib.len(), 2);

    let mut rib6 = LocRib::new();
    rib6.insert(peer(1), route(v6("2001:db8::1/128"), 100), &AlwaysReachable);
    rib6.insert(peer(1), route(v6("2001:db8::2/128"), 100), &AlwaysReachable);
    assert_eq!(rib6.len(), 2);
}

/// RFC 4271 §8.2.2 (session down) removes every route learned from the peer,
/// including ones inserted with host bits.
#[test]
fn withdraw_peer_reports_canonical_prefixes_and_leaves_nothing() {
    let mut rib = LocRib::new();
    rib.insert(peer(1), route(v4("10.1.2.3/8"), 100), &AlwaysReachable);
    rib.insert(peer(1), route(v4("10.200.0.1/8"), 100), &AlwaysReachable);
    rib.insert(peer(1), route(v4("192.0.2.129/25"), 100), &AlwaysReachable);

    let changes = rib.withdraw_peer(&peer(1), &AlwaysReachable);

    let withdrawn: BTreeSet<_> = changes
        .iter()
        .map(|c| match c {
            BestPathChange::Withdrawn(n) => n.to_string(),
            other => panic!("expected Withdrawn, got {other:?}"),
        })
        .collect();
    assert_eq!(changes.len(), 2, "two destinations, not three");
    assert_eq!(
        withdrawn,
        BTreeSet::from(["10.0.0.0/8".to_string(), "192.0.2.128/25".to_string()])
    );
    assert!(rib.is_empty());
    assert_eq!(rib.best_routes().count(), 0);
}

// ── Adj-RIB-In ───────────────────────────────────────────────────────────────

fn adj_rib_in_treats_variants_as_one_destination<A: IpAddress>(
    canonical: Nlri<A>,
    variant_a: Nlri<A>,
    variant_b: Nlri<A>,
) {
    let mut table = AdjRibIn::new(peer(1));
    assert_eq!(table.insert(route(variant_a, 100)), None);
    // RFC 4271 §9: replaces, and hands back what it replaced.
    assert_eq!(
        table.insert(route(variant_b, 200)),
        Some(route(canonical, 100))
    );
    assert_eq!(table.len(), 1);

    for form in [canonical, variant_a, variant_b] {
        assert_eq!(table.get(&form), Some(&route(canonical, 200)), "{form}");
    }
    let stored: Vec<_> = table.routes().map(|(n, r)| (*n, r.nlri)).collect();
    assert_eq!(stored, vec![(canonical, canonical)]);

    assert_eq!(table.withdraw(&variant_a), Some(route(canonical, 200)));
    assert!(table.is_empty());

    table.insert(route(variant_a, 100));
    assert_eq!(table.withdraw(&canonical), Some(route(canonical, 100)));
    assert!(table.is_empty());
}

#[test]
fn adj_rib_in_ipv4() {
    adj_rib_in_treats_variants_as_one_destination(
        v4("172.16.2.0/23"),
        v4("172.16.3.255/23"),
        v4("172.16.2.1/23"),
    );
}

#[test]
fn adj_rib_in_ipv6() {
    adj_rib_in_treats_variants_as_one_destination(
        v6("2001:db8:8::/45"),
        v6("2001:db8:f:ffff::1/45"),
        v6("2001:db8:9::/45"),
    );
}

// ── Adj-RIB-Out ──────────────────────────────────────────────────────────────

fn adj_rib_out_treats_variants_as_one_destination<A: IpAddress>(
    canonical: Nlri<A>,
    variant_a: Nlri<A>,
    variant_b: Nlri<A>,
) {
    let mut table = AdjRibOut::new(peer(1), PeerType::External);
    assert!(matches!(
        table.insert(route(variant_a, 100)),
        InsertOutcome::Accepted(None)
    ));
    match table.insert(route(variant_b, 200)) {
        InsertOutcome::Accepted(Some(old)) => assert_eq!(old, route(canonical, 100)),
        other => panic!("expected a replacement, got {other:?}"),
    }
    assert_eq!(table.len(), 1);

    for form in [canonical, variant_a, variant_b] {
        assert_eq!(table.get(&form), Some(&route(canonical, 200)), "{form}");
    }
    let stored: Vec<_> = table.routes().map(|(n, r)| (*n, r.nlri)).collect();
    assert_eq!(stored, vec![(canonical, canonical)]);

    assert_eq!(table.withdraw(&variant_a), Some(route(canonical, 200)));
    assert!(table.is_empty());

    table.insert(route(variant_a, 100));
    assert_eq!(table.withdraw(&canonical), Some(route(canonical, 100)));
    assert!(table.is_empty());
}

#[test]
fn adj_rib_out_ipv4() {
    adj_rib_out_treats_variants_as_one_destination(
        v4("172.16.2.0/23"),
        v4("172.16.3.255/23"),
        v4("172.16.2.1/23"),
    );
}

#[test]
fn adj_rib_out_ipv6() {
    adj_rib_out_treats_variants_as_one_destination(
        v6("2001:db8:8::/45"),
        v6("2001:db8:f:ffff::1/45"),
        v6("2001:db8:9::/45"),
    );
}

/// The split-horizon branch of `insert` has its own removal: it must find the
/// previously advertised route (RFC 4271 §9.2) when the suppressed
/// replacement spells the prefix differently, or the caller sends no WITHDRAW.
#[test]
fn adj_rib_out_split_horizon_evicts_across_variants() {
    let mut table: AdjRibOut<Ipv4Addr> = AdjRibOut::new(peer(1), PeerType::Internal);
    table.insert(route(v4("10.0.0.0/8"), 100));

    let mut from_ibgp = route(v4("10.1.2.3/8"), 100);
    from_ibgp.peer_type = PeerType::Internal;
    match table.insert(from_ibgp) {
        InsertOutcome::Filtered(Some(old)) => assert_eq!(old.nlri, v4("10.0.0.0/8")),
        other => panic!("expected the old advertisement to be evicted, got {other:?}"),
    }
    assert!(table.is_empty());
}

// ── Properties: the hash-keyed views and the prefix-tree views agree ─────────
//
// `LocRib` answers `len`/`best`/`best_peer`/`candidates` from hash maps and
// `best_routes`/`longest_match` through its prefix tree. After every operation
// in a random sequence, both must agree with a model keyed on the destination.

const PEERS: u8 = 3;

/// The addresses and prefix lengths a run draws from: small, so that distinct
/// spellings of one destination (and nested destinations) collide often.
#[derive(Debug, Clone, Copy)]
struct Universe {
    addrs: &'static [u128],
    lens: &'static [u8],
}

const V4: Universe = Universe {
    // 10.0.0.0, 10.1.2.3, 10.1.3.200, 192.0.2.129, 192.0.2.1, 255.255.255.255
    addrs: &[
        0x0A00_0000,
        0x0A01_0203,
        0x0A01_03C8,
        0xC000_0281,
        0xC000_0201,
        0xFFFF_FFFF,
    ],
    lens: &[0, 7, 8, 13, 23, 24, 31, 32],
};

const V6: Universe = Universe {
    addrs: &[
        0x2001_0db8_0000_0000_0000_0000_0000_0000,
        0x2001_0db8_000f_ffff_0000_0000_0000_0001,
        0x2001_0db8_0009_0000_0000_0000_0000_0000,
        0x2001_0db8_8000_0000_0000_0000_0000_0003,
        0xfd00_0000_0000_0000_0000_0000_0000_0002,
        0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
    ],
    lens: &[0, 3, 32, 33, 45, 64, 127, 128],
};

/// A prefix as a caller might supply it: an address from the universe, a
/// length, and noise to XOR into the bits beyond that length.
#[derive(Debug, Clone, Copy)]
struct Spelling {
    addr: usize,
    len: usize,
    noise: u128,
}

impl Spelling {
    fn nlri<A: IpAddress>(self, universe: Universe) -> Nlri<A> {
        let len = universe.lens[self.len];
        let width_mask = u128::MAX >> (128 - u32::from(A::BITS));
        let host_mask = width_mask ^ network::<A>(width_mask, len);
        let bits = universe.addrs[self.addr] ^ (self.noise & host_mask);
        Nlri::new(A::from_u128(bits), len).unwrap()
    }
}

fn arb_spelling() -> impl Strategy<Value = Spelling> {
    // Half the spellings are the universe address itself.
    (
        0..6usize,
        0..8usize,
        prop_oneof![Just(0u128), any::<u128>()],
    )
        .prop_map(|(addr, len, noise)| Spelling { addr, len, noise })
}

#[derive(Debug, Clone)]
enum LocOp {
    Insert(u8, Spelling, u32),
    Withdraw(u8, Spelling),
    WithdrawPeer(u8),
    RecomputeAll,
}

fn arb_loc_op() -> impl Strategy<Value = LocOp> {
    prop_oneof![
        6 => (1..=PEERS, arb_spelling(), 0u32..4).prop_map(|(p, s, lp)| LocOp::Insert(p, s, lp)),
        3 => (1..=PEERS, arb_spelling()).prop_map(|(p, s)| LocOp::Withdraw(p, s)),
        1 => (1..=PEERS).prop_map(LocOp::WithdrawPeer),
        1 => Just(LocOp::RecomputeAll),
    ]
}

/// Destination → peer → `LOCAL_PREF`.
type Model = BTreeMap<Dest, BTreeMap<u8, u32>>;

/// The highest `LOCAL_PREF` wins (RFC 4271 §9.1.1 degree of preference); the
/// generator makes it unique per peer, so no tie-break is ever needed.
fn model_best(peers: &BTreeMap<u8, u32>) -> (u8, u32) {
    peers
        .iter()
        .map(|(&p, &lp)| (p, lp))
        .max_by_key(|&(_, lp)| lp)
        .expect("model never keeps an empty destination")
}

fn check_loc_rib<A: IpAddress>(
    rib: &LocRib<A>,
    model: &Model,
    universe: Universe,
    noise: u128,
) -> Result<(), TestCaseError> {
    // Hash-keyed count.
    prop_assert_eq!(rib.len(), model.len());
    prop_assert_eq!(rib.is_empty(), model.is_empty());

    // Tree view: exactly one best route per destination, canonical.
    let mut tree = BTreeMap::new();
    for (nlri, r) in rib.best_routes() {
        assert_canonical(nlri);
        prop_assert_eq!(nlri, r.nlri);
        let lp = r.local_pref.map(LocalPref::as_u32);
        prop_assert!(tree.insert(dest(nlri), lp).is_none(), "duplicate {}", nlri);
    }
    let expected: BTreeMap<_, _> = model
        .iter()
        .map(|(&d, peers)| (d, Some(model_best(peers).1)))
        .collect();
    prop_assert_eq!(&tree, &expected);

    // Hash views, asked in canonical and non-canonical spellings.
    for addr in 0..universe.addrs.len() {
        for len in 0..universe.lens.len() {
            for noise in [0, noise] {
                let nlri: Nlri<A> = Spelling { addr, len, noise }.nlri(universe);
                let want = model.get(&dest(nlri));
                prop_assert_eq!(
                    rib.best_peer(&nlri),
                    want.map(|peers| peer(model_best(peers).0))
                );
                prop_assert_eq!(
                    rib.best(&nlri)
                        .and_then(|r| r.local_pref)
                        .map(LocalPref::as_u32),
                    want.map(|peers| model_best(peers).1)
                );
                let got: BTreeSet<PeerId> = rib
                    .candidates(&nlri)
                    .into_iter()
                    .flat_map(|map| {
                        map.into_iter().map(|(p, r)| {
                            assert_canonical(r.nlri);
                            p
                        })
                    })
                    .collect();
                let want_peers: BTreeSet<PeerId> = want
                    .into_iter()
                    .flat_map(|peers| peers.keys().map(|&p| peer(p)))
                    .collect();
                prop_assert_eq!(got, want_peers);
            }
        }
    }

    // Forwarding lookup: the longest destination covering the address.
    for &base in universe.addrs {
        let width_mask = u128::MAX >> (128 - u32::from(A::BITS));
        for addr in [base, (base ^ noise) & width_mask] {
            let want = model
                .iter()
                .filter(|&(&(net, len), _)| network::<A>(addr, len) == net)
                .max_by_key(|&(&(_, len), _)| len)
                .map(|(&d, peers)| (d, Some(model_best(peers).1)));
            let got = rib
                .longest_match(A::from_u128(addr))
                .map(|r| (dest(r.nlri), r.local_pref.map(LocalPref::as_u32)));
            prop_assert_eq!(got, want);
        }
    }

    for p in 1..=PEERS {
        let wins = model.values().filter(|c| model_best(c).0 == p).count();
        prop_assert_eq!(rib.best_win_count(&peer(p)), wins);
    }
    prop_assert!(rib.best_win_counts_consistent());
    Ok(())
}

/// Applies one reported change to a replica of the best-route table. A change
/// must name its prefix canonically, or the replica (a FIB, a peer's view)
/// ends up with entries it cannot remove.
fn replay<A: IpAddress>(
    replica: &mut BTreeMap<Dest, u32>,
    change: &BestPathChange<A>,
) -> Result<(), TestCaseError> {
    match change {
        BestPathChange::Announced(nlri, r) => {
            assert_canonical(*nlri);
            prop_assert_eq!(*nlri, r.nlri);
            replica.insert(dest(*nlri), r.local_pref.expect("set").as_u32());
        }
        BestPathChange::Withdrawn(nlri) => {
            assert_canonical(*nlri);
            prop_assert!(replica.remove(&dest(*nlri)).is_some(), "{}", nlri);
        }
        BestPathChange::Unchanged => {}
    }
    Ok(())
}

fn run_loc_rib<A: IpAddress>(
    universe: Universe,
    ops: &[LocOp],
    noise: u128,
) -> Result<(), TestCaseError> {
    let mut rib: LocRib<A> = LocRib::new();
    let mut model = Model::new();
    let mut replica = BTreeMap::new();

    for op in ops {
        match *op {
            LocOp::Insert(p, spelling, lp) => {
                let nlri: Nlri<A> = spelling.nlri(universe);
                // Distinct per peer, so the winner is never a tie.
                let lp = lp * 10 + u32::from(p);
                let change = rib.insert(peer(p), route(nlri, lp), &AlwaysReachable);
                model.entry(dest(nlri)).or_default().insert(p, lp);
                replay(&mut replica, &change)?;
            }
            LocOp::Withdraw(p, spelling) => {
                let nlri: Nlri<A> = spelling.nlri(universe);
                let change = rib.withdraw(&peer(p), &nlri, &AlwaysReachable);
                if let Some(peers) = model.get_mut(&dest(nlri)) {
                    peers.remove(&p);
                }
                model.retain(|_, peers| !peers.is_empty());
                replay(&mut replica, &change)?;
            }
            LocOp::WithdrawPeer(p) => {
                let changes = rib.withdraw_peer(&peer(p), &AlwaysReachable);
                for peers in model.values_mut() {
                    peers.remove(&p);
                }
                model.retain(|_, peers| !peers.is_empty());
                for change in &changes {
                    replay(&mut replica, change)?;
                }
            }
            LocOp::RecomputeAll => {
                for change in rib.recompute_all(&AlwaysReachable) {
                    replay(&mut replica, &change)?;
                }
            }
        }
        check_loc_rib(&rib, &model, universe, noise)?;
        let expected: BTreeMap<_, _> = model
            .iter()
            .map(|(&d, peers)| (d, model_best(peers).1))
            .collect();
        prop_assert_eq!(&replica, &expected);
    }
    Ok(())
}

#[derive(Debug, Clone)]
enum AdjOp {
    Insert(Spelling, u32),
    Withdraw(Spelling),
}

fn arb_adj_op() -> impl Strategy<Value = AdjOp> {
    prop_oneof![
        2 => (arb_spelling(), 0u32..100).prop_map(|(s, lp)| AdjOp::Insert(s, lp)),
        1 => arb_spelling().prop_map(AdjOp::Withdraw),
    ]
}

fn run_adj_ribs<A: IpAddress>(universe: Universe, ops: &[AdjOp]) -> Result<(), TestCaseError> {
    let mut inbound: AdjRibIn<A> = AdjRibIn::new(peer(1));
    let mut outbound: AdjRibOut<A> = AdjRibOut::new(peer(1), PeerType::External);
    let mut model: BTreeMap<Dest, u32> = BTreeMap::new();
    let lp_of = |r: &Route<A>| r.local_pref.expect("set").as_u32();

    for op in ops {
        match *op {
            AdjOp::Insert(spelling, lp) => {
                let nlri: Nlri<A> = spelling.nlri(universe);
                let previous = model.insert(dest(nlri), lp);
                let replaced_in = inbound.insert(route(nlri, lp));
                prop_assert_eq!(replaced_in.as_ref().map(lp_of), previous);
                match outbound.insert(route(nlri, lp)) {
                    InsertOutcome::Accepted(old) => {
                        prop_assert_eq!(old.as_ref().map(lp_of), previous);
                    }
                    InsertOutcome::Filtered(_) => prop_assert!(false, "eBGP is never filtered"),
                }
            }
            AdjOp::Withdraw(spelling) => {
                let nlri: Nlri<A> = spelling.nlri(universe);
                let previous = model.remove(&dest(nlri));
                prop_assert_eq!(inbound.withdraw(&nlri).as_ref().map(lp_of), previous);
                prop_assert_eq!(outbound.withdraw(&nlri).as_ref().map(lp_of), previous);
            }
        }

        prop_assert_eq!(inbound.len(), model.len());
        prop_assert_eq!(outbound.len(), model.len());
        for routes in [
            inbound.routes().collect::<Vec<_>>(),
            outbound.routes().collect::<Vec<_>>(),
        ] {
            let mut seen = BTreeMap::new();
            for (nlri, r) in routes {
                assert_canonical(*nlri);
                prop_assert_eq!(*nlri, r.nlri);
                seen.insert(dest(*nlri), lp_of(r));
            }
            prop_assert_eq!(&seen, &model);
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]

    #[test]
    fn prop_loc_rib_hash_and_tree_views_agree_v4(
        ops in proptest::collection::vec(arb_loc_op(), 1..40),
        noise in any::<u128>(),
    ) {
        run_loc_rib::<Ipv4Addr>(V4, &ops, noise)?;
    }

    #[test]
    fn prop_loc_rib_hash_and_tree_views_agree_v6(
        ops in proptest::collection::vec(arb_loc_op(), 1..40),
        noise in any::<u128>(),
    ) {
        run_loc_rib::<Ipv6Addr>(V6, &ops, noise)?;
    }

    #[test]
    fn prop_adj_ribs_key_on_the_destination_v4(
        ops in proptest::collection::vec(arb_adj_op(), 1..60),
    ) {
        run_adj_ribs::<Ipv4Addr>(V4, &ops)?;
    }

    #[test]
    fn prop_adj_ribs_key_on_the_destination_v6(
        ops in proptest::collection::vec(arb_adj_op(), 1..60),
    ) {
        run_adj_ribs::<Ipv6Addr>(V6, &ops)?;
    }
}
