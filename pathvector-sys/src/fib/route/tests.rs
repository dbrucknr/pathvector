//! Tests for kernel route identity and the route mirror.
//!
//! Sources (Linux v6.12):
//! - `net/ipv4/fib_trie.c`: `fib_valid_key_len`, `fib_table_insert`,
//!   `fib_table_delete`, `fib_table_lookup`.
//! - `net/ipv6/ip6_fib.c`: `fib6_add_rt2node`, `fib6_del_route`.
//! - `include/net/ip6_route.h`: `rt6_qualify_for_ecmp`.
//!
//! The expected values are worked out from those functions, not from this
//! module's implementation. The property tests compare the mirror with a
//! separate reference model written directly from the lookup rule.

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
};

use proptest::prelude::*;

use super::*;

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn p4(s: &str) -> Ipv4Prefix {
    let (addr, len) = s.split_once('/').unwrap();
    Ipv4Prefix::new(addr.parse().unwrap(), len.parse().unwrap()).unwrap()
}

fn p6(s: &str) -> Ipv6Prefix {
    let (addr, len) = s.split_once('/').unwrap();
    Ipv6Prefix::new(addr.parse().unwrap(), len.parse().unwrap()).unwrap()
}

fn via(gateway: Option<&str>) -> NextHopPath {
    NextHopPath {
        gateway: gateway.map(|g| g.parse::<IpAddr>().unwrap()),
        oif: NonZeroU32::new(1),
    }
}

fn v4(prefix: &str, priority: u32, gateway: Option<&str>) -> KernelRouteV4 {
    KernelRouteV4 {
        slot: RouteSlotV4 {
            table: TableId::MAIN,
            dst: p4(prefix),
            tos: 0,
            priority,
        },
        protocol: 3,
        scope: 0,
        prefsrc: None,
        next_hop: NextHopV4::Path(via(gateway)),
    }
}

fn v6(prefix: &str, priority: u32, gateway: Option<&str>) -> KernelRouteV6 {
    KernelRouteV6 {
        slot: RouteSlotV6 {
            table: TableId::MAIN,
            dst: p6(prefix),
            src: Ipv6Prefix::DEFAULT,
            priority,
        },
        protocol: 3,
        next_hop: NextHopV6::Path(via(gateway)),
    }
}

fn a4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn a6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn metric4(list: &RouteList<KernelRouteV4>, addr: &str) -> Option<u32> {
    list.lookup(a4(addr)).map(|r| r.slot.priority)
}

fn metric6(list: &RouteList<KernelRouteV6>, addr: &str) -> Option<u32> {
    list.lookup(a6(addr)).map(|r| r.slot.priority)
}

// ── Prefix and table newtypes ─────────────────────────────────────────────────

#[test]
fn prefix_rejects_what_the_kernel_rejects() {
    // fib_valid_key_len: plen > KEYLENGTH → "Invalid prefix length";
    // (key << plen) != 0 → "Invalid prefix for given prefix length".
    assert_eq!(
        Ipv4Prefix::new(a4("10.0.0.0"), 33),
        Err(PrefixError::LengthOutOfRange { len: 33, max: 32 })
    );
    assert_eq!(
        Ipv4Prefix::new(a4("10.0.0.1"), 24),
        Err(PrefixError::HostBitsSet)
    );
    assert_eq!(
        Ipv6Prefix::new(a6("2001:db8::"), 129),
        Err(PrefixError::LengthOutOfRange { len: 129, max: 128 })
    );
    assert_eq!(
        Ipv6Prefix::new(a6("2001:db8::1"), 64),
        Err(PrefixError::HostBitsSet)
    );
    assert!(Ipv4Prefix::new(a4("10.0.0.1"), 32).is_ok());
    assert!(Ipv6Prefix::new(a6("2001:db8::1"), 128).is_ok());
    assert!(Ipv4Prefix::new(a4("0.0.0.0"), 0).unwrap().is_default());
}

#[test]
fn prefix_display_and_errors_are_readable() {
    assert_eq!(p4("10.1.0.0/16").to_string(), "10.1.0.0/16");
    assert_eq!(p6("2001:db8::/32").to_string(), "2001:db8::/32");
    assert_eq!(
        PrefixError::HostBitsSet.to_string(),
        "address has bits set beyond the prefix length"
    );
    assert_eq!(
        PrefixError::LengthOutOfRange { len: 40, max: 32 }.to_string(),
        "prefix length 40 exceeds the address width of 32"
    );
}

#[test]
fn table_zero_is_not_a_table() {
    // RT_TABLE_UNSPEC = 0 in <linux/rtnetlink.h>.
    assert_eq!(TableId::new(0), None);
    assert_eq!(TableId::new(254), Some(TableId::MAIN));
    assert_eq!(TableId::MAIN.get(), 254);
}

// ── Issue #56 acceptance at the domain level ─────────────────────────────────

#[test]
fn ipv4_metric_10_and_100_coexist_in_either_order() {
    // fib_table_insert keys aliases by "[prefix,dscp,priority]", so these are
    // two routes; fib_table_lookup takes the first alias, i.e. priority 10.
    let primary = v4("198.51.100.0/24", 10, None);
    let backup = v4("198.51.100.0/24", 100, None);
    for order in [[&primary, &backup], [&backup, &primary]] {
        let mut list = RouteList::default();
        for r in order {
            assert!(list.insert_front(r.clone()));
        }
        assert_eq!(list.len(), 2);
        assert_eq!(metric4(&list, "198.51.100.1"), Some(10));

        let mut l = list.clone();
        assert!(l.remove(&backup));
        assert_eq!(metric4(&l, "198.51.100.1"), Some(10));

        let mut l = list.clone();
        assert!(l.remove(&primary));
        assert_eq!(metric4(&l, "198.51.100.1"), Some(100));
        assert!(l.remove(&backup));
        assert_eq!(metric4(&l, "198.51.100.1"), None);
    }
}

#[test]
fn ipv6_metric_10_and_100_coexist_in_either_order() {
    // fib6_add_rt2node: different metrics are different "priority levels";
    // the node's routes are sorted by metric and the lowest is used.
    let primary = v6("2001:db8:1::/64", 10, None);
    let backup = v6("2001:db8:1::/64", 100, None);
    for order in [[&primary, &backup], [&backup, &primary]] {
        let mut list = RouteList::default();
        for r in order {
            assert!(list.insert_back(r.clone()));
        }
        assert_eq!(metric6(&list, "2001:db8:1::1"), Some(10));

        let mut l = list.clone();
        assert!(l.remove(&backup));
        assert_eq!(metric6(&l, "2001:db8:1::1"), Some(10));

        let mut l = list.clone();
        assert!(l.remove(&primary));
        assert_eq!(metric6(&l, "2001:db8:1::1"), Some(100));
    }
}

#[test]
fn removing_one_route_falls_back_to_a_shorter_prefix() {
    // When no alias of a leaf matches, fib_table_lookup backtracks.
    let mut list = RouteList::default();
    list.insert_back(v4("0.0.0.0/0", 1, Some("192.0.2.1")));
    list.insert_back(v4("10.0.0.0/8", 50, None));
    assert_eq!(metric4(&list, "10.1.1.1"), Some(50));
    list.remove(&v4("10.0.0.0/8", 50, None));
    assert_eq!(metric4(&list, "10.1.1.1"), Some(1));
}

// ── Other selectors ───────────────────────────────────────────────────────────

#[test]
fn tables_tos_and_source_prefix_are_part_of_the_slot() {
    let main = v4("10.0.0.0/8", 10, None);
    let mut other_table = main.clone();
    other_table.slot.table = TableId::new(100).unwrap();
    let mut tos = main.clone();
    tos.slot.tos = 0x10;

    let mut list = RouteList::default();
    assert!(list.insert_back(main.clone()));
    assert!(list.insert_back(other_table.clone()));
    assert!(list.insert_back(tos.clone()));
    assert_eq!(list.len(), 3);
    assert!(list.remove(&main));
    assert!(list.contains(&other_table) && list.contains(&tos));

    let plain = v6("2001:db8::/32", 10, None);
    let mut sourced = plain.clone();
    sourced.slot.src = p6("2001:db8:ffff::/48");
    let mut list6 = RouteList::default();
    assert!(list6.insert_back(plain.clone()));
    assert!(list6.insert_back(sourced.clone()));
    assert!(list6.remove(&plain));
    assert!(list6.contains(&sourced));
}

#[test]
fn tos_and_source_specific_routes_are_not_used_for_best_effort_lookups() {
    // fib_table_lookup skips `fa->fa_dscp && !fib_dscp_masked_match(...)`;
    // an IPv6 source-specific route only matches traffic from that source.
    let mut tos = v4("10.0.0.0/8", 1, None);
    tos.slot.tos = 0x10;
    let mut list = RouteList::default();
    list.insert_back(tos);
    assert_eq!(metric4(&list, "10.1.1.1"), None);
    list.insert_back(v4("10.0.0.0/8", 50, None));
    assert_eq!(metric4(&list, "10.1.1.1"), Some(50));

    let mut sourced = v6("2001:db8::/32", 1, None);
    sourced.slot.src = p6("2001:db8:ffff::/48");
    let mut list6 = RouteList::default();
    list6.insert_back(sourced);
    assert_eq!(metric6(&list6, "2001:db8::1"), None);
}

#[test]
fn routes_in_one_slot_are_kept_and_removed_individually() {
    // fib_table_insert rejects only "a perfect match which uses the same
    // scope, type, and nexthop information"; rt6_duplicate_nexthop likewise.
    let a = v4("10.0.0.0/8", 10, Some("192.0.2.1"));
    let b = v4("10.0.0.0/8", 10, Some("192.0.2.2"));
    let mut list = RouteList::default();
    assert!(list.insert_back(a.clone()));
    assert!(list.insert_back(b.clone()));
    assert!(!list.insert_back(a.clone()), "exact duplicate is not added");
    assert!(list.remove(&a));
    assert_eq!(metric4(&list, "10.1.1.1"), Some(10));
    assert!(!list.remove(&a), "already gone");
}

#[test]
fn ipv6_protocol_is_not_part_of_identity() {
    // rt6_duplicate_nexthop compares device, gateway and encap only.
    let a = v6("2001:db8::/32", 10, Some("fe80::1"));
    let mut b = a.clone();
    b.protocol = 16;
    let mut list = RouteList::default();
    list.insert_back(a);
    assert!(!list.insert_back(b.clone()));
    assert!(list.remove(&b));
}

#[test]
fn equal_routes_tie_break_on_mirror_order() {
    let a = v4("10.0.0.0/8", 10, Some("192.0.2.1"));
    let b = v4("10.0.0.0/8", 10, Some("192.0.2.2"));
    let mut list = RouteList::default();
    list.insert_back(a.clone());
    list.insert_back(b.clone());
    assert_eq!(list.lookup(a4("10.1.1.1")), Some(&a));
    let mut list = RouteList::default();
    list.insert_back(a.clone());
    list.insert_front(b.clone());
    assert_eq!(list.lookup(a4("10.1.1.1")), Some(&b));
}

#[test]
fn insert_front_and_back_place_routes_within_their_slot() {
    let a = v4("10.0.0.0/8", 10, Some("192.0.2.1"));
    let b = v4("10.0.0.0/8", 10, Some("192.0.2.2"));
    let c = v4("10.0.0.0/8", 10, Some("192.0.2.3"));
    let other = v4("172.16.0.0/12", 10, None);
    let mut list = RouteList::default();
    list.insert_back(a.clone());
    list.insert_back(other.clone());
    list.insert_back(b.clone()); // after a, before `other`
    list.insert_front(c.clone()); // before a
    let order: Vec<_> = list.iter().cloned().collect();
    assert_eq!(order, vec![c, a, b, other]);
}

// ── IPv4 NLM_F_REPLACE ────────────────────────────────────────────────────────

#[test]
fn ipv4_replace_targets_the_slots_first_alias() {
    // fib_table_insert with NLM_F_REPLACE: `fa = fa_first; ...
    // hlist_replace_rcu(&fa->fa_list, &new_fa->fa_list);`
    let a = v4("10.0.0.0/8", 10, Some("192.0.2.1"));
    let b = v4("10.0.0.0/8", 10, Some("192.0.2.2"));
    let c = v4("10.0.0.0/8", 10, Some("192.0.2.3"));
    let mut list = RouteList::default();
    list.insert_back(a.clone());
    list.insert_back(b.clone());
    assert!(list.replace(&a.slot, Some(c.clone())));
    let order: Vec<_> = list.iter().cloned().collect();
    assert_eq!(order, vec![c.clone(), b.clone()]);

    // Replacing with the route that is already first changes nothing.
    assert!(!list.replace(&c.slot, Some(c.clone())));
    // An untracked replacement still displaces the first alias.
    assert!(list.replace(&c.slot, None));
    assert_eq!(list.iter().cloned().collect::<Vec<_>>(), vec![b.clone()]);
    // A replace into an empty slot (the displaced route was untracked) adds.
    let mut empty = RouteList::<KernelRouteV4>::default();
    assert!(empty.replace(&a.slot, Some(a.clone())));
    assert!(!RouteList::<KernelRouteV4>::default().replace(&a.slot, None));
}

#[test]
fn ipv4_replace_does_not_touch_other_slots() {
    let low = v4("10.0.0.0/8", 10, None);
    let high = v4("10.0.0.0/8", 100, None);
    let new_high = v4("10.0.0.0/8", 100, Some("192.0.2.9"));
    let mut list = RouteList::default();
    list.insert_back(low.clone());
    list.insert_back(high);
    assert!(list.replace(&new_high.slot, Some(new_high.clone())));
    assert_eq!(
        list.iter().cloned().collect::<Vec<_>>(),
        vec![low, new_high]
    );
}

// ── IPv6 NLM_F_REPLACE ────────────────────────────────────────────────────────

#[test]
fn ipv6_ecmp_eligibility_follows_rt6_qualify_for_ecmp() {
    // !(RTF_ADDRCONF) && !nh && has a gateway.
    assert!(v6("2001:db8::/32", 1, Some("fe80::1")).qualifies_for_ecmp());
    assert!(!v6("2001:db8::/32", 1, None).qualifies_for_ecmp());
    let mut ra = v6("::/0", 1024, Some("fe80::1"));
    ra.protocol = RTPROT_RA;
    assert!(!ra.qualifies_for_ecmp());
    let mut object = v6("2001:db8::/32", 1, None);
    object.next_hop = NextHopV6::Object(7);
    assert!(!object.qualifies_for_ecmp());
}

#[test]
fn ipv6_replace_of_an_ecmp_route_removes_all_its_siblings() {
    let dev = v6("2001:db8::/32", 10, None);
    let a = v6("2001:db8::/32", 10, Some("fe80::1"));
    let b = v6("2001:db8::/32", 10, Some("fe80::2"));
    let c = v6("2001:db8::/32", 10, Some("fe80::3"));
    let mut list = RouteList::default();
    for r in [&dev, &a, &b] {
        list.insert_back(r.clone());
    }
    // New route is ECMP-capable: the victim is the first ECMP route (a), which
    // has a sibling (b), so b goes as well. The device route stays.
    assert!(list.replace(&c.slot, true, Some(c.clone())));
    assert_eq!(list.iter().cloned().collect::<Vec<_>>(), vec![dev, c]);
}

#[test]
fn ipv6_replace_with_a_non_ecmp_route_prefers_a_non_ecmp_victim() {
    let dev = v6("2001:db8::/32", 10, None);
    let a = v6("2001:db8::/32", 10, Some("fe80::1"));
    let b = v6("2001:db8::/32", 10, Some("fe80::2"));
    let mut new_dev = dev.clone();
    new_dev.next_hop = NextHopV6::Path(NextHopPath {
        gateway: None,
        oif: NonZeroU32::new(9),
    });
    let mut list = RouteList::default();
    for r in [&a, &dev, &b] {
        list.insert_back(r.clone());
    }
    assert!(list.replace(&new_dev.slot, false, Some(new_dev.clone())));
    assert_eq!(
        list.iter().cloned().collect::<Vec<_>>(),
        vec![a, new_dev, b]
    );
}

#[test]
fn ipv6_replace_falls_back_to_the_first_route_of_the_group() {
    // `if (fallback_ins && !found)`: no route with the same ECMP eligibility,
    // so the group's first route is replaced; it had siblings, so they go too.
    let a = v6("2001:db8::/32", 10, Some("fe80::1"));
    let b = v6("2001:db8::/32", 10, Some("fe80::2"));
    let dev = v6("2001:db8::/32", 10, None);
    let mut list = RouteList::default();
    list.insert_back(a.clone());
    list.insert_back(b);
    assert!(list.replace(&dev.slot, false, Some(dev.clone())));
    assert_eq!(list.iter().cloned().collect::<Vec<_>>(), vec![dev]);
}

#[test]
fn ipv6_replace_edge_cases() {
    let a = v6("2001:db8::/32", 10, Some("fe80::1"));
    let mut list = RouteList::<KernelRouteV6>::default();
    assert!(!list.replace(&a.slot, true, None), "nothing to displace");
    assert!(
        list.replace(&a.slot, true, Some(a.clone())),
        "empty slot: added"
    );
    assert!(
        !list.replace(&a.slot, true, Some(a.clone())),
        "same route, no siblings"
    );
    assert!(
        list.replace(&a.slot, true, None),
        "untracked replacement displaces"
    );
    assert!(list.is_empty());
}

// ── Property tests ────────────────────────────────────────────────────────────

/// Reference lookup written straight from the kernel rule, independently of
/// `RouteList::lookup`: try prefix lengths from longest to shortest; the first
/// length that has an eligible covering route decides, and among those routes
/// the lowest priority wins.
fn reference_lookup_v4(routes: &[KernelRouteV4], addr: Ipv4Addr) -> Option<(u8, u32)> {
    let bits = u32::from(addr);
    (0..=32u8).rev().find_map(|len| {
        let net = if len == 0 { 0 } else { bits >> (32 - len) };
        routes
            .iter()
            .filter(|r| {
                let d = r.slot.dst;
                let dnet = if len == 0 {
                    0
                } else {
                    u32::from(d.addr()) >> (32 - len)
                };
                r.slot.tos == 0 && d.prefix_len() == len && dnet == net
            })
            .map(|r| r.slot.priority)
            .min()
            .map(|p| (len, p))
    })
}

fn reference_lookup_v6(routes: &[KernelRouteV6], addr: Ipv6Addr) -> Option<(u8, u32)> {
    let bits = u128::from(addr);
    (0..=128u8).rev().find_map(|len| {
        let net = if len == 0 { 0 } else { bits >> (128 - len) };
        routes
            .iter()
            .filter(|r| {
                let d = r.slot.dst;
                let dnet = if len == 0 {
                    0
                } else {
                    u128::from(d.addr()) >> (128 - len)
                };
                r.slot.src.is_default() && d.prefix_len() == len && dnet == net
            })
            .map(|r| r.slot.priority)
            .min()
            .map(|p| (len, p))
    })
}

/// A small universe so that sequences collide on prefix, priority, table, TOS
/// and next hop often.
fn arb_v4() -> impl Strategy<Value = KernelRouteV4> {
    let prefixes = prop::sample::select(vec![
        "0.0.0.0/0",
        "10.0.0.0/8",
        "10.1.0.0/16",
        "10.1.2.0/24",
        "10.1.2.3/32",
        "192.0.2.0/24",
    ]);
    (
        prefixes,
        prop::sample::select(vec![0u32, 10, 100]),
        prop::sample::select(vec![254u32, 100]),
        prop::sample::select(vec![0u8, 0, 0, 0x10]),
        prop::sample::select(vec![None, Some("192.0.2.1"), Some("192.0.2.2")]),
    )
        .prop_map(|(prefix, priority, table, tos, gw)| {
            let mut r = v4(prefix, priority, gw);
            r.slot.table = TableId::new(table).unwrap();
            r.slot.tos = tos;
            r
        })
}

fn arb_v6() -> impl Strategy<Value = KernelRouteV6> {
    let prefixes = prop::sample::select(vec![
        "::/0",
        "2001:db8::/32",
        "2001:db8:1::/48",
        "2001:db8:1:2::/64",
        "2001:db8:1:2::3/128",
    ]);
    (
        prefixes,
        prop::sample::select(vec![1u32, 10, 100]),
        prop::sample::select(vec![None, None, None, Some("2001:db8:ffff::/48")]),
        prop::sample::select(vec![None, Some("fe80::1"), Some("fe80::2")]),
    )
        .prop_map(|(prefix, priority, src, gw)| {
            let mut r = v6(prefix, priority, gw);
            if let Some(src) = src {
                r.slot.src = p6(src);
            }
            r
        })
}

fn probes_v4() -> Vec<Ipv4Addr> {
    [
        "10.1.2.3",
        "10.1.2.4",
        "10.1.9.9",
        "10.9.9.9",
        "192.0.2.77",
        "8.8.8.8",
    ]
    .iter()
    .map(|s| a4(s))
    .collect()
}

fn probes_v6() -> Vec<Ipv6Addr> {
    [
        "2001:db8:1:2::3",
        "2001:db8:1:2::4",
        "2001:db8:1:9::1",
        "2001:db8:9::1",
        "2001:db9::1",
    ]
    .iter()
    .map(|s| a6(s))
    .collect()
}

#[derive(Debug, Clone)]
enum Op<R> {
    Add { route: R, front: bool },
    Del(R),
}

fn arb_ops_v4() -> impl Strategy<Value = Vec<Op<KernelRouteV4>>> {
    prop::collection::vec(
        prop_oneof![
            2 => (arb_v4(), any::<bool>()).prop_map(|(route, front)| Op::Add { route, front }),
            1 => arb_v4().prop_map(Op::Del),
        ],
        0..40,
    )
}

fn arb_ops_v6() -> impl Strategy<Value = Vec<Op<KernelRouteV6>>> {
    prop::collection::vec(
        prop_oneof![
            2 => arb_v6().prop_map(|route| Op::Add { route, front: false }),
            1 => arb_v6().prop_map(Op::Del),
        ],
        0..40,
    )
}

proptest! {
    /// Prefix construction accepts exactly the canonical prefixes, and
    /// `contains` agrees with a shift-based comparison of the top bits.
    #[test]
    fn prefix_v4_invariants(bits: u32, len in 0u8..=40, probe: u32) {
        let addr = Ipv4Addr::from(bits);
        let canonical = len <= 32 && (len == 32 || bits.checked_shl(u32::from(len)).unwrap_or(0) == 0);
        let built = Ipv4Prefix::new(addr, len);
        prop_assert_eq!(built.is_ok(), canonical);
        if let Ok(p) = built {
            let same_top = len == 0 || (probe >> (32 - len)) == (bits >> (32 - len));
            prop_assert_eq!(p.contains(Ipv4Addr::from(probe)), same_top);
            prop_assert!(p.contains(addr));
        }
    }

    #[test]
    fn prefix_v6_invariants(bits: u128, len in 0u8..=140, probe: u128) {
        let addr = Ipv6Addr::from(bits);
        let canonical = len <= 128 && (len == 128 || bits.checked_shl(u32::from(len)).unwrap_or(0) == 0);
        let built = Ipv6Prefix::new(addr, len);
        prop_assert_eq!(built.is_ok(), canonical);
        if let Ok(p) = built {
            let same_top = len == 0 || (probe >> (128 - len)) == (bits >> (128 - len));
            prop_assert_eq!(p.contains(Ipv6Addr::from(probe)), same_top);
        }
    }

    /// Model test: after any sequence of adds and deletes (no replace), the
    /// mirror holds exactly the set of routes the kernel would hold, and every
    /// lookup agrees with the reference rule. A delete never removes a route
    /// other than the one named, and an add never displaces another route.
    #[test]
    fn ipv4_mirror_matches_kernel_set_semantics(ops in arb_ops_v4()) {
        let mut list = RouteList::default();
        let mut model: Vec<KernelRouteV4> = Vec::new();
        for op in ops {
            match op {
                Op::Add { route, front } => {
                    let fresh = !model.contains(&route);
                    if fresh {
                        model.push(route.clone());
                    }
                    let changed = if front { list.insert_front(route) } else { list.insert_back(route) };
                    prop_assert_eq!(changed, fresh);
                }
                Op::Del(route) => {
                    let present = model.contains(&route);
                    model.retain(|r| r != &route);
                    prop_assert_eq!(list.remove(&route), present);
                }
            }
            let stored: HashSet<_> = list.iter().cloned().collect();
            let expected: HashSet<_> = model.iter().cloned().collect();
            prop_assert_eq!(stored.len(), list.len(), "no duplicates");
            prop_assert_eq!(&stored, &expected);
            for addr in probes_v4() {
                let got = list.lookup(addr).map(|r| (r.slot.dst.prefix_len(), r.slot.priority));
                prop_assert_eq!(got, reference_lookup_v4(&model, addr));
            }
        }
    }

    #[test]
    fn ipv6_mirror_matches_kernel_set_semantics(ops in arb_ops_v6()) {
        let mut list = RouteList::default();
        let mut model: Vec<KernelRouteV6> = Vec::new();
        for op in ops {
            match op {
                Op::Add { route, .. } => {
                    let fresh = !model.iter().any(|r| r.is_same_route(&route));
                    if fresh {
                        model.push(route.clone());
                    }
                    prop_assert_eq!(list.insert_back(route), fresh);
                }
                Op::Del(route) => {
                    let present = model.iter().any(|r| r.is_same_route(&route));
                    model.retain(|r| !r.is_same_route(&route));
                    prop_assert_eq!(list.remove(&route), present);
                }
            }
            prop_assert_eq!(list.len(), model.len());
            for addr in probes_v6() {
                let got = list.lookup(addr).map(|r| (r.slot.dst.prefix_len(), r.slot.priority));
                prop_assert_eq!(got, reference_lookup_v6(&model, addr));
            }
        }
    }

    /// Dump-order independence: the same set of routes loaded in any order
    /// gives the same answer for every lookup.
    #[test]
    fn lookup_does_not_depend_on_load_order(
        routes in prop::collection::vec(arb_v4(), 0..12).prop_shuffle(),
        seed in any::<u64>(),
    ) {
        let mut forward = RouteList::default();
        for r in &routes {
            forward.insert_back(r.clone());
        }
        let mut shuffled = routes.clone();
        // A deterministic second order derived from the seed.
        let n = shuffled.len();
        if n > 1 {
            #[allow(clippy::cast_possible_truncation)]
            shuffled.rotate_left((seed % n as u64) as usize);
            shuffled.reverse();
        }
        let mut other = RouteList::default();
        for r in &shuffled {
            other.insert_back(r.clone());
        }
        for addr in probes_v4() {
            let a = forward.lookup(addr).map(|r| (r.slot.dst.prefix_len(), r.slot.priority));
            let b = other.lookup(addr).map(|r| (r.slot.dst.prefix_len(), r.slot.priority));
            prop_assert_eq!(a, b);
        }
    }

    /// Adding a route and then deleting it restores every lookup.
    #[test]
    fn add_then_delete_restores_lookups(
        base in prop::collection::vec(arb_v4(), 0..10),
        extra in arb_v4(),
    ) {
        let mut list = RouteList::default();
        for r in base {
            list.insert_back(r);
        }
        prop_assume!(!list.contains(&extra));
        let before: Vec<_> = probes_v4().into_iter().map(|a| list.lookup(a).cloned()).collect();
        list.insert_front(extra.clone());
        list.remove(&extra);
        let after: Vec<_> = probes_v4().into_iter().map(|a| list.lookup(a).cloned()).collect();
        prop_assert_eq!(before, after);
    }

    /// Slot contiguity: routes that share a slot stay adjacent whatever the
    /// order of inserts, replaces and deletes. "The first route of a slot"
    /// relies on this.
    #[test]
    fn routes_of_a_slot_stay_contiguous(
        ops in arb_ops_v4(),
        replaces in prop::collection::vec((arb_v4(), any::<bool>()), 0..8),
    ) {
        let mut list = RouteList::default();
        for op in ops {
            match op {
                Op::Add { route, front } => {
                    if front { list.insert_front(route); } else { list.insert_back(route); }
                }
                Op::Del(route) => { list.remove(&route); }
            }
        }
        for (route, tracked) in replaces {
            let slot = route.slot;
            list.replace(&slot, tracked.then_some(route));
        }
        let slots: Vec<_> = list.iter().map(|r| r.slot).collect();
        for (i, s) in slots.iter().enumerate() {
            let last = slots.iter().rposition(|x| x == s).unwrap();
            prop_assert!(slots[i..=last].iter().all(|x| x == s), "slot {:?} split", s);
        }
    }
}
