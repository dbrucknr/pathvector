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
//! separate model of the kernel's slot lists, written directly from those
//! functions, and with a reference lookup written from the lookup rule.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
};

use proptest::prelude::*;

use super::*;

// ── Fixtures ──────────────────────────────────────────────────────────────────

const RTN_BLACKHOLE: u8 = 6;
const RTPROT_STATIC: u8 = 4;

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
        kind: RTN_UNICAST,
        protocol: RTPROT_STATIC,
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
        kind: RTN_UNICAST,
        protocol: RTPROT_STATIC,
        next_hop: NextHopV6::Path(via(gateway)),
    }
}

fn bgp4(prefix: &str, priority: u32, gateway: Option<&str>) -> KernelRouteV4 {
    KernelRouteV4 {
        protocol: RTPROT_BGP,
        ..v4(prefix, priority, gateway)
    }
}

fn bgp6(prefix: &str, priority: u32, gateway: Option<&str>) -> KernelRouteV6 {
    KernelRouteV6 {
        protocol: RTPROT_BGP,
        ..v6(prefix, priority, gateway)
    }
}

fn a4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn a6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

type Mirror4 = RouteMirror<KernelRouteV4>;
type Mirror6 = RouteMirror<KernelRouteV6>;

fn metric4(m: &Mirror4, addr: &str) -> Option<u32> {
    m.lookup(a4(addr)).map(|r| r.slot.priority)
}

fn metric6(m: &Mirror6, addr: &str) -> Option<u32> {
    m.lookup(a6(addr)).map(|r| r.slot.priority)
}

fn order4(m: &Mirror4, routes: &[&KernelRouteV4]) -> bool {
    let expected: Vec<_> = routes
        .iter()
        .map(|r| (r.identity(), r.is_tracked()))
        .collect();
    m.slot_order(&routes[0].slot) == expected
}

fn order6(m: &Mirror6, routes: &[&KernelRouteV6]) -> bool {
    let expected: Vec<_> = routes
        .iter()
        .map(|r| (r.identity(), r.is_tracked()))
        .collect();
    m.slot_order(&routes[0].slot) == expected
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

#[test]
fn tracking_rule_is_unicast_and_not_bgp() {
    assert!(v4("10.0.0.0/8", 1, None).is_tracked());
    assert!(!bgp4("10.0.0.0/8", 1, None).is_tracked());
    let blackhole = KernelRouteV4 {
        kind: RTN_BLACKHOLE,
        ..v4("10.0.0.0/8", 1, None)
    };
    assert!(!blackhole.is_tracked());
    assert!(v6("2001:db8::/32", 1, None).is_tracked());
    assert!(!bgp6("2001:db8::/32", 1, None).is_tracked());
}

// ── Issue #56 acceptance at the domain level ─────────────────────────────────

#[test]
fn ipv4_metric_10_and_100_coexist_in_either_order() {
    // fib_table_insert keys aliases by "[prefix,dscp,priority]", so these are
    // two routes; fib_table_lookup takes the first alias, i.e. priority 10.
    let primary = v4("198.51.100.0/24", 10, None);
    let backup = v4("198.51.100.0/24", 100, None);
    for order in [[&primary, &backup], [&backup, &primary]] {
        let mut m = Mirror4::default();
        for r in order {
            assert!(m.insert(r.clone(), Position::Front));
        }
        assert_eq!(m.len(), 2);
        assert_eq!(metric4(&m, "198.51.100.1"), Some(10));

        let mut l = m.clone();
        assert!(l.remove(&backup));
        assert_eq!(metric4(&l, "198.51.100.1"), Some(10));

        let mut l = m.clone();
        assert!(l.remove(&primary));
        assert_eq!(metric4(&l, "198.51.100.1"), Some(100));
        assert!(l.remove(&backup));
        assert_eq!(metric4(&l, "198.51.100.1"), None);
        assert!(l.is_empty());
    }
}

#[test]
fn ipv6_metric_10_and_100_coexist_in_either_order() {
    // fib6_add_rt2node: different metrics are different "priority levels";
    // the node's routes are sorted by metric and the lowest is used.
    let primary = v6("2001:db8:1::/64", 10, None);
    let backup = v6("2001:db8:1::/64", 100, None);
    for order in [[&primary, &backup], [&backup, &primary]] {
        let mut m = Mirror6::default();
        for r in order {
            assert!(m.insert(r.clone(), Position::Back));
        }
        assert_eq!(metric6(&m, "2001:db8:1::1"), Some(10));

        let mut l = m.clone();
        assert!(l.remove(&backup));
        assert_eq!(metric6(&l, "2001:db8:1::1"), Some(10));

        let mut l = m.clone();
        assert!(l.remove(&primary));
        assert_eq!(metric6(&l, "2001:db8:1::1"), Some(100));
    }
}

#[test]
fn removing_one_route_falls_back_to_a_shorter_prefix() {
    // When no alias of a leaf matches, fib_table_lookup backtracks.
    let mut m = Mirror4::default();
    m.insert(v4("0.0.0.0/0", 1, Some("192.0.2.1")), Position::Back);
    m.insert(v4("10.0.0.0/8", 50, None), Position::Back);
    assert_eq!(metric4(&m, "10.1.1.1"), Some(50));
    m.remove(&v4("10.0.0.0/8", 50, None));
    assert_eq!(metric4(&m, "10.1.1.1"), Some(1));
}

// ── Other selectors ───────────────────────────────────────────────────────────

#[test]
fn tables_tos_and_source_prefix_are_part_of_the_slot() {
    let main = v4("10.0.0.0/8", 10, None);
    let mut other_table = main.clone();
    other_table.slot.table = TableId::new(100).unwrap();
    let mut tos = main.clone();
    tos.slot.tos = 0x10;

    let mut m = Mirror4::default();
    assert!(m.insert(main.clone(), Position::Back));
    assert!(m.insert(other_table.clone(), Position::Back));
    assert!(m.insert(tos.clone(), Position::Back));
    assert_eq!(m.len(), 3);
    assert!(m.remove(&main));
    assert!(m.contains(&other_table) && m.contains(&tos));

    let plain = v6("2001:db8::/32", 10, None);
    let mut sourced = plain.clone();
    sourced.slot.src = p6("2001:db8:ffff::/48");
    let mut m6 = Mirror6::default();
    assert!(m6.insert(plain.clone(), Position::Back));
    assert!(m6.insert(sourced.clone(), Position::Back));
    assert!(m6.remove(&plain));
    assert!(m6.contains(&sourced));
}

#[test]
fn tos_and_source_specific_routes_are_not_used_for_best_effort_lookups() {
    // fib_table_lookup skips `fa->fa_dscp && !fib_dscp_masked_match(...)`;
    // an IPv6 source-specific route only matches traffic from that source.
    let mut tos = v4("10.0.0.0/8", 1, None);
    tos.slot.tos = 0x10;
    let mut m = Mirror4::default();
    m.insert(tos, Position::Back);
    assert_eq!(metric4(&m, "10.1.1.1"), None);
    m.insert(v4("10.0.0.0/8", 50, None), Position::Back);
    assert_eq!(metric4(&m, "10.1.1.1"), Some(50));

    let mut sourced = v6("2001:db8::/32", 1, None);
    sourced.slot.src = p6("2001:db8:ffff::/48");
    let mut m6 = Mirror6::default();
    m6.insert(sourced, Position::Back);
    assert_eq!(metric6(&m6, "2001:db8::1"), None);
}

#[test]
fn routes_in_one_slot_are_kept_and_removed_individually() {
    // fib_table_insert rejects only "a perfect match which uses the same
    // scope, type, and nexthop information"; rt6_duplicate_nexthop likewise.
    let a = v4("10.0.0.0/8", 10, Some("192.0.2.1"));
    let b = v4("10.0.0.0/8", 10, Some("192.0.2.2"));
    let mut m = Mirror4::default();
    assert!(m.insert(a.clone(), Position::Back));
    assert!(m.insert(b.clone(), Position::Back));
    assert!(!m.insert(a.clone(), Position::Back), "exact duplicate");
    assert!(m.remove(&a));
    assert_eq!(metric4(&m, "10.1.1.1"), Some(10));
    assert!(!m.remove(&a), "already gone");
}

#[test]
fn ipv6_type_and_protocol_are_not_part_of_identity() {
    // rt6_duplicate_nexthop compares device, gateway and encap only.
    let a = v6("2001:db8::/32", 10, Some("fe80::1"));
    let b = bgp6("2001:db8::/32", 10, Some("fe80::1"));
    let mut m = Mirror6::default();
    m.insert(a, Position::Back);
    assert!(!m.insert(b.clone(), Position::Back));
    assert!(m.contains(&b));
    assert!(m.remove(&b));
}

#[test]
fn equal_routes_tie_break_on_kernel_order_then_table() {
    let a = v4("10.0.0.0/8", 10, Some("192.0.2.1"));
    let b = v4("10.0.0.0/8", 10, Some("192.0.2.2"));
    let mut m = Mirror4::default();
    m.insert(a.clone(), Position::Back);
    m.insert(b.clone(), Position::Back);
    assert_eq!(m.lookup(a4("10.1.1.1")), Some(&a));
    let mut m = Mirror4::default();
    m.insert(a.clone(), Position::Back);
    m.insert(b.clone(), Position::Front);
    assert_eq!(m.lookup(a4("10.1.1.1")), Some(&b));

    // Same prefix and priority in two tables: deterministic, lowest ID.
    let mut t100 = a.clone();
    t100.slot.table = TableId::new(100).unwrap();
    let mut m = Mirror4::default();
    m.insert(a, Position::Back);
    m.insert(t100.clone(), Position::Back);
    assert_eq!(m.lookup(a4("10.1.1.1")), Some(&t100));
}

#[test]
fn front_and_back_place_routes_within_their_slot() {
    let a = v4("10.0.0.0/8", 10, Some("192.0.2.1"));
    let b = v4("10.0.0.0/8", 10, Some("192.0.2.2"));
    let c = bgp4("10.0.0.0/8", 10, Some("192.0.2.3"));
    let mut m = Mirror4::default();
    m.insert(a.clone(), Position::Back);
    m.insert(b.clone(), Position::Back);
    m.insert(c.clone(), Position::Front);
    assert!(order4(&m, &[&c, &a, &b]));
}

// ── Untracked routes ─────────────────────────────────────────────────────────

#[test]
fn untracked_routes_are_mirrored_but_never_used_or_signalled() {
    let bgp = bgp4("10.0.0.0/8", 10, Some("192.0.2.1"));
    let mut m = Mirror4::default();
    assert!(
        !m.insert(bgp.clone(), Position::Back),
        "no change signalled"
    );
    assert!(m.contains(&bgp));
    assert_eq!(m.len(), 1);
    assert_eq!(m.iter().count(), 0);
    assert_eq!(metric4(&m, "10.1.1.1"), None);
    assert!(!m.remove(&bgp));
    assert!(m.is_empty());
}

#[test]
fn upsert_reclassifies_a_route_in_place() {
    // An IPv6 leg first seen inside another route's message is untracked;
    // the message that describes it settles its protocol.
    let a = v6("2001:db8::/32", 10, Some("fe80::1"));
    let b = v6("2001:db8::/32", 10, Some("fe80::2"));
    let mut m = Mirror6::default();
    m.insert(a.clone(), Position::Back);
    assert!(!m.insert_unknown_origin(&b));
    assert_eq!(m.iter().count(), 1);
    assert!(m.upsert(b.clone(), Position::Back));
    assert!(order6(&m, &[&a, &b]), "keeps its position");
    assert!(!m.upsert(b.clone(), Position::Back), "nothing new");
    // And the other way: a leg later described as BGP stops being used.
    assert!(m.upsert(bgp6("2001:db8::/32", 10, Some("fe80::2")), Position::Back));
    assert_eq!(m.iter().count(), 1);
    assert!(!m.insert_unknown_origin(&a), "already present");
}

// ── IPv4 NLM_F_REPLACE ────────────────────────────────────────────────────────

#[test]
fn ipv4_replace_targets_the_slots_first_alias() {
    // fib_table_insert with NLM_F_REPLACE: `fa = fa_first; ...
    // hlist_replace_rcu(&fa->fa_list, &new_fa->fa_list);`
    let a = v4("10.0.0.0/8", 10, Some("192.0.2.1"));
    let b = v4("10.0.0.0/8", 10, Some("192.0.2.2"));
    let c = v4("10.0.0.0/8", 10, Some("192.0.2.3"));
    let mut m = Mirror4::default();
    m.insert(a.clone(), Position::Back);
    m.insert(b.clone(), Position::Back);
    assert!(m.replace(c.clone()));
    assert!(order4(&m, &[&c, &b]));
    // `fa_match`: the new alias already exists, so nothing changes.
    assert!(!m.replace(c.clone()));
    assert!(!m.replace(b.clone()));
    assert!(order4(&m, &[&c, &b]));
    // A replace into an empty slot adds the route.
    assert!(Mirror4::default().replace(a));
}

#[test]
fn ipv4_replace_of_an_untracked_first_alias_keeps_the_tracked_one() {
    // Review of PR #122: slot order [BGP, static]; replacing the BGP alias
    // must leave the static alias alone.
    let bgp1 = bgp4("198.18.1.0/24", 10, Some("192.0.2.1"));
    let bgp2 = bgp4("198.18.1.0/24", 10, Some("192.0.2.2"));
    let stat = v4("198.18.1.0/24", 10, None);
    let mut m = Mirror4::default();
    m.insert(stat.clone(), Position::Back);
    m.insert(bgp1, Position::Front);
    assert!(!m.replace(bgp2.clone()), "tracked routes unchanged");
    assert!(order4(&m, &[&bgp2, &stat]));
    assert_eq!(metric4(&m, "198.18.1.1"), Some(10));
}

#[test]
fn ipv4_untracked_replacement_of_a_tracked_alias_removes_it() {
    // FibWriter installs with NLM_F_REPLACE: a BGP route with the same prefix
    // and priority as an IGP route replaces it in the kernel.
    let stat = v4("10.0.0.0/8", 20, None);
    let bgp = bgp4("10.0.0.0/8", 20, Some("192.0.2.1"));
    let mut m = Mirror4::default();
    m.insert(stat, Position::Back);
    assert!(m.replace(bgp.clone()));
    assert!(order4(&m, &[&bgp]));
    assert_eq!(metric4(&m, "10.1.1.1"), None);
}

#[test]
fn ipv4_replace_does_not_touch_other_slots() {
    let low = v4("10.0.0.0/8", 10, None);
    let high = v4("10.0.0.0/8", 100, None);
    let new_high = v4("10.0.0.0/8", 100, Some("192.0.2.9"));
    let mut m = Mirror4::default();
    m.insert(low.clone(), Position::Back);
    m.insert(high, Position::Back);
    assert!(m.replace(new_high.clone()));
    assert!(order4(&m, &[&low]) && order4(&m, &[&new_high]));
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
    let b = bgp6("2001:db8::/32", 10, Some("fe80::2"));
    let c = v6("2001:db8::/32", 10, Some("fe80::3"));
    let mut m = Mirror6::default();
    for r in [&dev, &a, &b] {
        m.insert(r.clone(), Position::Back);
    }
    // New route is ECMP-capable: the victim is the first ECMP route (a), which
    // has a sibling (b, untracked but still a sibling), so b goes as well.
    assert!(m.replace(c.clone()));
    assert!(order6(&m, &[&dev, &c]));
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
    let mut m = Mirror6::default();
    for r in [&a, &dev, &b] {
        m.insert(r.clone(), Position::Back);
    }
    assert!(m.replace(new_dev.clone()));
    assert!(order6(&m, &[&a, &new_dev, &b]));
}

#[test]
fn ipv6_replace_falls_back_to_the_first_route_of_the_group() {
    // `if (fallback_ins && !found)`: no route with the same ECMP eligibility,
    // so the group's first route is replaced; it had siblings, so they go too.
    let a = v6("2001:db8::/32", 10, Some("fe80::1"));
    let b = v6("2001:db8::/32", 10, Some("fe80::2"));
    let dev = v6("2001:db8::/32", 10, None);
    let mut m = Mirror6::default();
    m.insert(a, Position::Back);
    m.insert(b, Position::Back);
    assert!(m.replace(dev.clone()));
    assert!(order6(&m, &[&dev]));
}

#[test]
fn ipv6_replace_edge_cases() {
    let a = v6("2001:db8::/32", 10, Some("fe80::1"));
    let mut m = Mirror6::default();
    assert!(m.replace(a.clone()), "empty slot: added");
    assert!(!m.replace(a.clone()), "same route, no siblings");
    let bgp = bgp6("2001:db8::/32", 10, Some("fe80::9"));
    assert!(m.replace(bgp.clone()), "untracked replacement displaces a");
    assert!(order6(&m, &[&bgp]));
    assert!(!m.replace(bgp6("2001:db8::/32", 10, Some("fe80::8"))));
}

// ── Property tests ────────────────────────────────────────────────────────────

/// Reference lookup written straight from the kernel rule, independently of
/// `RouteMirror::lookup`: try prefix lengths from longest to shortest; the
/// first length that has a usable covering route decides, and among those the
/// lowest priority wins.
fn reference_lookup_v4<'a>(
    routes: impl Iterator<Item = &'a KernelRouteV4>,
    addr: Ipv4Addr,
) -> Option<(u8, u32)> {
    let routes: Vec<_> = routes
        .filter(|r| r.kind == RTN_UNICAST && r.protocol != RTPROT_BGP && r.slot.tos == 0)
        .collect();
    let bits = u32::from(addr);
    (0..=32u8).rev().find_map(|len| {
        let top = |x: u32| if len == 0 { 0 } else { x >> (32 - len) };
        routes
            .iter()
            .filter(|r| {
                r.slot.dst.prefix_len() == len && top(u32::from(r.slot.dst.addr())) == top(bits)
            })
            .map(|r| r.slot.priority)
            .min()
            .map(|p| (len, p))
    })
}

fn reference_lookup_v6<'a>(
    routes: impl Iterator<Item = &'a KernelRouteV6>,
    addr: Ipv6Addr,
) -> Option<(u8, u32)> {
    let routes: Vec<_> = routes
        .filter(|r| r.kind == RTN_UNICAST && r.protocol != RTPROT_BGP && r.slot.src.is_default())
        .collect();
    let bits = u128::from(addr);
    (0..=128u8).rev().find_map(|len| {
        let top = |x: u128| if len == 0 { 0 } else { x >> (128 - len) };
        routes
            .iter()
            .filter(|r| {
                r.slot.dst.prefix_len() == len && top(u128::from(r.slot.dst.addr())) == top(bits)
            })
            .map(|r| r.slot.priority)
            .min()
            .map(|p| (len, p))
    })
}

/// The kernel's IPv4 slot lists, written from `fib_table_insert` /
/// `fib_table_delete`: create inserts in front of the slot (or at the end
/// with `NLM_F_APPEND`) unless an identical alias exists; replace swaps the
/// slot's first alias unless the new one already exists; delete removes the
/// named alias.
#[derive(Default)]
struct KernelV4 {
    slots: HashMap<RouteSlotV4, Vec<KernelRouteV4>>,
}

impl KernelV4 {
    fn add(&mut self, r: KernelRouteV4, front: bool) {
        let s = self.slots.entry(r.slot).or_default();
        if !s.contains(&r) {
            if front {
                s.insert(0, r);
            } else {
                s.push(r);
            }
        }
    }
    fn replace(&mut self, r: KernelRouteV4) {
        let s = self.slots.entry(r.slot).or_default();
        if s.is_empty() {
            s.push(r);
        } else if !s.contains(&r) {
            s[0] = r;
        }
    }
    fn delete(&mut self, r: &KernelRouteV4) {
        if let Some(s) = self.slots.get_mut(&r.slot)
            && let Some(i) = s.iter().position(|x| x == r)
        {
            s.remove(i);
        }
    }
    /// Tracked routes per slot, in kernel order (order decides lookup ties).
    fn tracked(&self) -> HashMap<RouteSlotV4, Vec<KernelRouteV4>> {
        self.slots
            .iter()
            .map(|(s, rs)| {
                (
                    *s,
                    rs.iter()
                        .filter(|r| r.is_tracked())
                        .cloned()
                        .collect::<Vec<_>>(),
                )
            })
            .filter(|(_, rs)| !rs.is_empty())
            .collect()
    }
}

/// The kernel's IPv6 metric groups, written from `fib6_add_rt2node` /
/// `fib6_del`: an add goes to the end of its group unless the next hop is
/// already there; replace picks the first route with the new route's ECMP
/// eligibility (else the first route), and drops its ECMP siblings.
#[derive(Default)]
struct KernelV6 {
    slots: HashMap<RouteSlotV6, Vec<KernelRouteV6>>,
}

impl KernelV6 {
    fn add(&mut self, r: KernelRouteV6) {
        let s = self.slots.entry(r.slot).or_default();
        if !s.iter().any(|x| x.next_hop == r.next_hop) {
            s.push(r);
        }
    }
    fn replace(&mut self, r: KernelRouteV6) {
        let s = self.slots.entry(r.slot).or_default();
        if s.is_empty() {
            s.push(r);
            return;
        }
        let ecmp = r.qualifies_for_ecmp();
        let v = s
            .iter()
            .position(|x| x.qualifies_for_ecmp() == ecmp)
            .unwrap_or(0);
        let siblings = s[v].qualifies_for_ecmp()
            && s.iter()
                .enumerate()
                .any(|(i, x)| i != v && x.qualifies_for_ecmp());
        s[v] = r;
        if siblings {
            let mut i = 0;
            s.retain(|x| {
                let keep = i == v || !x.qualifies_for_ecmp();
                i += 1;
                keep
            });
        }
    }
    fn delete(&mut self, r: &KernelRouteV6) {
        if let Some(s) = self.slots.get_mut(&r.slot)
            && let Some(i) = s.iter().position(|x| x.next_hop == r.next_hop)
        {
            s.remove(i);
        }
    }
    /// Tracked routes per slot, in kernel order (order decides lookup ties).
    fn tracked(&self) -> HashMap<RouteSlotV6, Vec<KernelRouteV6>> {
        self.slots
            .iter()
            .map(|(s, rs)| {
                (
                    *s,
                    rs.iter()
                        .filter(|r| r.is_tracked())
                        .cloned()
                        .collect::<Vec<_>>(),
                )
            })
            .filter(|(_, rs)| !rs.is_empty())
            .collect()
    }
}

/// A small universe so that sequences collide on prefix, priority, table, TOS,
/// type, protocol and next hop often.
fn arb_v4() -> impl Strategy<Value = KernelRouteV4> + Clone {
    let prefixes = prop::sample::select(vec![
        "0.0.0.0/0",
        "10.0.0.0/8",
        "10.1.0.0/16",
        "10.1.2.0/24",
        "10.1.2.3/32",
    ]);
    (
        prefixes,
        prop::sample::select(vec![0u32, 10, 100]),
        prop::sample::select(vec![254u32, 254, 100]),
        prop::sample::select(vec![0u8, 0, 0, 0x10]),
        prop::sample::select(vec![RTPROT_STATIC, RTPROT_STATIC, RTPROT_BGP]),
        prop::sample::select(vec![RTN_UNICAST, RTN_UNICAST, RTN_UNICAST, RTN_BLACKHOLE]),
        prop::sample::select(vec![None, Some("192.0.2.1"), Some("192.0.2.2")]),
    )
        .prop_map(|(prefix, priority, table, tos, protocol, kind, gw)| {
            let mut r = v4(prefix, priority, gw);
            r.slot.table = TableId::new(table).unwrap();
            r.slot.tos = tos;
            r.protocol = protocol;
            r.kind = kind;
            r
        })
}

fn arb_v6() -> impl Strategy<Value = KernelRouteV6> + Clone {
    let prefixes = prop::sample::select(vec![
        "::/0",
        "2001:db8::/32",
        "2001:db8:1::/48",
        "2001:db8:1:2::/64",
    ]);
    (
        prefixes,
        prop::sample::select(vec![1u32, 10]),
        prop::sample::select(vec![None, None, None, Some("2001:db8:ffff::/48")]),
        prop::sample::select(vec![RTPROT_STATIC, RTPROT_STATIC, RTPROT_BGP, RTPROT_RA]),
        prop::sample::select(vec![
            None,
            Some("fe80::1"),
            Some("fe80::2"),
            Some("fe80::3"),
        ]),
    )
        .prop_map(|(prefix, priority, src, protocol, gw)| {
            let mut r = v6(prefix, priority, gw);
            if let Some(src) = src {
                r.slot.src = p6(src);
            }
            r.protocol = protocol;
            r
        })
}

fn probes_v4() -> Vec<Ipv4Addr> {
    ["10.1.2.3", "10.1.2.4", "10.1.9.9", "10.9.9.9", "8.8.8.8"]
        .iter()
        .map(|s| a4(s))
        .collect()
}

fn probes_v6() -> Vec<Ipv6Addr> {
    [
        "2001:db8:1:2::3",
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
    Replace(R),
    Del(R),
}

fn arb_ops<R: std::fmt::Debug + Clone>(
    route: impl Strategy<Value = R> + Clone,
) -> impl Strategy<Value = Vec<Op<R>>> {
    prop::collection::vec(
        prop_oneof![
            3 => (route.clone(), any::<bool>()).prop_map(|(route, front)| Op::Add { route, front }),
            1 => route.clone().prop_map(Op::Replace),
            2 => route.prop_map(Op::Del),
        ],
        0..50,
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

    /// Model test over adds (front/back), replaces and deletes of tracked and
    /// untracked routes: after every step each slot holds the same routes in
    /// the same order as the kernel model, the tracked routes and every lookup
    /// agree with the model, and the return value says exactly whether the
    /// tracked routes changed.
    #[test]
    fn ipv4_mirror_follows_the_kernel_model(ops in arb_ops(arb_v4())) {
        let mut mirror = Mirror4::default();
        let mut kernel = KernelV4::default();
        for op in ops {
            let before = kernel.tracked();
            let changed = match op {
                Op::Add { route, front } => {
                    kernel.add(route.clone(), front);
                    mirror.insert(route, if front { Position::Front } else { Position::Back })
                }
                Op::Replace(route) => {
                    kernel.replace(route.clone());
                    mirror.replace(route)
                }
                Op::Del(route) => {
                    kernel.delete(&route);
                    mirror.remove(&route)
                }
            };
            let after = kernel.tracked();
            prop_assert_eq!(changed, before != after);
            for (slot, routes) in &kernel.slots {
                let expected: Vec<_> = routes.iter().map(|r| (r.identity(), r.is_tracked())).collect();
                prop_assert_eq!(mirror.slot_order(slot), expected);
            }
            prop_assert_eq!(mirror.len(), kernel.slots.values().map(Vec::len).sum::<usize>());
            let tracked: HashSet<_> = mirror.iter().cloned().collect();
            prop_assert_eq!(tracked, after.values().flatten().cloned().collect::<HashSet<_>>());
            for addr in probes_v4() {
                let got = mirror.lookup(addr).map(|r| (r.slot.dst.prefix_len(), r.slot.priority));
                prop_assert_eq!(got, reference_lookup_v4(kernel.slots.values().flatten(), addr));
            }
        }
    }

    #[test]
    fn ipv6_mirror_follows_the_kernel_model(ops in arb_ops(arb_v6())) {
        let mut mirror = Mirror6::default();
        let mut kernel = KernelV6::default();
        for op in ops {
            let before = kernel.tracked();
            let changed = match op {
                Op::Add { route, .. } => {
                    kernel.add(route.clone());
                    mirror.insert(route, Position::Back)
                }
                Op::Replace(route) => {
                    kernel.replace(route.clone());
                    mirror.replace(route)
                }
                Op::Del(route) => {
                    kernel.delete(&route);
                    mirror.remove(&route)
                }
            };
            let after = kernel.tracked();
            prop_assert_eq!(changed, before != after);
            for (slot, routes) in &kernel.slots {
                let expected: Vec<_> = routes.iter().map(|r| (r.identity(), r.is_tracked())).collect();
                prop_assert_eq!(mirror.slot_order(slot), expected);
            }
            let tracked: HashSet<_> = mirror.iter().cloned().collect();
            prop_assert_eq!(tracked, after.values().flatten().cloned().collect::<HashSet<_>>());
            for addr in probes_v6() {
                let got = mirror.lookup(addr).map(|r| (r.slot.dst.prefix_len(), r.slot.priority));
                prop_assert_eq!(got, reference_lookup_v6(kernel.slots.values().flatten(), addr));
            }
        }
    }

    /// Dump-order independence: the same set of routes loaded in any order
    /// gives the same answer for every lookup.
    #[test]
    fn lookup_does_not_depend_on_load_order(
        routes in prop::collection::vec(arb_v4(), 0..12),
        rotate in any::<usize>(),
    ) {
        let mut forward = Mirror4::default();
        for r in &routes {
            forward.insert(r.clone(), Position::Back);
        }
        let mut shuffled = routes.clone();
        if !shuffled.is_empty() {
            let n = shuffled.len();
            shuffled.rotate_left(rotate % n);
            shuffled.reverse();
        }
        let mut other = Mirror4::default();
        for r in &shuffled {
            other.insert(r.clone(), Position::Back);
        }
        for addr in probes_v4() {
            let a = forward.lookup(addr).map(|r| (r.slot.dst.prefix_len(), r.slot.priority));
            let b = other.lookup(addr).map(|r| (r.slot.dst.prefix_len(), r.slot.priority));
            prop_assert_eq!(a, b);
        }
    }
}
