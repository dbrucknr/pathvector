//! Tests for kernel route identity and the route mirror.
//!
//! Sources (Linux v6.12):
//! - `net/ipv4/fib_trie.c`: `fib_valid_key_len`, `fib_table_insert`,
//!   `fib_table_delete`, `fib_table_lookup`.
//! - `net/ipv6/ip6_fib.c`: `fib6_add_rt2node`, `fib6_del_route`.
//! - `include/net/ip6_route.h`: `rt6_qualify_for_ecmp`, `rt6_duplicate_nexthop`.
//! - `net/ipv4/fib_semantics.c`: `fib_props`; `net/ipv6/route.c`: `fib6_prop`,
//!   `rt6_score_route`, `find_match`, `ip6_route_info_create`; `ip-route(8)`
//!   "Route types".
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

const RTN_LOCAL: u8 = 2;
const RTN_BLACKHOLE: u8 = 6;
const RTN_UNREACHABLE: u8 = 7;
const RTN_PROHIBIT: u8 = 8;
const RTN_THROW: u8 = 9;
const RTPROT_STATIC: u8 = 4;

const NEGATIVE_KINDS: [RouteKind; 4] = [
    RouteKind::Reject(RejectKind::Blackhole),
    RouteKind::Reject(RejectKind::Unreachable),
    RouteKind::Reject(RejectKind::Prohibit),
    RouteKind::Throw,
];

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
        protocol_inferred: false,
        preference: RoutePreference::Medium,
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

/// A negative IPv4 route as the kernel reports it: no gateway, no device
/// (`fib_create_info` refuses both for these types).
fn neg4(prefix: &str, priority: u32, kind: RouteKind) -> KernelRouteV4 {
    KernelRouteV4 {
        kind: kind.rtm_type(),
        next_hop: NextHopV4::Path(NextHopPath {
            gateway: None,
            oif: None,
        }),
        ..v4(prefix, priority, None)
    }
}

/// A negative IPv6 route as the kernel reports it: on the loopback device
/// (ifindex 1), no gateway (`fib6_nh_init`), medium preference.
fn neg6(prefix: &str, priority: u32, kind: RouteKind) -> KernelRouteV6 {
    KernelRouteV6 {
        kind: kind.rtm_type(),
        ..v6(prefix, priority, None)
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
fn tracking_rule_is_unicast_or_negative_and_not_bgp() {
    assert!(v4("10.0.0.0/8", 1, None).is_tracked());
    assert!(!bgp4("10.0.0.0/8", 1, None).is_tracked());
    assert!(v6("2001:db8::/32", 1, None).is_tracked());
    assert!(!bgp6("2001:db8::/32", 1, None).is_tracked());
    // Issue #57: a negative route decides reachability for what it covers.
    for kind in NEGATIVE_KINDS {
        assert!(neg4("10.0.0.0/8", 1, kind).is_tracked(), "{kind:?}");
        assert!(neg6("2001:db8::/32", 1, kind).is_tracked(), "{kind:?}");
        assert_eq!(neg4("10.0.0.0/8", 1, kind).route_kind(), Some(kind));
        // FibWriter's own RFC 7999 blackholes stay excluded like every other
        // BGP route.
        let bgp = KernelRouteV4 {
            protocol: RTPROT_BGP,
            ..neg4("10.0.0.0/8", 1, kind)
        };
        assert!(!bgp.is_tracked(), "BGP {kind:?}");
    }
    // local, broadcast, anycast, multicast, nat, xresolve, unspec: mirrored
    // for slot order only.
    for kind in [0, RTN_LOCAL, 3, 4, 5, 10, 11] {
        let r = KernelRouteV4 {
            kind,
            ..v4("10.0.0.0/8", 1, None)
        };
        assert!(!r.is_tracked(), "{kind}");
        assert_eq!(r.route_kind(), None);
    }
}

// ── Issue #57: negative routes ────────────────────────────────────────────────

#[test]
fn route_kind_round_trips_the_rtnetlink_constants() {
    // <linux/rtnetlink.h>: RTN_UNICAST 1, RTN_LOCAL 2, RTN_BROADCAST 3,
    // RTN_ANYCAST 4, RTN_MULTICAST 5, RTN_BLACKHOLE 6, RTN_UNREACHABLE 7,
    // RTN_PROHIBIT 8, RTN_THROW 9, RTN_NAT 10, RTN_XRESOLVE 11.
    let mirrored = [
        (1, RouteKind::Unicast),
        (6, RouteKind::Reject(RejectKind::Blackhole)),
        (7, RouteKind::Reject(RejectKind::Unreachable)),
        (8, RouteKind::Reject(RejectKind::Prohibit)),
        (9, RouteKind::Throw),
    ];
    for (rtm_type, kind) in mirrored {
        assert_eq!(RouteKind::from_rtm_type(rtm_type), Some(kind));
        assert_eq!(kind.rtm_type(), rtm_type);
    }
    for unmirrored in [0, 2, 3, 4, 5, 10, 11, 12, 255] {
        assert_eq!(RouteKind::from_rtm_type(unmirrored), None, "{unmirrored}");
    }
}

#[test]
fn ipv4_negative_route_beneath_a_covering_route_ends_the_lookup() {
    // fib_table_lookup: `err = fib_props[fa->fa_type].error; if (unlikely(err
    // < 0)) { out_reject: ... return err; }` — no backtracking to the default.
    for kind in NEGATIVE_KINDS {
        let default = v4("0.0.0.0/0", 0, Some("192.0.2.1"));
        let neg = neg4("10.1.0.0/16", 1024, kind);
        let mut list = RouteMirror::default();
        list.insert(default.clone(), Position::Back);
        list.insert(neg.clone(), Position::Back);

        assert_eq!(
            list.lookup(a4("10.1.2.3")),
            Some(&neg),
            "{kind:?} is selected"
        );
        let outcome = list.resolve(a4("10.1.2.3"));
        assert!(!outcome.is_reachable(), "{kind:?}");
        assert_eq!(outcome.forwarding(), None, "{kind:?}");
        assert_eq!(outcome.selected(), Some(&neg), "{kind:?}");
        match kind {
            RouteKind::Reject(k) => {
                assert_eq!(
                    outcome,
                    FibLookup::Reject {
                        route: &neg,
                        kind: k
                    }
                );
            }
            RouteKind::Throw => assert_eq!(outcome, FibLookup::Throw(&neg)),
            RouteKind::Unicast => unreachable!(),
        }
        assert_eq!(list.resolve(a4("10.2.0.1")), FibLookup::Forward(&default));

        assert!(list.remove(&neg));
        assert_eq!(list.resolve(a4("10.1.2.3")), FibLookup::Forward(&default));
    }
}

#[test]
fn ipv6_negative_route_beneath_a_covering_route_ends_the_lookup() {
    // fib6_table_lookup backtracks only when rt6_select yields the null entry;
    // a reject route is selected like any other and its fib6_prop error ends
    // the lookup (ip6_rt_init_dst_reject).
    for kind in NEGATIVE_KINDS {
        let default = v6("::/0", 1024, Some("fe80::1"));
        let neg = neg6("2001:db8:1::/48", 1024, kind);
        let mut list = RouteMirror::default();
        list.insert(default.clone(), Position::Back);
        list.insert(neg.clone(), Position::Back);

        let outcome = list.resolve(a6("2001:db8:1::3"));
        assert!(!outcome.is_reachable(), "{kind:?}");
        assert_eq!(outcome.selected(), Some(&neg), "{kind:?}");
        assert_eq!(
            list.resolve(a6("2001:db8:2::1")),
            FibLookup::Forward(&default)
        );

        assert!(list.remove(&neg));
        assert_eq!(
            list.resolve(a6("2001:db8:1::3")),
            FibLookup::Forward(&default)
        );
    }
}

#[test]
fn empty_list_resolves_to_no_route() {
    let list = Mirror4::default();
    let outcome = list.resolve(a4("10.0.0.1"));
    assert_eq!(outcome, FibLookup::NoRoute);
    assert_eq!(outcome.selected(), None);
    assert!(!outcome.is_reachable());
}

#[test]
fn negative_and_unicast_in_one_ipv4_slot_follow_kernel_order() {
    // fib_table_insert: aliases of one [prefix, dscp, priority] slot coexist
    // when their type differs (the duplicate test requires `fa->fa_type ==
    // cfg->fc_type`); `ip route append` puts the new one last, `prepend`
    // first. fib_table_lookup takes the first alias of the slot.
    for kind in NEGATIVE_KINDS {
        let uni = v4("10.0.0.0/8", 10, None);
        let neg = neg4("10.0.0.0/8", 10, kind);

        let mut appended = RouteMirror::default();
        appended.insert(uni.clone(), Position::Back);
        assert!(
            appended.insert(neg.clone(), Position::Back),
            "different type, new alias"
        );
        assert_eq!(appended.resolve(a4("10.1.1.1")), FibLookup::Forward(&uni));

        let mut prepended = RouteMirror::default();
        prepended.insert(uni.clone(), Position::Back);
        assert!(prepended.insert(neg.clone(), Position::Front));
        assert!(
            !prepended.resolve(a4("10.1.1.1")).is_reachable(),
            "{kind:?}"
        );
        // Deleting the negative alias leaves the unicast one.
        assert!(prepended.remove(&neg));
        assert_eq!(prepended.resolve(a4("10.1.1.1")), FibLookup::Forward(&uni));
    }
}

#[test]
fn ipv4_type_is_part_of_the_alias_identity() {
    // "a perfect match which uses the same scope, type, and nexthop
    // information" — a blackhole and an unreachable alias are two routes.
    let bh = neg4("10.0.0.0/8", 10, RouteKind::Reject(RejectKind::Blackhole));
    let un = neg4("10.0.0.0/8", 10, RouteKind::Reject(RejectKind::Unreachable));
    let mut list = RouteMirror::default();
    assert!(list.insert(bh.clone(), Position::Back));
    assert!(list.insert(un.clone(), Position::Back));
    assert!(list.remove(&bh));
    assert_eq!(
        list.resolve(a4("10.1.1.1")),
        FibLookup::Reject {
            route: &un,
            kind: RejectKind::Unreachable
        }
    );
}

#[test]
fn ipv6_negative_routes_of_one_metric_are_one_route() {
    // fib6_nh_init puts every reject route on the loopback device with no
    // gateway, and rt6_duplicate_nexthop compares only device, gateway and
    // encap, so a second negative route of the same metric is a duplicate
    // (-EEXIST) whatever its type.
    let bh = neg6(
        "2001:db8::/32",
        10,
        RouteKind::Reject(RejectKind::Blackhole),
    );
    let un = neg6(
        "2001:db8::/32",
        10,
        RouteKind::Reject(RejectKind::Unreachable),
    );
    let mut list = RouteMirror::default();
    assert!(list.insert(bh.clone(), Position::Back));
    assert!(!list.insert(un.clone(), Position::Back));
    assert!(
        !bh.qualifies_for_ecmp(),
        "no gateway: never an ECMP sibling"
    );
    assert!(list.remove(&un));
    assert!(list.is_empty());
}

#[test]
fn route_preference_is_normalised_like_rtm_to_fib6_config() {
    // <linux/icmpv6.h>: LOW 0x3, MEDIUM 0x0, HIGH 0x1, INVALID 0x2.
    // rtm_to_fib6_config: "if (pref != ICMPV6_ROUTER_PREF_LOW && pref !=
    // ICMPV6_ROUTER_PREF_HIGH) pref = ICMPV6_ROUTER_PREF_MEDIUM;"
    assert_eq!(RoutePreference::from_rta_pref(3), RoutePreference::Low);
    assert_eq!(RoutePreference::from_rta_pref(1), RoutePreference::High);
    for other in [0, 2, 4, 255] {
        assert_eq!(
            RoutePreference::from_rta_pref(other),
            RoutePreference::Medium
        );
    }
    assert_eq!(RoutePreference::default(), RoutePreference::Medium);
}

#[test]
fn ipv6_preference_ranks_routes_within_a_metric_group() {
    // rt6_score_route: `m |= IPV6_DECODE_PREF(IPV6_EXTRACT_PREF(fib6_flags))
    // << 2`; find_match keeps a route only `if (m > *mpri)`. So within the
    // lowest-metric group the highest preference wins, and among equal
    // preferences the first in list order. Negative routes are always medium
    // (ip6_route_info_create overwrites their fib6_flags).
    let bh = RouteKind::Reject(RejectKind::Blackhole);
    let pref = |mut r: KernelRouteV6, p| {
        r.preference = p;
        r
    };
    let neg = neg6("2001:db8:1::/64", 100, bh);

    // A later high-preference unicast route beats an earlier negative one.
    let high_uni = pref(
        v6("2001:db8:1::/64", 100, Some("fe80::1")),
        RoutePreference::High,
    );
    let mut list = RouteMirror::default();
    list.insert(neg.clone(), Position::Back);
    list.insert(high_uni.clone(), Position::Back);
    assert_eq!(
        list.resolve(a6("2001:db8:1::1")),
        FibLookup::Forward(&high_uni)
    );

    // An earlier low-preference unicast route loses to a later negative one.
    let low_uni = pref(
        v6("2001:db8:1::/64", 100, Some("fe80::1")),
        RoutePreference::Low,
    );
    let mut list = RouteMirror::default();
    list.insert(low_uni, Position::Back);
    list.insert(neg.clone(), Position::Back);
    assert!(!list.resolve(a6("2001:db8:1::1")).is_reachable());

    // Equal (medium) preference: list order.
    let uni = v6("2001:db8:1::/64", 100, Some("fe80::1"));
    let mut list = RouteMirror::default();
    list.insert(uni.clone(), Position::Back);
    list.insert(neg.clone(), Position::Back);
    assert_eq!(list.resolve(a6("2001:db8:1::1")), FibLookup::Forward(&uni));

    // Preference never crosses metric groups or prefix lengths.
    let mut list = RouteMirror::default();
    list.insert(high_uni.clone(), Position::Back);
    list.insert(neg6("2001:db8:1::/64", 10, bh), Position::Back);
    assert!(!list.resolve(a6("2001:db8:1::1")).is_reachable());
    let mut list = RouteMirror::default();
    list.insert(
        pref(
            v6("2001:db8::/32", 100, Some("fe80::1")),
            RoutePreference::High,
        ),
        Position::Back,
    );
    list.insert(neg, Position::Back);
    assert!(!list.resolve(a6("2001:db8:1::1")).is_reachable());
}

#[test]
fn ipv6_preference_is_not_part_of_the_identity() {
    // rt6_duplicate_nexthop compares device, gateway and encap only.
    let a = v6("2001:db8::/32", 10, Some("fe80::1"));
    let mut b = a.clone();
    b.preference = RoutePreference::High;
    let mut list = RouteMirror::default();
    list.insert(a, Position::Back);
    assert!(list.contains(&b));
    assert!(!list.insert(b.clone(), Position::Back));
    assert!(list.remove(&b));
}

#[test]
fn tos_and_source_specific_negative_routes_do_not_affect_best_effort_lookups() {
    // fib_table_lookup checks the DSCP before the type, so a TOS-specific
    // blackhole only drops traffic with that TOS.
    let mut tos = neg4("10.1.0.0/16", 0, RouteKind::Reject(RejectKind::Blackhole));
    tos.slot.tos = 0x10;
    let mut list = RouteMirror::default();
    list.insert(v4("10.0.0.0/8", 50, None), Position::Back);
    list.insert(tos, Position::Back);
    assert_eq!(metric4(&list, "10.1.1.1"), Some(50));
    assert!(list.resolve(a4("10.1.1.1")).is_reachable());

    let mut sourced = neg6("2001:db8:1::/48", 0, RouteKind::Throw);
    sourced.slot.src = p6("2001:db8:ffff::/48");
    let mut list6 = RouteMirror::default();
    list6.insert(v6("2001:db8::/32", 50, None), Position::Back);
    list6.insert(sourced, Position::Back);
    assert!(list6.resolve(a6("2001:db8:1::1")).is_reachable());
}

#[test]
fn replacing_a_unicast_route_with_a_negative_one_makes_it_unreachable() {
    // `ip route replace blackhole ...` sends one RTM_NEWROUTE with
    // NLM_F_REPLACE; the unicast alias it displaced gets no RTM_DELROUTE.
    for kind in NEGATIVE_KINDS {
        let uni = v4("10.0.0.0/8", 10, Some("192.0.2.1"));
        let neg = neg4("10.0.0.0/8", 10, kind);
        let mut list = RouteMirror::default();
        list.insert(v4("0.0.0.0/0", 0, Some("192.0.2.9")), Position::Back);
        list.insert(uni.clone(), Position::Back);
        assert!(list.replace(neg.clone()));
        assert!(!list.contains(&uni));
        assert!(!list.resolve(a4("10.1.1.1")).is_reachable(), "{kind:?}");
        // And back again.
        assert!(list.replace(uni.clone()));
        assert_eq!(list.resolve(a4("10.1.1.1")), FibLookup::Forward(&uni));

        let uni6 = v6("2001:db8::/32", 10, Some("fe80::1"));
        let neg6 = neg6("2001:db8::/32", 10, kind);
        let mut list6 = RouteMirror::default();
        list6.insert(uni6.clone(), Position::Back);
        assert!(list6.replace(neg6.clone()));
        assert!(!list6.resolve(a6("2001:db8::1")).is_reachable(), "{kind:?}");
    }
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
fn inferred_protocol_is_used_until_a_message_reports_it() {
    // An IPv6 ECMP leg seen only inside another sibling's message has no
    // reported protocol (fib6_dump_node never dumps it on its own); it takes
    // the described sibling's protocol as an inference.
    let a = v6("2001:db8::/32", 10, Some("fe80::1"));
    let inferred_static = KernelRouteV6 {
        protocol_inferred: true,
        ..v6("2001:db8::/32", 10, Some("fe80::2"))
    };
    let inferred_bgp = KernelRouteV6 {
        protocol_inferred: true,
        ..bgp6("2001:db8::/32", 10, Some("fe80::2"))
    };
    assert!(inferred_static.is_tracked() && !inferred_bgp.is_tracked());

    let mut m = Mirror6::default();
    m.insert(a.clone(), Position::Back);
    assert!(
        !m.insert(inferred_bgp, Position::Back),
        "an inferred BGP leg is not a path"
    );
    assert_eq!(m.iter().count(), 1);
    // A message reporting it as static settles it, in place.
    let b = v6("2001:db8::/32", 10, Some("fe80::2"));
    assert!(m.upsert(b.clone(), Position::Back));
    assert!(order6(&m, &[&a, &b]), "keeps its position");
    assert!(!m.upsert(b, Position::Back), "nothing new");
    // An inference never overwrites a reported protocol.
    assert!(!m.insert(
        KernelRouteV6 {
            protocol_inferred: true,
            ..bgp6("2001:db8::/32", 10, Some("fe80::2"))
        },
        Position::Back
    ));
    assert_eq!(m.iter().count(), 2);
    // Reported as BGP: no longer a path.
    assert!(m.upsert(bgp6("2001:db8::/32", 10, Some("fe80::2")), Position::Back));
    assert_eq!(m.iter().count(), 1);
}

// ── Re-reading a sibling set after a delete ──────────────────────────────────
//
// fib6_dump_node dumps an ECMP set once, through its first sibling
// (rt6_fill_node takes rtm_protocol from that route). After that sibling is
// deleted, a dump describes the next one, and a lone route is described in
// full. `redescribe` applies such a message.

fn inferred(r: KernelRouteV6) -> KernelRouteV6 {
    KernelRouteV6 {
        protocol_inferred: true,
        ..r
    }
}

const SET: &str = "2001:db8::/32";

#[test]
fn an_untracked_inferred_route_is_kept_and_found() {
    // BGP-first dump of a BGP+static set: the static route is inferred BGP.
    let b1 = bgp6(SET, 10, Some("fe80::1"));
    let s2 = inferred(bgp6(SET, 10, Some("fe80::2")));
    let mut m = Mirror6::default();
    m.upsert(b1.clone(), Position::Back);
    m.insert(s2.clone(), Position::Back);
    assert_eq!(m.iter().count(), 0, "neither is a path");
    assert_eq!(m.first_inferred(&b1.slot), Some(&s2));
    assert!(order6(&m, &[&b1, &s2]));
    assert!(!m.remove(&b1));
    assert_eq!(m.first_inferred(&b1.slot), Some(&s2));
    assert!(!m.remove(&s2));
    assert_eq!(m.first_inferred(&b1.slot), None);
    assert!(m.is_empty());
    // A reported route is never "inferred".
    m.insert(v6(SET, 10, Some("fe80::3")), Position::Back);
    assert_eq!(m.first_inferred(&b1.slot), None);
}

#[test]
fn redescribe_settles_the_lone_survivor_of_a_bgp_first_set() {
    let b1 = bgp6(SET, 10, Some("fe80::1"));
    let mut m = Mirror6::default();
    m.upsert(b1.clone(), Position::Back);
    m.insert(inferred(bgp6(SET, 10, Some("fe80::2"))), Position::Back);
    m.remove(&b1);
    assert_eq!(metric6(&m, "2001:db8::1"), None);
    // The kernel now describes the static route itself.
    let s2 = v6(SET, 10, Some("fe80::2"));
    assert!(m.redescribe([s2.clone()]));
    assert_eq!(metric6(&m, "2001:db8::1"), Some(10));
    assert_eq!(m.first_inferred(&s2.slot), None);
    assert!(!m.redescribe([s2]), "nothing new");
}

#[test]
fn redescribe_stops_counting_the_bgp_survivor_of_a_static_first_set() {
    let s1 = v6(SET, 10, Some("fe80::1"));
    let mut m = Mirror6::default();
    m.upsert(s1.clone(), Position::Back);
    m.insert(inferred(v6(SET, 10, Some("fe80::2"))), Position::Back);
    m.remove(&s1);
    assert_eq!(
        metric6(&m, "2001:db8::1"),
        Some(10),
        "still inferred static"
    );
    assert!(m.redescribe([bgp6(SET, 10, Some("fe80::2"))]));
    assert_eq!(metric6(&m, "2001:db8::1"), None);
    assert_eq!(m.len(), 1, "still mirrored");
}

#[test]
fn redescribe_reinfers_inferred_siblings_and_keeps_reported_ones() {
    // Kernel order [x, y, z]. y's protocol was reported (static); x and z
    // are inferred BGP. The kernel now describes x as static.
    let x = inferred(bgp6(SET, 10, Some("fe80::1")));
    let y = v6(SET, 10, Some("fe80::2"));
    let z = inferred(bgp6(SET, 10, Some("fe80::3")));
    let mut m = Mirror6::default();
    for r in [&x, &y, &z] {
        m.insert(r.clone(), Position::Back);
    }
    assert_eq!(m.iter().count(), 1);
    // The message lists x (described) and its siblings under x's protocol,
    // here BGP for y to show that the inference does not override y.
    let message = [
        v6(SET, 10, Some("fe80::1")),
        bgp6(SET, 10, Some("fe80::2")),
        v6(SET, 10, Some("fe80::3")),
    ];
    assert!(m.redescribe(message));
    let got: Vec<_> = m
        .iter()
        .map(|r| (r.next_hop, r.protocol_inferred))
        .collect();
    assert_eq!(
        got,
        vec![(x.next_hop, false), (y.next_hop, false), (z.next_hop, true)],
        "all static, in kernel order; only z is still a guess"
    );
    assert_eq!(
        m.first_inferred(&x.slot).map(|r| r.next_hop),
        Some(z.next_hop)
    );
}

#[test]
fn redescribe_touches_only_mirrored_routes_of_the_described_slot() {
    let b1 = bgp6(SET, 10, Some("fe80::1"));
    let mut m = Mirror6::default();
    m.upsert(b1.clone(), Position::Back);
    m.insert(inferred(bgp6(SET, 10, Some("fe80::2"))), Position::Back);
    let before = m.clone();
    // A route the events have not added yet is left to its own event.
    assert!(!m.redescribe([v6(SET, 10, Some("fe80::9"))]));
    // So is a slot with nothing mirrored, and an empty message.
    assert!(!m.redescribe([v6(SET, 20, Some("fe80::2"))]));
    assert!(!m.redescribe([]));
    assert_eq!(m.len(), before.len());
    assert_eq!(m.slot_order(&b1.slot), before.slot_order(&b1.slot));
    // A sibling leg from another slot cannot occur, and is ignored.
    assert!(!m.redescribe([b1.clone(), v6(SET, 20, Some("fe80::2"))]));
    assert_eq!(m.iter().count(), 0);
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

/// The tracking rule written out independently of the implementation: these
/// `rtm_type`s (unicast and the four negative types), not `RTPROT_BGP`.
fn ref_tracked(kind: u8, protocol: u8) -> bool {
    matches!(
        kind,
        RTN_UNICAST | RTN_BLACKHOLE | RTN_UNREACHABLE | RTN_PROHIBIT | RTN_THROW
    ) && protocol != RTPROT_BGP
}

/// `IPV6_DECODE_PREF` ("1:low,2:med,3:high"), written out independently of
/// `RoutePreference`'s ordering.
fn decode_pref(p: RoutePreference) -> u8 {
    match p {
        RoutePreference::Low => 1,
        RoutePreference::Medium => 2,
        RoutePreference::High => 3,
    }
}

/// Reference lookup over the kernel model's slot lists, written straight from
/// the kernel rule and independently of `RouteMirror::lookup`: among slots
/// that cover `addr`, can match best-effort traffic and hold a tracked route,
/// the longest prefix, then the lowest priority, then the lowest table ID;
/// within that slot, the tracked routes in kernel order, and the first with
/// the highest preference score. The route type plays no part in selection.
fn reference_select<S, R: Clone>(
    slots: &HashMap<S, Vec<R>>,
    covers: impl Fn(&S) -> bool,
    rank: impl Fn(&S) -> (u8, u32, u32),
    tracked: impl Fn(&R) -> bool,
    pref: impl Fn(&R) -> u8,
) -> Option<R> {
    let (_, routes) = slots
        .iter()
        .filter(|(s, rs)| covers(s) && rs.iter().any(&tracked))
        .min_by_key(|(s, _)| {
            let (len, priority, table) = rank(s);
            (u8::MAX - len, priority, table)
        })?;
    let best = routes.iter().filter(|r| tracked(r)).map(&pref).max()?;
    routes
        .iter()
        .find(|r| tracked(r) && pref(r) == best)
        .cloned()
}

fn reference_lookup_v4(
    slots: &HashMap<RouteSlotV4, Vec<KernelRouteV4>>,
    addr: Ipv4Addr,
) -> Option<KernelRouteV4> {
    let bits = u32::from(addr);
    reference_select(
        slots,
        |s| {
            let len = s.dst.prefix_len();
            let top = |x: u32| if len == 0 { 0 } else { x >> (32 - len) };
            s.tos == 0 && top(u32::from(s.dst.addr())) == top(bits)
        },
        |s| (s.dst.prefix_len(), s.priority, s.table.get()),
        |r| ref_tracked(r.kind, r.protocol),
        |_| 2,
    )
}

fn reference_lookup_v6(
    slots: &HashMap<RouteSlotV6, Vec<KernelRouteV6>>,
    addr: Ipv6Addr,
) -> Option<KernelRouteV6> {
    let bits = u128::from(addr);
    reference_select(
        slots,
        |s| {
            let len = s.dst.prefix_len();
            let top = |x: u128| if len == 0 { 0 } else { x >> (128 - len) };
            s.src.is_default() && top(u128::from(s.dst.addr())) == top(bits)
        },
        |s| (s.dst.prefix_len(), s.priority, s.table.get()),
        |r| ref_tracked(r.kind, r.protocol),
        |r| decode_pref(r.preference),
    )
}

/// The mirror's outcome must name the reference route, and its variant must
/// follow from that route's `rtm_type` alone (ip-route(8): only unicast
/// forwards; blackhole, unreachable and prohibit reject; throw ends the
/// table lookup).
fn check_outcome<R: PartialEq + std::fmt::Debug>(
    got: FibLookup<'_, R>,
    expected: Option<&R>,
    kind_of: impl Fn(&R) -> u8,
) -> Result<(), TestCaseError> {
    let Some(e) = expected else {
        prop_assert_eq!(got, FibLookup::NoRoute);
        return Ok(());
    };
    let want = match kind_of(e) {
        RTN_UNICAST => FibLookup::Forward(e),
        RTN_BLACKHOLE => FibLookup::Reject {
            route: e,
            kind: RejectKind::Blackhole,
        },
        RTN_UNREACHABLE => FibLookup::Reject {
            route: e,
            kind: RejectKind::Unreachable,
        },
        RTN_PROHIBIT => FibLookup::Reject {
            route: e,
            kind: RejectKind::Prohibit,
        },
        RTN_THROW => FibLookup::Throw(e),
        other => {
            return Err(TestCaseError::fail(format!(
                "untracked kind {other} selected"
            )));
        }
    };
    prop_assert_eq!(got, want);
    prop_assert_eq!(got.is_reachable(), kind_of(e) == RTN_UNICAST);
    Ok(())
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

/// Route types: mostly unicast, every negative type, and `local` (mirrored but
/// never tracked).
fn arb_rtm_type() -> impl Strategy<Value = u8> + Clone {
    prop::sample::select(vec![
        RTN_UNICAST,
        RTN_UNICAST,
        RTN_UNICAST,
        RTN_BLACKHOLE,
        RTN_UNREACHABLE,
        RTN_PROHIBIT,
        RTN_THROW,
        RTN_LOCAL,
    ])
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
        arb_rtm_type(),
        prop::sample::select(vec![None, Some("192.0.2.1"), Some("192.0.2.2")]),
    )
        .prop_map(|(prefix, priority, table, tos, protocol, kind, gw)| {
            let mut r = v4(prefix, priority, gw);
            r.slot.table = TableId::new(table).unwrap();
            r.slot.tos = tos;
            r.protocol = protocol;
            r.kind = kind;
            if RouteKind::from_rtm_type(kind).is_some_and(|k| k != RouteKind::Unicast) {
                // Negative routes have no gateway or device (fib_create_info).
                r.next_hop = NextHopV4::Path(NextHopPath {
                    gateway: None,
                    oif: None,
                });
            }
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
        any::<bool>(),
        prop::sample::select(vec![
            None,
            Some("fe80::1"),
            Some("fe80::2"),
            Some("fe80::3"),
        ]),
        arb_rtm_type(),
        prop::sample::select(vec![
            RoutePreference::Medium,
            RoutePreference::Medium,
            RoutePreference::Low,
            RoutePreference::High,
        ]),
    )
        .prop_map(
            |(prefix, priority, src, protocol, inferred, gw, kind, preference)| {
                let mut r = v6(prefix, priority, gw);
                if let Some(src) = src {
                    r.slot.src = p6(src);
                }
                r.protocol = protocol;
                r.protocol_inferred = inferred;
                r.kind = kind;
                if RouteKind::from_rtm_type(kind).is_some_and(|k| k != RouteKind::Unicast) {
                    // Negative routes sit on the loopback device with no gateway
                    // (fib6_nh_init) and are always medium (ip6_route_info_create
                    // overwrites their fib6_flags).
                    r.next_hop = NextHopV6::Path(via(None));
                    // Never an ECMP leg, so its protocol is always reported.
                    r.protocol_inferred = false;
                } else {
                    r.preference = preference;
                }
                r
            },
        )
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
                let expected = reference_lookup_v4(&kernel.slots, addr);
                check_outcome(mirror.resolve(addr), expected.as_ref(), |r| r.kind)?;
                prop_assert_eq!(mirror.lookup(addr), expected.as_ref());
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
                let expected = reference_lookup_v6(&kernel.slots, addr);
                check_outcome(mirror.resolve(addr), expected.as_ref(), |r| r.kind)?;
                prop_assert_eq!(mirror.lookup(addr), expected.as_ref());
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
