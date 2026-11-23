//! Tests for kernel route identity and the route mirror.
//!
//! Sources (Linux v6.12):
//! - `net/ipv4/fib_trie.c`: `fib_valid_key_len`, `fib_table_insert`,
//!   `fib_table_delete`, `fib_table_lookup`.
//! - `net/ipv6/ip6_fib.c`: `fib6_add_rt2node`, `fib6_del_route`.
//! - `include/net/ip6_route.h`: `rt6_qualify_for_ecmp`, `rt6_duplicate_nexthop`.
//! - `net/ipv4/fib_semantics.c`: `fib_props`; `net/ipv6/route.c`: `fib6_prop`,
//!   `fib6_table_lookup`; `ip-route(8)` "Route types".
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
        kind: RouteKind::Unicast,
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
        kind: RouteKind::Unicast,
        protocol: 3,
        next_hop: NextHopV6::Path(via(gateway)),
    }
}

const NEGATIVE_KINDS: [RouteKind; 4] = [
    RouteKind::Reject(RejectKind::Blackhole),
    RouteKind::Reject(RejectKind::Unreachable),
    RouteKind::Reject(RejectKind::Prohibit),
    RouteKind::Throw,
];

/// A negative IPv4 route as the kernel reports it: no gateway, no device
/// (`fib_create_info` refuses both for these types).
fn neg4(prefix: &str, priority: u32, kind: RouteKind) -> KernelRouteV4 {
    KernelRouteV4 {
        kind,
        next_hop: NextHopV4::Path(NextHopPath {
            gateway: None,
            oif: None,
        }),
        ..v4(prefix, priority, None)
    }
}

/// A negative IPv6 route as the kernel reports it: on the loopback device
/// (ifindex 1), no gateway (`fib6_nh_init`).
fn neg6(prefix: &str, priority: u32, kind: RouteKind) -> KernelRouteV6 {
    KernelRouteV6 {
        kind,
        ..v6(prefix, priority, None)
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
        let mut list = RouteList::default();
        list.insert_back(default.clone());
        list.insert_back(neg.clone());

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
        let mut list = RouteList::default();
        list.insert_back(default.clone());
        list.insert_back(neg.clone());

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
    let list = RouteList::<KernelRouteV4>::default();
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

        let mut appended = RouteList::default();
        appended.insert_back(uni.clone());
        assert!(
            appended.insert_back(neg.clone()),
            "different type, new alias"
        );
        assert_eq!(appended.resolve(a4("10.1.1.1")), FibLookup::Forward(&uni));

        let mut prepended = RouteList::default();
        prepended.insert_back(uni.clone());
        assert!(prepended.insert_front(neg.clone()));
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
    let mut list = RouteList::default();
    assert!(list.insert_back(bh.clone()));
    assert!(list.insert_back(un.clone()));
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
    let mut list = RouteList::default();
    assert!(list.insert_back(bh.clone()));
    assert!(!list.insert_back(un.clone()));
    assert!(
        !bh.qualifies_for_ecmp(),
        "no gateway: never an ECMP sibling"
    );
    assert!(list.remove(&un));
    assert!(list.is_empty());
}

#[test]
fn tos_and_source_specific_negative_routes_do_not_affect_best_effort_lookups() {
    // fib_table_lookup checks the DSCP before the type, so a TOS-specific
    // blackhole only drops traffic with that TOS.
    let mut tos = neg4("10.1.0.0/16", 0, RouteKind::Reject(RejectKind::Blackhole));
    tos.slot.tos = 0x10;
    let mut list = RouteList::default();
    list.insert_back(v4("10.0.0.0/8", 50, None));
    list.insert_back(tos);
    assert_eq!(metric4(&list, "10.1.1.1"), Some(50));
    assert!(list.resolve(a4("10.1.1.1")).is_reachable());

    let mut sourced = neg6("2001:db8:1::/48", 0, RouteKind::Throw);
    sourced.slot.src = p6("2001:db8:ffff::/48");
    let mut list6 = RouteList::default();
    list6.insert_back(v6("2001:db8::/32", 50, None));
    list6.insert_back(sourced);
    assert!(list6.resolve(a6("2001:db8:1::1")).is_reachable());
}

#[test]
fn replacing_a_unicast_route_with_a_negative_one_makes_it_unreachable() {
    // `ip route replace blackhole ...` sends one RTM_NEWROUTE with
    // NLM_F_REPLACE; the unicast alias it displaced gets no RTM_DELROUTE.
    for kind in NEGATIVE_KINDS {
        let uni = v4("10.0.0.0/8", 10, Some("192.0.2.1"));
        let neg = neg4("10.0.0.0/8", 10, kind);
        let mut list = RouteList::default();
        list.insert_back(v4("0.0.0.0/0", 0, Some("192.0.2.9")));
        list.insert_back(uni.clone());
        assert!(list.replace(&neg.slot, Some(neg.clone())));
        assert!(!list.contains(&uni));
        assert!(!list.resolve(a4("10.1.1.1")).is_reachable(), "{kind:?}");
        // And back again.
        assert!(list.replace(&uni.slot, Some(uni.clone())));
        assert_eq!(list.resolve(a4("10.1.1.1")), FibLookup::Forward(&uni));

        let uni6 = v6("2001:db8::/32", 10, Some("fe80::1"));
        let neg6 = neg6("2001:db8::/32", 10, kind);
        let mut list6 = RouteList::default();
        list6.insert_back(uni6.clone());
        assert!(list6.replace(&neg6.slot, neg6.qualifies_for_ecmp(), Some(neg6.clone())));
        assert!(!list6.resolve(a6("2001:db8::1")).is_reachable(), "{kind:?}");
    }
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
/// the lowest priority wins. The route type plays no part in the selection.
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

/// The kinds of the routes that tie for selection under the reference rule.
/// The kernel picks among them by list order, so a correct mirror's outcome
/// must be one of these kinds, and exactly it when they all agree.
fn reference_kinds<R: MirroredRoute>(
    routes: &[R],
    selected: Option<(u8, u32)>,
    addr: R::Addr,
) -> HashSet<RouteKind> {
    routes
        .iter()
        .filter(|r| r.matches(addr) && selected == Some((r.prefix_len(), r.priority())))
        .map(MirroredRoute::kind)
        .collect()
}

/// Checks a mirror outcome against the reference: same rank, a kind that
/// tied for selection, and reachability exactly when that kind is unicast.
fn check_outcome<R: MirroredRoute>(
    outcome: FibLookup<'_, R>,
    reference: Option<(u8, u32)>,
    kinds: &HashSet<RouteKind>,
) -> Result<(), TestCaseError> {
    let got = outcome.selected().map(|r| (r.prefix_len(), r.priority()));
    prop_assert_eq!(got, reference);
    let Some(route) = outcome.selected() else {
        prop_assert!(matches!(outcome, FibLookup::NoRoute));
        return Ok(());
    };
    prop_assert!(kinds.contains(&route.kind()));
    if kinds.len() == 1 {
        prop_assert_eq!(Some(route.kind()), kinds.iter().next().copied());
    }
    let expected_reachable = route.kind() == RouteKind::Unicast;
    prop_assert_eq!(outcome.is_reachable(), expected_reachable);
    prop_assert_eq!(outcome.forwarding().is_some(), expected_reachable);
    match (outcome, route.kind()) {
        (FibLookup::Forward(_), RouteKind::Unicast) | (FibLookup::Throw(_), RouteKind::Throw) => {}
        (FibLookup::Reject { kind, .. }, RouteKind::Reject(k)) => prop_assert_eq!(kind, k),
        (o, k) => prop_assert!(
            false,
            "outcome {:?} for kind {:?}",
            o.selected().is_some(),
            k
        ),
    }
    Ok(())
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

/// Route kinds, weighted towards unicast.
fn arb_kind() -> impl Strategy<Value = RouteKind> {
    prop::sample::select(vec![
        RouteKind::Unicast,
        RouteKind::Unicast,
        RouteKind::Unicast,
        RouteKind::Reject(RejectKind::Blackhole),
        RouteKind::Reject(RejectKind::Unreachable),
        RouteKind::Reject(RejectKind::Prohibit),
        RouteKind::Throw,
    ])
}

/// A small universe so that sequences collide on prefix, priority, table, TOS,
/// type and next hop often. Negative routes carry no next hop, as the kernel
/// reports them.
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
        arb_kind(),
    )
        .prop_map(|(prefix, priority, table, tos, gw, kind)| {
            let mut r = if kind == RouteKind::Unicast {
                v4(prefix, priority, gw)
            } else {
                neg4(prefix, priority, kind)
            };
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
        arb_kind(),
    )
        .prop_map(|(prefix, priority, src, gw, kind)| {
            let mut r = if kind == RouteKind::Unicast {
                v6(prefix, priority, gw)
            } else {
                neg6(prefix, priority, kind)
            };
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
                let reference = reference_lookup_v4(&model, addr);
                let kinds = reference_kinds(&model, reference, addr);
                check_outcome(list.resolve(addr), reference, &kinds)?;
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
                let reference = reference_lookup_v6(&model, addr);
                let kinds = reference_kinds(&model, reference, addr);
                check_outcome(list.resolve(addr), reference, &kinds)?;
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
            // Reachability is order-independent too unless routes of different
            // reachability tie, where the kernel itself decides by list order.
            let kinds = reference_kinds(&routes, a, addr);
            let ambiguous = kinds.contains(&RouteKind::Unicast) && kinds.len() > 1;
            if !ambiguous {
                prop_assert_eq!(forward.resolve(addr).is_reachable(), other.resolve(addr).is_reachable());
            }
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
