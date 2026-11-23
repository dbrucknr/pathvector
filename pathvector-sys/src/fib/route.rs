//! Kernel route identity and the ordered route mirror behind [`FibSnapshot`].
//!
//! This module is the platform-independent *domain* half of the FIB
//! integration. It knows nothing about netlink: the Linux adapter
//! (`linux.rs`) decodes `RTM_NEWROUTE` / `RTM_DELROUTE` messages into the
//! types defined here and calls the mutation methods below. Everything here
//! compiles and is tested on every platform.
//!
//! # Why a prefix is not a route
//!
//! Linux keeps several routes for one destination prefix. Each address family
//! groups them differently, and this module mirrors each grouping exactly.
//!
//! **IPv4** (`net/ipv4/fib_trie.c`, `fib_table_insert`): a table holds one
//! leaf per destination, and the leaf holds an ordered list of *aliases*. The
//! kernel's own comment names the key that groups them:
//!
//! > "the first fib alias with the same keys [prefix,dscp,priority]"
//!
//! Aliases are ordered by DSCP (descending) and then priority (ascending).
//! Inside one `[prefix, dscp, priority]` group several aliases can coexist
//! (`ip route append` / `ip route prepend`); the kernel rejects only "a perfect
//! match which uses the same scope, type, and nexthop information". That group
//! is [`RouteSlotV4`]; the full alias identity is [`KernelRouteV4`].
//!
//! **IPv6** (`net/ipv6/ip6_fib.c`, `fib6_add_rt2node`): a node holds a list of
//! `fib6_info` routes ordered by metric. Routes with the same metric are
//! "Same priority level"; a new one is a duplicate only when
//! `rt6_duplicate_nexthop` holds (same device, gateway and encapsulation, or
//! the same nexthop object). ECMP siblings are separate `fib6_info` entries, so
//! a multipath message is decomposed into one [`KernelRouteV6`] per sibling.
//! The group is [`RouteSlotV6`]. IPv6 has no TOS selector but does have an
//! optional source prefix (`CONFIG_IPV6_SUBTREES`).
//!
//! In both families the table is part of the slot, so routes in different
//! tables never collide when the snapshot tracks all tables.
//!
//! # Lookup
//!
//! The kernel walks a leaf's aliases in order and uses the first that matches
//! the packet (`fib_table_lookup`, "Process the leaf"). Because priority sorts
//! ascending, the route that wins for a prefix is the one with the **lowest
//! priority**. When no alias of a leaf matches, the lookup backtracks to a
//! shorter prefix. IPv6 is the same except that, within the lowest-metric
//! group, `rt6_score_route` ranks routes by their router preference
//! (`RTA_PREF`), so a high-preference route beats an earlier medium one
//! ([`RoutePreference`]). [`RouteList::lookup`] reproduces this: longest
//! prefix first, then lowest priority, then (IPv6) highest preference, then
//! kernel list order.
//!
//! The oracle answers for best-effort traffic from an unspecified source, so
//! only routes that such a lookup can match are eligible:
//!
//! - IPv4 aliases with a non-zero TOS/DSCP are skipped. The kernel only uses
//!   them for packets carrying that DSCP (`if (fa->fa_dscp &&
//!   !fib_dscp_masked_match(fa->fa_dscp, flp)) continue;`).
//! - IPv6 routes with a source prefix are skipped, since they only match
//!   packets from that source.
//!
//! Ineligible routes are still stored so that their identity and position are
//! right for later replacements and deletions.
//!
//! # Negative routes
//!
//! A lookup selects a route **before** it decides whether the destination is
//! reachable. `ip-route(8)` describes the route types:
//!
//! > "blackhole - these destinations are unreachable. Packets are discarded
//! > silently."
//! >
//! > "unreachable - these destinations are unreachable. Packets are discarded
//! > and the ICMP message host unreachable is generated."
//! >
//! > "prohibit - these destinations are unreachable. Packets are discarded and
//! > the ICMP message communication administratively prohibited is generated."
//! >
//! > "throw - a special control route used together with policy rules. If such
//! > a route is selected, lookup in this table is terminated pretending that no
//! > route was found."
//!
//! In the kernel each type has a fixed lookup error (`fib_props` in
//! `net/ipv4/fib_semantics.c`, `fib6_prop` in `net/ipv6/route.c`): blackhole
//! `-EINVAL`, unreachable `-EHOSTUNREACH`, prohibit `-EACCES`, throw
//! `-EAGAIN`, unicast `0`. `fib_table_lookup` returns that error as soon as the
//! winning alias is chosen (`err = fib_props[fa->fa_type].error; if
//! (unlikely(err < 0)) { out_reject: ... return err; }`); it does **not**
//! backtrack to a shorter prefix. IPv6 is the same: `fib6_table_lookup` only
//! backtracks when no route of the node was selected, and the selected reject
//! route's error ends the lookup (`ip6_rt_init_dst_reject`). So a negative
//! route beneath a covering unicast route makes the covered destinations
//! unreachable. [`RouteList::resolve`] reports this as a [`FibLookup`], so a
//! negative route can never be read as a forwarding one.
//!
//! **Throw.** `-EAGAIN` is also what a table returns when nothing matches, and
//! the rule walk (`fib_rules_lookup`) moves on to the next policy rule on
//! `-EAGAIN`. With the default rules (`fib_default_rules_init`: local, main,
//! then default for IPv4; local, main for IPv6) a throw in `main` leaves only
//! the `default` table, which is normally empty, and the lookup fails with
//! `-ENETUNREACH`. The snapshot mirrors a single table and does not model
//! policy rules, so it reports a throw as [`FibLookup::Throw`]: no route in
//! the mirrored table, therefore not reachable through it.
//!
//! [`FibSnapshot`]: super::FibSnapshot

use std::{
    cmp::Reverse,
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
};

// ── Prefixes ──────────────────────────────────────────────────────────────────

/// Why a prefix could not be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixError {
    /// The prefix length is wider than the address.
    LengthOutOfRange {
        /// The rejected prefix length.
        len: u8,
        /// The address width in bits (32 or 128).
        max: u8,
    },
    /// The address has bits set past the prefix length.
    ///
    /// Linux rejects such a destination too: `fib_valid_key_len` fails with
    /// "Invalid prefix for given prefix length".
    HostBitsSet,
}

impl fmt::Display for PrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOutOfRange { len, max } => {
                write!(f, "prefix length {len} exceeds the address width of {max}")
            }
            Self::HostBitsSet => f.write_str("address has bits set beyond the prefix length"),
        }
    }
}

impl Error for PrefixError {}

/// Network mask with the top `len` bits set. `len` must be at most 32.
const fn mask_v4(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - len) }
}

/// Network mask with the top `len` bits set. `len` must be at most 128.
const fn mask_v6(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        u128::MAX << (128 - len)
    }
}

/// A canonical IPv4 prefix: length at most 32 and no bits set past it.
///
/// These are the same rules the kernel applies to a route destination, so any
/// destination the kernel reports can be represented and nothing else can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Prefix {
    addr: Ipv4Addr,
    len: u8,
}

impl Ipv4Prefix {
    /// `0.0.0.0/0`.
    pub const DEFAULT: Self = Self {
        addr: Ipv4Addr::UNSPECIFIED,
        len: 0,
    };

    /// Creates a prefix, rejecting a length over 32 or set host bits.
    ///
    /// # Errors
    ///
    /// Returns [`PrefixError::LengthOutOfRange`] if `len > 32` and
    /// [`PrefixError::HostBitsSet`] if `addr` has bits set past `len`.
    pub const fn new(addr: Ipv4Addr, len: u8) -> Result<Self, PrefixError> {
        if len > 32 {
            return Err(PrefixError::LengthOutOfRange { len, max: 32 });
        }
        if addr.to_bits() & !mask_v4(len) != 0 {
            return Err(PrefixError::HostBitsSet);
        }
        Ok(Self { addr, len })
    }

    /// The network address.
    #[must_use]
    pub const fn addr(self) -> Ipv4Addr {
        self.addr
    }

    /// The prefix length in bits.
    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.len
    }

    /// Returns `true` for the zero-length prefix `0.0.0.0/0`.
    #[must_use]
    pub const fn is_default(self) -> bool {
        self.len == 0
    }

    /// Returns `true` if `addr` falls inside this prefix.
    #[must_use]
    pub const fn contains(self, addr: Ipv4Addr) -> bool {
        addr.to_bits() & mask_v4(self.len) == self.addr.to_bits()
    }
}

impl fmt::Display for Ipv4Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// A canonical IPv6 prefix: length at most 128 and no bits set past it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Prefix {
    addr: Ipv6Addr,
    len: u8,
}

impl Ipv6Prefix {
    /// `::/0`.
    pub const DEFAULT: Self = Self {
        addr: Ipv6Addr::UNSPECIFIED,
        len: 0,
    };

    /// Creates a prefix, rejecting a length over 128 or set host bits.
    ///
    /// # Errors
    ///
    /// Returns [`PrefixError::LengthOutOfRange`] if `len > 128` and
    /// [`PrefixError::HostBitsSet`] if `addr` has bits set past `len`.
    pub const fn new(addr: Ipv6Addr, len: u8) -> Result<Self, PrefixError> {
        if len > 128 {
            return Err(PrefixError::LengthOutOfRange { len, max: 128 });
        }
        if addr.to_bits() & !mask_v6(len) != 0 {
            return Err(PrefixError::HostBitsSet);
        }
        Ok(Self { addr, len })
    }

    /// The network address.
    #[must_use]
    pub const fn addr(self) -> Ipv6Addr {
        self.addr
    }

    /// The prefix length in bits.
    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.len
    }

    /// Returns `true` for the zero-length prefix `::/0`.
    #[must_use]
    pub const fn is_default(self) -> bool {
        self.len == 0
    }

    /// Returns `true` if `addr` falls inside this prefix.
    #[must_use]
    pub const fn contains(self, addr: Ipv6Addr) -> bool {
        addr.to_bits() & mask_v6(self.len) == self.addr.to_bits()
    }
}

impl fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

// ── Table ─────────────────────────────────────────────────────────────────────

/// A kernel routing table ID.
///
/// Zero is `RT_TABLE_UNSPEC` in `<linux/rtnetlink.h>`. It is a request
/// wildcard, not a table a route can live in, so it cannot be represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TableId(NonZeroU32);

impl TableId {
    /// `RT_TABLE_MAIN` (254).
    pub const MAIN: Self = Self(NonZeroU32::new(254).unwrap());

    /// Returns `None` for `RT_TABLE_UNSPEC` (0).
    #[must_use]
    pub const fn new(id: u32) -> Option<Self> {
        match NonZeroU32::new(id) {
            Some(id) => Some(Self(id)),
            None => None,
        }
    }

    /// The numeric table ID.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

// ── Next hops ─────────────────────────────────────────────────────────────────

/// One forwarding path: an optional gateway and an optional output interface.
///
/// A device route has an interface and no gateway. The gateway family can
/// differ from the route's family (an IPv4 route via an IPv6 gateway uses
/// `RTA_VIA`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NextHopPath {
    /// `RTA_GATEWAY` or `RTA_VIA`.
    pub gateway: Option<IpAddr>,
    /// `RTA_OIF` (or `rtnh_ifindex` inside `RTA_MULTIPATH`); 0 is stored as `None`.
    pub oif: Option<NonZeroU32>,
}

/// One leg of an IPv4 multipath route (`struct rtnexthop`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MultipathLeg {
    /// The leg's gateway and interface.
    pub path: NextHopPath,
    /// `rtnh_hops`, the leg's weight minus one. Part of the alias identity
    /// because `nh_comp` compares weights.
    pub hops: u8,
}

/// The forwarding part of an IPv4 alias's identity.
///
/// An IPv4 multipath route is one alias with several legs, and the kernel adds
/// and deletes it as a unit, so the legs stay together here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NextHopV4 {
    /// A nexthop object (`RTA_NH_ID`).
    Object(u32),
    /// A single path.
    Path(NextHopPath),
    /// `RTA_MULTIPATH` legs, in kernel order.
    Multipath(Box<[MultipathLeg]>),
}

/// The forwarding part of an IPv6 route's identity.
///
/// There is no multipath variant: each IPv6 ECMP sibling is a separate kernel
/// route and is stored separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NextHopV6 {
    /// A nexthop object (`RTA_NH_ID`).
    Object(u32),
    /// A single path.
    Path(NextHopPath),
}

// ── Route types ───────────────────────────────────────────────────────────────

/// `RTN_*` values from `<linux/rtnetlink.h>`.
const RTN_UNICAST: u8 = 1;
const RTN_BLACKHOLE: u8 = 6;
const RTN_UNREACHABLE: u8 = 7;
const RTN_PROHIBIT: u8 = 8;
const RTN_THROW: u8 = 9;

/// A route type whose lookup ends in a discard: the kernel does not forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectKind {
    /// `RTN_BLACKHOLE`: discarded silently; local senders get `EINVAL`.
    Blackhole,
    /// `RTN_UNREACHABLE`: discarded with ICMP host unreachable; local senders
    /// get `EHOSTUNREACH`.
    Unreachable,
    /// `RTN_PROHIBIT`: discarded with ICMP administratively prohibited; local
    /// senders get `EACCES`.
    Prohibit,
}

/// The type (`rtm_type`) of a route the snapshot mirrors.
///
/// Only the types that can live in a routing table used for forwarding and
/// that decide what happens to forwarded traffic are represented: unicast and
/// the negative types. `local`, `broadcast`, `anycast` and `multicast` routes
/// (normally in the `local` table) and the obsolete `nat` and `xresolve` types
/// are not mirrored; [`RouteKind::from_rtm_type`] returns `None` for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteKind {
    /// `RTN_UNICAST`: "real paths to the destinations covered by the route
    /// prefix".
    Unicast,
    /// `RTN_BLACKHOLE`, `RTN_UNREACHABLE` or `RTN_PROHIBIT`.
    Reject(RejectKind),
    /// `RTN_THROW`: ends the lookup in this table as if no route was found.
    Throw,
}

impl RouteKind {
    /// Maps an `rtm_type` to a mirrored kind, or `None` for a type the
    /// snapshot does not mirror.
    #[must_use]
    pub const fn from_rtm_type(rtm_type: u8) -> Option<Self> {
        match rtm_type {
            RTN_UNICAST => Some(Self::Unicast),
            RTN_BLACKHOLE => Some(Self::Reject(RejectKind::Blackhole)),
            RTN_UNREACHABLE => Some(Self::Reject(RejectKind::Unreachable)),
            RTN_PROHIBIT => Some(Self::Reject(RejectKind::Prohibit)),
            RTN_THROW => Some(Self::Throw),
            _ => None,
        }
    }

    /// The `rtm_type` value of this kind.
    #[must_use]
    pub const fn rtm_type(self) -> u8 {
        match self {
            Self::Unicast => RTN_UNICAST,
            Self::Reject(RejectKind::Blackhole) => RTN_BLACKHOLE,
            Self::Reject(RejectKind::Unreachable) => RTN_UNREACHABLE,
            Self::Reject(RejectKind::Prohibit) => RTN_PROHIBIT,
            Self::Throw => RTN_THROW,
        }
    }
}

// ── Lookup result ─────────────────────────────────────────────────────────────

/// How a best-effort kernel lookup for one destination ends.
///
/// The route is chosen first (longest prefix, then lowest priority) and only
/// then does its kind decide the outcome, as in `fib_table_lookup`. Only
/// [`FibLookup::Forward`] means the destination is reachable.
#[derive(Debug, PartialEq, Eq)]
pub enum FibLookup<'a, R> {
    /// The selected route is unicast: traffic is forwarded along it.
    Forward(&'a R),
    /// The selected route discards the traffic.
    Reject {
        /// The selected negative route.
        route: &'a R,
        /// Which kind of negative route it is.
        kind: RejectKind,
    },
    /// The selected route is a throw route: the lookup in the mirrored table
    /// ends with no route. The kernel would go on to the next policy rule's
    /// table, which the snapshot does not mirror.
    Throw(&'a R),
    /// No mirrored route covers the destination.
    NoRoute,
}

// Manual impls: the enum only holds references, so it is `Copy` whatever `R`
// is; a derive would require `R: Copy`.
impl<R> Clone for FibLookup<'_, R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R> Copy for FibLookup<'_, R> {}

impl<'a, R> FibLookup<'a, R> {
    /// The route traffic is forwarded along, if the lookup ends in one.
    #[must_use]
    pub const fn forwarding(self) -> Option<&'a R> {
        match self {
            Self::Forward(route) => Some(route),
            _ => None,
        }
    }

    /// Whether the lookup ends in a forwarding route.
    #[must_use]
    pub const fn is_reachable(self) -> bool {
        matches!(self, Self::Forward(_))
    }

    /// The route the lookup selected, of any kind.
    #[must_use]
    pub const fn selected(self) -> Option<&'a R> {
        match self {
            Self::Forward(route) | Self::Reject { route, .. } | Self::Throw(route) => Some(route),
            Self::NoRoute => None,
        }
    }
}

// ── Route identity ────────────────────────────────────────────────────────────

/// The kernel's IPv4 alias group: `[prefix, dscp, priority]` within one table.
///
/// `NLM_F_EXCL` rejects a second route in an occupied slot, and
/// `NLM_F_REPLACE` replaces the slot's first alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteSlotV4 {
    /// Routing table.
    pub table: TableId,
    /// Destination prefix.
    pub dst: Ipv4Prefix,
    /// `rtm_tos` (DSCP). Zero matches all traffic.
    pub tos: u8,
    /// `RTA_PRIORITY` (the metric; absent means 0). Lower is preferred.
    pub priority: u32,
}

/// One IPv4 route alias as the kernel identifies it.
///
/// Two aliases in the same slot are the same route when their type, scope,
/// protocol, preferred source and next hops match. That mirrors the kernel's
/// duplicate test ("a perfect match which uses the same scope, type, and
/// nexthop information": `fa->fa_type == cfg->fc_type && fa->fa_info == fi`),
/// minus `RTA_METRICS`, which only `ip route append` with identical next hops
/// and different metrics could make significant.
///
/// A negative route has no gateway or device: `fib_create_info` rejects them
/// ("Gateway, device and multipath can not be specified for this route
/// type"). A unicast route through a blackhole nexthop object is reported by
/// the kernel as `RTN_BLACKHOLE` (`fib_dump_info`), so it arrives here as a
/// [`RejectKind::Blackhole`] route with [`NextHopV4::Object`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KernelRouteV4 {
    /// The alias group.
    pub slot: RouteSlotV4,
    /// `rtm_type`. Part of the identity.
    pub kind: RouteKind,
    /// `rtm_protocol`.
    pub protocol: u8,
    /// `rtm_scope`.
    pub scope: u8,
    /// `RTA_PREFSRC`.
    pub prefsrc: Option<Ipv4Addr>,
    /// Next hops.
    pub next_hop: NextHopV4,
}

/// The kernel's IPv6 "same priority level": one metric within one node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteSlotV6 {
    /// Routing table.
    pub table: TableId,
    /// Destination prefix.
    pub dst: Ipv6Prefix,
    /// Source prefix (`RTA_SRC`); `::/0` when the route is not source-specific.
    pub src: Ipv6Prefix,
    /// `RTA_PRIORITY` (the metric). Lower is preferred.
    pub priority: u32,
}

/// IPv6 router preference (`RTA_PREF`, RFC 4191), which ranks routes of
/// equal prefix and metric.
///
/// `rt6_score_route` (under `CONFIG_IPV6_ROUTER_PREF`) adds
/// `IPV6_DECODE_PREF(IPV6_EXTRACT_PREF(fib6_flags)) << 2` to a route's score,
/// where `IPV6_DECODE_PREF` is "1:low,2:med,3:high", and `find_match` keeps a
/// route only if its score is strictly higher than the best so far. So within
/// the lowest-metric group a higher preference wins, and equal preferences
/// keep list order. The kernel stores only these three values:
/// `rtm_to_fib6_config` turns anything but low or high into medium.
///
/// A negative route is always medium: `ip6_route_info_create` copies the
/// preference into `fib6_flags` and then, for a reject route, overwrites them
/// with `RTF_REJECT | RTF_NONEXTHOP`, so an `RTA_PREF` given with `ip -6 route
/// add blackhole ...` is dropped and the route is reported as medium.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum RoutePreference {
    /// `ICMPV6_ROUTER_PREF_LOW` (3).
    Low,
    /// `ICMPV6_ROUTER_PREF_MEDIUM` (0), the value when `RTA_PREF` is absent.
    #[default]
    Medium,
    /// `ICMPV6_ROUTER_PREF_HIGH` (1).
    High,
}

impl RoutePreference {
    /// Maps an `RTA_PREF` value the way `rtm_to_fib6_config` does: low and
    /// high are kept, anything else becomes medium.
    #[must_use]
    pub const fn from_rta_pref(pref: u8) -> Self {
        match pref {
            3 => Self::Low,
            1 => Self::High,
            _ => Self::Medium,
        }
    }
}

/// One IPv6 route (a single `fib6_info`, so one ECMP sibling at most).
///
/// The kernel creates every negative IPv6 route on the loopback device with
/// no gateway (`fib6_nh_init`: "hold loopback dev/idev"), so negative routes
/// of the same metric are duplicates of each other whatever their type, and a
/// negative route is never an ECMP sibling.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KernelRouteV6 {
    /// The metric group.
    pub slot: RouteSlotV6,
    /// `rtm_type`. Not part of the identity: `rt6_duplicate_nexthop` compares
    /// device, gateway and encapsulation only.
    pub kind: RouteKind,
    /// `rtm_protocol`. Not part of the identity (`rt6_duplicate_nexthop`
    /// ignores it), but needed to tell router-advertisement routes apart.
    pub protocol: u8,
    /// `RTA_PREF`. Not part of the identity, but ranks routes of one metric
    /// group during lookup. Medium for every negative route (see
    /// [`RoutePreference`]).
    pub preference: RoutePreference,
    /// Next hop.
    pub next_hop: NextHopV6,
}

/// `RTPROT_RA` in `<linux/rtnetlink.h>`.
const RTPROT_RA: u8 = 9;

impl KernelRouteV6 {
    /// Whether the kernel would make this route an ECMP sibling.
    ///
    /// `rt6_qualify_for_ecmp` is `!(fib6_flags & RTF_ADDRCONF) && !f6i->nh &&
    /// f6i->fib6_nh->fib_nh_gw_family`. `RTF_ADDRCONF` is not visible over
    /// netlink, but every route the kernel creates with it carries
    /// `RTPROT_RA`, which stands in for it here.
    #[must_use]
    pub fn qualifies_for_ecmp(&self) -> bool {
        qualifies_for_ecmp_v6(self.protocol, &self.next_hop)
    }
}

/// `rt6_qualify_for_ecmp` for a route with this protocol and next hop. The
/// route type plays no part; negative routes have no gateway and so never
/// qualify.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
pub(crate) fn qualifies_for_ecmp_v6(protocol: u8, next_hop: &NextHopV6) -> bool {
    protocol != RTPROT_RA && matches!(next_hop, NextHopV6::Path(p) if p.gateway.is_some())
}

// ── Ordered route mirror ──────────────────────────────────────────────────────

/// A kernel route that [`RouteList`] can mirror: [`KernelRouteV4`] or
/// [`KernelRouteV6`].
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
pub(crate) trait MirroredRoute: Clone + PartialEq {
    /// The group a route belongs to.
    type Slot: Copy + Eq;
    /// The address type lookups are made with.
    type Addr: Copy;

    /// The group this route belongs to.
    fn slot(&self) -> &Self::Slot;

    /// Whether `other` is the same kernel route (possibly with different
    /// non-identifying attributes).
    fn is_same_route(&self, other: &Self) -> bool;

    /// Whether a best-effort lookup for `addr` from an unspecified source can
    /// match this route.
    fn matches(&self, addr: Self::Addr) -> bool;

    /// Prefix length of the destination.
    fn prefix_len(&self) -> u8;

    /// The route priority (metric).
    fn priority(&self) -> u32;

    /// Rank among routes with the same prefix and priority; higher wins.
    /// Always equal for IPv4, which has no such ranking.
    fn preference(&self) -> RoutePreference;

    /// The route type.
    fn kind(&self) -> RouteKind;
}

impl MirroredRoute for KernelRouteV4 {
    type Slot = RouteSlotV4;
    type Addr = Ipv4Addr;

    fn slot(&self) -> &RouteSlotV4 {
        &self.slot
    }

    fn is_same_route(&self, other: &Self) -> bool {
        self == other
    }

    fn matches(&self, addr: Ipv4Addr) -> bool {
        self.slot.tos == 0 && self.slot.dst.contains(addr)
    }

    fn prefix_len(&self) -> u8 {
        self.slot.dst.prefix_len()
    }

    fn priority(&self) -> u32 {
        self.slot.priority
    }

    fn preference(&self) -> RoutePreference {
        RoutePreference::Medium
    }

    fn kind(&self) -> RouteKind {
        self.kind
    }
}

impl MirroredRoute for KernelRouteV6 {
    type Slot = RouteSlotV6;
    type Addr = Ipv6Addr;

    fn slot(&self) -> &RouteSlotV6 {
        &self.slot
    }

    fn is_same_route(&self, other: &Self) -> bool {
        self.slot == other.slot && self.next_hop == other.next_hop
    }

    fn matches(&self, addr: Ipv6Addr) -> bool {
        self.slot.src.is_default() && self.slot.dst.contains(addr)
    }

    fn prefix_len(&self) -> u8 {
        self.slot.dst.prefix_len()
    }

    fn priority(&self) -> u32 {
        self.slot.priority
    }

    fn preference(&self) -> RoutePreference {
        self.preference
    }

    fn kind(&self) -> RouteKind {
        self.kind
    }
}

/// An ordered mirror of one family's kernel routes.
///
/// Routes in the same slot are kept next to each other and in kernel order,
/// so "the first route of a slot" means the same thing here as in the kernel.
/// Every mutation returns `true` only when the stored routes changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteList<R> {
    routes: Vec<R>,
}

impl<R> Default for RouteList<R> {
    fn default() -> Self {
        Self { routes: Vec::new() }
    }
}

// The mutation methods are called only by the Linux netlink adapter (and the
// tests); on other platforms the snapshot stays empty.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
impl<R: MirroredRoute> RouteList<R> {
    /// Number of stored routes.
    #[cfg(test)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Returns `true` when no routes are stored.
    #[cfg(test)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Stored routes in mirror order.
    pub fn iter(&self) -> impl Iterator<Item = &R> {
        self.routes.iter()
    }

    /// Returns `true` if the same kernel route is stored.
    #[must_use]
    pub fn contains(&self, route: &R) -> bool {
        self.routes.iter().any(|r| r.is_same_route(route))
    }

    fn first_in_slot(&self, slot: &R::Slot) -> Option<usize> {
        self.routes.iter().position(|r| r.slot() == slot)
    }

    fn last_in_slot(&self, slot: &R::Slot) -> Option<usize> {
        self.routes.iter().rposition(|r| r.slot() == slot)
    }

    /// Adds `route` at the front of its slot, unless it is already stored.
    ///
    /// This is IPv4 `NLM_F_CREATE` without `NLM_F_APPEND`: the kernel inserts
    /// before the slot's first alias.
    pub fn insert_front(&mut self, route: R) -> bool {
        if self.contains(&route) {
            return false;
        }
        match self.first_in_slot(route.slot()) {
            Some(i) => self.routes.insert(i, route),
            None => self.routes.push(route),
        }
        true
    }

    /// Adds `route` at the end of its slot, unless it is already stored.
    ///
    /// This is IPv4 `NLM_F_APPEND`, every IPv6 add (`fib6_add_rt2node` links a
    /// new route after all routes of the same metric), and kernel dump order.
    pub fn insert_back(&mut self, route: R) -> bool {
        if self.contains(&route) {
            return false;
        }
        match self.last_in_slot(route.slot()) {
            Some(i) => self.routes.insert(i + 1, route),
            None => self.routes.push(route),
        }
        true
    }

    /// Removes exactly the kernel route `route`. Other routes in the same slot
    /// survive.
    pub fn remove(&mut self, route: &R) -> bool {
        match self.routes.iter().position(|r| r.is_same_route(route)) {
            Some(i) => {
                self.routes.remove(i);
                true
            }
            None => false,
        }
    }

    /// The route a best-effort kernel lookup would select for `addr`, of any
    /// kind.
    ///
    /// Longest matching prefix first, then lowest priority, then (IPv6) the
    /// highest [`RoutePreference`], then mirror order. Negative routes take
    /// part like any other: the kernel picks the route before it looks at its
    /// type. With several tables mirrored, they are compared as one table:
    /// policy routing rules are not modelled.
    #[must_use]
    pub fn lookup(&self, addr: R::Addr) -> Option<&R> {
        // `min_by_key` returns the first of several equal minima, which keeps
        // kernel order as the last tie-breaker.
        self.routes
            .iter()
            .filter(|r| r.matches(addr))
            .min_by_key(|r| {
                (
                    Reverse(r.prefix_len()),
                    r.priority(),
                    Reverse(r.preference()),
                )
            })
    }

    /// How a best-effort kernel lookup for `addr` ends: the selected route
    /// (see [`lookup`](Self::lookup)) classified by its kind.
    #[must_use]
    pub fn resolve(&self, addr: R::Addr) -> FibLookup<'_, R> {
        match self.lookup(addr) {
            None => FibLookup::NoRoute,
            Some(route) => match route.kind() {
                RouteKind::Unicast => FibLookup::Forward(route),
                RouteKind::Reject(kind) => FibLookup::Reject { route, kind },
                RouteKind::Throw => FibLookup::Throw(route),
            },
        }
    }
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
impl RouteList<KernelRouteV4> {
    /// Applies an IPv4 `RTM_NEWROUTE` carrying `NLM_F_REPLACE`.
    ///
    /// `fib_table_insert` replaces the first alias of the slot in place and
    /// sends no `RTM_DELROUTE` for it. `new` is `None` when the replacing route
    /// is one this mirror does not track; the displaced route is still removed.
    /// If no stored route is displaced (the kernel displaced an untracked one),
    /// `new` is added to the slot.
    pub fn replace(&mut self, slot: &RouteSlotV4, new: Option<KernelRouteV4>) -> bool {
        let Some(first) = self.first_in_slot(slot) else {
            return new.is_some_and(|n| self.insert_back(n));
        };
        match new {
            // Already the slot's first alias, or a duplicate further down: the
            // kernel returns 0 or -EEXIST and changes nothing.
            Some(n) if self.contains(&n) => false,
            Some(n) => {
                self.routes[first] = n;
                true
            }
            None => {
                self.routes.remove(first);
                true
            }
        }
    }
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
impl RouteList<KernelRouteV6> {
    /// Applies an IPv6 `RTM_NEWROUTE` carrying `NLM_F_REPLACE`.
    ///
    /// `fib6_add_rt2node` replaces the first route of the metric group whose
    /// ECMP eligibility equals the new route's, or the group's first route if
    /// none does. If the displaced route had ECMP siblings, every ECMP route of
    /// the group is removed too ("Replacing an ECMP route, remove all
    /// siblings"). No `RTM_DELROUTE` is sent for any of them.
    ///
    /// `new_is_ecmp` is the replacing route's ECMP eligibility, which is needed
    /// even when `new` is `None` because the route is not tracked.
    pub fn replace(
        &mut self,
        slot: &RouteSlotV6,
        new_is_ecmp: bool,
        new: Option<KernelRouteV6>,
    ) -> bool {
        let victim = self
            .routes
            .iter()
            .position(|r| &r.slot == slot && r.qualifies_for_ecmp() == new_is_ecmp)
            .or_else(|| self.first_in_slot(slot));
        let Some(victim) = victim else {
            return new.is_some_and(|n| self.insert_back(n));
        };

        let had_siblings = self.routes[victim].qualifies_for_ecmp()
            && self
                .routes
                .iter()
                .enumerate()
                .any(|(i, r)| i != victim && &r.slot == slot && r.qualifies_for_ecmp());

        if !had_siblings && new.as_ref() == Some(&self.routes[victim]) {
            return false;
        }

        // Siblings sit after the victim (it is the group's first ECMP route),
        // so removing them leaves the victim's index unchanged.
        if had_siblings {
            let mut i = 0;
            self.routes.retain(|r| {
                let sibling = i != victim && &r.slot == slot && r.qualifies_for_ecmp();
                i += 1;
                !sibling
            });
        }
        // `fib6_add_rt2node` does no duplicate check on replace, so neither
        // does this: an identical route elsewhere in the group is left alone,
        // exactly as the kernel leaves it.
        match new {
            Some(n) => self.routes[victim] = n,
            None => {
                self.routes.remove(victim);
            }
        }
        true
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
