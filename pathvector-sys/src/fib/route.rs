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
//! ([`RoutePreference`]). [`RouteMirror::lookup`] reproduces this: longest
//! prefix first, then lowest priority, then (IPv6) highest preference, then
//! kernel list order.
//!
//! Only *tracked* routes are used: unicast and negative routes (see below)
//! not installed by BGP. The oracle answers for best-effort traffic from an
//! unspecified source, so of those only routes that such a lookup can match
//! are eligible:
//!
//! - IPv4 aliases with a non-zero TOS/DSCP are skipped. The kernel only uses
//!   them for packets carrying that DSCP (`if (fa->fa_dscp &&
//!   !fib_dscp_masked_match(fa->fa_dscp, flp)) continue;`).
//! - IPv6 routes with a source prefix are skipped, since they only match
//!   packets from that source.
//!
//! # Every route is mirrored
//!
//! Untracked and ineligible routes are still mirrored, because the kernel's
//! replace rules act on a slot's real order. If a BGP alias sits ahead of a
//! static alias in one IPv4 slot, an `NLM_F_REPLACE` of the BGP alias must not
//! remove the static one. Untracked routes are kept only as an identity hash.
//!
//! # IPv6 multipath messages
//!
//! `rt6_fill_node` sets `rtm_protocol` and `rtm_type` from the one route the
//! message represents and lists it first in `RTA_MULTIPATH`, followed by its
//! siblings. A leg carries only its interface, weight, flags and gateway, so
//! the siblings' own protocols are not in the message, and Linux allows one
//! ECMP set to mix, say, static and BGP routes. Dumps never fill the gap:
//! `fib6_dump_node` emits a sibling set once and then jumps past its siblings
//! ("no need to dump the sibling routes again").
//!
//! So a dump message for an all-BGP set and one for a BGP-first static+BGP set
//! are the same bytes: no decoder can tell them apart, and some policy must
//! decide what an unreported sibling is. The policy here:
//!
//! - The first leg is the route the header describes.
//! - Another leg not yet mirrored takes the header's protocol. Without
//!   `NLM_F_APPEND` (a create or replace), that is exact:
//!   `ip6_route_multipath_add` reports its own first new route, so every new
//!   leg comes from that request. In a dump or an `NLM_F_APPEND`, the protocol
//!   is *inferred* ([`KernelRouteV6::protocol_inferred`]). An ECMP set is
//!   almost always installed by one daemon, so this is exact for every
//!   single-protocol set, BGP and IGP alike, and keeps a dump and incremental
//!   events in agreement for them.
//! - A message that later reports the leg's protocol replaces the inference.
//!   An inference never overwrites a known protocol.
//!
//! - When a delete leaves a slot holding a route whose protocol is inferred,
//!   the adapter reads the set back from the kernel and applies it with
//!   [`RouteMirror::redescribe`]. A dump now describes a different sibling
//!   (the deleted one is gone), and describes a lone remaining route fully.
//!
//! Only an ECMP set that mixes protocols and is learned from a dump (or an
//! append) can be misclassified: its unreported siblings take the first
//! sibling's protocol, in either direction. Treating every unreported sibling
//! as IGP instead would make each all-BGP ECMP set count as IGP reachability
//! after a restart; treating it as BGP would lose the second path of every
//! all-static set. Both are worse in the common case. The re-read bounds how
//! long a misclassification lasts: for a two-route set it ends at the first
//! delete of either route. A dump cannot end it earlier, since it always
//! describes the same sibling. (`RTM_GETROUTE` with `RTM_F_FIB_MATCH` describes
//! whichever sibling the multipath hash picks, and only for the slot that wins
//! a full policy lookup, so it cannot target a given slot or sibling.)
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
//! unreachable. [`RouteMirror::resolve`] reports this as a [`FibLookup`], so a
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
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    hash::{DefaultHasher, Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
};

use smallvec::SmallVec;

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

/// `RTN_UNICAST` in `<linux/rtnetlink.h>`.
pub const RTN_UNICAST: u8 = 1;
/// `RTPROT_BGP` in `<linux/rtnetlink.h>`.
pub const RTPROT_BGP: u8 = 186;
/// `RTPROT_RA` in `<linux/rtnetlink.h>`.
const RTPROT_RA: u8 = 9;

// ── Route types ───────────────────────────────────────────────────────────────

/// `RTN_*` values from `<linux/rtnetlink.h>` (`RTN_UNICAST` is above).
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
/// Only the types that decide what happens to forwarded traffic are
/// represented: unicast and the negative types. `local`, `broadcast`,
/// `anycast` and `multicast` routes (normally in the `local` table) and the
/// obsolete `nat` and `xresolve` types are mirrored for slot order but never
/// used by lookups; [`RouteKind::from_rtm_type`] returns `None` for them.
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

/// The kind of a route the snapshot uses for next-hop reachability: unicast
/// or negative (blackhole, unreachable, prohibit, throw), and not installed by
/// BGP. `None` for every other route, which is mirrored for slot order only.
///
/// BGP routes are destinations we compute, not the IGP paths that reach BGP
/// next hops; counting them would also make every `FibWriter` install wake the
/// decision process. Negative routes must be used: a lookup selects the route
/// before it looks at its type, so a negative route beneath a covering
/// unicast route makes the covered destinations unreachable (issue #57).
const fn tracked_kind(kind: u8, protocol: u8) -> Option<RouteKind> {
    if protocol == RTPROT_BGP {
        None
    } else {
        RouteKind::from_rtm_type(kind)
    }
}

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
/// duplicate test (`fa->fa_type == cfg->fc_type && fa->fa_info == fi`), minus
/// `RTA_METRICS`, which only `ip route append` with identical next hops and
/// different metrics could make significant.
///
/// A negative route has no gateway or device: `fib_create_info` rejects them
/// ("Gateway, device and multipath can not be specified for this route
/// type"). A unicast route through a blackhole nexthop object is reported by
/// the kernel as `RTN_BLACKHOLE` (`fib_dump_info`), so it arrives here as a
/// blackhole route with [`NextHopV4::Object`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KernelRouteV4 {
    /// The alias group.
    pub slot: RouteSlotV4,
    /// `rtm_type` (`RTN_UNICAST`, `RTN_BLACKHOLE`, ...).
    pub kind: u8,
    /// `rtm_protocol`.
    pub protocol: u8,
    /// `rtm_scope`.
    pub scope: u8,
    /// `RTA_PREFSRC`.
    pub prefsrc: Option<Ipv4Addr>,
    /// Next hops.
    pub next_hop: NextHopV4,
}

impl KernelRouteV4 {
    /// The route's type, if it is one the snapshot can use (unicast or
    /// negative), whatever its protocol.
    #[must_use]
    pub const fn route_kind(&self) -> Option<RouteKind> {
        RouteKind::from_rtm_type(self.kind)
    }

    /// Whether the snapshot uses this route for reachability (unicast or
    /// negative, not BGP). Other routes are still mirrored, so that their
    /// position in the slot is known.
    #[must_use]
    pub const fn is_tracked(&self) -> bool {
        tracked_kind(self.kind, self.protocol).is_some()
    }
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
/// Its identity is the slot plus the next hop (`rt6_duplicate_nexthop`); type,
/// protocol and preference are attributes.
///
/// The kernel creates every negative IPv6 route on the loopback device with
/// no gateway (`fib6_nh_init`: "hold loopback dev/idev"), so negative routes
/// of the same metric are duplicates of each other whatever their type, and a
/// negative route is never an ECMP sibling.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KernelRouteV6 {
    /// The metric group.
    pub slot: RouteSlotV6,
    /// `rtm_type`.
    pub kind: u8,
    /// `rtm_protocol`.
    pub protocol: u8,
    /// `true` when no message has reported this route's protocol and it was
    /// taken from the sibling the message described (see the module docs on
    /// IPv6 multipath messages).
    pub protocol_inferred: bool,
    /// `RTA_PREF`. Ranks routes of one metric group during lookup. Medium for
    /// every negative route (see [`RoutePreference`]).
    pub preference: RoutePreference,
    /// Next hop.
    pub next_hop: NextHopV6,
}

impl KernelRouteV6 {
    /// Whether the kernel would make this route an ECMP sibling.
    ///
    /// `rt6_qualify_for_ecmp` is `!(fib6_flags & RTF_ADDRCONF) && !f6i->nh &&
    /// f6i->fib6_nh->fib_nh_gw_family`. `RTF_ADDRCONF` is not visible over
    /// netlink, but every route the kernel creates with it carries
    /// `RTPROT_RA`, which stands in for it here.
    #[must_use]
    pub fn qualifies_for_ecmp(&self) -> bool {
        self.protocol != RTPROT_RA
            && matches!(self.next_hop, NextHopV6::Path(p) if p.gateway.is_some())
    }

    /// The route's type, if it is one the snapshot can use (unicast or
    /// negative), whatever its protocol.
    #[must_use]
    pub const fn route_kind(&self) -> Option<RouteKind> {
        RouteKind::from_rtm_type(self.kind)
    }

    /// Whether the snapshot uses this route for reachability: unicast or
    /// negative, and not installed by BGP. An inferred protocol is used like
    /// a reported one.
    #[must_use]
    pub const fn is_tracked(&self) -> bool {
        tracked_kind(self.kind, self.protocol).is_some()
    }
}

// ── Mirror ────────────────────────────────────────────────────────────────────

/// A kernel route that [`RouteMirror`] can hold: [`KernelRouteV4`] or
/// [`KernelRouteV6`].
pub(crate) trait MirroredRoute: Clone + PartialEq {
    /// The group a route belongs to.
    type Slot: Copy + Eq + Hash;
    /// The address type lookups are made with.
    type Addr: Copy;

    /// The group this route belongs to.
    fn slot(&self) -> &Self::Slot;

    /// Hash of the identity fields other than the slot.
    fn identity(&self) -> u64;

    /// Whether `other` is the same kernel route. Both must be in one slot.
    fn same_identity(&self, other: &Self) -> bool;

    /// The route's kind if lookups may use it at all, else `None`.
    fn tracked_kind(&self) -> Option<RouteKind>;

    /// Rank among the tracked routes of one slot; higher wins. Always medium
    /// for IPv4, which has no such ranking.
    fn preference(&self) -> RoutePreference;

    /// Whether this route's protocol was inferred rather than reported
    /// (always `false` for IPv4, whose messages describe every route).
    fn protocol_inferred(&self) -> bool;

    /// Whether this route is an IPv6 ECMP sibling candidate (always `false`
    /// for IPv4, where a multipath route is a single alias).
    fn ecmp(&self) -> bool;

    /// Whether a best-effort lookup for `addr` from an unspecified source can
    /// match routes in `slot`.
    fn slot_matches(slot: &Self::Slot, addr: Self::Addr) -> bool;

    /// Lookup preference of a slot; smaller wins. Longest prefix first, then
    /// lowest priority, then lowest table ID so that ties are deterministic.
    fn slot_rank(slot: &Self::Slot) -> (Reverse<u8>, u32, u32);
}

fn hash_of(value: &impl Hash) -> u64 {
    // SipHash with fixed keys: deterministic for the life of the process.
    let mut h = DefaultHasher::new();
    value.hash(&mut h);
    h.finish()
}

impl MirroredRoute for KernelRouteV4 {
    type Slot = RouteSlotV4;
    type Addr = Ipv4Addr;

    fn slot(&self) -> &RouteSlotV4 {
        &self.slot
    }

    fn identity(&self) -> u64 {
        hash_of(&(
            self.kind,
            self.protocol,
            self.scope,
            self.prefsrc,
            &self.next_hop,
        ))
    }

    fn same_identity(&self, other: &Self) -> bool {
        self == other
    }

    fn tracked_kind(&self) -> Option<RouteKind> {
        tracked_kind(self.kind, self.protocol)
    }

    fn preference(&self) -> RoutePreference {
        RoutePreference::Medium
    }

    fn protocol_inferred(&self) -> bool {
        false
    }

    fn ecmp(&self) -> bool {
        false
    }

    fn slot_matches(slot: &RouteSlotV4, addr: Ipv4Addr) -> bool {
        slot.tos == 0 && slot.dst.contains(addr)
    }

    fn slot_rank(slot: &RouteSlotV4) -> (Reverse<u8>, u32, u32) {
        (
            Reverse(slot.dst.prefix_len()),
            slot.priority,
            slot.table.get(),
        )
    }
}

impl MirroredRoute for KernelRouteV6 {
    type Slot = RouteSlotV6;
    type Addr = Ipv6Addr;

    fn slot(&self) -> &RouteSlotV6 {
        &self.slot
    }

    fn identity(&self) -> u64 {
        hash_of(&self.next_hop)
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.next_hop == other.next_hop
    }

    fn tracked_kind(&self) -> Option<RouteKind> {
        tracked_kind(self.kind, self.protocol)
    }

    fn preference(&self) -> RoutePreference {
        self.preference
    }

    fn protocol_inferred(&self) -> bool {
        self.protocol_inferred
    }

    fn ecmp(&self) -> bool {
        self.qualifies_for_ecmp()
    }

    fn slot_matches(slot: &RouteSlotV6, addr: Ipv6Addr) -> bool {
        slot.src.is_default() && slot.dst.contains(addr)
    }

    fn slot_rank(slot: &RouteSlotV6) -> (Reverse<u8>, u32, u32) {
        (
            Reverse(slot.dst.prefix_len()),
            slot.priority,
            slot.table.get(),
        )
    }
}

/// One mirrored route. Routes lookups never use are kept only as an identity
/// hash, so a full BGP table installed in the kernel costs little memory. A
/// tracked route keeps its typed kind, so a lookup can classify it without a
/// fallible conversion. An untracked route whose protocol is only inferred is
/// kept whole, because a later re-read of its slot may show that it is
/// tracked after all.
#[derive(Debug, Clone, PartialEq)]
enum Entry<R> {
    Tracked {
        kind: RouteKind,
        route: Box<R>,
    },
    /// Untracked under an inferred protocol.
    Unconfirmed(Box<R>),
    Untracked {
        identity: u64,
        ecmp: bool,
    },
}

impl<R: MirroredRoute> Entry<R> {
    fn new(route: R) -> Self {
        if let Some(kind) = route.tracked_kind() {
            Self::Tracked {
                kind,
                route: Box::new(route),
            }
        } else if route.protocol_inferred() {
            Self::Unconfirmed(Box::new(route))
        } else {
            Self::Untracked {
                identity: route.identity(),
                ecmp: route.ecmp(),
            }
        }
    }

    fn is(&self, route: &R) -> bool {
        match self {
            Self::Tracked { route: r, .. } | Self::Unconfirmed(r) => r.same_identity(route),
            Self::Untracked { identity, .. } => *identity == route.identity(),
        }
    }

    fn is_tracked(&self) -> bool {
        matches!(self, Self::Tracked { .. })
    }

    fn ecmp(&self) -> bool {
        match self {
            Self::Tracked { route: r, .. } | Self::Unconfirmed(r) => r.ecmp(),
            Self::Untracked { ecmp, .. } => *ecmp,
        }
    }

    /// The route, if lookups may use it.
    fn route(&self) -> Option<&R> {
        self.tracked().map(|(route, _)| route)
    }

    fn tracked(&self) -> Option<(&R, RouteKind)> {
        match self {
            Self::Tracked { kind, route } => Some((route, *kind)),
            Self::Unconfirmed(_) | Self::Untracked { .. } => None,
        }
    }

    /// The route, if its protocol is only inferred.
    fn inferred(&self) -> Option<&R> {
        match self {
            Self::Tracked { route: r, .. } | Self::Unconfirmed(r) if r.protocol_inferred() => {
                Some(r)
            }
            _ => None,
        }
    }
}

/// The routes of one slot, in kernel order. Almost every slot holds one route.
type Group<R> = SmallVec<[Entry<R>; 1]>;

/// Where a new route goes within its slot.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Position {
    /// Before the slot's routes (IPv4 `NLM_F_CREATE` without `NLM_F_APPEND`).
    Front,
    /// After the slot's routes (IPv4 `NLM_F_APPEND`, every IPv6 add, dumps).
    Back,
}

/// A mirror of one family's kernel routes, grouped by slot in kernel order.
///
/// It holds **every** route the kernel reports, including ones lookups never
/// use (BGP, non-unicast), because the kernel's replace rules act on the
/// slot's real order: a replacement displaces "the first alias", whatever it
/// is. Lookups only visit slots that hold a tracked route.
///
/// Every mutation returns `true` only when the tracked routes changed, so BGP
/// route churn never signals a change.
#[derive(Debug, Clone)]
pub(crate) struct RouteMirror<R: MirroredRoute> {
    slots: HashMap<R::Slot, Group<R>>,
    /// Slots holding at least one tracked route.
    tracked: HashSet<R::Slot>,
}

impl<R: MirroredRoute> Default for RouteMirror<R> {
    fn default() -> Self {
        Self {
            slots: HashMap::new(),
            tracked: HashSet::new(),
        }
    }
}

// The mutation methods are called only by the Linux netlink adapter (and the
// tests); on other platforms the snapshot stays empty.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
impl<R: MirroredRoute> RouteMirror<R> {
    /// Number of mirrored routes, tracked or not.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.slots.values().map(SmallVec::len).sum()
    }

    /// Returns `true` when no routes are mirrored.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// The identity hash of each route in `slot`, in kernel order, with
    /// whether it is tracked.
    #[cfg(test)]
    pub fn slot_order(&self, slot: &R::Slot) -> Vec<(u64, bool)> {
        self.slots.get(slot).map_or_else(Vec::new, |g| {
            g.iter()
                .map(|e| match e {
                    Entry::Tracked { route, .. } => (route.identity(), true),
                    Entry::Unconfirmed(r) => (r.identity(), false),
                    Entry::Untracked { identity, .. } => (*identity, false),
                })
                .collect()
        })
    }

    /// Tracked routes; within a slot in kernel order.
    pub fn iter(&self) -> impl Iterator<Item = &R> {
        self.tracked
            .iter()
            .filter_map(|s| self.slots.get(s))
            .flat_map(|g| g.iter().filter_map(Entry::route))
    }

    /// Returns `true` if the same kernel route is mirrored, tracked or not.
    pub fn contains(&self, route: &R) -> bool {
        self.slots
            .get(route.slot())
            .is_some_and(|g| g.iter().any(|e| e.is(route)))
    }

    /// The route a best-effort kernel lookup would select for `addr`, of any
    /// tracked kind, with that kind: longest matching prefix, then lowest
    /// priority, then (IPv6) the highest [`RoutePreference`] among the slot's
    /// tracked routes, then the first of those in kernel order. Negative
    /// routes take part like any other: the kernel picks the route before it
    /// looks at its type. With several tables mirrored, they are compared as
    /// one table (lowest ID wins a tie): policy routing rules are not
    /// modelled.
    fn select(&self, addr: R::Addr) -> Option<(&R, RouteKind)> {
        let slot = self
            .tracked
            .iter()
            .filter(|s| R::slot_matches(s, addr))
            .min_by_key(|s| R::slot_rank(s))?;
        // `min_by_key` returns the first of several equal minima, which keeps
        // kernel order as the last tie-breaker.
        self.slots
            .get(slot)?
            .iter()
            .filter_map(Entry::tracked)
            .min_by_key(|(route, _)| Reverse(route.preference()))
    }

    /// The route a best-effort kernel lookup would select for `addr`, of any
    /// tracked kind (see [`resolve`](Self::resolve) for the outcome).
    #[cfg(test)]
    pub fn lookup(&self, addr: R::Addr) -> Option<&R> {
        self.select(addr).map(|(route, _)| route)
    }

    /// How a best-effort kernel lookup for `addr` ends: the selected route
    /// classified by its kind.
    pub fn resolve(&self, addr: R::Addr) -> FibLookup<'_, R> {
        match self.select(addr) {
            None => FibLookup::NoRoute,
            Some((route, RouteKind::Unicast)) => FibLookup::Forward(route),
            Some((route, RouteKind::Reject(kind))) => FibLookup::Reject { route, kind },
            Some((route, RouteKind::Throw)) => FibLookup::Throw(route),
        }
    }

    /// The first route of `slot`, in kernel order, whose protocol is only
    /// inferred, tracked or not.
    pub fn first_inferred(&self, slot: &R::Slot) -> Option<&R> {
        self.slots.get(slot)?.iter().find_map(Entry::inferred)
    }

    /// The tracked routes of `slot`, in kernel order. Slots are tiny, so
    /// comparing this before and after a replace is cheap and exact.
    fn tracked_in(&self, slot: &R::Slot) -> Vec<R> {
        self.slots.get(slot).map_or_else(Vec::new, |g| {
            g.iter().filter_map(Entry::route).cloned().collect()
        })
    }

    /// Recomputes `slot`'s tracked flag and drops it if empty.
    fn settle(&mut self, slot: R::Slot) {
        match self.slots.get(&slot) {
            Some(g) if g.is_empty() => {
                self.slots.remove(&slot);
                self.tracked.remove(&slot);
            }
            Some(g) if g.iter().any(Entry::is_tracked) => {
                self.tracked.insert(slot);
            }
            _ => {
                self.tracked.remove(&slot);
            }
        }
    }

    fn insert_entry(&mut self, slot: R::Slot, entry: Entry<R>, at: Position) {
        let group = self.slots.entry(slot).or_default();
        match at {
            Position::Front => group.insert(0, entry),
            Position::Back => group.push(entry),
        }
        self.settle(slot);
    }

    /// Adds `route` to its slot unless it is already mirrored.
    pub fn insert(&mut self, route: R, at: Position) -> bool {
        if self.contains(&route) {
            return false;
        }
        let tracked = route.tracked_kind().is_some();
        let slot = *route.slot();
        self.insert_entry(slot, Entry::new(route), at);
        tracked
    }

    /// Adds `route`, or updates it in place if already mirrored. Used when the
    /// message describes this very route, so its type and protocol are known.
    pub fn upsert(&mut self, route: R, at: Position) -> bool {
        let slot = *route.slot();
        let Some(i) = self
            .slots
            .get(&slot)
            .and_then(|g| g.iter().position(|e| e.is(&route)))
        else {
            return self.insert(route, at);
        };
        let before = self.tracked_in(&slot);
        let group = self.slots.get_mut(&slot).expect("slot exists");
        group[i] = Entry::new(route);
        self.settle(slot);
        self.tracked_in(&slot) != before
    }

    /// Removes exactly the kernel route `route`; other routes of the slot stay.
    pub fn remove(&mut self, route: &R) -> bool {
        let slot = *route.slot();
        let Some(group) = self.slots.get_mut(&slot) else {
            return false;
        };
        let Some(i) = group.iter().position(|e| e.is(route)) else {
            return false;
        };
        let removed = group.remove(i);
        self.settle(slot);
        removed.is_tracked()
    }
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
impl RouteMirror<KernelRouteV4> {
    /// Applies an IPv4 `RTM_NEWROUTE` carrying `NLM_F_REPLACE`.
    ///
    /// `fib_table_insert` replaces the slot's first alias in place (`fa =
    /// fa_first`), whatever its type or protocol, and sends no `RTM_DELROUTE`
    /// for it. If the new alias already exists in the slot the kernel changes
    /// nothing (`fa_match`).
    pub fn replace(&mut self, new: KernelRouteV4) -> bool {
        let slot = new.slot;
        let Some(group) = self.slots.get_mut(&slot) else {
            return self.insert(new, Position::Back);
        };
        if group.iter().any(|e| e.is(&new)) {
            return false;
        }
        let before = self.tracked_in(&slot);
        self.slots.get_mut(&slot).expect("slot exists")[0] = Entry::new(new);
        self.settle(slot);
        self.tracked_in(&slot) != before
    }
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
impl RouteMirror<KernelRouteV6> {
    /// Applies an IPv6 `RTM_NEWROUTE` carrying `NLM_F_REPLACE` for `new`.
    ///
    /// `fib6_add_rt2node` replaces the first route of the metric group whose
    /// ECMP eligibility equals the new route's, or the group's first route if
    /// none does. If the displaced route had ECMP siblings, every ECMP route of
    /// the group is removed too ("Replacing an ECMP route, remove all
    /// siblings"). No `RTM_DELROUTE` is sent for any of them, and there is no
    /// duplicate check.
    pub fn replace(&mut self, new: KernelRouteV6) -> bool {
        let slot = new.slot;
        let Some(group) = self.slots.get_mut(&slot) else {
            return self.insert(new, Position::Back);
        };
        let new_is_ecmp = new.qualifies_for_ecmp();
        let victim = group
            .iter()
            .position(|e| e.ecmp() == new_is_ecmp)
            .unwrap_or(0);
        let had_siblings = group[victim].ecmp()
            && group
                .iter()
                .enumerate()
                .any(|(i, e)| i != victim && e.ecmp());
        let before = self.tracked_in(&slot);
        let group = self.slots.get_mut(&slot).expect("slot exists");
        if had_siblings {
            // Siblings follow the victim (it is the group's first ECMP route),
            // so removing them leaves the victim's index unchanged.
            let mut i = 0;
            group.retain(|e| {
                let sibling = i != victim && e.ecmp();
                i += 1;
                !sibling
            });
        }
        group[victim] = Entry::new(new);
        self.settle(slot);
        self.tracked_in(&slot) != before
    }

    /// Applies a fresh kernel description of one sibling set, read back from
    /// the kernel after its routes changed.
    ///
    /// `set` is decoded from one kernel message: the first route is the one
    /// the message describes, with its reported protocol; the others are its
    /// siblings and carry that protocol as an inference (they are marked so
    /// here, whatever their flag says).
    /// The kernel was read after the events applied so far, so only routes
    /// already mirrored are touched: one that is missing was added after
    /// those events, and its own notification is still to come.
    ///
    /// - The described route is updated in place.
    /// - A sibling whose protocol is itself inferred takes the new inference.
    ///   Its old one came from a sibling that a fresh dump no longer
    ///   describes, and this keeps the result equal to what a restart's dump
    ///   would give.
    /// - A sibling whose protocol was reported keeps it.
    ///
    /// Returns `true` if the tracked routes changed.
    pub fn redescribe(&mut self, set: impl IntoIterator<Item = KernelRouteV6>) -> bool {
        let mut set = set.into_iter();
        let Some(described) = set.next() else {
            return false;
        };
        let slot = described.slot;
        let before = self.tracked_in(&slot);
        let Some(group) = self.slots.get_mut(&slot) else {
            return false;
        };
        let described = std::iter::once((
            KernelRouteV6 {
                protocol_inferred: false,
                ..described
            },
            false,
        ));
        let siblings = set.map(|r| {
            let r = KernelRouteV6 {
                protocol_inferred: true,
                ..r
            };
            (r, true)
        });
        for (route, only_if_inferred) in described.chain(siblings) {
            if route.slot != slot {
                continue;
            }
            if let Some(entry) = group.iter_mut().find(|e| e.is(&route))
                && (!only_if_inferred || entry.inferred().is_some())
            {
                *entry = Entry::new(route);
            }
        }
        self.settle(slot);
        self.tracked_in(&slot) != before
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
