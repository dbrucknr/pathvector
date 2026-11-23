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
//! shorter prefix. [`RouteMirror::lookup`] reproduces this: longest prefix
//! first, then lowest priority, then kernel list order.
//!
//! Only *tracked* routes are used: unicast routes not installed by BGP. The
//! oracle answers for best-effort traffic from an unspecified source, so of
//! those only routes that such a lookup can match are eligible:
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
//! ECMP set to mix, say, static and BGP routes. The adapter therefore treats
//! the first leg as described by the header. Another leg it has not seen takes
//! the header's type and protocol only if the message comes from the request
//! that created it (a create or replace without `NLM_F_APPEND`, where
//! `ip6_route_multipath_add` reports the first new route). Otherwise, such as
//! in a dump or an append, the leg is mirrored as untracked until a message
//! describing it arrives. Each sibling's own dump message does that.
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

// ── Route identity ────────────────────────────────────────────────────────────

/// `RTN_UNICAST` in `<linux/rtnetlink.h>`.
pub const RTN_UNICAST: u8 = 1;
/// `RTPROT_BGP` in `<linux/rtnetlink.h>`.
pub const RTPROT_BGP: u8 = 186;
/// `RTPROT_RA` in `<linux/rtnetlink.h>`.
const RTPROT_RA: u8 = 9;

/// Whether the snapshot uses a route of this type and protocol for next-hop
/// reachability: unicast, and not installed by BGP.
///
/// BGP routes are destinations we compute, not the IGP paths that reach BGP
/// next hops; counting them would also make every `FibWriter` install wake the
/// decision process. Non-unicast routes are not used for reachability yet.
const fn is_igp_unicast(kind: u8, protocol: u8) -> bool {
    kind == RTN_UNICAST && protocol != RTPROT_BGP
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
    /// Whether the snapshot uses this route for reachability (unicast, not
    /// BGP). Other routes are still mirrored, so that their position in the
    /// slot is known.
    #[must_use]
    pub const fn is_tracked(&self) -> bool {
        is_igp_unicast(self.kind, self.protocol)
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

/// One IPv6 route (a single `fib6_info`, so one ECMP sibling at most).
///
/// Its identity is the slot plus the next hop (`rt6_duplicate_nexthop`); type
/// and protocol are attributes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KernelRouteV6 {
    /// The metric group.
    pub slot: RouteSlotV6,
    /// `rtm_type`.
    pub kind: u8,
    /// `rtm_protocol`.
    pub protocol: u8,
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

    /// Whether the snapshot uses this route for reachability (unicast, not
    /// BGP).
    #[must_use]
    pub const fn is_tracked(&self) -> bool {
        is_igp_unicast(self.kind, self.protocol)
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

    /// Whether lookups may use this route at all.
    fn tracked(&self) -> bool;

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

    fn tracked(&self) -> bool {
        self.is_tracked()
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

    fn tracked(&self) -> bool {
        self.is_tracked()
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
/// hash, so a full BGP table installed in the kernel costs little memory.
#[derive(Debug, Clone, PartialEq)]
enum Entry<R> {
    Tracked(Box<R>),
    Untracked { identity: u64, ecmp: bool },
}

impl<R: MirroredRoute> Entry<R> {
    fn new(route: R) -> Self {
        if route.tracked() {
            Self::Tracked(Box::new(route))
        } else {
            Self::Untracked {
                identity: route.identity(),
                ecmp: route.ecmp(),
            }
        }
    }

    /// An entry for a route whose type and protocol are unknown (an IPv6
    /// sibling leg the message does not describe). It is never used for
    /// lookups until a message describing it arrives.
    fn unknown_origin(route: &R) -> Self {
        Self::Untracked {
            identity: route.identity(),
            ecmp: route.ecmp(),
        }
    }

    fn is(&self, route: &R) -> bool {
        match self {
            Self::Tracked(r) => r.same_identity(route),
            Self::Untracked { identity, .. } => *identity == route.identity(),
        }
    }

    fn is_tracked(&self) -> bool {
        matches!(self, Self::Tracked(_))
    }

    fn ecmp(&self) -> bool {
        match self {
            Self::Tracked(r) => r.ecmp(),
            Self::Untracked { ecmp, .. } => *ecmp,
        }
    }

    fn route(&self) -> Option<&R> {
        match self {
            Self::Tracked(r) => Some(r),
            Self::Untracked { .. } => None,
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
                    Entry::Tracked(r) => (r.identity(), true),
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

    /// The route a best-effort kernel lookup would use for `addr`: longest
    /// matching prefix, then lowest priority, then the first tracked route of
    /// that slot in kernel order. With several tables mirrored, they are
    /// compared as one table (lowest ID wins a tie): policy routing rules are
    /// not modelled.
    pub fn lookup(&self, addr: R::Addr) -> Option<&R> {
        let slot = self
            .tracked
            .iter()
            .filter(|s| R::slot_matches(s, addr))
            .min_by_key(|s| R::slot_rank(s))?;
        self.slots.get(slot)?.iter().find_map(Entry::route)
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
        let tracked = route.tracked();
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

    /// Adds a route whose type and protocol the message does not give (see
    /// [`Entry::unknown_origin`]) unless it is already mirrored.
    pub fn insert_unknown_origin(&mut self, route: &R) -> bool {
        if !self.contains(route) {
            self.insert_entry(*route.slot(), Entry::unknown_origin(route), Position::Back);
        }
        false
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
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
