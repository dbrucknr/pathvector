use std::net::{Ipv4Addr, Ipv6Addr};

/// The ORIGIN path attribute (type code 1, well-known mandatory).
///
/// Every BGP UPDATE must carry an ORIGIN attribute. It describes how the
/// route was originally introduced into BGP — not where it has been since,
/// but how it was born.
///
/// ORIGIN participates in best-path selection: when all higher-priority
/// criteria tie, the router prefers the route with the lowest origin value.
/// `Igp` is preferred, then `Egp`, then `Incomplete`.
///
/// In practice the vast majority of routes you will see carry `Igp` — they
/// were injected from an interior routing protocol (OSPF, IS-IS) or via
/// `network` statements. `Egp` refers to the now-obsolete EGP protocol
/// that preceded BGP. `Incomplete` means the origin could not be determined,
/// typically because the route was redistributed from a static route or
/// another protocol that doesn't map cleanly to IGP or EGP.
///
/// # Examples
///
/// ```
/// use pathvector_types::Origin;
///
/// // IGP is preferred over INCOMPLETE in best-path selection
/// assert!(Origin::Igp < Origin::Incomplete);
/// assert!(Origin::Igp < Origin::Egp);
/// assert!(Origin::Egp < Origin::Incomplete);
///
/// assert_eq!(Origin::Igp.as_u8(), 0);
/// assert_eq!(Origin::Egp.as_u8(), 1);
/// assert_eq!(Origin::Incomplete.as_u8(), 2);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// Route was learned from an Interior Gateway Protocol (OSPF, IS-IS, etc.)
    /// or statically configured with `network`. The most common and most
    /// preferred origin value.
    Igp = 0,
    /// Route was learned from the Exterior Gateway Protocol — the predecessor
    /// to BGP, now obsolete. Rare in modern networks.
    Egp = 1,
    /// Origin cannot be determined. Typically produced by route redistribution
    /// from a protocol that has no clean mapping to IGP or EGP (e.g. static
    /// routes, connected routes, EIGRP). Least preferred.
    Incomplete = 2,
}

impl Origin {
    /// Returns the wire value of this origin code.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Origin;
    ///
    /// assert_eq!(Origin::Igp.as_u8(), 0);
    /// assert_eq!(Origin::Incomplete.as_u8(), 2);
    /// ```
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parses an origin from its wire byte.
    ///
    /// Returns `None` for any value outside `[0, 2]`.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Origin;
    ///
    /// assert_eq!(Origin::from_u8(0), Some(Origin::Igp));
    /// assert_eq!(Origin::from_u8(2), Some(Origin::Incomplete));
    /// assert_eq!(Origin::from_u8(3), None);
    /// ```
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Igp),
            1 => Some(Self::Egp),
            2 => Some(Self::Incomplete),
            _ => None,
        }
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Igp => write!(f, "igp"),
            Self::Egp => write!(f, "egp"),
            Self::Incomplete => write!(f, "incomplete"),
        }
    }
}

/// The `LOCAL_PREF` path attribute (type code 5, well-known discretionary).
///
/// `LOCAL_PREF` is the primary tool for expressing route preference *inside*
/// an AS. It is only exchanged between iBGP peers — when a route is
/// advertised to an eBGP peer, this attribute is stripped.
///
/// **Higher `LOCAL_PREF` wins.** A router receiving the same prefix from
/// multiple iBGP peers selects the route with the highest `LOCAL_PREF`. This
/// is the first meaningful criterion in the BGP decision process.
///
/// Common operator convention: default is 100. Routes set above 100 are
/// preferred, routes set below 100 are used only as a last resort.
///
/// ```text
/// Traffic engineering with LOCAL_PREF:
///
///   ISP-A ─── 200 ─── [your AS] ─── 100 ─── ISP-B
///
///   All outbound traffic prefers ISP-A (higher LOCAL_PREF).
///   ISP-B is backup.
/// ```
///
/// # Examples
///
/// ```
/// use pathvector_types::LocalPref;
///
/// let preferred = LocalPref::new(200);
/// let backup    = LocalPref::new(50);
///
/// // Higher LOCAL_PREF wins in best-path selection
/// assert!(preferred > backup);
/// assert_eq!(LocalPref::DEFAULT, LocalPref::new(100));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalPref(u32);

impl LocalPref {
    /// The conventional default `LOCAL_PREF` value used by most implementations.
    ///
    /// Routes without an explicit `LOCAL_PREF` are typically treated as if they
    /// carry this value. Setting routes above 100 makes them preferred; below
    /// 100 marks them as backup.
    pub const DEFAULT: Self = Self(100);

    /// Creates a new `LocalPref` from a raw 32-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::LocalPref;
    ///
    /// let lp = LocalPref::new(150);
    /// assert_eq!(lp.as_u32(), 150);
    /// ```
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw 32-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::LocalPref;
    ///
    /// assert_eq!(LocalPref::new(200).as_u32(), 200);
    /// ```
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl Default for LocalPref {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl From<u32> for LocalPref {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for LocalPref {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The `MULTI_EXIT_DISC` (MED) path attribute (type code 4, optional
/// non-transitive).
///
/// MED is a hint an AS sends to its directly connected neighbors suggesting
/// which of its entry points they should prefer. Unlike `LOCAL_PREF`, MED
/// crosses the AS boundary — but only one hop. A router that receives a MED
/// value must not propagate it to its own eBGP peers (it is non-transitive).
///
/// **Lower MED wins.** This is the opposite direction from `LOCAL_PREF`.
///
/// MED is only meaningful between directly peering ASes. If a prefix arrives
/// via two different ASes, those MED values are from different sources and are
/// not directly comparable — most implementations will not compare MED across
/// different neighboring ASes by default (though `always-compare-med` can
/// override this).
///
/// ```text
/// Traffic engineering with MED:
///
///   [ISP] ─── MED 10 ─── POP-A ─── [your AS]
///         ─── MED 20 ─── POP-B ─── [your AS]
///
///   ISP signals: please enter via POP-A if you can.
///   Your AS honours this — traffic to ISP prefers POP-A.
/// ```
///
/// # Examples
///
/// ```
/// use pathvector_types::Med;
///
/// let preferred = Med::new(10);
/// let less_preferred = Med::new(100);
///
/// // Lower MED wins — note this is the opposite of LOCAL_PREF
/// assert!(preferred < less_preferred);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Med(u32);

impl Med {
    /// Creates a new `Med` from a raw 32-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Med;
    ///
    /// let med = Med::new(50);
    /// assert_eq!(med.as_u32(), 50);
    /// ```
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw 32-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Med;
    ///
    /// assert_eq!(Med::new(10).as_u32(), 10);
    /// ```
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<u32> for Med {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for Med {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The `NEXT_HOP` path attribute (type code 3, well-known mandatory for IPv4
/// unicast) and its IPv6 multiprotocol equivalent.
///
/// The next-hop is the IP address a router must forward packets to in order
/// to reach the advertised prefix. It is not necessarily the BGP peer that
/// sent the route — in iBGP, the next-hop is typically the *eBGP* peer's
/// address, preserved unchanged as the route propagates inside the AS (the
/// "next-hop unchanged" rule). This is why IGP reachability of BGP next-hops
/// is so important: every router in the AS needs an IGP route to the
/// next-hop address in order to actually use the BGP route.
///
/// For IPv6, RFC 4760 allows a next-hop in `MP_REACH_NLRI` to carry both a
/// global unicast address and an optional link-local address. The link-local
/// is used for directly connected peers where the global address may not be
/// routable without the link-local context.
///
/// # Examples
///
/// ```
/// use std::net::{Ipv4Addr, Ipv6Addr};
/// use pathvector_types::NextHop;
///
/// // IPv4 unicast next-hop
/// let v4 = NextHop::V4(Ipv4Addr::new(10, 0, 0, 1));
/// assert_eq!(v4.to_string(), "10.0.0.1");
///
/// // IPv6 next-hop
/// let v6 = NextHop::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
/// assert_eq!(v6.to_string(), "2001:db8::1");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NextHop {
    /// An IPv4 next-hop address. Used for the classic IPv4 unicast `NEXT_HOP`
    /// attribute (type code 3) and IPv4 multiprotocol next-hops.
    V4(Ipv4Addr),
    /// An IPv6 next-hop address. Carried in `MP_REACH_NLRI` for IPv6 routes.
    V6(Ipv6Addr),
    /// An IPv6 next-hop with both a global unicast address and a link-local
    /// address (RFC 4760). The link-local is used for directly connected
    /// peers where the global next-hop is not directly reachable.
    V6WithLinkLocal {
        /// The global unicast next-hop address.
        global: Ipv6Addr,
        /// The link-local next-hop address (`fe80::/10`).
        link_local: Ipv6Addr,
    },
}

impl NextHop {
    /// Returns `true` if this is an IPv4 next-hop.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use pathvector_types::NextHop;
    ///
    /// assert!(NextHop::V4(Ipv4Addr::UNSPECIFIED).is_v4());
    /// ```
    #[must_use]
    pub const fn is_v4(&self) -> bool {
        matches!(self, Self::V4(_))
    }

    /// Returns `true` if this is an IPv6 next-hop (with or without link-local).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv6Addr;
    /// use pathvector_types::NextHop;
    ///
    /// assert!(NextHop::V6(Ipv6Addr::UNSPECIFIED).is_v6());
    /// ```
    #[must_use]
    pub const fn is_v6(&self) -> bool {
        matches!(self, Self::V6(_) | Self::V6WithLinkLocal { .. })
    }
}

impl std::fmt::Display for NextHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4(addr) => write!(f, "{addr}"),
            Self::V6(addr) => write!(f, "{addr}"),
            Self::V6WithLinkLocal { global, link_local } => {
                write!(f, "{global} link-local {link_local}")
            }
        }
    }
}

/// The `ATOMIC_AGGREGATE` path attribute (type code 6, well-known
/// discretionary).
///
/// This is a flag attribute — its *presence* is the signal; it carries no
/// value. A router sets this attribute when it selects and advertises a less
/// specific (shorter) aggregate prefix instead of the more specific routes
/// that make it up.
///
/// The concern: if AS 65001 aggregates `10.0.0.0/8` from `10.1.0.0/16` and
/// `10.2.0.0/16`, the resulting aggregate has no AS path entries for the
/// ASes that originated those more-specific routes. Downstream routers can't
/// tell they're receiving an aggregate. `ATOMIC_AGGREGATE` signals this —
/// "I have suppressed some path information."
///
/// Per RFC 4271, a router that receives a route with `ATOMIC_AGGREGATE`
/// must not de-aggregate it (i.e. must not advertise more-specific routes
/// that were part of the aggregate).
///
/// # Examples
///
/// ```
/// use pathvector_types::AtomicAggregate;
///
/// let flag = AtomicAggregate;
/// assert_eq!(flag.to_string(), "atomic-aggregate");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AtomicAggregate;

impl std::fmt::Display for AtomicAggregate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "atomic-aggregate")
    }
}

/// The AGGREGATOR path attribute (type code 7, optional transitive).
///
/// Paired with [`AtomicAggregate`], this attribute identifies *which* router
/// performed the aggregation — the AS number and IP address of that router.
/// Unlike `ATOMIC_AGGREGATE`, this attribute is optional; an aggregating
/// router may omit it.
///
/// The IP address in `AGGREGATOR` is always IPv4 per RFC 4271. For 4-byte
/// ASN support, RFC 6793 defines `AS4_AGGREGATOR` (type code 18), which
/// carries the same information but with a 4-byte AS number. The session
/// layer handles the negotiation between these two forms.
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use pathvector_types::{Aggregator, Asn};
///
/// let agg = Aggregator {
///     asn: Asn::new(65000),
///     ip: Ipv4Addr::new(10, 0, 0, 1),
/// };
/// assert_eq!(agg.to_string(), "AS65000 10.0.0.1");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Aggregator {
    /// The AS number of the router that performed aggregation.
    pub asn: crate::Asn,
    /// The IP address (router-id) of the aggregating router.
    pub ip: Ipv4Addr,
}

impl Aggregator {
    /// Creates a new `Aggregator`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use pathvector_types::{Aggregator, Asn};
    ///
    /// let agg = Aggregator::new(Asn::new(65000), Ipv4Addr::new(10, 0, 0, 1));
    /// assert_eq!(agg.asn, Asn::new(65000));
    /// assert_eq!(agg.ip, Ipv4Addr::new(10, 0, 0, 1));
    /// ```
    #[must_use]
    pub const fn new(asn: crate::Asn, ip: Ipv4Addr) -> Self {
        Self { asn, ip }
    }
}

impl std::fmt::Display for Aggregator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.asn, self.ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Asn;

    // --- Origin ---

    #[test]
    fn test_origin_values() {
        assert_eq!(Origin::Igp.as_u8(), 0);
        assert_eq!(Origin::Egp.as_u8(), 1);
        assert_eq!(Origin::Incomplete.as_u8(), 2);
    }

    #[test]
    fn test_origin_from_u8() {
        assert_eq!(Origin::from_u8(0), Some(Origin::Igp));
        assert_eq!(Origin::from_u8(1), Some(Origin::Egp));
        assert_eq!(Origin::from_u8(2), Some(Origin::Incomplete));
        assert_eq!(Origin::from_u8(3), None);
        assert_eq!(Origin::from_u8(255), None);
    }

    #[test]
    fn test_origin_ordering() {
        // IGP is most preferred (lowest value), INCOMPLETE least preferred
        assert!(Origin::Igp < Origin::Egp);
        assert!(Origin::Egp < Origin::Incomplete);
        assert!(Origin::Igp < Origin::Incomplete);
    }

    #[test]
    fn test_origin_display() {
        assert_eq!(Origin::Igp.to_string(), "igp");
        assert_eq!(Origin::Egp.to_string(), "egp");
        assert_eq!(Origin::Incomplete.to_string(), "incomplete");
    }

    // --- LocalPref ---

    #[test]
    fn test_local_pref_default() {
        assert_eq!(LocalPref::DEFAULT.as_u32(), 100);
        assert_eq!(LocalPref::default(), LocalPref::new(100));
    }

    #[test]
    fn test_local_pref_ordering() {
        // Higher LOCAL_PREF wins
        assert!(LocalPref::new(200) > LocalPref::new(100));
        assert!(LocalPref::new(50) < LocalPref::DEFAULT);
    }

    #[test]
    fn test_local_pref_display() {
        assert_eq!(LocalPref::new(150).to_string(), "150");
    }

    #[test]
    fn test_local_pref_from_u32() {
        assert_eq!(LocalPref::from(200u32), LocalPref::new(200));
    }

    // --- Med ---

    #[test]
    fn test_med_ordering() {
        // Lower MED wins — opposite direction from LOCAL_PREF
        assert!(Med::new(10) < Med::new(100));
        assert!(Med::new(0) < Med::new(1));
    }

    #[test]
    fn test_med_display() {
        assert_eq!(Med::new(50).to_string(), "50");
    }

    #[test]
    fn test_med_from_u32() {
        assert_eq!(Med::from(42u32), Med::new(42));
    }

    // --- NextHop ---

    #[test]
    fn test_next_hop_v4() {
        let nh = NextHop::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(nh.is_v4());
        assert!(!nh.is_v6());
        assert_eq!(nh.to_string(), "10.0.0.1");
    }

    #[test]
    fn test_next_hop_v6() {
        let nh = NextHop::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        assert!(!nh.is_v4());
        assert!(nh.is_v6());
        assert_eq!(nh.to_string(), "2001:db8::1");
    }

    #[test]
    fn test_next_hop_v6_with_link_local() {
        let global = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let nh = NextHop::V6WithLinkLocal { global, link_local };
        assert!(nh.is_v6());
        assert!(!nh.is_v4());
        assert_eq!(nh.to_string(), "2001:db8::1 link-local fe80::1");
    }

    // --- AtomicAggregate ---

    #[test]
    fn test_atomic_aggregate_display() {
        assert_eq!(AtomicAggregate.to_string(), "atomic-aggregate");
    }

    #[test]
    fn test_atomic_aggregate_equality() {
        assert_eq!(AtomicAggregate, AtomicAggregate);
    }

    // --- Aggregator ---

    #[test]
    fn test_aggregator_new() {
        let agg = Aggregator::new(Asn::new(65000), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(agg.asn, Asn::new(65000));
        assert_eq!(agg.ip, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_aggregator_display() {
        let agg = Aggregator::new(Asn::new(65000), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(agg.to_string(), "AS65000 10.0.0.1");
    }

    #[test]
    fn test_aggregator_equality() {
        let a = Aggregator::new(Asn::new(65000), Ipv4Addr::new(10, 0, 0, 1));
        let b = Aggregator::new(Asn::new(65000), Ipv4Addr::new(10, 0, 0, 1));
        let c = Aggregator::new(Asn::new(65001), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
