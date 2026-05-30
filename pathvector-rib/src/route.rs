use ipnetx::interfaces::IpAddress;
use pathvector_policy::BgpRoute;
use pathvector_types::{
    Aggregator, AsPath, Community, ExtendedCommunity, LargeCommunity, LocalPref, Med, NextHop,
    Nlri, Origin,
};

/// A concrete BGP route stored in the RIB.
///
/// `Route<A>` is the type that lives in [`AdjRibIn`](crate::AdjRibIn),
/// [`LocRib`](crate::LocRib), and [`AdjRibOut`](crate::AdjRibOut). It holds
/// every standard BGP path attribute alongside the advertised prefix.
///
/// The generic parameter `A` is the address family: `Ipv4Addr` for IPv4
/// routes, `Ipv6Addr` for IPv6 routes.
///
/// `Route<A>` implements [`BgpRoute`] from `pathvector-policy`, so import
/// and export policies can be applied directly to routes stored in the RIB.
///
/// # Construction
///
/// Use [`RouteBuilder`] for ergonomic construction — only `nlri`, `origin`,
/// and `as_path` are mandatory.
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use pathvector_rib::{Route, RouteBuilder};
/// use pathvector_types::{AsPath, Asn, Nlri, Origin};
///
/// let route = RouteBuilder::new(
///     "10.0.0.0/8".parse::<Nlri<Ipv4Addr>>().unwrap(),
///     Origin::Igp,
///     AsPath::from_sequence(vec![Asn::new(65001)]),
/// )
/// .build();
///
/// assert_eq!(route.origin(), Origin::Igp);
/// assert_eq!(route.as_path().path_length(), 1);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Route<A: IpAddress> {
    /// The advertised prefix.
    pub nlri: Nlri<A>,
    /// How this route was introduced into BGP.
    pub origin: Origin,
    /// The sequence of ASes this route has traversed.
    pub as_path: AsPath,
    /// The next-hop IP address for forwarding.
    pub next_hop: Option<NextHop>,
    /// Internal preference (iBGP only; stripped on eBGP export).
    pub local_pref: Option<LocalPref>,
    /// External exit discriminator (hint to neighboring ASes).
    pub med: Option<Med>,
    /// Standard BGP communities (RFC 1997).
    pub communities: Vec<Community>,
    /// Large communities (RFC 8092).
    pub large_communities: Vec<LargeCommunity>,
    /// Extended communities (RFC 4360).
    pub extended_communities: Vec<ExtendedCommunity>,
    /// Flag indicating this route is an aggregate with suppressed path info.
    pub atomic_aggregate: bool,
    /// The router that performed aggregation, if known.
    pub aggregator: Option<Aggregator>,
}

impl<A: IpAddress> BgpRoute for Route<A> {
    type Addr = A;

    fn nlri(&self) -> Nlri<A> { self.nlri }
    fn origin(&self) -> Origin { self.origin }
    fn local_pref(&self) -> Option<LocalPref> { self.local_pref }
    fn med(&self) -> Option<Med> { self.med }
    fn as_path(&self) -> &AsPath { &self.as_path }
    fn communities(&self) -> &[Community] { &self.communities }
    fn large_communities(&self) -> &[LargeCommunity] { &self.large_communities }
    fn extended_communities(&self) -> &[ExtendedCommunity] { &self.extended_communities }
    fn next_hop(&self) -> Option<NextHop> { self.next_hop }

    fn set_origin(&mut self, origin: Origin) { self.origin = origin; }
    fn set_local_pref(&mut self, lp: Option<LocalPref>) { self.local_pref = lp; }
    fn set_med(&mut self, med: Option<Med>) { self.med = med; }
    fn set_as_path(&mut self, path: AsPath) { self.as_path = path; }
    fn set_communities(&mut self, c: Vec<Community>) { self.communities = c; }
    fn set_large_communities(&mut self, c: Vec<LargeCommunity>) { self.large_communities = c; }
    fn set_extended_communities(&mut self, c: Vec<ExtendedCommunity>) { self.extended_communities = c; }
    fn set_next_hop(&mut self, nh: Option<NextHop>) { self.next_hop = nh; }
}

/// Builder for constructing a [`Route<A>`].
///
/// Only `nlri`, `origin`, and `as_path` are mandatory — all other attributes
/// are optional and default to absent (`None` or empty `Vec`).
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use pathvector_rib::{Route, RouteBuilder};
/// use pathvector_types::{AsPath, Asn, Community, LocalPref, NextHop, Nlri, Origin};
/// use std::net::Ipv4Addr as V4;
///
/// let route = RouteBuilder::new(
///     "192.168.1.0/24".parse::<Nlri<Ipv4Addr>>().unwrap(),
///     Origin::Igp,
///     AsPath::from_sequence(vec![Asn::new(65002), Asn::new(65001)]),
/// )
/// .next_hop(NextHop::V4(V4::new(10, 0, 0, 1)))
/// .local_pref(LocalPref::new(200))
/// .community(Community::from_parts(65000, 100))
/// .build();
///
/// assert_eq!(route.local_pref, Some(LocalPref::new(200)));
/// assert_eq!(route.communities.len(), 1);
/// ```
pub struct RouteBuilder<A: IpAddress> {
    nlri: Nlri<A>,
    origin: Origin,
    as_path: AsPath,
    next_hop: Option<NextHop>,
    local_pref: Option<LocalPref>,
    med: Option<Med>,
    communities: Vec<Community>,
    large_communities: Vec<LargeCommunity>,
    extended_communities: Vec<ExtendedCommunity>,
    atomic_aggregate: bool,
    aggregator: Option<Aggregator>,
}

impl<A: IpAddress> RouteBuilder<A> {
    /// Creates a builder with the three mandatory BGP attributes.
    ///
    /// `nlri` is the advertised prefix, `origin` describes how the route was
    /// introduced into BGP, and `as_path` is the sequence of ASes it has
    /// traversed.
    #[must_use]
    pub fn new(nlri: Nlri<A>, origin: Origin, as_path: AsPath) -> Self {
        Self {
            nlri,
            origin,
            as_path,
            next_hop: None,
            local_pref: None,
            med: None,
            communities: Vec::new(),
            large_communities: Vec::new(),
            extended_communities: Vec::new(),
            atomic_aggregate: false,
            aggregator: None,
        }
    }

    /// Sets the `NEXT_HOP` attribute.
    #[must_use]
    pub fn next_hop(mut self, nh: NextHop) -> Self {
        self.next_hop = Some(nh);
        self
    }

    /// Sets the `LOCAL_PREF` attribute.
    #[must_use]
    pub fn local_pref(mut self, lp: LocalPref) -> Self {
        self.local_pref = Some(lp);
        self
    }

    /// Sets the `MED` attribute.
    #[must_use]
    pub fn med(mut self, med: Med) -> Self {
        self.med = Some(med);
        self
    }

    /// Appends a standard community.
    #[must_use]
    pub fn community(mut self, c: Community) -> Self {
        self.communities.push(c);
        self
    }

    /// Appends a large community.
    #[must_use]
    pub fn large_community(mut self, lc: LargeCommunity) -> Self {
        self.large_communities.push(lc);
        self
    }

    /// Appends an extended community.
    #[must_use]
    pub fn extended_community(mut self, ec: ExtendedCommunity) -> Self {
        self.extended_communities.push(ec);
        self
    }

    /// Sets the `ATOMIC_AGGREGATE` flag.
    #[must_use]
    pub fn atomic_aggregate(mut self) -> Self {
        self.atomic_aggregate = true;
        self
    }

    /// Sets the `AGGREGATOR` attribute.
    #[must_use]
    pub fn aggregator(mut self, agg: Aggregator) -> Self {
        self.aggregator = Some(agg);
        self
    }

    /// Consumes the builder and returns a [`Route<A>`].
    #[must_use]
    pub fn build(self) -> Route<A> {
        Route {
            nlri: self.nlri,
            origin: self.origin,
            as_path: self.as_path,
            next_hop: self.next_hop,
            local_pref: self.local_pref,
            med: self.med,
            communities: self.communities,
            large_communities: self.large_communities,
            extended_communities: self.extended_communities,
            atomic_aggregate: self.atomic_aggregate,
            aggregator: self.aggregator,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    #[test]
    fn test_route_builder_minimal() {
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new()).build();
        assert_eq!(route.origin, Origin::Igp);
        assert!(route.next_hop.is_none());
        assert!(route.local_pref.is_none());
        assert!(route.med.is_none());
        assert!(route.communities.is_empty());
        assert!(!route.atomic_aggregate);
        assert!(route.aggregator.is_none());
    }

    #[test]
    fn test_route_builder_full() {
        use pathvector_types::{Aggregator, Asn, Community, LocalPref, Med, NextHop};
        let route = RouteBuilder::new(
            nlri("192.168.1.0/24"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65002), Asn::new(65001)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .local_pref(LocalPref::new(200))
        .med(Med::new(50))
        .community(Community::from_parts(65000, 100))
        .atomic_aggregate()
        .aggregator(Aggregator::new(Asn::new(65001), Ipv4Addr::new(1, 1, 1, 1)))
        .build();

        assert_eq!(route.local_pref, Some(LocalPref::new(200)));
        assert_eq!(route.med, Some(Med::new(50)));
        assert_eq!(route.communities.len(), 1);
        assert!(route.atomic_aggregate);
        assert!(route.aggregator.is_some());
    }

    #[test]
    fn test_route_bgproute_getters() {
        use pathvector_types::{Asn, LocalPref};
        use pathvector_policy::BgpRoute;

        let route = RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65001)]),
        )
        .local_pref(LocalPref::new(150))
        .build();

        assert_eq!(route.origin(), Origin::Igp);
        assert_eq!(route.local_pref(), Some(LocalPref::new(150)));
        assert_eq!(route.as_path().path_length(), 1);
        assert_eq!(route.nlri(), nlri("10.0.0.0/8"));
    }

    #[test]
    fn test_route_bgproute_setters() {
        use pathvector_types::{Asn, LocalPref};
        use pathvector_policy::BgpRoute;

        let mut route =
            RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Incomplete, AsPath::new()).build();

        route.set_origin(Origin::Igp);
        assert_eq!(route.origin(), Origin::Igp);

        route.set_local_pref(Some(LocalPref::new(200)));
        assert_eq!(route.local_pref(), Some(LocalPref::new(200)));

        route.set_local_pref(None);
        assert_eq!(route.local_pref(), None);

        route.set_as_path(AsPath::from_sequence(vec![Asn::new(65001)]));
        assert_eq!(route.as_path().path_length(), 1);
    }

    #[test]
    fn test_route_clone() {
        let original =
            RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new()).build();
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }
}
