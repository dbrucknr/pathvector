use std::{net::Ipv4Addr, sync::Arc};

use ipnetx::interfaces::IpAddress;
use pathvector_policy::BgpRoute;
use pathvector_types::{
    Aggregator, AsPath, Asn, Community, ExtendedCommunity, LargeCommunity, LocalPref, Med, NextHop,
    Nlri, Origin, PeerType,
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
/// assert_eq!(route.origin, Origin::Igp);
/// assert_eq!(route.as_path.path_length(), 1);
/// ```
/// Path attributes that are absent on the vast majority of routes.
///
/// Stored behind `Option<Box<_>>` on [`Route`] so that routes without any of
/// these attributes pay only 8 bytes (a null pointer) instead of 96+ bytes of
/// inline empty `Vec`s. The box is allocated lazily — only when at least one
/// field is non-default.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RareAttrs {
    /// Standard BGP communities (RFC 1997).
    pub communities: Vec<Community>,
    /// Large communities (RFC 8092).
    pub large_communities: Vec<LargeCommunity>,
    /// Extended communities (RFC 4360).
    pub extended_communities: Vec<ExtendedCommunity>,
    /// Ordered list of cluster IDs this route has passed through
    /// (RFC 4456 `CLUSTER_LIST`, type 10). Empty for non-reflected routes.
    pub cluster_list: Vec<u32>,
    /// Flag indicating this route is an aggregate with suppressed path info.
    pub atomic_aggregate: bool,
    /// The router that performed aggregation, if known.
    pub aggregator: Option<Aggregator>,
    /// BGP Identifier of the router that first introduced this route into the
    /// iBGP mesh via a route reflector (RFC 4456 `ORIGINATOR_ID`, type 9).
    pub originator_id: Option<Ipv4Addr>,
    /// `ONLY_TO_CUSTOMER` (RFC 9234 §3) — route-leak prevention marker. Once
    /// set (either by the peer we received it from, or by us on ingress
    /// per RFC 9234 §5), must be preserved unchanged and must not be
    /// forwarded to a Provider, Peer, or Route Server.
    pub otc: Option<Asn>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Route<A: IpAddress> {
    /// The advertised prefix.
    pub nlri: Nlri<A>,
    /// How this route was introduced into BGP.
    pub origin: Origin,
    /// The sequence of ASes this route has traversed.
    ///
    /// Stored as `Arc` so routes from the same UPDATE message can share a
    /// single allocation. Use `Arc::make_mut` for copy-on-write mutation.
    pub as_path: Arc<AsPath>,
    /// The next-hop IP address for forwarding.
    pub next_hop: Option<NextHop>,
    /// Internal preference (iBGP only; stripped on eBGP export).
    pub local_pref: Option<LocalPref>,
    /// External exit discriminator (hint to neighboring ASes).
    pub med: Option<Med>,
    /// Whether this route was learned from an iBGP peer, eBGP peer, or
    /// locally originated.
    ///
    /// Used in best-path selection (RFC 4271 §9.1 steps 3 and 7) and iBGP
    /// split horizon enforcement. Defaults to [`PeerType::External`] when
    /// built with [`RouteBuilder`] without an explicit call to `.peer_type()`.
    pub peer_type: PeerType,
    /// Unix timestamp (seconds) when this route was first received or created.
    ///
    /// Stored as `u32` (saves 12 bytes vs `Instant`). Used for best-path
    /// step 9 (RFC 4271 §9.1): when two eBGP routes are otherwise equal,
    /// prefer the one received first (smaller value). Set automatically by
    /// [`RouteBuilder::build`]. Wraps in year 2106.
    pub received_at: u32,
    /// The BGP Identifier (router-id) of the peer this route was learned
    /// from, as advertised in that peer's OPEN message — `None` for locally
    /// originated routes or if the identifier isn't known for some other
    /// reason.
    ///
    /// Distinct from the peer's session/transport IP address (`PeerId`,
    /// tracked separately by the caller): a router's BGP Identifier is
    /// commonly a loopback address unrelated to the physical interface used
    /// for a given peering. Used in best-path step (f) (RFC 4271 §9.1.2.2):
    /// when routes are tied through every prior criterion, the route from
    /// the peer with the lowest BGP Identifier wins, evaluated *before* the
    /// final peer-IP-address tiebreak (step (g)). Set by
    /// [`RouteBuilder::peer_bgp_id`]; `None` skips step (f) and falls
    /// through directly to step (g).
    pub peer_bgp_id: Option<Ipv4Addr>,
    /// Infrequently-set attributes: communities, cluster list, aggregator, etc.
    ///
    /// `None` when all rare attributes are at their default values, saving
    /// ~96 bytes per route (four empty `Vec`s + padding) on the common path.
    pub rare: Option<Box<RareAttrs>>,
    /// RFC 4724 §4.2 — set when this route is being held during a peer's GR
    /// restart window.  Stale routes are de-preferred in best-path selection
    /// (non-stale beats stale before all other criteria), so a fresh alternate
    /// path from another peer wins immediately.  Cleared when the peer
    /// re-announces the route during re-establishment.  Never encoded on wire.
    pub stale: bool,
}

impl<A: IpAddress> Route<A> {
    /// Returns the rare attributes, or a static default if absent.
    #[inline]
    pub fn rare_or_default(&self) -> &RareAttrs {
        self.rare.as_deref().unwrap_or(&RARE_DEFAULT)
    }

    /// Returns a mutable reference to rare attributes, allocating the box if
    /// not yet present.
    #[inline]
    pub fn rare_mut(&mut self) -> &mut RareAttrs {
        self.rare.get_or_insert_with(Box::default)
    }
}

static RARE_DEFAULT: RareAttrs = RareAttrs {
    communities: Vec::new(),
    large_communities: Vec::new(),
    extended_communities: Vec::new(),
    cluster_list: Vec::new(),
    atomic_aggregate: false,
    aggregator: None,
    originator_id: None,
    otc: None,
};

impl<A: IpAddress> BgpRoute for Route<A> {
    type Addr = A;

    fn nlri(&self) -> Nlri<A> {
        self.nlri
    }
    fn origin(&self) -> Origin {
        self.origin
    }
    fn local_pref(&self) -> Option<LocalPref> {
        self.local_pref
    }
    fn med(&self) -> Option<Med> {
        self.med
    }
    fn as_path(&self) -> &AsPath {
        &self.as_path
    }
    fn communities(&self) -> &[Community] {
        &self.rare_or_default().communities
    }
    fn large_communities(&self) -> &[LargeCommunity] {
        &self.rare_or_default().large_communities
    }
    fn extended_communities(&self) -> &[ExtendedCommunity] {
        &self.rare_or_default().extended_communities
    }
    fn next_hop(&self) -> Option<NextHop> {
        self.next_hop
    }
    fn otc(&self) -> Option<Asn> {
        self.rare_or_default().otc
    }

    fn set_origin(&mut self, origin: Origin) {
        self.origin = origin;
    }
    fn set_local_pref(&mut self, lp: Option<LocalPref>) {
        self.local_pref = lp;
    }
    fn set_med(&mut self, med: Option<Med>) {
        self.med = med;
    }
    fn set_as_path(&mut self, path: AsPath) {
        self.as_path = Arc::new(path);
    }
    fn set_communities(&mut self, c: Vec<Community>) {
        if c.is_empty() {
            if let Some(r) = &mut self.rare {
                r.communities.clear();
            }
        } else {
            self.rare_mut().communities = c;
        }
    }
    fn set_large_communities(&mut self, c: Vec<LargeCommunity>) {
        if c.is_empty() {
            if let Some(r) = &mut self.rare {
                r.large_communities.clear();
            }
        } else {
            self.rare_mut().large_communities = c;
        }
    }
    fn set_extended_communities(&mut self, c: Vec<ExtendedCommunity>) {
        if c.is_empty() {
            if let Some(r) = &mut self.rare {
                r.extended_communities.clear();
            }
        } else {
            self.rare_mut().extended_communities = c;
        }
    }
    fn set_next_hop(&mut self, nh: Option<NextHop>) {
        self.next_hop = nh;
    }
    fn set_otc(&mut self, otc: Option<Asn>) {
        if otc.is_none() && self.rare.is_none() {
            return; // no allocation needed to represent "already absent"
        }
        self.rare_mut().otc = otc;
    }
}

fn shared_empty_as_path() -> Arc<AsPath> {
    static EMPTY: std::sync::OnceLock<Arc<AsPath>> = std::sync::OnceLock::new();
    Arc::clone(EMPTY.get_or_init(|| Arc::new(AsPath::new())))
}

fn now_unix_secs() -> u32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    u32::try_from(secs).unwrap_or(u32::MAX)
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
/// assert_eq!(route.rare_or_default().communities.len(), 1);
/// ```
pub struct RouteBuilder<A: IpAddress> {
    nlri: Nlri<A>,
    origin: Origin,
    as_path: Arc<AsPath>,
    next_hop: Option<NextHop>,
    local_pref: Option<LocalPref>,
    med: Option<Med>,
    peer_type: PeerType,
    received_at: u32,
    peer_bgp_id: Option<Ipv4Addr>,
    rare: Option<Box<RareAttrs>>,
}

impl<A: IpAddress> RouteBuilder<A> {
    /// Creates a builder with the three mandatory BGP attributes.
    ///
    /// `nlri` is the advertised prefix, `origin` describes how the route was
    /// introduced into BGP, and `as_path` is the sequence of ASes it has
    /// traversed.
    #[must_use]
    pub fn new(nlri: Nlri<A>, origin: Origin, as_path: AsPath) -> Self {
        let as_path = if as_path.is_empty() {
            shared_empty_as_path()
        } else {
            Arc::new(as_path)
        };
        Self {
            nlri,
            origin,
            as_path,
            next_hop: None,
            local_pref: None,
            med: None,
            peer_type: PeerType::External,
            received_at: now_unix_secs(),
            peer_bgp_id: None,
            rare: None,
        }
    }

    /// Creates a builder sharing an already-allocated `AsPath`.
    ///
    /// Use this in the UPDATE decode loop to share one `Arc<AsPath>` across all
    /// routes in the same UPDATE message instead of allocating per-NLRI.
    #[must_use]
    pub fn with_shared_as_path(nlri: Nlri<A>, origin: Origin, as_path: Arc<AsPath>) -> Self {
        Self {
            nlri,
            origin,
            as_path,
            next_hop: None,
            local_pref: None,
            med: None,
            peer_type: PeerType::External,
            received_at: now_unix_secs(),
            peer_bgp_id: None,
            rare: None,
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
        self.rare
            .get_or_insert_with(Box::default)
            .communities
            .push(c);
        self
    }

    /// Appends a large community.
    #[must_use]
    pub fn large_community(mut self, lc: LargeCommunity) -> Self {
        self.rare
            .get_or_insert_with(Box::default)
            .large_communities
            .push(lc);
        self
    }

    /// Appends an extended community.
    #[must_use]
    pub fn extended_community(mut self, ec: ExtendedCommunity) -> Self {
        self.rare
            .get_or_insert_with(Box::default)
            .extended_communities
            .push(ec);
        self
    }

    /// Sets the `ATOMIC_AGGREGATE` flag.
    #[must_use]
    pub fn atomic_aggregate(mut self) -> Self {
        self.rare.get_or_insert_with(Box::default).atomic_aggregate = true;
        self
    }

    /// Sets the `AGGREGATOR` attribute.
    #[must_use]
    pub fn aggregator(mut self, agg: Aggregator) -> Self {
        self.rare.get_or_insert_with(Box::default).aggregator = Some(agg);
        self
    }

    /// Sets the `ONLY_TO_CUSTOMER` attribute (RFC 9234 §3).
    #[must_use]
    pub fn otc(mut self, asn: Asn) -> Self {
        self.rare.get_or_insert_with(Box::default).otc = Some(asn);
        self
    }

    /// Sets the peer type (iBGP or eBGP) for this route.
    ///
    /// Defaults to [`PeerType::External`] if not called. Set to
    /// [`PeerType::Internal`] for routes received from an iBGP peer.
    #[must_use]
    pub fn peer_type(mut self, pt: PeerType) -> Self {
        self.peer_type = pt;
        self
    }

    /// Sets the BGP Identifier (router-id) of the peer this route was
    /// learned from, as advertised in that peer's OPEN message.
    ///
    /// Used in best-path step (f) (RFC 4271 §9.1.2.2) — see
    /// [`Route::peer_bgp_id`]. Leave unset (`None`) for locally originated
    /// routes.
    #[must_use]
    pub fn peer_bgp_id(mut self, id: Ipv4Addr) -> Self {
        self.peer_bgp_id = Some(id);
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
            peer_type: self.peer_type,
            received_at: self.received_at,
            peer_bgp_id: self.peer_bgp_id,
            rare: self.rare,
            stale: false,
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
        assert!(route.rare_or_default().communities.is_empty());
        assert!(!route.rare_or_default().atomic_aggregate);
        assert!(route.rare_or_default().aggregator.is_none());
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
        assert_eq!(route.rare_or_default().communities.len(), 1);
        assert!(route.rare_or_default().atomic_aggregate);
        assert!(route.rare_or_default().aggregator.is_some());
    }

    #[test]
    fn test_route_bgproute_getters() {
        use pathvector_policy::BgpRoute;
        use pathvector_types::{Asn, LocalPref};

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
        use pathvector_policy::BgpRoute;
        use pathvector_types::{Asn, LocalPref};

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
    fn test_route_builder_otc_defaults_to_none_and_lazily_allocates() {
        use pathvector_types::Asn;

        let bare = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new()).build();
        assert!(
            bare.rare.is_none(),
            "no rare attrs set — box stays unallocated"
        );
        assert_eq!(bare.rare_or_default().otc, None);

        let with_otc = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .otc(Asn::new(65001))
            .build();
        assert_eq!(with_otc.rare_or_default().otc, Some(Asn::new(65001)));
    }

    #[test]
    fn test_route_bgproute_otc_getter_and_setter() {
        use pathvector_policy::BgpRoute;
        use pathvector_types::Asn;

        let mut route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new()).build();
        assert_eq!(route.otc(), None);

        route.set_otc(Some(Asn::new(65099)));
        assert_eq!(route.otc(), Some(Asn::new(65099)));

        route.set_otc(None);
        assert_eq!(route.otc(), None);
    }

    #[test]
    fn test_route_set_otc_none_on_unallocated_rare_does_not_allocate() {
        use pathvector_policy::BgpRoute;

        let mut route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new()).build();
        assert!(route.rare.is_none());
        route.set_otc(None);
        assert!(
            route.rare.is_none(),
            "setting OTC to None on a route with no rare attrs must not allocate"
        );
    }

    #[test]
    fn test_route_builder_large_and_extended_community() {
        use pathvector_types::{ExtendedCommunity, LargeCommunity};

        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .large_community(LargeCommunity::new(65000, 1, 100))
            .large_community(LargeCommunity::new(65001, 2, 200))
            .extended_community(ExtendedCommunity::route_target_as2(65000, 1))
            .build();

        assert_eq!(route.rare_or_default().large_communities.len(), 2);
        assert_eq!(route.rare_or_default().extended_communities.len(), 1);
    }

    #[test]
    fn test_route_bgproute_remaining_getters() {
        use pathvector_policy::BgpRoute;
        use pathvector_types::{ExtendedCommunity, LargeCommunity, Med, NextHop};

        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .med(Med::new(50))
            .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .community(pathvector_types::Community::from_parts(65000, 100))
            .large_community(LargeCommunity::new(65000, 1, 2))
            .extended_community(ExtendedCommunity::route_target_as2(65000, 1))
            .build();

        assert_eq!(route.med(), Some(Med::new(50)));
        assert_eq!(
            route.next_hop(),
            Some(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(route.communities().len(), 1);
        assert_eq!(route.large_communities().len(), 1);
        assert_eq!(route.extended_communities().len(), 1);
    }

    #[test]
    fn test_route_bgproute_remaining_setters() {
        use pathvector_policy::BgpRoute;
        use pathvector_types::{Community, ExtendedCommunity, LargeCommunity, Med, NextHop};

        let mut route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new()).build();

        route.set_med(Some(Med::new(100)));
        assert_eq!(route.med(), Some(Med::new(100)));

        route.set_med(None);
        assert_eq!(route.med(), None);

        route.set_next_hop(Some(NextHop::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(
            route.next_hop(),
            Some(NextHop::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );

        route.set_next_hop(None);
        assert_eq!(route.next_hop(), None);

        route.set_communities(vec![Community::from_parts(65000, 1)]);
        assert_eq!(route.communities().len(), 1);

        route.set_large_communities(vec![LargeCommunity::new(65000, 1, 2)]);
        assert_eq!(route.large_communities().len(), 1);

        route.set_extended_communities(vec![ExtendedCommunity::route_target_as2(65000, 1)]);
        assert_eq!(route.extended_communities().len(), 1);
    }

    #[test]
    fn test_route_clone() {
        let original = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new()).build();
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }
}
