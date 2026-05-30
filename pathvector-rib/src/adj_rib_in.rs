use std::collections::HashMap;

use ipnetx::interfaces::IpAddress;
use pathvector_types::Nlri;

use crate::{peer::PeerId, route::Route};

/// Per-peer inbound routing table — routes exactly as received, before policy.
///
/// `AdjRibIn` stores one route per prefix per peer. When a BGP UPDATE arrives,
/// the session layer writes the advertised routes here and removes withdrawn
/// ones. Import policy is applied *outside* this table — after the caller
/// reads routes from here, it applies policy and inserts the accepted routes
/// into [`LocRib`](crate::LocRib).
///
/// Storing the pre-policy routes separately from the post-policy [`LocRib`]
/// is what makes soft reconfiguration possible: if you change your import
/// policy, you re-process the `AdjRibIn` without asking the peer to
/// re-advertise.
///
/// # Examples
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr};
/// use pathvector_rib::{AdjRibIn, PeerId, RouteBuilder};
/// use pathvector_types::{AsPath, Nlri, Origin};
///
/// let peer = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
/// let mut rib: AdjRibIn<Ipv4Addr> = AdjRibIn::new(peer);
///
/// let nlri: Nlri<Ipv4Addr> = "192.168.1.0/24".parse().unwrap();
/// let route = RouteBuilder::new(nlri, Origin::Igp, AsPath::new()).build();
///
/// rib.insert(route);
/// assert_eq!(rib.len(), 1);
///
/// rib.withdraw(&nlri);
/// assert!(rib.is_empty());
/// ```
pub struct AdjRibIn<A: IpAddress> {
    peer: PeerId,
    routes: HashMap<Nlri<A>, Route<A>>,
}

impl<A: IpAddress> AdjRibIn<A> {
    /// Creates an empty `AdjRibIn` for the given peer.
    #[must_use]
    pub fn new(peer: PeerId) -> Self {
        Self { peer, routes: HashMap::new() }
    }

    /// Returns the peer this table belongs to.
    #[must_use]
    pub fn peer(&self) -> PeerId {
        self.peer
    }

    /// Inserts or replaces a route.
    ///
    /// If the peer previously advertised a different route for this prefix,
    /// the old route is replaced and returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr};
    /// use pathvector_rib::{AdjRibIn, PeerId, RouteBuilder};
    /// use pathvector_types::{AsPath, Nlri, Origin};
    ///
    /// let peer = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    /// let mut rib: AdjRibIn<Ipv4Addr> = AdjRibIn::new(peer);
    ///
    /// let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
    /// let old = rib.insert(RouteBuilder::new(nlri, Origin::Igp, AsPath::new()).build());
    /// assert!(old.is_none());
    /// ```
    pub fn insert(&mut self, route: Route<A>) -> Option<Route<A>> {
        self.routes.insert(route.nlri, route)
    }

    /// Removes the route for a prefix and returns it, if present.
    ///
    /// Called when the peer sends a WITHDRAW for this prefix.
    pub fn withdraw(&mut self, nlri: &Nlri<A>) -> Option<Route<A>> {
        self.routes.remove(nlri)
    }

    /// Returns the route for a prefix, if present.
    #[must_use]
    pub fn get(&self, nlri: &Nlri<A>) -> Option<&Route<A>> {
        self.routes.get(nlri)
    }

    /// Iterates over all `(prefix, route)` pairs in this table.
    pub fn routes(&self) -> impl Iterator<Item = (&Nlri<A>, &Route<A>)> {
        self.routes.iter()
    }

    /// Returns the number of prefixes in this table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Returns `true` if this table contains no routes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use pathvector_types::{AsPath, Asn, LocalPref, Origin};

    fn peer() -> PeerId {
        PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    }

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn route(prefix: &str) -> Route<Ipv4Addr> {
        crate::RouteBuilder::new(nlri(prefix), Origin::Igp, AsPath::new()).build()
    }

    #[test]
    fn test_adj_rib_in_new() {
        let rib: AdjRibIn<Ipv4Addr> = AdjRibIn::new(peer());
        assert!(rib.is_empty());
        assert_eq!(rib.len(), 0);
        assert_eq!(rib.peer(), peer());
    }

    #[test]
    fn test_adj_rib_in_insert_and_get() {
        let mut rib: AdjRibIn<Ipv4Addr> = AdjRibIn::new(peer());
        let n = nlri("10.0.0.0/8");
        rib.insert(route("10.0.0.0/8"));
        assert_eq!(rib.len(), 1);
        assert!(rib.get(&n).is_some());
    }

    #[test]
    fn test_adj_rib_in_insert_returns_old() {
        use crate::RouteBuilder;
        let mut rib: AdjRibIn<Ipv4Addr> = AdjRibIn::new(peer());
        let n = nlri("10.0.0.0/8");

        let old = rib.insert(RouteBuilder::new(n, Origin::Igp, AsPath::new()).build());
        assert!(old.is_none());

        let old = rib.insert(
            RouteBuilder::new(n, Origin::Igp, AsPath::new())
                .local_pref(LocalPref::new(200))
                .build(),
        );
        assert!(old.is_some());
        assert_eq!(old.unwrap().local_pref, None); // replaced the one without LP
    }

    #[test]
    fn test_adj_rib_in_withdraw() {
        let mut rib: AdjRibIn<Ipv4Addr> = AdjRibIn::new(peer());
        let n = nlri("10.0.0.0/8");
        rib.insert(route("10.0.0.0/8"));

        let withdrawn = rib.withdraw(&n);
        assert!(withdrawn.is_some());
        assert!(rib.is_empty());
    }

    #[test]
    fn test_adj_rib_in_withdraw_absent() {
        let mut rib: AdjRibIn<Ipv4Addr> = AdjRibIn::new(peer());
        let n = nlri("10.0.0.0/8");
        assert!(rib.withdraw(&n).is_none());
    }

    #[test]
    fn test_adj_rib_in_multiple_prefixes() {
        let mut rib: AdjRibIn<Ipv4Addr> = AdjRibIn::new(peer());
        rib.insert(route("10.0.0.0/8"));
        rib.insert(route("192.168.0.0/16"));
        rib.insert(route("172.16.0.0/12"));
        assert_eq!(rib.len(), 3);
    }

    #[test]
    fn test_adj_rib_in_routes_iterator() {
        let mut rib: AdjRibIn<Ipv4Addr> = AdjRibIn::new(peer());
        rib.insert(route("10.0.0.0/8"));
        rib.insert(route("192.168.0.0/16"));
        assert_eq!(rib.routes().count(), 2);
    }

    #[test]
    fn test_adj_rib_in_same_prefix_different_asn_in_path() {
        use crate::RouteBuilder;
        let mut rib: AdjRibIn<Ipv4Addr> = AdjRibIn::new(peer());
        let n = nlri("10.0.0.0/8");

        rib.insert(
            RouteBuilder::new(n, Origin::Igp, AsPath::from_sequence(vec![Asn::new(65001)])).build(),
        );
        rib.insert(
            RouteBuilder::new(n, Origin::Igp, AsPath::from_sequence(vec![Asn::new(65002)])).build(),
        );

        // Still only one route — same prefix, second overwrites first
        assert_eq!(rib.len(), 1);
        assert_eq!(
            rib.get(&n).unwrap().as_path.origin_as(),
            Some(Asn::new(65002))
        );
    }
}
