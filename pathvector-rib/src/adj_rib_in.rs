use ahash::AHashMap;
use ipnetx::interfaces::IpAddress;
use pathvector_types::Nlri;

use crate::{
    peer::PeerId,
    route::{Route, Staleness},
};

/// Per-peer inbound routing table — routes exactly as received, before policy.
///
/// `AdjRibIn` stores one route per prefix per peer. When a BGP UPDATE arrives,
/// the session layer writes the advertised routes here and removes withdrawn
/// ones. Import policy is applied *outside* this table — after the caller
/// reads routes from here, it applies policy and inserts the accepted routes
/// into [`LocRib`](crate::LocRib).
///
/// Storing the pre-policy routes separately from the post-policy [`LocRib`](crate::LocRib)
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
#[derive(Clone)]
pub struct AdjRibIn<A: IpAddress> {
    peer: PeerId,
    routes: AHashMap<Nlri<A>, Route<A>>,
}

impl<A: IpAddress> AdjRibIn<A> {
    /// Creates an empty `AdjRibIn` for the given peer.
    #[must_use]
    pub fn new(peer: PeerId) -> Self {
        Self {
            peer,
            routes: AHashMap::new(),
        }
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

    /// Marks all held routes [`Staleness::GrStale`] (RFC 4724 §4.2) and
    /// returns clones for `LocRib` re-insertion.
    ///
    /// Called when a Graceful-Restart-capable peer's session ends while GR
    /// is in effect: the Receiving Speaker "MUST retain the routes received
    /// from the peer [...] and MUST mark them as stale routing information".
    /// Re-inserting the returned routes keeps the `LocRib` copies' staleness
    /// in step with this table; it does **not** change their preference — a
    /// conventional-GR stale route competes on its attributes as before
    /// (RFC 9494 §1: "in conventional GR, route preference is not
    /// affected"). Stale routes leave by replacement (an ordinary
    /// [`insert`](Self::insert) of the re-announced route), by the
    /// End-of-RIB sweep, or by Restart Time expiry — all driven by the
    /// caller.
    pub fn mark_all_stale(&mut self) -> Vec<Route<A>> {
        self.routes
            .values_mut()
            .map(|r| {
                r.staleness = Staleness::GrStale;
                r.clone()
            })
            .collect()
    }

    /// Removes all routes from this table.
    ///
    /// Called when the peer session terminates. The `AdjRibIn` is kept in
    /// place so it can be repopulated when the session re-establishes, without
    /// requiring a new allocation.
    pub fn clear(&mut self) {
        self.routes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathvector_types::{AsPath, Asn, LocalPref, Origin};
    use std::net::{IpAddr, Ipv4Addr};

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
    fn test_adj_rib_in_clear() {
        let mut rib: AdjRibIn<Ipv4Addr> = AdjRibIn::new(peer());
        rib.insert(route("10.0.0.0/8"));
        rib.insert(route("192.168.0.0/16"));
        assert_eq!(rib.len(), 2);
        rib.clear();
        assert!(rib.is_empty());
        assert_eq!(rib.peer(), peer()); // peer identity preserved
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
            rib.get(&n).unwrap().as_path.origin_as(Asn::new(65000)),
            Some(Asn::new(65002))
        );
    }

    /// RFC 4724 §4.2: the Receiving Speaker "MUST retain the routes [...] and
    /// MUST mark them as stale" — every held route becomes `GrStale` with
    /// its attributes untouched, and the returned copies match the table.
    #[test]
    fn test_mark_all_stale_marks_every_route_and_keeps_attributes() {
        let mut rib: AdjRibIn<Ipv4Addr> = AdjRibIn::new(peer());
        let preferred = crate::RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(300))
            .build();
        rib.insert(preferred.clone());
        rib.insert(route("172.16.0.0/12"));

        let mut marked = rib.mark_all_stale();
        marked.sort_by_key(|r| r.nlri.to_string());

        assert_eq!(marked.len(), 2);
        assert!(rib.routes().all(|(_, r)| r.staleness == Staleness::GrStale));
        for r in &marked {
            assert_eq!(r.staleness, Staleness::GrStale);
            assert_eq!(rib.get(&r.nlri), Some(r), "returned copy matches the table");
        }
        let mut expected = preferred;
        expected.staleness = Staleness::GrStale;
        assert_eq!(rib.get(&nlri("10.0.0.0/8")), Some(&expected));
    }

    /// RFC 4724 §4.2: "The Receiving Speaker MUST replace the stale routes by
    /// the routing updates received from the peer." A re-announcement is an
    /// ordinary insert of a fresh route; it replaces the stale entry.
    #[test]
    fn test_reannouncement_replaces_stale_route_with_fresh_one() {
        let mut rib: AdjRibIn<Ipv4Addr> = AdjRibIn::new(peer());
        rib.insert(route("10.0.0.0/8"));
        rib.mark_all_stale();

        let old = rib.insert(route("10.0.0.0/8")).expect("replaced");
        assert_eq!(old.staleness, Staleness::GrStale);
        assert_eq!(
            rib.get(&nlri("10.0.0.0/8")).map(|r| r.staleness),
            Some(Staleness::Fresh)
        );
    }
}
