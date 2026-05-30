use std::collections::HashMap;

use ipnetx::interfaces::IpAddress;
use pathvector_types::Nlri;

use crate::{peer::PeerId, route::Route};

/// Per-peer outbound routing table — best routes after export policy.
///
/// `AdjRibOut` records what will be (or has been) advertised to a specific
/// peer. The caller reads best routes from [`LocRib`](crate::LocRib), applies
/// export policy (next-hop rewrite, community stripping, attribute
/// modification), and inserts the accepted routes here.
///
/// Maintaining a separate per-peer outbound table makes it straightforward
/// to compute route change messages: compare the new best route against what
/// is already in `AdjRibOut` — if it changed, send an UPDATE; if it was
/// removed, send a WITHDRAW.
///
/// # Examples
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr};
/// use pathvector_rib::{AdjRibOut, PeerId, RouteBuilder};
/// use pathvector_types::{AsPath, Nlri, Origin};
///
/// let peer = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
/// let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(peer);
///
/// let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
/// rib.insert(RouteBuilder::new(nlri, Origin::Igp, AsPath::new()).build());
/// assert_eq!(rib.len(), 1);
/// ```
pub struct AdjRibOut<A: IpAddress> {
    peer: PeerId,
    routes: HashMap<Nlri<A>, Route<A>>,
}

impl<A: IpAddress> AdjRibOut<A> {
    /// Creates an empty `AdjRibOut` for the given peer.
    #[must_use]
    pub fn new(peer: PeerId) -> Self {
        Self { peer, routes: HashMap::new() }
    }

    /// Returns the peer this outbound table belongs to.
    #[must_use]
    pub fn peer(&self) -> PeerId {
        self.peer
    }

    /// Inserts or replaces a route.
    ///
    /// Returns the previous route for this prefix, if one existed.
    /// A `Some` return value means an UPDATE message should be sent to the
    /// peer (the route changed); a `None` return means this is a new prefix
    /// announcement.
    pub fn insert(&mut self, route: Route<A>) -> Option<Route<A>> {
        self.routes.insert(route.nlri, route)
    }

    /// Removes the route for a prefix and returns it, if present.
    ///
    /// A `Some` return value means a WITHDRAW message should be sent to the
    /// peer.
    pub fn withdraw(&mut self, nlri: &Nlri<A>) -> Option<Route<A>> {
        self.routes.remove(nlri)
    }

    /// Returns the route currently advertised for `nlri`, if any.
    #[must_use]
    pub fn get(&self, nlri: &Nlri<A>) -> Option<&Route<A>> {
        self.routes.get(nlri)
    }

    /// Iterates over all `(prefix, route)` pairs being advertised to this peer.
    pub fn routes(&self) -> impl Iterator<Item = (&Nlri<A>, &Route<A>)> {
        self.routes.iter()
    }

    /// Returns the number of prefixes currently being advertised.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Returns `true` if no routes are being advertised to this peer.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use pathvector_types::{AsPath, LocalPref, Origin};
    use crate::RouteBuilder;

    fn peer() -> PeerId {
        PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
    }

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn route(prefix: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(nlri(prefix), Origin::Igp, AsPath::new()).build()
    }

    #[test]
    fn test_adj_rib_out_new() {
        let rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(peer());
        assert!(rib.is_empty());
        assert_eq!(rib.peer(), peer());
    }

    #[test]
    fn test_adj_rib_out_insert_and_get() {
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(peer());
        let n = nlri("10.0.0.0/8");
        rib.insert(route("10.0.0.0/8"));
        assert!(rib.get(&n).is_some());
        assert_eq!(rib.len(), 1);
    }

    #[test]
    fn test_adj_rib_out_insert_returns_old() {
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(peer());
        let n = nlri("10.0.0.0/8");

        let old = rib.insert(RouteBuilder::new(n, Origin::Igp, AsPath::new()).build());
        assert!(old.is_none()); // first insert: no prior route

        let old = rib.insert(
            RouteBuilder::new(n, Origin::Igp, AsPath::new())
                .local_pref(LocalPref::new(200))
                .build(),
        );
        assert!(old.is_some()); // second insert: replaced prior route
    }

    #[test]
    fn test_adj_rib_out_withdraw() {
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(peer());
        let n = nlri("10.0.0.0/8");
        rib.insert(route("10.0.0.0/8"));

        let removed = rib.withdraw(&n);
        assert!(removed.is_some());
        assert!(rib.is_empty());
    }

    #[test]
    fn test_adj_rib_out_withdraw_absent() {
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(peer());
        assert!(rib.withdraw(&nlri("10.0.0.0/8")).is_none());
    }

    #[test]
    fn test_adj_rib_out_routes_iterator() {
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(peer());
        rib.insert(route("10.0.0.0/8"));
        rib.insert(route("192.168.0.0/16"));
        assert_eq!(rib.routes().count(), 2);
    }
}
