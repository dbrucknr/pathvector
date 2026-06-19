use std::sync::Arc;

use ahash::AHashMap;

use ipnetx::interfaces::IpAddress;
use pathvector_types::{Nlri, PeerType};

use crate::{peer::PeerId, route::Route};

/// Outcome of [`AdjRibOut::insert`].
///
/// The caller uses this to drive UPDATE/WITHDRAW decisions:
///
/// - [`Accepted`](InsertOutcome::Accepted) — the route was stored; send an
///   UPDATE if the inner value differs from what was advertised before, or a
///   new announcement if it is `None`.
/// - [`Filtered`](InsertOutcome::Filtered) — iBGP split horizon suppressed
///   the route (RFC 4271 §9.2).  If the inner value is `Some`, a previously
///   advertised route was removed and a WITHDRAW must be sent.
#[derive(Debug)]
pub enum InsertOutcome<A: IpAddress> {
    /// Route accepted and stored. Contains the route previously stored for
    /// this prefix, if any.
    Accepted(Option<Route<A>>),
    /// Route rejected by iBGP split horizon. Contains any previously stored
    /// route that was evicted and must be withdrawn from the peer.
    Filtered(Option<Route<A>>),
}

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
/// # iBGP split horizon
///
/// Routes learned from an iBGP peer are never re-advertised to another iBGP
/// peer (RFC 4271 §9.2). `AdjRibOut::insert` enforces this automatically:
/// when the receiving peer is `Internal` and the route's [`PeerType`] is also
/// `Internal`, the route is suppressed and [`InsertOutcome::Filtered`] is
/// returned instead of `Accepted`.
///
/// # Confederation segment stripping
///
/// When the receiving peer is `External`, `AS_CONFED_SEQUENCE` and
/// `AS_CONFED_SET` segments are stripped from the `AS_PATH` before the route
/// is stored (RFC 5065 §5.1).
///
/// # Examples
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr};
/// use pathvector_rib::{AdjRibOut, InsertOutcome, PeerId, RouteBuilder};
/// use pathvector_types::{AsPath, Nlri, Origin, PeerType};
///
/// let peer = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
/// let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(peer, PeerType::External);
///
/// let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
/// let outcome = rib.insert(RouteBuilder::new(nlri, Origin::Igp, AsPath::new()).build());
/// assert!(matches!(outcome, InsertOutcome::Accepted(None)));
/// assert_eq!(rib.len(), 1);
/// ```
#[derive(Clone)]
pub struct AdjRibOut<A: IpAddress> {
    peer: PeerId,
    peer_type: PeerType,
    /// When `true`, the iBGP split-horizon check in [`insert`](AdjRibOut::insert)
    /// is bypassed. Set for Route Reflector destinations (RFC 4456) where the
    /// caller has already enforced the correct split-horizon at the propagation
    /// level.
    reflects: bool,
    routes: AHashMap<Nlri<A>, Route<A>>,
}

impl<A: IpAddress> AdjRibOut<A> {
    /// Creates an empty `AdjRibOut` for the given peer.
    #[must_use]
    pub fn new(peer: PeerId, peer_type: PeerType) -> Self {
        Self {
            peer,
            peer_type,
            reflects: false,
            routes: AHashMap::new(),
        }
    }

    /// Creates an `AdjRibOut` that bypasses iBGP split-horizon.
    ///
    /// Use this for peers that receive reflected routes in an RFC 4456 Route
    /// Reflector topology. The caller is responsible for enforcing the correct
    /// RR split-horizon rules (non-client→non-client blocking) before calling
    /// [`insert`](AdjRibOut::insert).
    #[must_use]
    pub fn new_reflecting(peer: PeerId, peer_type: PeerType) -> Self {
        Self {
            peer,
            peer_type,
            reflects: true,
            routes: AHashMap::new(),
        }
    }

    /// Returns `true` if this table was created in RR reflecting mode.
    #[must_use]
    pub fn reflects(&self) -> bool {
        self.reflects
    }

    /// Returns the peer this outbound table belongs to.
    #[must_use]
    pub fn peer(&self) -> PeerId {
        self.peer
    }

    /// Returns whether this peer is iBGP or eBGP.
    #[must_use]
    pub fn peer_type(&self) -> PeerType {
        self.peer_type
    }

    /// Inserts or replaces a route, enforcing iBGP split horizon and
    /// confederation segment stripping.
    ///
    /// Returns [`InsertOutcome::Filtered`] when iBGP split horizon suppresses
    /// the route (both this peer and the route source are `Internal`).  The
    /// inner `Option` carries any previously stored route that must now be
    /// withdrawn from the peer.
    ///
    /// Returns [`InsertOutcome::Accepted`] otherwise.  For eBGP peers,
    /// `AS_CONFED_SEQUENCE` and `AS_CONFED_SET` segments are stripped from the
    /// route's `AS_PATH` before it is stored (RFC 5065 §5.1).  The inner
    /// `Option` is the previous route for this prefix, if any.
    pub fn insert(&mut self, route: Route<A>) -> InsertOutcome<A> {
        if !self.reflects
            && self.peer_type == PeerType::Internal
            && route.peer_type == PeerType::Internal
        {
            return InsertOutcome::Filtered(self.routes.remove(&route.nlri));
        }

        let mut route = route;
        if self.peer_type == PeerType::External {
            route.as_path = Arc::new(route.as_path.strip_confed_segments());
        }

        InsertOutcome::Accepted(self.routes.insert(route.nlri, route))
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
    use crate::RouteBuilder;
    use pathvector_types::{AsPath, AsPathSegment, Asn, LocalPref, Origin};
    use std::net::{IpAddr, Ipv4Addr};

    fn ebgp_peer() -> PeerId {
        PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
    }

    fn ibgp_peer() -> PeerId {
        PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)))
    }

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn ebgp_route(prefix: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(nlri(prefix), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .build()
    }

    fn ibgp_route(prefix: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(nlri(prefix), Origin::Igp, AsPath::new())
            .peer_type(PeerType::Internal)
            .build()
    }

    // ── basic operations ──────────────────────────────────────────────────────

    #[test]
    fn test_adj_rib_out_new() {
        let rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(ebgp_peer(), PeerType::External);
        assert!(rib.is_empty());
        assert_eq!(rib.peer(), ebgp_peer());
        assert_eq!(rib.peer_type(), PeerType::External);
    }

    #[test]
    fn test_adj_rib_out_insert_and_get() {
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(ebgp_peer(), PeerType::External);
        let n = nlri("10.0.0.0/8");
        rib.insert(ebgp_route("10.0.0.0/8"));
        assert!(rib.get(&n).is_some());
        assert_eq!(rib.len(), 1);
    }

    #[test]
    fn test_adj_rib_out_insert_returns_old() {
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(ebgp_peer(), PeerType::External);
        let n = nlri("10.0.0.0/8");

        let outcome = rib.insert(RouteBuilder::new(n, Origin::Igp, AsPath::new()).build());
        assert!(matches!(outcome, InsertOutcome::Accepted(None)));

        let outcome = rib.insert(
            RouteBuilder::new(n, Origin::Igp, AsPath::new())
                .local_pref(LocalPref::new(200))
                .build(),
        );
        assert!(matches!(outcome, InsertOutcome::Accepted(Some(_))));
    }

    #[test]
    fn test_adj_rib_out_withdraw() {
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(ebgp_peer(), PeerType::External);
        let n = nlri("10.0.0.0/8");
        rib.insert(ebgp_route("10.0.0.0/8"));

        let removed = rib.withdraw(&n);
        assert!(removed.is_some());
        assert!(rib.is_empty());
    }

    #[test]
    fn test_adj_rib_out_withdraw_absent() {
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(ebgp_peer(), PeerType::External);
        assert!(rib.withdraw(&nlri("10.0.0.0/8")).is_none());
    }

    #[test]
    fn test_adj_rib_out_routes_iterator() {
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(ebgp_peer(), PeerType::External);
        rib.insert(ebgp_route("10.0.0.0/8"));
        rib.insert(ebgp_route("192.168.0.0/16"));
        assert_eq!(rib.routes().count(), 2);
    }

    // ── iBGP split horizon (RFC 4271 §9.2) ───────────────────────────────────

    #[test]
    fn test_ibgp_route_not_advertised_to_ibgp_peer() {
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(ibgp_peer(), PeerType::Internal);
        let outcome = rib.insert(ibgp_route("10.0.0.0/8"));
        assert!(matches!(outcome, InsertOutcome::Filtered(None)));
        assert!(rib.is_empty());
    }

    #[test]
    fn test_ibgp_split_horizon_evicts_previously_stored_route() {
        // A route was initially eBGP-learned (stored). The best route is now
        // iBGP-learned — the previously stored route must be withdrawn.
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(ibgp_peer(), PeerType::Internal);
        let n = nlri("10.0.0.0/8");

        let prior = RouteBuilder::new(n, Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .build();
        rib.insert(prior);
        assert_eq!(rib.len(), 1);

        let outcome = rib.insert(ibgp_route("10.0.0.0/8"));
        assert!(matches!(outcome, InsertOutcome::Filtered(Some(_))));
        assert!(rib.is_empty()); // prior route evicted
    }

    #[test]
    fn test_ebgp_route_advertised_to_ibgp_peer() {
        // eBGP-learned routes may be sent to iBGP peers.
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(ibgp_peer(), PeerType::Internal);
        let outcome = rib.insert(ebgp_route("10.0.0.0/8"));
        assert!(matches!(outcome, InsertOutcome::Accepted(_)));
        assert_eq!(rib.len(), 1);
    }

    #[test]
    fn test_ibgp_route_advertised_to_ebgp_peer() {
        // iBGP-learned routes may be sent to eBGP peers (no split horizon there).
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(ebgp_peer(), PeerType::External);
        let outcome = rib.insert(ibgp_route("10.0.0.0/8"));
        assert!(matches!(outcome, InsertOutcome::Accepted(_)));
        assert_eq!(rib.len(), 1);
    }

    // ── confederation segment stripping (RFC 5065 §5.1) ──────────────────────

    #[test]
    fn test_confed_segments_stripped_for_ebgp_peer() {
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(ebgp_peer(), PeerType::External);

        let path = AsPath::from_segments(vec![
            AsPathSegment::ConfedSequence(vec![Asn::new(65100), Asn::new(65101)]),
            AsPathSegment::Sequence(vec![Asn::new(65001), Asn::new(65002)]),
        ]);
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, path).build();
        rib.insert(route);

        let stored = rib.get(&nlri("10.0.0.0/8")).unwrap();
        // Confederation segments stripped; only the regular sequence remains.
        assert_eq!(stored.as_path.path_length(), 2);
        for seg in stored.as_path.segments() {
            assert!(
                !matches!(
                    seg,
                    AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_)
                ),
                "confed segment survived eBGP advertisement"
            );
        }
    }

    #[test]
    fn test_confed_segments_preserved_for_ibgp_peer() {
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(ibgp_peer(), PeerType::Internal);

        let path = AsPath::from_segments(vec![
            AsPathSegment::ConfedSequence(vec![Asn::new(65100)]),
            AsPathSegment::Sequence(vec![Asn::new(65001)]),
        ]);
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, path)
            .peer_type(PeerType::External)
            .build();
        rib.insert(route);

        let stored = rib.get(&nlri("10.0.0.0/8")).unwrap();
        // Confederation segments must survive for iBGP peers.
        let has_confed = stored
            .as_path
            .segments()
            .iter()
            .any(|s| matches!(s, AsPathSegment::ConfedSequence(_)));
        assert!(has_confed);
    }

    #[test]
    fn test_all_confed_path_stripped_to_empty_for_ebgp_peer() {
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(ebgp_peer(), PeerType::External);

        let path = AsPath::from_segments(vec![AsPathSegment::ConfedSequence(vec![
            Asn::new(65100),
            Asn::new(65101),
        ])]);
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, path).build();
        rib.insert(route);

        let stored = rib.get(&nlri("10.0.0.0/8")).unwrap();
        assert_eq!(stored.as_path.path_length(), 0);
        assert!(stored.as_path.segments().is_empty());
    }

    #[test]
    fn test_no_confed_path_unmodified_for_ebgp_peer() {
        let mut rib: AdjRibOut<Ipv4Addr> = AdjRibOut::new(ebgp_peer(), PeerType::External);

        let path = AsPath::from_sequence(vec![Asn::new(65001), Asn::new(65002)]);
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, path).build();
        rib.insert(route);

        let stored = rib.get(&nlri("10.0.0.0/8")).unwrap();
        assert_eq!(stored.as_path.path_length(), 2);
    }
}
