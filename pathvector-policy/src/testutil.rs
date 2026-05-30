use std::net::Ipv4Addr;
use pathvector_types::{
    AsPath, Community, ExtendedCommunity, LargeCommunity, LocalPref, Med, NextHop, Nlri, Origin,
};
use crate::route::BgpRoute;

/// A minimal IPv4 BGP route used exclusively in tests.
///
/// This type implements [`BgpRoute`] so that conditions and actions can be
/// tested without depending on `pathvector-rib`. It stores every standard
/// BGP attribute as a plain field — no encoding, no wire format.
pub struct TestRoute {
    pub nlri: Nlri<Ipv4Addr>,
    pub origin: Origin,
    pub local_pref: Option<LocalPref>,
    pub med: Option<Med>,
    pub as_path: AsPath,
    pub communities: Vec<Community>,
    pub large_communities: Vec<LargeCommunity>,
    pub extended_communities: Vec<ExtendedCommunity>,
    pub next_hop: Option<NextHop>,
}

impl TestRoute {
    /// Creates a minimal test route for the given CIDR prefix string.
    ///
    /// Defaults: ORIGIN IGP, no LOCAL_PREF, no MED, empty AS path,
    /// no communities, no NEXT_HOP.
    pub fn new(prefix: &str) -> Self {
        Self {
            nlri: prefix.parse().expect("invalid test prefix"),
            origin: Origin::Igp,
            local_pref: None,
            med: None,
            as_path: AsPath::new(),
            communities: Vec::new(),
            large_communities: Vec::new(),
            extended_communities: Vec::new(),
            next_hop: None,
        }
    }

    /// Creates a test route whose prefix has unmasked host bits.
    ///
    /// Used to verify that conditions correctly call `.masked()` before
    /// comparing network addresses.
    pub fn with_nlri_ip(prefix: &str) -> Self {
        Self::new(prefix)
    }
}

impl BgpRoute for TestRoute {
    type Addr = Ipv4Addr;

    fn nlri(&self) -> Nlri<Self::Addr> { self.nlri }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BgpRoute;

    #[test]
    fn test_testroute_next_hop_getter() {
        use std::net::Ipv4Addr;
        let mut route = TestRoute::new("10.0.0.0/8");
        assert_eq!(route.next_hop(), None);
        route.next_hop = Some(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(route.next_hop().is_some());
    }

    #[test]
    fn test_testroute_extended_communities() {
        let mut route = TestRoute::new("10.0.0.0/8");
        assert!(route.extended_communities().is_empty());
        let ec = ExtendedCommunity::route_target_as2(65000, 1);
        route.set_extended_communities(vec![ec]);
        assert_eq!(route.extended_communities(), &[ec]);
    }
}
