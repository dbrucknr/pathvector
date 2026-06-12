use std::net::Ipv4Addr;

use pathvector_types::{Asn, NextHop, PeerType};

use crate::Route;

/// Applies eBGP outbound transforms to a route clone before insertion into
/// `AdjRibOut` or serialisation into an UPDATE message:
///
/// - Prepend local AS to `AS_PATH` (RFC 4271 §9.2.1.2)
/// - Rewrite `NEXT_HOP` to the local BGP identifier (RFC 4271 §5.1.3)
/// - Strip `LOCAL_PREF` (RFC 4271 §5.1.5 — must not be sent to eBGP peers)
///
/// iBGP peers receive the route unmodified; confederation segment stripping
/// for eBGP is handled separately by `AdjRibOut::insert`.
#[must_use]
pub fn prepare_outbound(
    mut route: Route<Ipv4Addr>,
    peer_type: PeerType,
    local_as: u32,
    local_bgp_id: Ipv4Addr,
) -> Route<Ipv4Addr> {
    if peer_type == PeerType::External {
        route.as_path.prepend(Asn::new(local_as));
        route.next_hop = Some(NextHop::V4(local_bgp_id));
        route.local_pref = None;
    }
    route
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RouteBuilder;
    use pathvector_types::{AsPath, LocalPref, Nlri, Origin};

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    #[test]
    fn test_prepare_outbound_ebgp_transforms_route() {
        let local_as = 65000_u32;
        let local_bgp_id = Ipv4Addr::new(10, 0, 0, 1);
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(100))
            .build();

        let out = prepare_outbound(route, PeerType::External, local_as, local_bgp_id);

        assert_eq!(out.as_path.path_length(), 1);
        assert_eq!(out.next_hop, Some(NextHop::V4(local_bgp_id)));
        assert!(out.local_pref.is_none());
    }

    #[test]
    fn test_prepare_outbound_ibgp_leaves_route_unchanged() {
        let local_as = 65000_u32;
        let local_bgp_id = Ipv4Addr::new(10, 0, 0, 1);
        let lp = LocalPref::new(100);
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .local_pref(lp)
            .build();

        let out = prepare_outbound(route, PeerType::Internal, local_as, local_bgp_id);

        assert_eq!(out.as_path.path_length(), 0);
        assert!(out.next_hop.is_none());
        assert_eq!(out.local_pref, Some(lp));
    }
}
