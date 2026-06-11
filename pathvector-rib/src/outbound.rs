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
