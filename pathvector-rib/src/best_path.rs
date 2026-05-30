use std::{cmp::Ordering, collections::HashMap};

use ipnetx::interfaces::IpAddress;
use pathvector_types::LocalPref;

use crate::{peer::PeerId, route::Route};

/// Selects the best route from a set of candidates using the BGP decision
/// process (RFC 4271 §9.1).
///
/// Returns the winning `(PeerId, &Route)` pair, or `None` if the map is empty.
///
/// # Decision steps implemented
///
/// | Step | Criterion | Winner |
/// |---|---|---|
/// | 2 | `LOCAL_PREF` | higher (missing → 100) |
/// | 4 | AS path length | shorter |
/// | 5 | `ORIGIN` | lower (`IGP=0` best) |
/// | 6 | `MED` | lower (missing → `0`) |
/// | 10 | Peer IP address | lower |
///
/// Steps 1, 3, 7, 8, and 9 require information not available at the RIB
/// layer (IGP reachability, session type, route age). See `TODO.md`.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use std::net::{IpAddr, Ipv4Addr};
/// use pathvector_rib::{PeerId, Route, RouteBuilder, best_path::select_best};
/// use pathvector_types::{AsPath, Asn, LocalPref, Nlri, Origin};
///
/// let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
/// let peer_a = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
/// let peer_b = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
///
/// let mut candidates = HashMap::new();
/// candidates.insert(peer_a, RouteBuilder::new(nlri, Origin::Igp, AsPath::new())
///     .local_pref(LocalPref::new(200))
///     .build());
/// candidates.insert(peer_b, RouteBuilder::new(nlri, Origin::Igp, AsPath::new())
///     .local_pref(LocalPref::new(100))
///     .build());
///
/// let (winner, _) = select_best(&candidates).unwrap();
/// assert_eq!(winner, peer_a); // higher LOCAL_PREF wins
/// ```
#[must_use]
pub fn select_best<A: IpAddress, S: std::hash::BuildHasher>(
    candidates: &HashMap<PeerId, Route<A>, S>,
) -> Option<(PeerId, &Route<A>)> {
    candidates
        .iter()
        .max_by(|(peer_a, route_a), (peer_b, route_b)| prefer(peer_a, route_a, peer_b, route_b))
        .map(|(peer, route)| (*peer, route))
}

/// Compares two (peer, route) pairs and returns the ordering from the
/// perspective of route preference — `Ordering::Greater` means the first
/// pair is preferred.
///
/// This function encodes the partial BGP decision process. Steps that require
/// external information (IGP metrics, session type) are not implemented here;
/// the caller may wrap this with additional logic.
fn prefer<A: IpAddress>(
    peer_a: &PeerId,
    a: &Route<A>,
    peer_b: &PeerId,
    b: &Route<A>,
) -> Ordering {
    // Step 2: Highest LOCAL_PREF (missing treated as the conventional default of 100).
    // LOCAL_PREF is the most powerful inbound policy lever — an operator can
    // force any route to win by setting this high enough.
    let lp = a
        .local_pref
        .unwrap_or(LocalPref::DEFAULT)
        .cmp(&b.local_pref.unwrap_or(LocalPref::DEFAULT));
    if lp != Ordering::Equal {
        return lp; // higher LOCAL_PREF → Greater → preferred
    }

    // Step 4: Shortest AS path length.
    // Shorter paths are generally closer to the destination. This is the
    // main tool for influencing inbound traffic from eBGP peers.
    let path_len = b
        .as_path
        .path_length()
        .cmp(&a.as_path.path_length());
    if path_len != Ordering::Equal {
        return path_len; // reverse: shorter path_len(a) → Greater → preferred
    }

    // Step 5: Lowest ORIGIN value.
    // IGP (0) > EGP (1) > INCOMPLETE (2) in preference, so a lower numeric
    // value is better. We reverse the comparison to make Greater mean preferred.
    let origin = b.origin.cmp(&a.origin);
    if origin != Ordering::Equal {
        return origin; // reverse: lower origin → Greater → preferred
    }

    // Step 6: Lowest MED (Multi-Exit Discriminator).
    // MED is a hint from a neighboring AS about which of their entry points
    // to prefer. Lower is better. Missing MED is treated as 0 (prefer routes
    // that explicitly set MED=0 equally with routes that omit it).
    //
    // Note: Strictly speaking, MED should only be compared between routes
    // from the same neighboring AS. This implementation compares MED
    // globally. See TODO.md (deterministic-med, always-compare-med).
    let med_a = a.med.map_or(0, pathvector_types::Med::as_u32);
    let med_b = b.med.map_or(0, pathvector_types::Med::as_u32);
    let med = med_b.cmp(&med_a);
    if med != Ordering::Equal {
        return med; // reverse: lower MED → Greater → preferred
    }

    // Step 10: Lowest peer IP address (final tie-breaker).
    // When all policy-relevant attributes are equal, prefer the route from
    // the numerically lower peer address. This is deterministic and stable
    // across policy changes.
    peer_b.cmp(peer_a) // reverse: lower peer IP → Greater → preferred
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use pathvector_types::{AsPath, Asn, LocalPref, Med, Nlri, Origin};

    use crate::RouteBuilder;

    fn peer(last_octet: u8) -> PeerId {
        PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)))
    }

    fn nlri() -> Nlri<Ipv4Addr> {
        "10.0.0.0/8".parse().unwrap()
    }

    fn basic(origin: Origin, path_len: usize, lp: Option<u32>, med: Option<u32>) -> Route<Ipv4Addr> {
        let asns: Vec<_> = (1..=path_len as u32).map(Asn::new).collect();
        let mut b = RouteBuilder::new(
            nlri(),
            origin,
            if asns.is_empty() { AsPath::new() } else { AsPath::from_sequence(asns) },
        );
        if let Some(v) = lp { b = b.local_pref(LocalPref::new(v)); }
        if let Some(v) = med { b = b.med(Med::new(v)); }
        b.build()
    }

    #[test]
    fn test_select_best_empty() {
        let candidates: HashMap<PeerId, Route<Ipv4Addr>> = HashMap::new();
        assert!(select_best(&candidates).is_none());
    }

    #[test]
    fn test_select_best_single_candidate() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(100), None));
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1));
    }

    #[test]
    fn test_select_best_prefers_higher_local_pref() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(200), None));
        candidates.insert(peer(2), basic(Origin::Igp, 2, Some(100), None));
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // LOCAL_PREF 200 > 100
    }

    #[test]
    fn test_select_best_missing_local_pref_treated_as_100() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, None, None)); // missing → 100
        candidates.insert(peer(2), basic(Origin::Igp, 2, Some(150), None)); // 150 wins
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(2));
    }

    #[test]
    fn test_select_best_prefers_shorter_as_path() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(100), None));
        candidates.insert(peer(2), basic(Origin::Igp, 5, Some(100), None));
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // AS path length 2 < 5
    }

    #[test]
    fn test_select_best_prefers_lower_origin() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(100), None));
        candidates.insert(peer(2), basic(Origin::Incomplete, 2, Some(100), None));
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // IGP=0 < INCOMPLETE=2
    }

    #[test]
    fn test_select_best_prefers_lower_med() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(100), Some(10)));
        candidates.insert(peer(2), basic(Origin::Igp, 2, Some(100), Some(100)));
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // MED 10 < 100
    }

    #[test]
    fn test_select_best_missing_med_treated_as_zero() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(100), None));   // MED → 0
        candidates.insert(peer(2), basic(Origin::Igp, 2, Some(100), Some(1))); // MED = 1
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // MED 0 < 1
    }

    #[test]
    fn test_select_best_tiebreak_lower_peer_ip() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(100), None));
        candidates.insert(peer(2), basic(Origin::Igp, 2, Some(100), None));
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1)); // lower peer IP wins
    }

    #[test]
    fn test_select_best_local_pref_beats_path_length() {
        // A route with higher LOCAL_PREF wins even if its AS path is longer.
        // LOCAL_PREF is evaluated before AS path length in the decision process.
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 10, Some(200), None)); // long path, high LP
        candidates.insert(peer(2), basic(Origin::Igp, 1, Some(100), None));  // short path, low LP
        let (winner, _) = select_best(&candidates).unwrap();
        assert_eq!(winner, peer(1));
    }

    #[test]
    fn test_select_best_returns_correct_route_reference() {
        let mut candidates = HashMap::new();
        candidates.insert(peer(1), basic(Origin::Igp, 2, Some(200), None));
        candidates.insert(peer(2), basic(Origin::Igp, 2, Some(100), None));
        let (_, route) = select_best(&candidates).unwrap();
        assert_eq!(route.local_pref, Some(LocalPref::new(200)));
    }
}
