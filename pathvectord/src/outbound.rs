//! Outbound BGP UPDATE pipeline.
//!
//! Functions for building path attributes, computing per-peer prefix decisions,
//! and flushing batched UPDATE messages for both IPv4 and IPv6.

use std::net::{Ipv4Addr, Ipv6Addr};

use pathvector_policy::{Decision, Policy};
use pathvector_rib::{
    AdjRibOut, InsertOutcome, LocRib, RibView, Route,
    outbound::{prepare_outbound, prepare_outbound_v6},
};
use pathvector_session::message::{
    MpReachNlri, MpUnreachNlri, PathAttribute, Prefix, UpdateMessage, encode_attributes,
    nlri_encoded_len, nlri_v6_encoded_len,
};
use pathvector_types::{AfiSafi, NextHop, Nlri, PeerType};
use tokio::sync::mpsc;

/// BGP UPDATE wire overhead: 19-byte header + 2-byte withdrawn-len + 2-byte
/// attr-len field.
pub(crate) const UPDATE_FIXED_OVERHEAD: usize = 19 + 2 + 2;

/// Builds the path-attribute list for an outbound route.
///
/// `peer_type` controls attribute stripping:
/// - ORIGINATOR_ID and CLUSTER_LIST are route-reflector metadata (RFC 4456 §8)
///   and MUST be stripped before sending to eBGP peers.
/// - MED SHOULD NOT be sent to eBGP peers (RFC 4271 §5.1.4).
///
/// `peer_four_byte` indicates whether the peer negotiated RFC 6793
/// `FourByteAsn` capability. When `false`, any 4-byte ASN in AS_PATH is
/// replaced by AS_TRANS (23456) on the wire and the original path is included
/// as AS4_PATH so 4-byte-capable speakers on the other side can reconstruct it.
pub(crate) fn route_to_attributes(
    route: &Route<Ipv4Addr>,
    peer_type: PeerType,
    peer_four_byte: bool,
) -> Vec<PathAttribute> {
    let is_ebgp = peer_type == PeerType::External;
    let (wire_as_path, as4_path) = if peer_four_byte {
        (route.as_path.clone(), None)
    } else {
        let (d, orig) = route.as_path.downgrade_for_two_byte_peer();
        (d, orig)
    };
    let mut attrs = vec![
        PathAttribute::Origin(route.origin),
        PathAttribute::AsPath(wire_as_path),
    ];
    if let Some(NextHop::V4(nh)) = route.next_hop {
        attrs.push(PathAttribute::NextHop(nh));
    }
    if let Some(lp) = route.local_pref {
        attrs.push(PathAttribute::LocalPref(lp.as_u32()));
    }
    if !is_ebgp {
        // RFC 4271 §5.1.4: MED SHOULD NOT be sent to eBGP peers.
        if let Some(m) = route.med {
            attrs.push(PathAttribute::Med(m.as_u32()));
        }
    }
    if !route.communities.is_empty() {
        attrs.push(PathAttribute::Communities(route.communities.clone()));
    }
    if !route.large_communities.is_empty() {
        attrs.push(PathAttribute::LargeCommunities(
            route.large_communities.clone(),
        ));
    }
    if !route.extended_communities.is_empty() {
        attrs.push(PathAttribute::ExtendedCommunities(
            route.extended_communities.clone(),
        ));
    }
    if route.atomic_aggregate {
        attrs.push(PathAttribute::AtomicAggregate);
    }
    if let Some(agg) = route.aggregator {
        attrs.push(PathAttribute::Aggregator(agg));
    }
    if !is_ebgp {
        // RFC 4456 §8: ORIGINATOR_ID and CLUSTER_LIST MUST be stripped for eBGP.
        if let Some(id) = route.originator_id {
            attrs.push(PathAttribute::OriginatorId(id));
        }
        if !route.cluster_list.is_empty() {
            attrs.push(PathAttribute::ClusterList(route.cluster_list.clone()));
        }
    }
    // RFC 6793 §4: when the peer is 2-byte-only, include AS4_PATH so that
    // 4-byte-capable routers further along the path can reconstruct the full
    // AS path. Only emitted when downgrade actually substituted AS_TRANS above.
    if let Some(as4) = as4_path {
        attrs.push(PathAttribute::As4Path(as4));
    }
    attrs
}

/// The outbound decision for a single prefix after AdjRibOut processing.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum PrefixDecision {
    Announce(Route<Ipv4Addr>),
    Withdraw(Nlri<Ipv4Addr>),
    NoChange,
}

/// Determines the outbound decision for `nlri` for one peer.
///
/// Reads the current best from `loc_rib`, applies export policy, runs eBGP
/// attribute transforms, and calls `AdjRibOut::insert` to record the change.
/// Returns what should be sent without transmitting anything — callers batch
/// decisions and flush via [`flush_updates`].
pub(crate) fn propagate_prefix(
    nlri: Nlri<Ipv4Addr>,
    loc_rib: &impl RibView<Ipv4Addr>,
    adj_rib_out: &mut AdjRibOut<Ipv4Addr>,
    export_policy: &Policy<Route<Ipv4Addr>>,
    peer_type: PeerType,
    local_as: u32,
    local_next_hop: Ipv4Addr,
) -> PrefixDecision {
    match loc_rib.best(&nlri) {
        Some(best) => {
            // Never re-advertise a route back to the peer it was learned from.
            // This covers both eBGP and iBGP source-peer split horizon; the
            // iBGP case is also enforced by AdjRibOut::insert, but catching it
            // here avoids unnecessary prepare_outbound work and keeps eviction
            // logic consistent.
            if loc_rib.best_peer(&nlri) == Some(adj_rib_out.peer()) {
                return if adj_rib_out.withdraw(&nlri).is_some() {
                    PrefixDecision::Withdraw(nlri)
                } else {
                    PrefixDecision::NoChange
                };
            }
            let mut route = prepare_outbound(best.clone(), peer_type, local_as, local_next_hop);
            match export_policy.evaluate(&mut route) {
                Decision::Accept => match adj_rib_out.insert(route.clone()) {
                    InsertOutcome::Accepted(prev) => {
                        if prev.as_ref() == Some(&route) {
                            PrefixDecision::NoChange
                        } else {
                            PrefixDecision::Announce(route)
                        }
                    }
                    InsertOutcome::Filtered(Some(_)) => PrefixDecision::Withdraw(nlri),
                    InsertOutcome::Filtered(None) => PrefixDecision::NoChange,
                },
                Decision::Reject | Decision::Next => {
                    if adj_rib_out.withdraw(&nlri).is_some() {
                        PrefixDecision::Withdraw(nlri)
                    } else {
                        PrefixDecision::NoChange
                    }
                }
            }
        }
        None => {
            if adj_rib_out.withdraw(&nlri).is_some() {
                PrefixDecision::Withdraw(nlri)
            } else {
                PrefixDecision::NoChange
            }
        }
    }
}

/// Sends batched BGP UPDATE messages for a collected set of prefix decisions.
///
/// Announcements are grouped by identical path attributes; each group is packed
/// into the fewest UPDATE messages that fit within `max_len`. Withdrawals are
/// similarly batched into withdraw-only UPDATEs. Withdrawals are sent before
/// announcements (conventional BGP practice).
///
/// Returns `true` if all sends succeeded. Returns `false` on the first channel-full
/// error — the caller must schedule a session reset to restore a consistent peer view.
// (encoded-attribute-bytes, attribute-list, nlris-to-announce)
type AnnounceGroup = (Vec<u8>, Vec<PathAttribute>, Vec<Nlri<Ipv4Addr>>);

pub(crate) fn flush_updates(
    decisions: Vec<PrefixDecision>,
    max_len: usize,
    update_tx: &mpsc::Sender<UpdateMessage>,
    peer_type: PeerType,
    peer_four_byte: bool,
) -> bool {
    let mut withdrawals: Vec<Nlri<Ipv4Addr>> = Vec::new();
    let mut announce_groups: Vec<AnnounceGroup> = Vec::new();

    for decision in decisions {
        match decision {
            PrefixDecision::Withdraw(nlri) => withdrawals.push(nlri),
            PrefixDecision::Announce(route) => {
                let attrs = route_to_attributes(&route, peer_type, peer_four_byte);
                let attr_bytes = encode_attributes(&attrs);
                // Linear scan — typically 1-3 distinct attribute groups per batch.
                if let Some((_, _, nlris)) = announce_groups
                    .iter_mut()
                    .find(|(key, _, _)| *key == attr_bytes)
                {
                    nlris.push(route.nlri);
                } else {
                    announce_groups.push((attr_bytes, attrs, vec![route.nlri]));
                }
            }
            PrefixDecision::NoChange => {}
        }
    }

    // ── Send withdrawals ──────────────────────────────────────────────────────
    // Wire: header(19) + withdrawn_len(2) + nlris + attr_len(2)
    let withdraw_overhead = UPDATE_FIXED_OVERHEAD; // attr block is empty (0 bytes)
    let mut batch: Vec<Nlri<Ipv4Addr>> = Vec::new();
    let mut batch_bytes = withdraw_overhead;

    for nlri in withdrawals {
        let nlen = nlri_encoded_len(&nlri);
        if !batch.is_empty() && batch_bytes + nlen > max_len {
            if update_tx
                .try_send(UpdateMessage {
                    withdrawn: std::mem::take(&mut batch),
                    attributes: vec![],
                    announced: vec![],
                })
                .is_err()
            {
                return false;
            }
            batch_bytes = withdraw_overhead;
        }
        batch.push(nlri);
        batch_bytes += nlen;
    }
    if !batch.is_empty()
        && update_tx
            .try_send(UpdateMessage {
                withdrawn: batch,
                attributes: vec![],
                announced: vec![],
            })
            .is_err()
    {
        return false;
    }

    // ── Send announcements ────────────────────────────────────────────────────
    for (attr_bytes, attrs, nlris) in announce_groups {
        // base cost for this attribute group: fixed overhead + attribute block
        let base = UPDATE_FIXED_OVERHEAD + attr_bytes.len();
        let mut batch: Vec<Nlri<Ipv4Addr>> = Vec::new();
        let mut batch_bytes = base;

        for nlri in nlris {
            let nlen = nlri_encoded_len(&nlri);
            if !batch.is_empty() && batch_bytes + nlen > max_len {
                if update_tx
                    .try_send(UpdateMessage {
                        withdrawn: vec![],
                        attributes: attrs.clone(),
                        announced: std::mem::take(&mut batch),
                    })
                    .is_err()
                {
                    return false;
                }
                batch_bytes = base;
            }
            batch.push(nlri);
            batch_bytes += nlen;
        }
        if !batch.is_empty()
            && update_tx
                .try_send(UpdateMessage {
                    withdrawn: vec![],
                    attributes: attrs,
                    announced: batch,
                })
                .is_err()
        {
            return false;
        }
    }

    true
}

/// Outbound decision for a single IPv6 prefix after AdjRibOut processing.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum PrefixDecisionV6 {
    Announce(Route<Ipv6Addr>),
    Withdraw(Nlri<Ipv6Addr>),
    NoChange,
}

/// IPv6 equivalent of [`propagate_prefix`]: determines the outbound decision
/// for one IPv6 NLRI for a single peer.
///
/// For eBGP peers, `local_ipv6` must be `Some` for an announcement to be
/// generated; if `None`, eBGP routes are silently suppressed (no next-hop to
/// rewrite) but any previously advertised route is withdrawn.
pub(crate) fn propagate_prefix_v6(
    nlri: Nlri<Ipv6Addr>,
    loc_rib: &LocRib<Ipv6Addr>,
    adj_rib_out: &mut AdjRibOut<Ipv6Addr>,
    peer_type: PeerType,
    local_as: u32,
    local_ipv6: Option<Ipv6Addr>,
) -> PrefixDecisionV6 {
    // For eBGP with no local IPv6 address configured, we can't rewrite the
    // next-hop, so don't announce — but do withdraw if we previously did.
    let can_announce = peer_type != PeerType::External || local_ipv6.is_some();

    match loc_rib.best(&nlri) {
        Some(best) if can_announce => {
            // Never re-advertise a route back to the peer it was learned from.
            if loc_rib.best_peer(&nlri) == Some(adj_rib_out.peer()) {
                return if adj_rib_out.withdraw(&nlri).is_some() {
                    PrefixDecisionV6::Withdraw(nlri)
                } else {
                    PrefixDecisionV6::NoChange
                };
            }
            let route = prepare_outbound_v6(best.clone(), peer_type, local_as, local_ipv6);
            match adj_rib_out.insert(route.clone()) {
                InsertOutcome::Accepted(prev) => {
                    if prev.as_ref() == Some(&route) {
                        PrefixDecisionV6::NoChange
                    } else {
                        PrefixDecisionV6::Announce(route)
                    }
                }
                InsertOutcome::Filtered(Some(_)) => PrefixDecisionV6::Withdraw(nlri),
                InsertOutcome::Filtered(None) => PrefixDecisionV6::NoChange,
            }
        }
        _ => {
            if adj_rib_out.withdraw(&nlri).is_some() {
                PrefixDecisionV6::Withdraw(nlri)
            } else {
                PrefixDecisionV6::NoChange
            }
        }
    }
}

/// Sends batched BGP UPDATE messages for IPv6 prefix decisions using
/// MP_REACH_NLRI / MP_UNREACH_NLRI attributes (RFC 4760).
///
/// Announcements are grouped by identical path attributes; each group is packed
/// into the fewest UPDATE messages that fit within `max_len`. Withdrawals are
/// sent first as MP_UNREACH_NLRI UPDATE messages.
///
/// Returns `true` if all sends succeeded; `false` on the first channel-full
/// error.
pub(crate) fn flush_updates_v6(
    decisions: Vec<PrefixDecisionV6>,
    max_len: usize,
    update_tx: &mpsc::Sender<UpdateMessage>,
    peer_type: PeerType,
    peer_four_byte: bool,
) -> bool {
    // (encoded-attr-bytes, attribute-list-with-mp-reach, nlri-list)
    type AnnounceGroupV6 = (Vec<u8>, Vec<PathAttribute>, Vec<Nlri<Ipv6Addr>>);

    let mut withdrawals: Vec<Nlri<Ipv6Addr>> = Vec::new();
    let mut announce_groups: Vec<AnnounceGroupV6> = Vec::new();

    for decision in decisions {
        match decision {
            PrefixDecisionV6::Withdraw(nlri) => withdrawals.push(nlri),
            PrefixDecisionV6::Announce(route) => {
                // MP_UNREACH_NLRI is the only attribute on the announce message;
                // we group routes with identical scalar attributes (same attrs
                // minus the NLRI list) and pack them together.
                let (mut attrs, mp_reach) =
                    route_v6_to_attributes(&route, peer_type, peer_four_byte);
                let key = encode_attributes(&attrs);
                // Restore the MP_REACH_NLRI placeholder next-hop in the group leader.
                if let Some((_, group_attrs, nlris)) =
                    announce_groups.iter_mut().find(|(k, _, _)| *k == key)
                {
                    // Add this NLRI to the existing group's MP_REACH_NLRI prefix list.
                    if let Some(PathAttribute::MpReachNlri(mp)) = group_attrs
                        .iter_mut()
                        .find(|a| matches!(a, PathAttribute::MpReachNlri(_)))
                    {
                        mp.prefixes.push(Prefix::V6(route.nlri));
                    }
                    nlris.push(route.nlri);
                } else {
                    attrs.push(PathAttribute::MpReachNlri(mp_reach));
                    announce_groups.push((key, attrs, vec![route.nlri]));
                }
            }
            PrefixDecisionV6::NoChange => {}
        }
    }

    // ── Send MP_UNREACH_NLRI withdrawals ──────────────────────────────────────
    // Each MP_UNREACH_NLRI carries a batch of IPv6 NLRIs in a single UPDATE.
    // Fixed overhead: 19-byte header + 2 withdrawn_len (0) + 2 attr_len.
    let base_withdraw = UPDATE_FIXED_OVERHEAD;
    let mut batch: Vec<Nlri<Ipv6Addr>> = Vec::new();
    let mut batch_bytes = base_withdraw;

    for nlri in withdrawals {
        // Cost of this NLRI inside the MP_UNREACH_NLRI TLV.
        let nlen = nlri_v6_encoded_len(&nlri);
        // MP_UNREACH_NLRI attribute header: 4 bytes (flags+type+ext-len) + 3 afi/safi.
        let mp_hdr = if batch.is_empty() { 4 + 3 } else { 0 };
        if !batch.is_empty() && batch_bytes + mp_hdr + nlen > max_len {
            if !send_mp_unreach_v6(std::mem::take(&mut batch), update_tx) {
                return false;
            }
            batch_bytes = base_withdraw;
        }
        if batch.is_empty() {
            batch_bytes += 4 + 3; // first NLRI: pay for attribute header
        }
        batch.push(nlri);
        batch_bytes += nlen;
    }
    if !batch.is_empty() && !send_mp_unreach_v6(batch, update_tx) {
        return false;
    }

    // ── Send MP_REACH_NLRI announcements ──────────────────────────────────────
    // Each group shares the same scalar path attributes + next-hop. We already
    // built full attribute lists (including a single MpReachNlri) per group
    // above; here we just pack and send them as-is (splitting is uncommon for
    // v6 since the NLRI encoding is larger).
    for (_, attrs, _) in announce_groups {
        if update_tx
            .try_send(UpdateMessage {
                withdrawn: vec![],
                attributes: attrs,
                announced: vec![],
            })
            .is_err()
        {
            return false;
        }
    }

    true
}

pub(crate) fn send_mp_unreach_v6(
    nlris: Vec<Nlri<Ipv6Addr>>,
    update_tx: &mpsc::Sender<UpdateMessage>,
) -> bool {
    let prefixes = nlris.into_iter().map(Prefix::V6).collect();
    update_tx
        .try_send(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                prefixes,
            })],
            announced: vec![],
        })
        .is_ok()
}

/// Builds the path-attribute list for an outbound IPv6 route.
///
/// `peer_type` controls attribute stripping — same rules as [`route_to_attributes`]:
/// - MED SHOULD NOT be sent to eBGP peers (RFC 4271 §5.1.4).
/// - ORIGINATOR_ID and CLUSTER_LIST MUST be stripped for eBGP peers (RFC 4456 §8).
///
/// The NLRI is carried in MP_REACH_NLRI (RFC 4760); the traditional
/// `NEXT_HOP` attribute is not emitted for IPv6 routes.
pub(crate) fn route_v6_to_attributes(
    route: &Route<Ipv6Addr>,
    peer_type: PeerType,
    peer_four_byte: bool,
) -> (Vec<PathAttribute>, MpReachNlri) {
    let is_ebgp = peer_type == PeerType::External;
    let (wire_as_path, as4_path) = if peer_four_byte {
        (route.as_path.clone(), None)
    } else {
        let (d, orig) = route.as_path.downgrade_for_two_byte_peer();
        (d, orig)
    };
    let mut attrs = vec![
        PathAttribute::Origin(route.origin),
        PathAttribute::AsPath(wire_as_path),
    ];
    if let Some(lp) = route.local_pref {
        attrs.push(PathAttribute::LocalPref(lp.as_u32()));
    }
    if !is_ebgp {
        // RFC 4271 §5.1.4: MED SHOULD NOT be sent to eBGP peers.
        if let Some(m) = route.med {
            attrs.push(PathAttribute::Med(m.as_u32()));
        }
    }
    if !route.communities.is_empty() {
        attrs.push(PathAttribute::Communities(route.communities.clone()));
    }
    if !route.large_communities.is_empty() {
        attrs.push(PathAttribute::LargeCommunities(
            route.large_communities.clone(),
        ));
    }
    if !route.extended_communities.is_empty() {
        attrs.push(PathAttribute::ExtendedCommunities(
            route.extended_communities.clone(),
        ));
    }
    if route.atomic_aggregate {
        attrs.push(PathAttribute::AtomicAggregate);
    }
    if let Some(agg) = route.aggregator {
        attrs.push(PathAttribute::Aggregator(agg));
    }
    if !is_ebgp {
        // RFC 4456 §8: ORIGINATOR_ID and CLUSTER_LIST MUST be stripped for eBGP.
        if let Some(id) = route.originator_id {
            attrs.push(PathAttribute::OriginatorId(id));
        }
        if !route.cluster_list.is_empty() {
            attrs.push(PathAttribute::ClusterList(route.cluster_list.clone()));
        }
    }
    if let Some(as4) = as4_path {
        attrs.push(PathAttribute::As4Path(as4));
    }
    let next_hop = route.next_hop.unwrap_or(NextHop::V6(Ipv6Addr::UNSPECIFIED));
    let mp_reach = MpReachNlri {
        afi_safi: AfiSafi::IPV6_UNICAST,
        next_hop,
        prefixes: vec![Prefix::V6(route.nlri)],
    };
    (attrs, mp_reach)
}

// ── flush_updates tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod flush_updates_tests {
    use std::net::Ipv4Addr;

    use pathvector_rib::{Route, RouteBuilder};
    use pathvector_session::message::{MAX_LEN, UpdateMessage};
    use pathvector_types::{AsPath, Nlri, Origin, PeerType};
    use tokio::sync::mpsc;

    use super::{PrefixDecision, flush_updates};

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn base_route(prefix: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(nlri(prefix), Origin::Igp, AsPath::new()).build()
    }

    /// A single announcement is sent as one UPDATE with that NLRI.
    #[test]
    fn test_flush_single_announce() {
        let route = base_route("10.0.0.0/8");
        let decisions = vec![PrefixDecision::Announce(route)];
        let (tx, mut rx) = mpsc::channel(16);
        assert!(flush_updates(
            decisions,
            MAX_LEN,
            &tx,
            PeerType::External,
            true
        ));
        let msg = rx.try_recv().expect("one UPDATE expected");
        assert_eq!(msg.announced, vec![nlri("10.0.0.0/8")]);
        assert!(msg.withdrawn.is_empty());
        assert!(rx.try_recv().is_err(), "no extra messages");
    }

    /// Multiple NLRIs with identical path attributes are packed into one UPDATE.
    #[test]
    fn test_flush_same_attrs_batched_into_one_message() {
        let prefixes = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"];
        let decisions: Vec<PrefixDecision> = prefixes
            .iter()
            .map(|p| PrefixDecision::Announce(base_route(p)))
            .collect();
        let (tx, mut rx) = mpsc::channel(16);
        assert!(flush_updates(
            decisions,
            MAX_LEN,
            &tx,
            PeerType::External,
            true
        ));
        let msg = rx.try_recv().expect("one batched UPDATE expected");
        assert_eq!(msg.announced.len(), 3);
        assert!(rx.try_recv().is_err(), "all NLRIs in a single UPDATE");
    }

    /// Two routes with different attributes produce two separate UPDATEs.
    #[test]
    fn test_flush_different_attrs_two_messages() {
        use pathvector_types::NextHop;

        let r1 = base_route("10.0.0.0/8");
        // r2 has a NEXT_HOP, r1 does not — different attribute set.
        let r2 = RouteBuilder::new(nlri("192.168.0.0/16"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .build();
        let decisions = vec![PrefixDecision::Announce(r1), PrefixDecision::Announce(r2)];
        let (tx, mut rx) = mpsc::channel(16);
        assert!(flush_updates(
            decisions,
            MAX_LEN,
            &tx,
            PeerType::External,
            true
        ));
        let first = rx.try_recv().expect("first UPDATE");
        let second = rx.try_recv().expect("second UPDATE");
        assert_eq!(first.announced.len(), 1);
        assert_eq!(second.announced.len(), 1);
        assert!(rx.try_recv().is_err());
    }

    /// A batch too large for MAX_LEN is split across multiple UPDATEs.
    #[test]
    fn test_flush_splits_when_exceeding_max_len() {
        // 1 500 /24 NLRIs with identical attrs (Origin+AsPath) exceed MAX_LEN=4096
        // in a single group, exercising the mid-loop announcement batch-flush path.
        let decisions: Vec<PrefixDecision> = (0u32..1500)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let a = (i / 256) as u8;
                #[allow(clippy::cast_possible_truncation)]
                let b = (i % 256) as u8;
                let route = RouteBuilder::new(
                    Nlri::new(Ipv4Addr::new(10, a, b, 0), 24).unwrap(),
                    Origin::Igp,
                    AsPath::new(),
                )
                .build();
                PrefixDecision::Announce(route)
            })
            .collect();

        let (tx, mut rx) = mpsc::channel(128);
        assert!(flush_updates(
            decisions,
            MAX_LEN,
            &tx,
            PeerType::External,
            true
        ));

        let mut total = 0usize;
        while let Ok(msg) = rx.try_recv() {
            use pathvector_session::message::BgpMessage;
            let wire_len = BgpMessage::Update(msg.clone()).encode().len();
            assert!(
                wire_len <= MAX_LEN,
                "encoded message {wire_len} bytes exceeds MAX_LEN"
            );
            total += msg.announced.len();
        }
        assert_eq!(total, 1500, "all NLRIs must be sent");
    }

    /// Withdrawals are batched into a single withdraw-only UPDATE.
    #[test]
    fn test_flush_withdrawals_batched() {
        let decisions: Vec<PrefixDecision> = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
            .iter()
            .map(|p| PrefixDecision::Withdraw(nlri(p)))
            .collect();
        let (tx, mut rx) = mpsc::channel(16);
        assert!(flush_updates(
            decisions,
            MAX_LEN,
            &tx,
            PeerType::External,
            true
        ));
        let msg = rx.try_recv().expect("one withdraw UPDATE expected");
        assert_eq!(msg.withdrawn.len(), 3);
        assert!(msg.announced.is_empty());
        assert!(rx.try_recv().is_err());
    }

    /// Withdrawals are sent before announcements.
    #[test]
    fn test_flush_withdrawals_before_announces() {
        let decisions = vec![
            PrefixDecision::Announce(base_route("10.0.0.0/8")),
            PrefixDecision::Withdraw(nlri("192.168.0.0/16")),
        ];
        let (tx, mut rx) = mpsc::channel(16);
        assert!(flush_updates(
            decisions,
            MAX_LEN,
            &tx,
            PeerType::External,
            true
        ));
        let first = rx.try_recv().expect("first message");
        assert!(!first.withdrawn.is_empty(), "withdraw must come first");
        let second = rx.try_recv().expect("second message");
        assert!(!second.announced.is_empty(), "announce comes second");
    }

    /// NoChange decisions produce no messages.
    #[test]
    fn test_flush_no_change_produces_nothing() {
        let decisions = vec![PrefixDecision::NoChange, PrefixDecision::NoChange];
        let (tx, mut rx) = mpsc::channel(16);
        assert!(flush_updates(
            decisions,
            MAX_LEN,
            &tx,
            PeerType::External,
            true
        ));
        assert!(rx.try_recv().is_err(), "no messages for NoChange");
    }

    /// Returns false when the channel is full.
    #[test]
    fn test_flush_returns_false_on_full_channel() {
        let (tx, _rx) = mpsc::channel(1);
        // Pre-fill the channel.
        tx.try_send(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })
        .unwrap();

        let decisions = vec![PrefixDecision::Withdraw(nlri("10.0.0.0/8"))];
        assert!(!flush_updates(
            decisions,
            MAX_LEN,
            &tx,
            PeerType::External,
            true
        ));
    }

    /// Returns false when the channel is closed (announcement path).
    #[test]
    fn test_flush_announce_returns_false_on_closed_channel() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let decisions = vec![PrefixDecision::Announce(base_route("10.0.0.0/8"))];
        assert!(!flush_updates(
            decisions,
            MAX_LEN,
            &tx,
            PeerType::External,
            true
        ));
    }

    /// 1 500 withdrawals are all delivered even when they span multiple UPDATEs.
    ///
    /// 1 500 /24 NLRIs (4 bytes each) at MAX_LEN=4096 with 23-byte overhead
    /// fills more than one UPDATE, exercising the mid-loop batch-flush path.
    #[test]
    fn test_flush_withdrawal_split_delivers_all_nlris() {
        let decisions: Vec<PrefixDecision> = (0u32..1500)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let a = (i / 256) as u8;
                #[allow(clippy::cast_possible_truncation)]
                let b = (i % 256) as u8;
                PrefixDecision::Withdraw(Nlri::new(Ipv4Addr::new(10, a, b, 0), 24).unwrap())
            })
            .collect();

        let (tx, mut rx) = mpsc::channel(128);
        assert!(flush_updates(
            decisions,
            MAX_LEN,
            &tx,
            PeerType::External,
            true
        ));

        let mut total = 0usize;
        while let Ok(msg) = rx.try_recv() {
            use pathvector_session::message::BgpMessage;
            let wire_len = BgpMessage::Update(msg.clone()).encode().len();
            assert!(
                wire_len <= MAX_LEN,
                "withdraw UPDATE {wire_len} bytes exceeds MAX_LEN"
            );
            assert!(msg.announced.is_empty(), "withdraw batch must not announce");
            total += msg.withdrawn.len();
        }
        assert_eq!(total, 1500, "all withdrawals must be delivered");
    }

    /// Returns false when channel is pre-filled and a mid-batch overflow flush fails.
    ///
    /// max_len = 26: fits exactly one /8 NLRI (23-byte overhead + 2 bytes = 25 ≤ 26).
    /// The second /8 NLRI triggers overflow (25 + 2 = 27 > 26) and try_send fails
    /// because the channel was pre-filled — covering the `return false` at line 229.
    #[test]
    fn test_flush_withdrawal_mid_batch_overflow_full_channel_returns_false() {
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })
        .unwrap();
        let decisions = vec![
            PrefixDecision::Withdraw(nlri("10.0.0.0/8")),
            PrefixDecision::Withdraw(nlri("11.0.0.0/8")),
        ];
        assert!(!flush_updates(decisions, 26, &tx, PeerType::External, true));
    }

    /// Returns false when channel fills during a mid-batch announce overflow.
    ///
    /// max_len = 50: smaller than 23-byte overhead + minimal attr block + two /8 NLRIs,
    /// forcing the announcement batch to split mid-loop with a pre-filled channel.
    #[test]
    fn test_flush_announce_mid_batch_overflow_full_channel_returns_false() {
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })
        .unwrap();
        // Two identical-attrs /8 routes.  With max_len=50, the second NLRI triggers
        // an overflow try_send which fails because the channel is full.
        let decisions = vec![
            PrefixDecision::Announce(base_route("10.0.0.0/8")),
            PrefixDecision::Announce(base_route("11.0.0.0/8")),
        ];
        assert!(!flush_updates(decisions, 50, &tx, PeerType::External, true));
    }
}

#[cfg(test)]
mod v6_tests {
    use std::net::Ipv6Addr;

    use pathvector_rib::RouteBuilder;
    use pathvector_session::message::{MAX_LEN, PathAttribute, UpdateMessage};
    use pathvector_types::{
        Aggregator, AsPath, Asn, Community, ExtendedCommunity, LargeCommunity, LocalPref, Med,
        NextHop, Nlri, Origin, PeerType,
    };
    use tokio::sync::mpsc;

    use super::{PrefixDecisionV6, flush_updates_v6, route_v6_to_attributes};

    fn nlri6(s: &str) -> Nlri<Ipv6Addr> {
        s.parse().unwrap()
    }

    fn base_route_v6(prefix: &str) -> pathvector_rib::Route<Ipv6Addr> {
        RouteBuilder::new(nlri6(prefix), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build()
    }

    /// route_v6_to_attributes includes MED when set.
    #[test]
    fn test_route_v6_to_attributes_with_med() {
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .med(Med::new(100))
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        let (attrs, _) = route_v6_to_attributes(&route, PeerType::Internal, true);
        assert!(attrs.iter().any(|a| matches!(a, PathAttribute::Med(100))));
    }

    /// route_v6_to_attributes includes Community when set.
    #[test]
    fn test_route_v6_to_attributes_with_community() {
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .community(Community::from(0x0001_0001u32))
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        let (attrs, _) = route_v6_to_attributes(&route, PeerType::Internal, true);
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::Communities(_)))
        );
    }

    /// route_v6_to_attributes includes LargeCommunities when set.
    #[test]
    fn test_route_v6_to_attributes_with_large_community() {
        let lc = LargeCommunity {
            global_administrator: 65001,
            local_data_1: 1,
            local_data_2: 2,
        };
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .large_community(lc)
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        let (attrs, _) = route_v6_to_attributes(&route, PeerType::Internal, true);
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::LargeCommunities(_)))
        );
    }

    /// route_v6_to_attributes includes ExtendedCommunities when set.
    #[test]
    fn test_route_v6_to_attributes_with_extended_community() {
        let ec = ExtendedCommunity::from_bytes([0x00, 0x02, 0, 0, 0, 0, 0, 1]);
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .extended_community(ec)
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        let (attrs, _) = route_v6_to_attributes(&route, PeerType::Internal, true);
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::ExtendedCommunities(_)))
        );
    }

    /// route_v6_to_attributes includes LocalPref when set.
    #[test]
    fn test_route_v6_to_attributes_with_local_pref() {
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(200))
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        let (attrs, _) = route_v6_to_attributes(&route, PeerType::Internal, true);
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::LocalPref(200)))
        );
    }

    /// route_v6_to_attributes includes Aggregator when set.
    #[test]
    fn test_route_v6_to_attributes_with_aggregator() {
        let agg = Aggregator {
            asn: Asn::new(65001),
            ip: "10.0.0.1".parse().unwrap(),
        };
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .aggregator(agg)
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        let (attrs, _) = route_v6_to_attributes(&route, PeerType::Internal, true);
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::Aggregator(_)))
        );
    }

    // ── IPv6 eBGP attribute stripping (findings F and G) ─────────────────────

    /// MED must be stripped for eBGP peers on the IPv6 path (RFC 4271 §5.1.4).
    #[test]
    fn test_route_v6_to_attributes_ebgp_strips_med() {
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .med(Med::new(100))
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        let (attrs, _) = route_v6_to_attributes(&route, PeerType::External, true);
        assert!(
            !attrs.iter().any(|a| matches!(a, PathAttribute::Med(_))),
            "MED must be stripped for eBGP IPv6 peers (RFC 4271 §5.1.4)"
        );
    }

    /// MED must be preserved for iBGP peers on the IPv6 path.
    #[test]
    fn test_route_v6_to_attributes_ibgp_preserves_med() {
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .med(Med::new(100))
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        let (attrs, _) = route_v6_to_attributes(&route, PeerType::Internal, true);
        assert!(
            attrs.iter().any(|a| matches!(a, PathAttribute::Med(_))),
            "MED must be preserved for iBGP IPv6 peers"
        );
    }

    /// ORIGINATOR_ID and CLUSTER_LIST must be stripped for eBGP on the IPv6 path (RFC 4456 §8).
    #[test]
    fn test_route_v6_to_attributes_ebgp_strips_rr_attributes() {
        let mut route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        route.originator_id = Some("1.1.1.1".parse().unwrap());
        route.cluster_list = vec![0x0101_0101u32];

        let (attrs, _) = route_v6_to_attributes(&route, PeerType::External, true);
        assert!(
            !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::OriginatorId(_))),
            "ORIGINATOR_ID must be stripped for eBGP IPv6 peers (RFC 4456 §8)"
        );
        assert!(
            !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::ClusterList(_))),
            "CLUSTER_LIST must be stripped for eBGP IPv6 peers (RFC 4456 §8)"
        );
    }

    /// ORIGINATOR_ID and CLUSTER_LIST must be preserved for iBGP on the IPv6 path.
    #[test]
    fn test_route_v6_to_attributes_ibgp_preserves_rr_attributes() {
        let mut route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        route.originator_id = Some("1.1.1.1".parse().unwrap());
        route.cluster_list = vec![0x0101_0101u32];

        let (attrs, _) = route_v6_to_attributes(&route, PeerType::Internal, true);
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::OriginatorId(_))),
            "ORIGINATOR_ID must be preserved for iBGP IPv6 peers"
        );
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::ClusterList(_))),
            "CLUSTER_LIST must be preserved for iBGP IPv6 peers"
        );
    }

    /// flush_updates_v6 returns false when the channel is closed.
    #[test]
    fn test_flush_v6_returns_false_on_closed_channel() {
        let (tx, rx) = mpsc::channel::<UpdateMessage>(1);
        drop(rx);
        let decisions = vec![PrefixDecisionV6::Announce(base_route_v6("2001:db8::/32"))];
        assert!(!flush_updates_v6(
            decisions,
            MAX_LEN,
            &tx,
            PeerType::External,
            true
        ));
    }

    /// flush_updates_v6 returns false for withdrawals when channel is closed.
    #[test]
    fn test_flush_v6_withdrawal_returns_false_on_closed_channel() {
        let (tx, rx) = mpsc::channel::<UpdateMessage>(1);
        drop(rx);
        let decisions = vec![PrefixDecisionV6::Withdraw(nlri6("2001:db8::/32"))];
        assert!(!flush_updates_v6(
            decisions,
            MAX_LEN,
            &tx,
            PeerType::External,
            true
        ));
    }

    /// Returns false when channel fills during a mid-batch v6 withdrawal overflow.
    ///
    /// max_len = 35 fits exactly one /32 v6 NLRI (23-byte overhead + 7-byte
    /// MP_UNREACH_NLRI header + 5-byte /32 NLRI = 35).  The second NLRI triggers
    /// an overflow try_send which fails because the channel is pre-filled.
    #[test]
    fn test_flush_v6_withdrawal_mid_batch_overflow_full_channel_returns_false() {
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })
        .unwrap();
        let decisions = vec![
            PrefixDecisionV6::Withdraw(nlri6("2001:db8::/32")),
            PrefixDecisionV6::Withdraw(nlri6("2001:db8:1::/32")),
        ];
        assert!(!flush_updates_v6(
            decisions,
            35,
            &tx,
            PeerType::External,
            true
        ));
    }

    /// 1 500 IPv6 withdrawals span multiple MP_UNREACH_NLRI UPDATEs.
    ///
    /// Each /32 NLRI encodes to 5 bytes; MAX_LEN=4096 with 23-byte overhead
    /// and a 7-byte MP_UNREACH_NLRI header holds ~(4096-23-7)/5 ≈ 813 NLRIs per
    /// message.  1 500 NLRIs forces at least one mid-loop batch flush.
    #[test]
    fn test_flush_v6_withdrawal_split_delivers_all_nlris() {
        use pathvector_session::message::BgpMessage;
        let decisions: Vec<PrefixDecisionV6> = (0u32..1500)
            .map(|i| {
                let a = ((i >> 8) & 0xff) as u8;
                let b = (i & 0xff) as u8;
                let prefix: std::net::Ipv6Addr = format!("2001:{a:02x}{b:02x}::").parse().unwrap();
                PrefixDecisionV6::Withdraw(pathvector_types::Nlri::new(prefix, 32).unwrap())
            })
            .collect();

        let (tx, mut rx) = mpsc::channel(128);
        assert!(flush_updates_v6(
            decisions,
            MAX_LEN,
            &tx,
            PeerType::External,
            true
        ));

        let mut total = 0usize;
        while let Ok(msg) = rx.try_recv() {
            let wire_len = BgpMessage::Update(msg.clone()).encode().len();
            assert!(
                wire_len <= MAX_LEN,
                "v6 withdraw UPDATE {wire_len} bytes > MAX_LEN"
            );
            total += msg
                .attributes
                .iter()
                .filter_map(|a| {
                    if let PathAttribute::MpUnreachNlri(u) = a {
                        Some(u.prefixes.len())
                    } else {
                        None
                    }
                })
                .sum::<usize>();
        }
        assert_eq!(total, 1500, "all IPv6 withdrawals must be delivered");
    }

    /// route_v6_to_attributes includes AtomicAggregate when set.
    #[test]
    fn test_route_v6_to_attributes_with_atomic_aggregate() {
        use pathvector_rib::RouteBuilder;
        let n = nlri6("2001:db8::/32");
        let route = RouteBuilder::new(
            n,
            pathvector_types::Origin::Igp,
            pathvector_types::AsPath::new(),
        )
        .atomic_aggregate()
        .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
        .build();
        let (attrs, _) = route_v6_to_attributes(&route, PeerType::Internal, true);
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::AtomicAggregate)),
            "AtomicAggregate must be present when route.atomic_aggregate is true"
        );
    }

    /// route_v6_to_attributes includes As4Path when peer is two-byte-only.
    #[test]
    fn test_route_v6_to_attributes_includes_as4path_for_two_byte_peer() {
        use pathvector_rib::RouteBuilder;
        use pathvector_types::{AsPath, Asn};
        let n = nlri6("2001:db8::/32");
        // A 4-byte ASN triggers AS4_PATH when the peer is two-byte-only.
        let path = AsPath::from_sequence(vec![Asn::new(131_072)]); // 0x0002_0000 — four-byte
        let route = RouteBuilder::new(n, pathvector_types::Origin::Igp, path)
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        let (attrs, _) = route_v6_to_attributes(&route, PeerType::External, false);
        assert!(
            attrs.iter().any(|a| matches!(a, PathAttribute::As4Path(_))),
            "As4Path must be present when 4-byte ASNs are downgraded for a two-byte peer"
        );
    }
}

#[cfg(test)]
mod prop_tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pathvector_rib::RouteBuilder;
    use pathvector_session::message::{BgpMessage, MAX_LEN, PathAttribute, Prefix};
    use pathvector_types::{AsPath, NextHop, Nlri, Origin, PeerType};
    use proptest::prelude::*;
    use tokio::sync::mpsc;

    use super::{PrefixDecision, PrefixDecisionV6, flush_updates, flush_updates_v6};

    // ── Arbitrary generators ─────────────────────────────────────────────────

    fn arb_nlri_v4() -> impl Strategy<Value = Nlri<Ipv4Addr>> {
        (any::<[u8; 4]>(), 0u8..=32u8).prop_map(|(octets, len)| {
            // Mask to the prefix length so the NLRI is well-formed.
            let addr = if len == 0 {
                Ipv4Addr::UNSPECIFIED
            } else {
                let bits = u32::from_be_bytes(octets);
                let mask = !0u32 << (32 - len);
                Ipv4Addr::from(bits & mask)
            };
            Nlri::new(addr, len).unwrap()
        })
    }

    fn arb_nlri_v6() -> impl Strategy<Value = Nlri<Ipv6Addr>> {
        (any::<[u8; 16]>(), 0u8..=128u8).prop_map(|(octets, len)| {
            let addr = if len == 0 {
                Ipv6Addr::from([0u8; 16])
            } else {
                let bits = u128::from_be_bytes(octets);
                let mask = !0u128 << (128 - len);
                Ipv6Addr::from((bits & mask).to_be_bytes())
            };
            Nlri::new(addr, len).unwrap()
        })
    }

    fn arb_decision_v4() -> impl Strategy<Value = PrefixDecision> {
        prop_oneof![
            arb_nlri_v4().prop_map(|nlri| PrefixDecision::Announce(
                RouteBuilder::new(nlri, Origin::Igp, AsPath::new()).build()
            )),
            arb_nlri_v4().prop_map(PrefixDecision::Withdraw),
            Just(PrefixDecision::NoChange),
        ]
    }

    fn arb_decision_v6() -> impl Strategy<Value = PrefixDecisionV6> {
        let nh: Ipv6Addr = "2001:db8::1".parse().unwrap();
        prop_oneof![
            arb_nlri_v6().prop_map(move |nlri| PrefixDecisionV6::Announce(
                RouteBuilder::new(nlri, Origin::Igp, AsPath::new())
                    .next_hop(NextHop::V6(nh))
                    .build()
            )),
            arb_nlri_v6().prop_map(PrefixDecisionV6::Withdraw),
            Just(PrefixDecisionV6::NoChange),
        ]
    }

    // ── IPv4 flush_updates properties ────────────────────────────────────────

    proptest! {
        /// No UPDATE message may exceed `max_len` bytes on the wire.
        #[test]
        fn prop_flush_updates_no_message_exceeds_max_len(
            decisions in proptest::collection::vec(arb_decision_v4(), 0..=200),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build().unwrap();
            rt.block_on(async {
                let (tx, mut rx) = mpsc::channel(512);
                let _ = flush_updates(decisions, MAX_LEN, &tx, PeerType::External, true);
                while let Ok(msg) = rx.try_recv() {
                    let wire = BgpMessage::Update(msg).encode();
                    prop_assert!(wire.len() <= MAX_LEN,
                        "encoded UPDATE {} bytes > MAX_LEN {}", wire.len(), MAX_LEN);
                }
                Ok(())
            })?;
        }

        /// Every Announce decision appears in exactly one outbound UPDATE.
        #[test]
        fn prop_flush_updates_all_announces_sent(
            decisions in proptest::collection::vec(arb_decision_v4(), 0..=100),
        ) {
            let expected_announces: Vec<Nlri<Ipv4Addr>> = decisions.iter()
                .filter_map(|d| if let PrefixDecision::Announce(r) = d { Some(r.nlri) } else { None })
                .collect();

            let rt = tokio::runtime::Builder::new_current_thread()
                .build().unwrap();
            rt.block_on(async {
                let (tx, mut rx) = mpsc::channel(512);
                let _ = flush_updates(decisions, MAX_LEN, &tx, PeerType::External, true);
                let mut sent: Vec<Nlri<Ipv4Addr>> = Vec::new();
                while let Ok(msg) = rx.try_recv() {
                    sent.extend(msg.announced);
                }
                let mut sent_sorted = sent.clone();
                let mut expected_sorted = expected_announces.clone();
                sent_sorted.sort_by_key(|n| format!("{n}"));
                expected_sorted.sort_by_key(|n| format!("{n}"));
                prop_assert_eq!(sent_sorted, expected_sorted,
                    "every announced NLRI must appear in an outbound UPDATE");
                Ok(())
            })?;
        }

        /// Every Withdraw decision appears in exactly one outbound WITHDRAW.
        #[test]
        fn prop_flush_updates_all_withdrawals_sent(
            decisions in proptest::collection::vec(arb_decision_v4(), 0..=100),
        ) {
            let expected_withdrawals: Vec<Nlri<Ipv4Addr>> = decisions.iter()
                .filter_map(|d| if let PrefixDecision::Withdraw(n) = d { Some(*n) } else { None })
                .collect();

            let rt = tokio::runtime::Builder::new_current_thread()
                .build().unwrap();
            rt.block_on(async {
                let (tx, mut rx) = mpsc::channel(512);
                let _ = flush_updates(decisions, MAX_LEN, &tx, PeerType::External, true);
                let mut sent: Vec<Nlri<Ipv4Addr>> = Vec::new();
                while let Ok(msg) = rx.try_recv() {
                    sent.extend(msg.withdrawn);
                }
                let mut sent_sorted = sent.clone();
                let mut expected_sorted = expected_withdrawals.clone();
                sent_sorted.sort_by_key(|n| format!("{n}"));
                expected_sorted.sort_by_key(|n| format!("{n}"));
                prop_assert_eq!(sent_sorted, expected_sorted,
                    "every withdrawn NLRI must appear in an outbound WITHDRAW");
                Ok(())
            })?;
        }
    }

    // ── IPv6 flush_updates_v6 properties ─────────────────────────────────────

    proptest! {
        /// No IPv6 UPDATE message may exceed MAX_LEN bytes on the wire.
        #[test]
        fn prop_flush_updates_v6_no_message_exceeds_max_len(
            decisions in proptest::collection::vec(arb_decision_v6(), 0..=100),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build().unwrap();
            rt.block_on(async {
                let (tx, mut rx) = mpsc::channel(512);
                let _ = flush_updates_v6(decisions, MAX_LEN, &tx, PeerType::External, true);
                while let Ok(msg) = rx.try_recv() {
                    let wire = BgpMessage::Update(msg).encode();
                    prop_assert!(wire.len() <= MAX_LEN,
                        "encoded IPv6 UPDATE {} bytes > MAX_LEN {}", wire.len(), MAX_LEN);
                }
                Ok(())
            })?;
        }

        /// Every IPv6 Announce decision appears in exactly one outbound MP_REACH UPDATE.
        #[test]
        fn prop_flush_updates_v6_all_announces_sent(
            decisions in proptest::collection::vec(arb_decision_v6(), 0..=100),
        ) {
            let expected: Vec<Nlri<Ipv6Addr>> = decisions.iter()
                .filter_map(|d| if let PrefixDecisionV6::Announce(r) = d { Some(r.nlri) } else { None })
                .collect();

            let rt = tokio::runtime::Builder::new_current_thread()
                .build().unwrap();
            rt.block_on(async {
                let (tx, mut rx) = mpsc::channel(512);
                let _ = flush_updates_v6(decisions, MAX_LEN, &tx, PeerType::External, true);
                let mut sent: Vec<Nlri<Ipv6Addr>> = Vec::new();
                while let Ok(msg) = rx.try_recv() {
                    for attr in &msg.attributes {
                        if let PathAttribute::MpReachNlri(mp) = attr {
                            for p in &mp.prefixes {
                                if let Prefix::V6(nlri) = p {
                                    sent.push(*nlri);
                                }
                            }
                        }
                    }
                }
                let mut sent_sorted = sent.clone();
                let mut expected_sorted = expected.clone();
                sent_sorted.sort_by_key(|n| format!("{n}"));
                expected_sorted.sort_by_key(|n| format!("{n}"));
                prop_assert_eq!(sent_sorted, expected_sorted,
                    "every IPv6 announced NLRI must appear in an outbound MP_REACH UPDATE");
                Ok(())
            })?;
        }

        /// Every IPv6 Withdraw decision appears in exactly one outbound MP_UNREACH UPDATE.
        #[test]
        fn prop_flush_updates_v6_all_withdrawals_sent(
            decisions in proptest::collection::vec(arb_decision_v6(), 0..=100),
        ) {
            let expected: Vec<Nlri<Ipv6Addr>> = decisions.iter()
                .filter_map(|d| if let PrefixDecisionV6::Withdraw(n) = d { Some(*n) } else { None })
                .collect();

            let rt = tokio::runtime::Builder::new_current_thread()
                .build().unwrap();
            rt.block_on(async {
                let (tx, mut rx) = mpsc::channel(512);
                let _ = flush_updates_v6(decisions, MAX_LEN, &tx, PeerType::External, true);
                let mut sent: Vec<Nlri<Ipv6Addr>> = Vec::new();
                while let Ok(msg) = rx.try_recv() {
                    for attr in &msg.attributes {
                        if let PathAttribute::MpUnreachNlri(mp) = attr {
                            for p in &mp.prefixes {
                                if let Prefix::V6(nlri) = p {
                                    sent.push(*nlri);
                                }
                            }
                        }
                    }
                }
                let mut sent_sorted = sent.clone();
                let mut expected_sorted = expected.clone();
                sent_sorted.sort_by_key(|n| format!("{n}"));
                expected_sorted.sort_by_key(|n| format!("{n}"));
                prop_assert_eq!(sent_sorted, expected_sorted,
                    "every IPv6 withdrawn NLRI must appear in an outbound MP_UNREACH UPDATE");
                Ok(())
            })?;
        }
    }
}

// ── AS_TRANS / AS4_PATH (RFC 6793 §4) ────────────────────────────────────────
#[cfg(test)]
mod route_to_attributes_tests {
    use std::net::Ipv4Addr;

    use pathvector_rib::RouteBuilder;
    use pathvector_session::message::PathAttribute;
    use pathvector_types::{AsPath, Asn, NextHop, Nlri, Origin, PeerType};

    use super::route_to_attributes;

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn route_with_asns(asns: Vec<Asn>) -> pathvector_rib::Route<Ipv4Addr> {
        RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::from_sequence(asns))
            .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .build()
    }

    fn as_path_asns(attrs: &[PathAttribute]) -> Vec<Asn> {
        attrs
            .iter()
            .find_map(|a| {
                if let PathAttribute::AsPath(p) = a {
                    Some(p.clone())
                } else {
                    None
                }
            })
            .expect("AS_PATH must be present")
            .segments()
            .iter()
            .flat_map(|s| s.asns().to_vec())
            .collect()
    }

    fn as4_path_asns(attrs: &[PathAttribute]) -> Option<Vec<Asn>> {
        attrs.iter().find_map(|a| {
            if let PathAttribute::As4Path(p) = a {
                Some(
                    p.segments()
                        .iter()
                        .flat_map(|s| s.asns().to_vec())
                        .collect(),
                )
            } else {
                None
            }
        })
    }

    /// 2-byte-only peer with all-2-byte ASNs: no AS_TRANS substitution, no AS4_PATH.
    #[test]
    fn two_byte_asns_to_two_byte_peer_no_trans_no_as4_path() {
        let route = route_with_asns(vec![Asn::new(65001), Asn::new(65002)]);
        let attrs = route_to_attributes(&route, PeerType::External, false);

        let asns = as_path_asns(&attrs);
        assert!(
            !asns.contains(&Asn::TRANS),
            "no AS_TRANS for all-2-byte path"
        );
        assert!(asns.contains(&Asn::new(65001)));

        assert!(
            as4_path_asns(&attrs).is_none(),
            "no AS4_PATH when no substitution occurred"
        );
    }

    /// 4-byte ASN sent to 2-byte-only peer: AS_TRANS substituted in AS_PATH;
    /// original ASN preserved in AS4_PATH (RFC 6793 §4).
    #[test]
    fn four_byte_asn_to_two_byte_peer_inserts_trans_and_as4_path() {
        let route = route_with_asns(vec![Asn::new(65001), Asn::new(131_072)]);
        let attrs = route_to_attributes(&route, PeerType::External, false);

        let wire_asns = as_path_asns(&attrs);
        assert!(
            wire_asns.contains(&Asn::TRANS),
            "AS_TRANS must replace 4-byte ASN in AS_PATH"
        );
        assert!(
            !wire_asns.contains(&Asn::new(131_072)),
            "original 4-byte ASN must not appear in wire AS_PATH"
        );

        let as4_asns =
            as4_path_asns(&attrs).expect("AS4_PATH must be present for 2-byte-only peer");
        assert!(
            as4_asns.contains(&Asn::new(131_072)),
            "original 4-byte ASN must be preserved in AS4_PATH"
        );
    }

    /// 4-byte ASN sent to 4-byte-capable peer: no substitution, no AS4_PATH.
    #[test]
    fn four_byte_asn_to_four_byte_peer_no_trans_no_as4_path() {
        let route = route_with_asns(vec![Asn::new(65001), Asn::new(131_072)]);
        let attrs = route_to_attributes(&route, PeerType::External, true);

        let wire_asns = as_path_asns(&attrs);
        assert!(
            !wire_asns.contains(&Asn::TRANS),
            "no AS_TRANS for 4-byte-capable peer"
        );
        assert!(
            wire_asns.contains(&Asn::new(131_072)),
            "original 4-byte ASN preserved"
        );

        assert!(
            as4_path_asns(&attrs).is_none(),
            "no AS4_PATH for 4-byte-capable peer"
        );
    }

    /// AS4_PATH must appear as the last attribute so 2-byte speakers that don't
    /// understand it can skip it without affecting earlier well-known attributes.
    #[test]
    fn as4_path_is_last_attribute_for_two_byte_peer() {
        let route = route_with_asns(vec![Asn::new(131_072)]);
        let attrs = route_to_attributes(&route, PeerType::External, false);
        assert!(
            matches!(attrs.last(), Some(PathAttribute::As4Path(_))),
            "AS4_PATH must be the last attribute"
        );
    }

    /// All-4-byte path sent to 2-byte peer: every ASN becomes AS_TRANS, all
    /// original ASNs are recoverable from AS4_PATH.
    #[test]
    fn all_four_byte_asns_to_two_byte_peer_full_trans_substitution() {
        let asns = vec![Asn::new(131_072), Asn::new(262_144), Asn::new(393_216)];
        let route = route_with_asns(asns.clone());
        let attrs = route_to_attributes(&route, PeerType::External, false);

        let wire_asns = as_path_asns(&attrs);
        assert!(
            wire_asns.iter().all(|&a| a == Asn::TRANS),
            "every wire ASN must be AS_TRANS when all ASNs are 4-byte"
        );

        let as4_asns = as4_path_asns(&attrs).expect("AS4_PATH must be present");
        assert_eq!(
            as4_asns, asns,
            "AS4_PATH must preserve all original 4-byte ASNs in order"
        );
    }
}

#[cfg(test)]
mod propagate_tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pathvector_policy::{DefaultAction, Policy};
    use pathvector_rib::{AdjRibOut, LocRib, PeerId, RouteBuilder};
    use pathvector_types::{AsPath, NextHop, Nlri, Origin, PeerType};

    use super::{PrefixDecision, PrefixDecisionV6, propagate_prefix, propagate_prefix_v6};

    fn peer(ip: &str) -> PeerId {
        PeerId::from(ip.parse::<Ipv4Addr>().unwrap())
    }

    fn nlri4(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn nlri6(s: &str) -> Nlri<Ipv6Addr> {
        s.parse().unwrap()
    }

    fn route_v4(n: Nlri<Ipv4Addr>) -> pathvector_rib::Route<Ipv4Addr> {
        RouteBuilder::new(n, Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .peer_type(PeerType::External)
            .build()
    }

    fn route_v6(n: Nlri<Ipv6Addr>) -> pathvector_rib::Route<Ipv6Addr> {
        RouteBuilder::new(n, Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .peer_type(PeerType::External)
            .build()
    }

    fn accept_policy() -> Policy<pathvector_rib::Route<Ipv4Addr>> {
        Policy::new(DefaultAction::Accept)
    }

    // ── propagate_prefix ─────────────────────────────────────────────────────

    /// Split-horizon Withdraw: when the best route came from the target peer and
    /// there was a previously advertised route, propagate_prefix must withdraw it.
    #[test]
    fn test_propagate_prefix_split_horizon_withdraw() {
        let n = nlri4("10.0.0.0/8");
        let src = peer("10.0.0.2");
        let mut loc_rib: LocRib<Ipv4Addr> = LocRib::new();
        loc_rib.insert(src, route_v4(n), &pathvector_rib::oracle::AlwaysReachable);

        // adj_rib_out for the same source peer — split-horizon applies.
        let mut adj_out = AdjRibOut::new(src, PeerType::External);

        // Pre-advertise the route so withdraw() returns Some.
        adj_out.insert(route_v4(n));

        let decision = propagate_prefix(
            n,
            &loc_rib,
            &mut adj_out,
            &accept_policy(),
            PeerType::External,
            65001,
            Ipv4Addr::new(10, 1, 0, 1),
        );
        assert!(
            matches!(decision, PrefixDecision::Withdraw(_)),
            "split-horizon must produce Withdraw when route was previously advertised"
        );
    }

    // ── propagate_prefix_v6 ──────────────────────────────────────────────────

    /// Split-horizon Withdraw (v6): same as above for IPv6.
    #[test]
    fn test_propagate_prefix_v6_split_horizon_withdraw() {
        let n = nlri6("2001:db8::/32");
        let src = peer("10.0.0.2");
        let mut loc_rib: LocRib<Ipv6Addr> = LocRib::new();
        loc_rib.insert(src, route_v6(n), &pathvector_rib::oracle::AlwaysReachable);

        let mut adj_out = AdjRibOut::new(src, PeerType::External);
        adj_out.insert(route_v6(n));

        let decision = propagate_prefix_v6(
            n,
            &loc_rib,
            &mut adj_out,
            PeerType::External,
            65001,
            Some("2001:db8::ff".parse().unwrap()),
        );
        assert!(
            matches!(decision, PrefixDecisionV6::Withdraw(_)),
            "split-horizon must produce Withdraw for v6 when route was previously advertised"
        );
    }

    /// NoChange (v6): inserting the same route twice yields NoChange on the second call.
    #[test]
    fn test_propagate_prefix_v6_no_change_when_route_unchanged() {
        let n = nlri6("2001:db8::/32");
        let src = peer("10.0.0.2");
        let dest = peer("10.0.0.3");
        let mut loc_rib: LocRib<Ipv6Addr> = LocRib::new();
        loc_rib.insert(src, route_v6(n), &pathvector_rib::oracle::AlwaysReachable);

        let mut adj_out = AdjRibOut::new(dest, PeerType::External);

        // First call: Announce.
        let _ = propagate_prefix_v6(
            n,
            &loc_rib,
            &mut adj_out,
            PeerType::External,
            65001,
            Some("2001:db8::ff".parse().unwrap()),
        );

        // Second call with same best route: NoChange.
        let decision = propagate_prefix_v6(
            n,
            &loc_rib,
            &mut adj_out,
            PeerType::External,
            65001,
            Some("2001:db8::ff".parse().unwrap()),
        );
        assert!(
            matches!(decision, PrefixDecisionV6::NoChange),
            "re-propagating the same route must produce NoChange"
        );
    }

    /// Filtered(Some) (v6): iBGP split horizon evicts a previously stored route.
    #[test]
    fn test_propagate_prefix_v6_ibgp_filtered_with_eviction() {
        let n = nlri6("2001:db8::/32");
        let src = peer("10.0.0.2");
        let ibgp_dest = peer("10.0.0.3");

        // Route comes from an iBGP peer.
        let ibgp_route = RouteBuilder::new(n, Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .peer_type(PeerType::Internal)
            .build();

        let mut loc_rib: LocRib<Ipv6Addr> = LocRib::new();
        loc_rib.insert(
            src,
            ibgp_route.clone(),
            &pathvector_rib::oracle::AlwaysReachable,
        );

        // adj_rib_out for an iBGP peer — iBGP split horizon applies.
        let mut adj_out = AdjRibOut::new(ibgp_dest, PeerType::Internal);

        // Pre-seed adj_rib_out by forcing a direct insert (bypassing propagate),
        // so that AdjRibOut::insert later returns Filtered(Some(_)).
        let seed_route = RouteBuilder::new(n, Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .peer_type(PeerType::External) // eBGP type passes the filter
            .build();
        adj_out.insert(seed_route);

        // Now propagate with an iBGP-sourced route → AdjRibOut::insert returns
        // Filtered(Some(prev)) because peer_type == Internal on both sides.
        let decision =
            propagate_prefix_v6(n, &loc_rib, &mut adj_out, PeerType::Internal, 65001, None);
        assert!(
            matches!(decision, PrefixDecisionV6::Withdraw(_)),
            "iBGP split-horizon with evicted route must produce Withdraw"
        );
    }

    /// Filtered(None) (v6): iBGP split horizon with no previous entry → NoChange.
    #[test]
    fn test_propagate_prefix_v6_ibgp_filtered_no_prior_entry() {
        let n = nlri6("2001:db8::/32");
        let src = peer("10.0.0.2");
        let ibgp_dest = peer("10.0.0.3");

        let ibgp_route = RouteBuilder::new(n, Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .peer_type(PeerType::Internal)
            .build();

        let mut loc_rib: LocRib<Ipv6Addr> = LocRib::new();
        loc_rib.insert(src, ibgp_route, &pathvector_rib::oracle::AlwaysReachable);

        // Empty adj_rib_out for an iBGP peer → Filtered(None).
        let mut adj_out = AdjRibOut::new(ibgp_dest, PeerType::Internal);

        let decision =
            propagate_prefix_v6(n, &loc_rib, &mut adj_out, PeerType::Internal, 65001, None);
        assert!(
            matches!(decision, PrefixDecisionV6::NoChange),
            "iBGP split-horizon with no prior entry must produce NoChange"
        );
    }
}
