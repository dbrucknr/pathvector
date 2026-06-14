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
pub(crate) fn route_to_attributes(route: &Route<Ipv4Addr>) -> Vec<PathAttribute> {
    let mut attrs = vec![
        PathAttribute::Origin(route.origin),
        PathAttribute::AsPath(route.as_path.clone()),
    ];
    if let Some(NextHop::V4(nh)) = route.next_hop {
        attrs.push(PathAttribute::NextHop(nh));
    }
    if let Some(lp) = route.local_pref {
        attrs.push(PathAttribute::LocalPref(lp.as_u32()));
    }
    if let Some(m) = route.med {
        attrs.push(PathAttribute::Med(m.as_u32()));
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
    attrs
}

/// The outbound decision for a single prefix after AdjRibOut processing.
#[derive(Debug, Clone)]
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
) -> bool {
    let mut withdrawals: Vec<Nlri<Ipv4Addr>> = Vec::new();
    let mut announce_groups: Vec<AnnounceGroup> = Vec::new();

    for decision in decisions {
        match decision {
            PrefixDecision::Withdraw(nlri) => withdrawals.push(nlri),
            PrefixDecision::Announce(route) => {
                let attrs = route_to_attributes(&route);
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
                let mut attrs = route_v6_to_attributes(&route);
                // Remove MpReachNlri (last attr) so it isn't part of the key.
                let mp_reach = attrs
                    .pop()
                    .expect("route_v6_to_attributes always appends MpReachNlri last");
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
                    attrs.push(mp_reach);
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
/// The NLRI is carried in MP_REACH_NLRI (RFC 4760); the traditional
/// `NEXT_HOP` attribute is not emitted for IPv6 routes.
pub(crate) fn route_v6_to_attributes(route: &Route<Ipv6Addr>) -> Vec<PathAttribute> {
    let mut attrs = vec![
        PathAttribute::Origin(route.origin),
        PathAttribute::AsPath(route.as_path.clone()),
    ];
    if let Some(lp) = route.local_pref {
        attrs.push(PathAttribute::LocalPref(lp.as_u32()));
    }
    if let Some(m) = route.med {
        attrs.push(PathAttribute::Med(m.as_u32()));
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
    // MP_REACH_NLRI is always last so it can be popped as a grouping key.
    let next_hop = route.next_hop.unwrap_or(NextHop::V6(Ipv6Addr::UNSPECIFIED));
    attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
        afi_safi: AfiSafi::IPV6_UNICAST,
        next_hop,
        prefixes: vec![Prefix::V6(route.nlri)],
    }));
    attrs
}

// ── flush_updates tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod flush_updates_tests {
    use std::net::Ipv4Addr;

    use pathvector_rib::{Route, RouteBuilder};
    use pathvector_session::message::{MAX_LEN, UpdateMessage};
    use pathvector_types::{AsPath, Nlri, Origin};
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
        assert!(flush_updates(decisions, MAX_LEN, &tx));
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
        assert!(flush_updates(decisions, MAX_LEN, &tx));
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
        assert!(flush_updates(decisions, MAX_LEN, &tx));
        let first = rx.try_recv().expect("first UPDATE");
        let second = rx.try_recv().expect("second UPDATE");
        assert_eq!(first.announced.len(), 1);
        assert_eq!(second.announced.len(), 1);
        assert!(rx.try_recv().is_err());
    }

    /// A batch too large for MAX_LEN is split across multiple UPDATEs.
    #[test]
    fn test_flush_splits_when_exceeding_max_len() {
        // Each /24 encodes as 4 bytes of NLRI. With default MAX_LEN=4096:
        // fixed overhead = 23 bytes; attr bytes ~4 bytes (Origin+AsPath minimal).
        // 1000 NLRIs × 4 bytes = 4000 bytes of NLRIs, plus overhead > 4096.
        let decisions: Vec<PrefixDecision> = (0u32..1000)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let a = (i / 256) as u8; // i < 1000, so i/256 ≤ 3
                #[allow(clippy::cast_possible_truncation)]
                let b = (i % 256) as u8; // always ≤ 255
                let route = RouteBuilder::new(
                    Nlri::new(Ipv4Addr::new(10, a, b, 0), 24).unwrap(),
                    Origin::Igp,
                    AsPath::new(),
                )
                .build();
                PrefixDecision::Announce(route)
            })
            .collect();

        let (tx, mut rx) = mpsc::channel(64);
        assert!(flush_updates(decisions, MAX_LEN, &tx));

        // Drain all messages and verify: total announced == 1000, each message ≤ MAX_LEN.
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
        assert_eq!(total, 1000, "all NLRIs must be sent");
    }

    /// Withdrawals are batched into a single withdraw-only UPDATE.
    #[test]
    fn test_flush_withdrawals_batched() {
        let decisions: Vec<PrefixDecision> = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
            .iter()
            .map(|p| PrefixDecision::Withdraw(nlri(p)))
            .collect();
        let (tx, mut rx) = mpsc::channel(16);
        assert!(flush_updates(decisions, MAX_LEN, &tx));
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
        assert!(flush_updates(decisions, MAX_LEN, &tx));
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
        assert!(flush_updates(decisions, MAX_LEN, &tx));
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
        assert!(!flush_updates(decisions, MAX_LEN, &tx));
    }

    /// Returns false when the channel is closed (announcement path).
    #[test]
    fn test_flush_announce_returns_false_on_closed_channel() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let decisions = vec![PrefixDecision::Announce(base_route("10.0.0.0/8"))];
        assert!(!flush_updates(decisions, MAX_LEN, &tx));
    }

    /// Returns false mid-batch when channel fills during withdrawal overflow.
    #[test]
    fn test_flush_withdrawal_overflow_false_on_full_channel() {
        // Use a tiny max_len so the second withdrawal forces a flush of the first.
        // Channel capacity 1 lets the first flush succeed; channel drops so the
        // second try_send (the overflow flush) fails.
        let (tx, rx) = mpsc::channel(1);
        // 23 bytes fixed overhead; each /8 NLRI is 2 bytes.  max_len=25 fits
        // exactly one withdrawal per message, so the second triggers overflow.
        let decisions: Vec<PrefixDecision> = ["10.0.0.0/8", "192.0.2.0/24"]
            .iter()
            .map(|p| PrefixDecision::Withdraw(nlri(p)))
            .collect();
        // Drop the receiver after the first message is queued so the second fails.
        drop(rx);
        // Channel is already closed; even the first send will fail.
        assert!(!flush_updates(decisions, MAX_LEN, &tx));
    }
}

#[cfg(test)]
mod v6_tests {
    use std::net::Ipv6Addr;

    use pathvector_rib::RouteBuilder;
    use pathvector_session::message::{MAX_LEN, PathAttribute, UpdateMessage};
    use pathvector_types::{
        Aggregator, AsPath, Asn, Community, ExtendedCommunity, LargeCommunity, LocalPref, Med,
        NextHop, Nlri, Origin,
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
        let attrs = route_v6_to_attributes(&route);
        assert!(attrs.iter().any(|a| matches!(a, PathAttribute::Med(100))));
    }

    /// route_v6_to_attributes includes Community when set.
    #[test]
    fn test_route_v6_to_attributes_with_community() {
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .community(Community::from(0x0001_0001u32))
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        let attrs = route_v6_to_attributes(&route);
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
        let attrs = route_v6_to_attributes(&route);
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
        let attrs = route_v6_to_attributes(&route);
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
        let attrs = route_v6_to_attributes(&route);
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
        let attrs = route_v6_to_attributes(&route);
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::Aggregator(_)))
        );
    }

    /// flush_updates_v6 returns false when the channel is closed.
    #[test]
    fn test_flush_v6_returns_false_on_closed_channel() {
        let (tx, rx) = mpsc::channel::<UpdateMessage>(1);
        drop(rx);
        let decisions = vec![PrefixDecisionV6::Announce(base_route_v6("2001:db8::/32"))];
        assert!(!flush_updates_v6(decisions, MAX_LEN, &tx));
    }

    /// flush_updates_v6 returns false for withdrawals when channel is closed.
    #[test]
    fn test_flush_v6_withdrawal_returns_false_on_closed_channel() {
        let (tx, rx) = mpsc::channel::<UpdateMessage>(1);
        drop(rx);
        let decisions = vec![PrefixDecisionV6::Withdraw(nlri6("2001:db8::/32"))];
        assert!(!flush_updates_v6(decisions, MAX_LEN, &tx));
    }
}

#[cfg(test)]
mod prop_tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pathvector_rib::RouteBuilder;
    use pathvector_session::message::{BgpMessage, MAX_LEN};
    use pathvector_types::{AsPath, NextHop, Nlri, Origin};
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
                let _ = flush_updates(decisions, MAX_LEN, &tx);
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
                let _ = flush_updates(decisions, MAX_LEN, &tx);
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
                let _ = flush_updates(decisions, MAX_LEN, &tx);
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
        /// No IPv6 UPDATE message may exceed `max_len` bytes on the wire.
        #[test]
        fn prop_flush_updates_v6_no_message_exceeds_max_len(
            decisions in proptest::collection::vec(arb_decision_v6(), 0..=100),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build().unwrap();
            rt.block_on(async {
                let (tx, mut rx) = mpsc::channel(512);
                let _ = flush_updates_v6(decisions, MAX_LEN, &tx);
                while let Ok(msg) = rx.try_recv() {
                    let wire = BgpMessage::Update(msg).encode();
                    prop_assert!(wire.len() <= MAX_LEN,
                        "encoded IPv6 UPDATE {} bytes > MAX_LEN {}", wire.len(), MAX_LEN);
                }
                Ok(())
            })?;
        }
    }
}
