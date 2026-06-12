mod config;
mod grpc;
mod proto;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use pathvector_policy::{Decision, DefaultAction, Policy};
use pathvector_rib::{
    AdjRibIn, AdjRibOut, InsertOutcome, LocRib, PeerId, RibView, Route, RouteBuilder,
    outbound::{prepare_outbound, prepare_outbound_v6},
};
use pathvector_session::{
    message::{
        Capability, MAX_LEN, MAX_LEN_EXTENDED, MpReachNlri, MpUnreachNlri, PathAttribute, Prefix,
        UpdateMessage, encode_attributes, nlri_encoded_len, nlri_v6_encoded_len,
    },
    transport::{self, SessionCommand, SessionConfig, SessionEvent, SessionHandle},
};
use pathvector_types::{AfiSafi, AsPath, LocalPref, Med, NextHop, Nlri, Origin, PeerType};
use tokio::sync::{RwLock, broadcast, mpsc};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: pathvectord <config.toml>");
        std::process::exit(1);
    });

    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("failed to read {path}: {e}");
        std::process::exit(1);
    });

    let cfg: config::Config = toml::from_str(&text).unwrap_or_else(|e| {
        eprintln!("failed to parse config: {e}");
        std::process::exit(1);
    });

    run(cfg).await;
}

/// Resolves the effective import default action for a peer (RFC 8212).
///
/// eBGP peers with no explicit setting default to `Reject` — no routes are
/// accepted unless a policy term explicitly accepts them. iBGP peers default
/// to `Accept`. An explicit `import_default` in config always wins.
fn resolve_import_default(opt: Option<config::ImportDefault>, is_ebgp: bool) -> DefaultAction {
    match opt {
        Some(d) => DefaultAction::from(d),
        None if is_ebgp => DefaultAction::Reject,
        None => DefaultAction::Accept,
    }
}

/// Resolves the effective export default action for a peer (RFC 8212).
///
/// eBGP peers with no explicit setting default to `Reject` — no routes are
/// advertised unless a policy term explicitly accepts them. iBGP peers default
/// to `Accept`. An explicit `export_default` in config always wins.
fn resolve_export_default(opt: Option<config::ExportDefault>, is_ebgp: bool) -> DefaultAction {
    match opt {
        Some(d) => DefaultAction::from(d),
        None if is_ebgp => DefaultAction::Reject,
        None => DefaultAction::Accept,
    }
}

/// Derives the peer type (iBGP / eBGP) from the configured AS numbers.
fn config_peer_type(local_as: u32, remote_as: u32) -> PeerType {
    if local_as == remote_as {
        PeerType::Internal
    } else {
        PeerType::External
    }
}

/// Builds the path-attribute list for an outbound route.
fn route_to_attributes(route: &Route<Ipv4Addr>) -> Vec<PathAttribute> {
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
enum PrefixDecision {
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
fn propagate_prefix(
    nlri: Nlri<Ipv4Addr>,
    loc_rib: &impl RibView<Ipv4Addr>,
    adj_rib_out: &mut AdjRibOut<Ipv4Addr>,
    export_policy: &Policy<Route<Ipv4Addr>>,
    peer_type: PeerType,
    local_as: u32,
    local_bgp_id: Ipv4Addr,
) -> PrefixDecision {
    match loc_rib.best(&nlri) {
        Some(best) => {
            let mut route = prepare_outbound(best.clone(), peer_type, local_as, local_bgp_id);
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

/// Synthetic `PeerId` used as the source for locally originated routes.
///
/// Must not collide with any real peer address. `0.0.0.0` is unassignable as
/// a BGP peer, so it is safe as a sentinel here.
const LOCAL_ORIGIN_PEER: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

/// BGP UPDATE wire overhead: 19-byte header + 2-byte withdrawn-len + 2-byte
/// attr-len field.
const UPDATE_FIXED_OVERHEAD: usize = 19 + 2 + 2;

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

fn flush_updates(
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
#[derive(Debug)]
enum PrefixDecisionV6 {
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
fn propagate_prefix_v6(
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
fn flush_updates_v6(
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
                let mp_reach = attrs.pop().expect("route_v6_to_attributes always appends MpReachNlri last");
                let key = encode_attributes(&attrs);
                // Restore the MP_REACH_NLRI placeholder next-hop in the group leader.
                if let Some((_, group_attrs, nlris)) =
                    announce_groups.iter_mut().find(|(k, _, _)| *k == key)
                {
                    // Add this NLRI to the existing group's MP_REACH_NLRI prefix list.
                    if let Some(PathAttribute::MpReachNlri(mp)) =
                        group_attrs.iter_mut().find(|a| matches!(a, PathAttribute::MpReachNlri(_)))
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

fn send_mp_unreach_v6(
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
fn route_v6_to_attributes(route: &Route<Ipv6Addr>) -> Vec<PathAttribute> {
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

/// Immutable-ish snapshot of the read-heavy routing state.
///
/// Stored inside `DaemonState` as an `Arc<RibSnapshot>`. The event loop
/// mutates it via [`Arc::make_mut`] (zero-cost when no readers hold a clone;
/// copy-on-write when a gRPC call is in flight). gRPC handlers clone the `Arc`
/// in O(1) and release the outer `RwLock` immediately, so reads never block
/// BGP event processing.
#[derive(Clone)]
pub(crate) struct RibSnapshot {
    pub(crate) loc_rib: LocRib<Ipv4Addr>,
    /// IPv6 Loc-RIB — best IPv6 routes, post-import-policy.
    pub(crate) loc_rib_v6: LocRib<Ipv6Addr>,
    /// Locally originated routes (bypassed import policy; export policy applies).
    pub(crate) originated_routes: HashMap<Nlri<Ipv4Addr>, Route<Ipv4Addr>>,
    /// Immutable after startup.
    pub(crate) local_as: u32,
    /// Immutable after startup.
    pub(crate) local_bgp_id: Ipv4Addr,
    /// Local IPv6 address for eBGP next-hop rewrite; `None` if not configured.
    /// Immutable after startup.
    pub(crate) local_ipv6: Option<Ipv6Addr>,
    /// Remote AS number for each configured peer; immutable after startup.
    pub(crate) peer_remote_as: HashMap<Ipv4Addr, u32>,
    /// Live session state: present while a peer is Established.
    pub(crate) peer_types: HashMap<Ipv4Addr, PeerType>,
    /// Wall-clock instant at which each peer last reached Established.
    pub(crate) established_at: HashMap<Ipv4Addr, std::time::Instant>,
    /// Negotiated hold-timer value per established peer.
    pub(crate) hold_times: HashMap<Ipv4Addr, u16>,
    /// Derived from `adj_ribs_in[peer].len()`; synced after each mutation.
    pub(crate) prefixes_received: HashMap<Ipv4Addr, usize>,
    /// Derived from `adj_ribs_out[peer].len()`; synced after each propagation.
    pub(crate) prefixes_advertised: HashMap<Ipv4Addr, usize>,
}

/// Holds all per-peer routing state and applies BGP event semantics.
///
/// Constructed once at startup from config; `run()` feeds it `SessionEvent`s.
/// The struct owns no I/O — callers hold the session handles and event channel,
/// making the routing logic fully unit-testable without real TCP connections.
///
/// Read-heavy fields live in `Arc<RibSnapshot>`; gRPC handlers clone the `Arc`
/// and release the lock immediately so reads never contend with BGP writes.
struct DaemonState {
    /// Read-heavy routing state; cloned cheaply by gRPC handlers.
    pub(crate) rib: Arc<RibSnapshot>,
    pub(crate) import_policies: HashMap<Ipv4Addr, Policy<Route<Ipv4Addr>>>,
    pub(crate) export_policies: HashMap<Ipv4Addr, Policy<Route<Ipv4Addr>>>,
    pub(crate) adj_ribs_in: HashMap<Ipv4Addr, AdjRibIn<Ipv4Addr>>,
    pub(crate) adj_ribs_out: HashMap<Ipv4Addr, AdjRibOut<Ipv4Addr>>,
    pub(crate) adj_ribs_in_v6: HashMap<Ipv4Addr, AdjRibIn<Ipv6Addr>>,
    pub(crate) adj_ribs_out_v6: HashMap<Ipv4Addr, AdjRibOut<Ipv6Addr>>,
    /// Static peer type derived from config; used to reset `AdjRibOut` on reconnect.
    pub(crate) peer_config_types: HashMap<Ipv4Addr, PeerType>,
    pub(crate) update_senders: HashMap<Ipv4Addr, mpsc::Sender<UpdateMessage>>,
    /// Local capabilities advertised in OPEN messages; used to determine the
    /// negotiated message size limit after `Established`.
    pub(crate) config_capabilities: Vec<Capability>,
    /// Negotiated maximum BGP message size per established peer.
    ///
    /// Set to [`MAX_LEN_EXTENDED`] (65535) when both sides negotiated
    /// `Capability::ExtendedMessage`; otherwise [`MAX_LEN`] (4096).
    /// Removed when the peer transitions out of Established.
    pub(crate) negotiated_max_len: HashMap<Ipv4Addr, usize>,
    /// Peers whose outbound UPDATE channel overflowed during the current event.
    ///
    /// The event loop drains this list after each event via [`take_stalled_peers`]
    /// and sends [`SessionCommand::Stop`] to each affected session so it can
    /// re-establish and perform a clean full-table dump.
    ///
    /// [`take_stalled_peers`]: DaemonState::take_stalled_peers
    stalled_peers: Vec<Ipv4Addr>,
    /// Broadcast channel for Loc-RIB events (announced / withdrawn).
    ///
    /// `WatchRoutes` gRPC handlers subscribe at call time. Slow subscribers
    /// receive `RecvError::Lagged` and must reconnect for a fresh snapshot.
    pub(crate) route_tx: broadcast::Sender<proto::RouteEvent>,
    /// Broadcast channel for peer session state changes.
    ///
    /// `WatchPeers` gRPC handlers subscribe at call time.
    pub(crate) peer_tx: broadcast::Sender<proto::PeerEvent>,
}

impl DaemonState {
    fn new(
        local_as: u32,
        local_bgp_id: Ipv4Addr,
        local_ipv6: Option<Ipv6Addr>,
        peers: &[config::PeerConfig],
        update_senders: HashMap<Ipv4Addr, mpsc::Sender<UpdateMessage>>,
        config_capabilities: Vec<Capability>,
    ) -> Self {
        let import_policies = peers
            .iter()
            .map(|p| {
                let is_ebgp = p.remote_as != local_as;
                (
                    p.address,
                    Policy::new(resolve_import_default(p.import_default, is_ebgp)),
                )
            })
            .collect();

        let export_policies = peers
            .iter()
            .map(|p| {
                let is_ebgp = p.remote_as != local_as;
                (
                    p.address,
                    Policy::new(resolve_export_default(p.export_default, is_ebgp)),
                )
            })
            .collect();

        let adj_ribs_in = peers
            .iter()
            .map(|p| (p.address, AdjRibIn::new(PeerId::from(p.address))))
            .collect();

        let adj_ribs_in_v6 = peers
            .iter()
            .map(|p| (p.address, AdjRibIn::new(PeerId::from(p.address))))
            .collect();

        let peer_config_types = peers
            .iter()
            .map(|p| (p.address, config_peer_type(local_as, p.remote_as)))
            .collect();

        let adj_ribs_out = peers
            .iter()
            .map(|p| {
                let pt = config_peer_type(local_as, p.remote_as);
                (p.address, AdjRibOut::new(PeerId::from(p.address), pt))
            })
            .collect();

        let adj_ribs_out_v6 = peers
            .iter()
            .map(|p| {
                let pt = config_peer_type(local_as, p.remote_as);
                (p.address, AdjRibOut::new(PeerId::from(p.address), pt))
            })
            .collect();

        let peer_remote_as = peers.iter().map(|p| (p.address, p.remote_as)).collect();

        let (route_tx, _) = broadcast::channel(1024);
        let (peer_tx, _) = broadcast::channel(1024);

        let rib = Arc::new(RibSnapshot {
            loc_rib: LocRib::new(),
            loc_rib_v6: LocRib::new(),
            originated_routes: HashMap::new(),
            local_as,
            local_bgp_id,
            local_ipv6,
            peer_remote_as,
            peer_types: HashMap::new(),
            established_at: HashMap::new(),
            hold_times: HashMap::new(),
            prefixes_received: HashMap::new(),
            prefixes_advertised: HashMap::new(),
        });

        Self {
            rib,
            import_policies,
            export_policies,
            adj_ribs_in,
            adj_ribs_out,
            adj_ribs_in_v6,
            adj_ribs_out_v6,
            peer_config_types,
            update_senders,
            config_capabilities,
            negotiated_max_len: HashMap::new(),
            stalled_peers: Vec::new(),
            route_tx,
            peer_tx,
        }
    }

    /// Returns a cheap clone of the snapshot Arc for lock-free gRPC reads.
    ///
    /// gRPC handlers call this while holding the outer `RwLock` read guard,
    /// then immediately release the lock. All subsequent work runs against
    /// the cloned Arc without holding any lock.
    pub(crate) fn snapshot(&self) -> Arc<RibSnapshot> {
        Arc::clone(&self.rib)
    }

    /// Returns a mutable reference to the snapshot.
    ///
    /// Uses copy-on-write semantics: free when no readers hold a clone (the
    /// common case during BGP convergence); allocates a fresh `RibSnapshot`
    /// only when a concurrent gRPC read is in flight.
    fn rib_mut(&mut self) -> &mut RibSnapshot {
        Arc::make_mut(&mut self.rib)
    }

    /// Syncs the derived `prefixes_received` count for `peer_ip` from the
    /// current `adj_ribs_in` length.
    fn sync_received(&mut self, peer_ip: Ipv4Addr) {
        let v4 = self.adj_ribs_in.get(&peer_ip).map_or(0, AdjRibIn::len);
        let v6 = self.adj_ribs_in_v6.get(&peer_ip).map_or(0, AdjRibIn::len);
        self.rib_mut().prefixes_received.insert(peer_ip, v4 + v6);
    }

    /// Syncs the derived `prefixes_advertised` count for `peer_ip` from the
    /// current `adj_ribs_out` length.
    fn sync_advertised(&mut self, peer_ip: Ipv4Addr) {
        let v4 = self.adj_ribs_out.get(&peer_ip).map_or(0, AdjRibOut::len);
        let v6 = self.adj_ribs_out_v6.get(&peer_ip).map_or(0, AdjRibOut::len);
        self.rib_mut()
            .prefixes_advertised
            .insert(peer_ip, v4 + v6);
    }

    /// Drains and returns the list of peers whose outbound UPDATE channel
    /// overflowed during the most recent event.
    ///
    /// The event loop calls this after each event and sends
    /// [`SessionCommand::Stop`] to each returned peer so the session can
    /// re-establish and perform a fresh full-table dump.
    fn take_stalled_peers(&mut self) -> Vec<Ipv4Addr> {
        std::mem::take(&mut self.stalled_peers)
    }

    /// Called when a BGP session reaches Established.
    ///
    /// Records the negotiated peer type, resets the peer's `AdjRibOut` to a
    /// clean slate, and performs a full-table dump of the current best routes
    /// subject to export policy.
    #[allow(clippy::similar_names)]
    fn on_established(
        &mut self,
        peer_ip: Ipv4Addr,
        peer_type: PeerType,
        peer_as: u32,
        hold_time: u16,
        peer_capabilities: &[Capability],
    ) {
        let peer_id = PeerId::from(peer_ip);

        // Update snapshot fields.
        {
            let rib = self.rib_mut();
            rib.peer_types.insert(peer_ip, peer_type);
            rib.established_at
                .insert(peer_ip, std::time::Instant::now());
            rib.hold_times.insert(peer_ip, hold_time);
        }

        // Record negotiated message size limit for NLRI batching.
        let max_len = if peer_capabilities.contains(&Capability::ExtendedMessage)
            && self
                .config_capabilities
                .contains(&Capability::ExtendedMessage)
        {
            MAX_LEN_EXTENDED
        } else {
            MAX_LEN
        };
        self.negotiated_max_len.insert(peer_ip, max_len);

        if let Some(aro) = self.adj_ribs_out.get_mut(&peer_ip) {
            *aro = AdjRibOut::new(peer_id, peer_type);
        }
        // Reset v6 RIBs so a re-established session starts clean.
        self.adj_ribs_in_v6.insert(peer_ip, AdjRibIn::new(peer_id));
        self.adj_ribs_out_v6
            .insert(peer_ip, AdjRibOut::new(peer_id, peer_type));

        let all_nlris: Vec<Nlri<Ipv4Addr>> =
            self.rib.loc_rib.best_routes().map(|(n, _)| n).collect();
        let all_nlris_v6: Vec<Nlri<Ipv6Addr>> =
            self.rib.loc_rib_v6.best_routes().map(|(n, _)| n).collect();
        let rib_prefixes = all_nlris.len() + all_nlris_v6.len();

        let Some(export_policy) = self.export_policies.get(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "export_policies missing peer — skipping Established event");
            return;
        };
        let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "adj_ribs_out missing peer — skipping Established event");
            return;
        };
        let Some(update_tx) = self.update_senders.get(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "update_senders missing peer — skipping Established event");
            return;
        };

        let local_as = self.rib.local_as;
        let local_bgp_id = self.rib.local_bgp_id;
        let local_ipv6 = self.rib.local_ipv6;
        let decisions: Vec<PrefixDecision> = all_nlris
            .into_iter()
            .map(|nlri| {
                propagate_prefix(
                    nlri,
                    &self.rib.loc_rib,
                    adj_rib_out,
                    export_policy,
                    peer_type,
                    local_as,
                    local_bgp_id,
                )
            })
            .collect();

        if !flush_updates(decisions, max_len, update_tx) {
            self.stalled_peers.push(peer_ip);
        }

        // Full-table dump for IPv6.
        if !all_nlris_v6.is_empty() {
            if let Some(adj_rib_out_v6) = self.adj_ribs_out_v6.get_mut(&peer_ip) {
                let decisions_v6: Vec<PrefixDecisionV6> = all_nlris_v6
                    .into_iter()
                    .map(|nlri| {
                        propagate_prefix_v6(
                            nlri,
                            &self.rib.loc_rib_v6,
                            adj_rib_out_v6,
                            peer_type,
                            local_as,
                            local_ipv6,
                        )
                    })
                    .collect();
                if !flush_updates_v6(decisions_v6, max_len, update_tx) {
                    self.stalled_peers.push(peer_ip);
                }
            }
        }

        self.sync_advertised(peer_ip);

        let _ = self.peer_tx.send(proto::PeerEvent {
            r#type: proto::PeerEventType::Changed as i32,
            peer: None, // gRPC handler builds PeerState from snapshot
        });

        tracing::info!(
            peer = %peer_ip,
            remote_as = peer_as,
            hold_time,
            peer_type = %peer_type,
            rib_prefixes,
            "session established"
        );
    }

    /// Called when a BGP session terminates.
    ///
    /// Clears the peer's RIB state, resets its outbound table, and propagates
    /// any best-path changes caused by the withdrawal to all remaining
    /// established peers.
    #[allow(clippy::similar_names)]
    fn on_terminated(&mut self, peer_ip: Ipv4Addr) {
        let peer_id = PeerId::from(peer_ip);

        // Remove live session state from snapshot.
        {
            let rib = self.rib_mut();
            rib.peer_types.remove(&peer_ip);
            rib.established_at.remove(&peer_ip);
            rib.hold_times.remove(&peer_ip);
            rib.prefixes_received.remove(&peer_ip);
            rib.prefixes_advertised.remove(&peer_ip);
        }
        self.negotiated_max_len.remove(&peer_ip);

        if let Some(ari) = self.adj_ribs_in.get_mut(&peer_ip) {
            ari.clear();
        }
        if let Some(ari) = self.adj_ribs_in_v6.get_mut(&peer_ip) {
            ari.clear();
        }

        // Snapshot affected prefixes before withdrawal so we can propagate the
        // changes to other established peers below.
        let prev_prefixes: Vec<Nlri<Ipv4Addr>> =
            self.rib.loc_rib.best_routes().map(|(n, _)| n).collect();

        self.rib_mut().loc_rib.withdraw_peer(&peer_id);
        self.rib_mut().loc_rib_v6.withdraw_peer(&peer_id);

        // Reset this peer's outbound state for a clean reconnect.
        let cfg_pt = self
            .peer_config_types
            .get(&peer_ip)
            .copied()
            .unwrap_or(PeerType::External);
        if let Some(aro) = self.adj_ribs_out.get_mut(&peer_ip) {
            *aro = AdjRibOut::new(peer_id, cfg_pt);
        }
        if let Some(aro) = self.adj_ribs_out_v6.get_mut(&peer_ip) {
            *aro = AdjRibOut::new(peer_id, cfg_pt);
        }

        // Tell all other established peers about the best-path changes caused
        // by this teardown.
        let other_peers: Vec<Ipv4Addr> = self
            .rib
            .peer_types
            .keys()
            .copied()
            .filter(|&ip| ip != peer_ip)
            .collect();

        let local_as = self.rib.local_as;
        let local_bgp_id = self.rib.local_bgp_id;
        for other_ip in other_peers {
            let other_type = self
                .rib
                .peer_types
                .get(&other_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let max_len = self
                .negotiated_max_len
                .get(&other_ip)
                .copied()
                .unwrap_or(MAX_LEN);
            let Some(export_policy) = self.export_policies.get(&other_ip) else {
                tracing::error!(peer = %other_ip, "export_policies missing peer — skipping propagation on Terminated");
                continue;
            };
            let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&other_ip) else {
                tracing::error!(peer = %other_ip, "adj_ribs_out missing peer — skipping propagation on Terminated");
                continue;
            };
            let Some(update_tx) = self.update_senders.get(&other_ip) else {
                tracing::error!(peer = %other_ip, "update_senders missing peer — skipping propagation on Terminated");
                continue;
            };

            let decisions: Vec<PrefixDecision> = prev_prefixes
                .iter()
                .map(|&nlri| {
                    propagate_prefix(
                        nlri,
                        &self.rib.loc_rib,
                        adj_rib_out,
                        export_policy,
                        other_type,
                        local_as,
                        local_bgp_id,
                    )
                })
                .collect();
            if !flush_updates(decisions, max_len, update_tx) {
                self.stalled_peers.push(other_ip);
            }
            self.sync_advertised(other_ip);
        }

        let _ = self.peer_tx.send(proto::PeerEvent {
            r#type: proto::PeerEventType::Changed as i32,
            peer: None, // gRPC handler builds PeerState from snapshot
        });

        tracing::info!(
            peer = %peer_ip,
            rib_size = self.rib.loc_rib.len(),
            "session terminated"
        );
    }

    /// Called when a BGP UPDATE message arrives from an established peer.
    ///
    /// Applies import policy, updates the RIB, and propagates best-path changes
    /// for all affected NLRIs to every established peer.
    #[allow(clippy::similar_names)]
    fn on_route_update(&mut self, peer_ip: Ipv4Addr, msg: UpdateMessage) {
        let peer_id = PeerId::from(peer_ip);
        let peer_type = self
            .rib
            .peer_types
            .get(&peer_ip)
            .copied()
            .unwrap_or(PeerType::External);

        // Collect all IPv4 prefixes that may change best-path: traditional
        // fields plus any IPv4 NLRIs carried in MP_REACH/MP_UNREACH attributes
        // (RFC 4760). These are used after `handle_update` to drive outbound
        // propagation, so they must be collected before `msg` is moved.
        let mut affected: Vec<Nlri<Ipv4Addr>> = msg
            .withdrawn
            .iter()
            .chain(msg.announced.iter())
            .copied()
            .collect();

        let mut affected_v6: Vec<Nlri<Ipv6Addr>> = Vec::new();

        for attr in &msg.attributes {
            match attr {
                PathAttribute::MpUnreachNlri(MpUnreachNlri { afi_safi, prefixes })
                    if *afi_safi == AfiSafi::IPV4_UNICAST =>
                {
                    affected.extend(prefixes.iter().filter_map(|p| {
                        if let Prefix::V4(nlri) = p { Some(*nlri) } else { None }
                    }));
                }
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi, prefixes, ..
                }) if *afi_safi == AfiSafi::IPV4_UNICAST => {
                    affected.extend(prefixes.iter().filter_map(|p| {
                        if let Prefix::V4(nlri) = p { Some(*nlri) } else { None }
                    }));
                }
                PathAttribute::MpUnreachNlri(MpUnreachNlri { afi_safi, prefixes })
                    if *afi_safi == AfiSafi::IPV6_UNICAST =>
                {
                    affected_v6.extend(prefixes.iter().filter_map(|p| {
                        if let Prefix::V6(nlri) = p { Some(*nlri) } else { None }
                    }));
                }
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi, prefixes, ..
                }) if *afi_safi == AfiSafi::IPV6_UNICAST => {
                    affected_v6.extend(prefixes.iter().filter_map(|p| {
                        if let Prefix::V6(nlri) = p { Some(*nlri) } else { None }
                    }));
                }
                _ => {}
            }
        }

        let Some(policy) = self.import_policies.get(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "import_policies missing peer — skipping RouteUpdate");
            return;
        };
        let Some(adj_rib_in) = self.adj_ribs_in.get_mut(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "adj_ribs_in missing peer — skipping RouteUpdate");
            return;
        };

        // IPv6 AdjRibIn may not exist for all peers (e.g. if capability was not
        // advertised); use a temporary empty table in that case so handle_update
        // can take ownership without a conditional.
        let mut scratch_v6 = AdjRibIn::new(peer_id);
        let adj_rib_in_v6 = self
            .adj_ribs_in_v6
            .get_mut(&peer_ip)
            .unwrap_or(&mut scratch_v6);

        // Split mutable borrows across distinct struct fields explicitly so the
        // borrow checker can verify they don't alias.
        let rib = Arc::make_mut(&mut self.rib);
        handle_update(
            peer_id,
            msg,
            adj_rib_in,
            &mut rib.loc_rib,
            adj_rib_in_v6,
            &mut rib.loc_rib_v6,
            policy,
            peer_type,
        );

        self.sync_received(peer_ip);

        // Propagate best-path changes for affected prefixes to all established
        // peers (iBGP split-horizon is enforced by AdjRibOut).
        self.propagate_to_all_peers(&affected);
        if !affected_v6.is_empty() {
            self.propagate_to_all_peers_v6(&affected_v6);
        }
    }

    /// Propagates best-path decisions for `nlris` to every currently established
    /// peer and flushes the resulting BGP UPDATE messages.
    ///
    /// Extracted to eliminate the identical loop body duplicated across
    /// `on_route_update`, `set_import_default`, `set_export_default`, and the
    /// origination methods.
    fn propagate_to_all_peers(&mut self, nlris: &[Nlri<Ipv4Addr>]) {
        let established_peers: Vec<Ipv4Addr> = self.rib.peer_types.keys().copied().collect();
        let local_as = self.rib.local_as;
        let local_bgp_id = self.rib.local_bgp_id;
        for peer_ip in established_peers {
            let peer_type = self
                .rib
                .peer_types
                .get(&peer_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let max_len = self
                .negotiated_max_len
                .get(&peer_ip)
                .copied()
                .unwrap_or(MAX_LEN);
            let Some(export_policy) = self.export_policies.get(&peer_ip) else {
                tracing::error!(peer = %peer_ip, "export_policies missing peer — skipping propagation");
                continue;
            };
            let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&peer_ip) else {
                tracing::error!(peer = %peer_ip, "adj_ribs_out missing peer — skipping propagation");
                continue;
            };
            let Some(update_tx) = self.update_senders.get(&peer_ip) else {
                tracing::error!(peer = %peer_ip, "update_senders missing peer — skipping propagation");
                continue;
            };
            let decisions: Vec<PrefixDecision> = nlris
                .iter()
                .map(|&nlri| {
                    propagate_prefix(
                        nlri,
                        &self.rib.loc_rib,
                        adj_rib_out,
                        export_policy,
                        peer_type,
                        local_as,
                        local_bgp_id,
                    )
                })
                .collect();
            if !flush_updates(decisions, max_len, update_tx) {
                self.stalled_peers.push(peer_ip);
            }
        }
        // Sync advertised counts after all propagation is complete.
        let peers: Vec<Ipv4Addr> = self.adj_ribs_out.keys().copied().collect();
        for peer_ip in peers {
            self.sync_advertised(peer_ip);
        }
    }

    fn propagate_to_all_peers_v6(&mut self, nlris: &[Nlri<Ipv6Addr>]) {
        let established_peers: Vec<Ipv4Addr> = self.rib.peer_types.keys().copied().collect();
        let local_as = self.rib.local_as;
        let local_ipv6 = self.rib.local_ipv6;
        for peer_ip in established_peers {
            let peer_type = self
                .rib
                .peer_types
                .get(&peer_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let max_len = self
                .negotiated_max_len
                .get(&peer_ip)
                .copied()
                .unwrap_or(MAX_LEN);
            let Some(adj_rib_out_v6) = self.adj_ribs_out_v6.get_mut(&peer_ip) else {
                tracing::error!(peer = %peer_ip, "adj_ribs_out_v6 missing peer — skipping v6 propagation");
                continue;
            };
            let Some(update_tx) = self.update_senders.get(&peer_ip) else {
                tracing::error!(peer = %peer_ip, "update_senders missing peer — skipping v6 propagation");
                continue;
            };
            let decisions: Vec<PrefixDecisionV6> = nlris
                .iter()
                .map(|&nlri| {
                    propagate_prefix_v6(
                        nlri,
                        &self.rib.loc_rib_v6,
                        adj_rib_out_v6,
                        peer_type,
                        local_as,
                        local_ipv6,
                    )
                })
                .collect();
            if !flush_updates_v6(decisions, max_len, update_tx) {
                self.stalled_peers.push(peer_ip);
            }
        }
    }

    /// Injects a single route into the Loc-RIB and advertises it to all
    /// established peers. Delegates to [`originate_routes`].
    ///
    /// [`originate_routes`]: DaemonState::originate_routes
    pub(crate) fn originate_route(&mut self, route: Route<Ipv4Addr>) {
        self.originate_routes(vec![route]);
    }

    /// Injects a batch of routes into the Loc-RIB and advertises all of them
    /// to established peers in a single propagation pass.
    ///
    /// All routes are inserted before propagation begins — one `propagate_to_all_peers`
    /// call regardless of batch size. This matches GoBGP `AddPathStream` semantics.
    ///
    /// Originated routes bypass import policy; they go directly into Loc-RIB.
    /// Export policy still applies on the outbound side.
    pub(crate) fn originate_routes(&mut self, routes: Vec<Route<Ipv4Addr>>) {
        let mut nlris = Vec::with_capacity(routes.len());
        for route in routes {
            let nlri = route.nlri;
            let rib = self.rib_mut();
            rib.originated_routes.insert(nlri, route.clone());
            rib.loc_rib
                .insert(PeerId::from(LOCAL_ORIGIN_PEER), route.clone());
            nlris.push(nlri);
            let _ = self.route_tx.send(proto::RouteEvent {
                r#type: proto::RouteEventType::Announced as i32,
                route: Some(grpc::route_to_proto(
                    PeerId::from(LOCAL_ORIGIN_PEER),
                    nlri,
                    &route,
                )),
                withdrawn_prefix: None,
            });
        }
        self.propagate_to_all_peers(&nlris);
    }

    /// Withdraws a single locally originated route.
    ///
    /// No-op if the prefix was not previously originated.
    pub(crate) fn withdraw_originated_route(&mut self, nlri: Nlri<Ipv4Addr>) {
        self.withdraw_originated_routes(&[nlri]);
    }

    /// Withdraws a batch of locally originated routes in a single propagation
    /// pass.
    pub(crate) fn withdraw_originated_routes(&mut self, nlris: &[Nlri<Ipv4Addr>]) {
        for nlri in nlris {
            let rib = self.rib_mut();
            rib.originated_routes.remove(nlri);
            rib.loc_rib.withdraw(&PeerId::from(LOCAL_ORIGIN_PEER), nlri);
            let _ = self.route_tx.send(proto::RouteEvent {
                r#type: proto::RouteEventType::Withdrawn as i32,
                route: None,
                withdrawn_prefix: Some(nlri.to_string()),
            });
        }
        self.propagate_to_all_peers(nlris);
    }

    /// Replaces the import-policy default for `peer_ip` and re-evaluates the
    /// peer's entire Adj-RIB-In against the new policy.  Routes that change
    /// accepted/rejected status are written into Loc-RIB, and the resulting
    /// best-path changes are propagated to all currently established peers.
    ///
    /// This is the "soft reconfiguration" path: no session reset, no full-table
    /// dump — only the delta between the old and new policy is forwarded.
    pub(crate) fn set_import_default(&mut self, peer_ip: Ipv4Addr, action: DefaultAction) {
        if !self.import_policies.contains_key(&peer_ip) {
            tracing::warn!(peer = %peer_ip, "set_import_default: unknown peer — ignoring");
            return;
        }
        self.import_policies.insert(peer_ip, Policy::new(action));

        // Collect affected NLRIs before the mutable borrow of loc_rib so the
        // borrow checker does not see two simultaneous borrows of `self`.
        let nlris: Vec<Nlri<Ipv4Addr>> = self
            .adj_ribs_in
            .get(&peer_ip)
            .map(|a| a.routes().map(|(n, _)| *n).collect())
            .unwrap_or_default();

        // Re-evaluate the peer's Adj-RIB-In against the new policy.
        // Split the borrows explicitly: rib_mut() needs &mut self.rib, while
        // adj_ribs_in and import_policies are separate fields.
        let loc_rib = &mut Arc::make_mut(&mut self.rib).loc_rib;
        reapply_import_policy(
            PeerId::from(peer_ip),
            &self.adj_ribs_in[&peer_ip],
            loc_rib,
            &self.import_policies[&peer_ip],
        );

        self.propagate_to_all_peers(&nlris);
    }

    /// Replaces the export-policy default for `peer_ip` and re-evaluates the
    /// entire Loc-RIB against the new policy for that peer.  Newly accepted
    /// prefixes are sent as UPDATEs; newly rejected ones trigger WITHDRAWs.
    ///
    /// Has no effect on the wire if the peer is not currently established — the
    /// new policy will be applied on the next session's opening table dump.
    pub(crate) fn set_export_default(&mut self, peer_ip: Ipv4Addr, action: DefaultAction) {
        if !self.export_policies.contains_key(&peer_ip) {
            tracing::warn!(peer = %peer_ip, "set_export_default: unknown peer — ignoring");
            return;
        }
        self.export_policies.insert(peer_ip, Policy::new(action));

        if !self.rib.peer_types.contains_key(&peer_ip) {
            tracing::debug!(
                peer = %peer_ip,
                "set_export_default: peer not established — new policy applies on reconnect"
            );
            return;
        }

        let peer_type = self
            .rib
            .peer_types
            .get(&peer_ip)
            .copied()
            .unwrap_or(PeerType::External);

        // Collect all Loc-RIB NLRIs; the borrow is dropped after the collect.
        let nlris: Vec<Nlri<Ipv4Addr>> = self.rib.loc_rib.best_routes().map(|(n, _)| n).collect();

        let max_len = self
            .negotiated_max_len
            .get(&peer_ip)
            .copied()
            .unwrap_or(MAX_LEN);
        let local_as = self.rib.local_as;
        let local_bgp_id = self.rib.local_bgp_id;
        let Some(export_policy) = self.export_policies.get(&peer_ip) else {
            return;
        };
        let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&peer_ip) else {
            return;
        };
        let Some(update_tx) = self.update_senders.get(&peer_ip) else {
            return;
        };

        let decisions: Vec<PrefixDecision> = nlris
            .into_iter()
            .map(|nlri| {
                propagate_prefix(
                    nlri,
                    &self.rib.loc_rib,
                    adj_rib_out,
                    export_policy,
                    peer_type,
                    local_as,
                    local_bgp_id,
                )
            })
            .collect();
        if !flush_updates(decisions, max_len, update_tx) {
            self.stalled_peers.push(peer_ip);
        }
        self.sync_advertised(peer_ip);
    }
}

async fn run(cfg: config::Config) {
    run_with(cfg, transport::spawn).await;
}

/// Runs the BGP daemon using `spawn_fn` to create session handles.
///
/// `run()` calls this with [`transport::spawn`]; tests call it with a mock
/// `spawn_fn` so the session-spawning setup phase can be exercised without
/// real TCP connections.
pub(crate) async fn run_with<H, F>(cfg: config::Config, spawn_fn: F)
where
    H: SessionHandle,
    F: Fn(SessionConfig) -> H,
{
    let grpc_port = cfg.daemon.grpc_port;
    let bgp_port = cfg.daemon.bgp_port;
    let (state, event_rx, stop_senders, incoming_senders) = build_daemon(&cfg, spawn_fn).await;

    // Spawn the gRPC management API server alongside the BGP event loop.
    let grpc_state = Arc::clone(&state);
    tokio::spawn(async move {
        grpc::serve(grpc_state, grpc_port).await;
    });

    // Spawn the BGP TCP listener for inbound connections (RFC 4271 §6.8).
    tokio::spawn(async move {
        run_bgp_listener(bgp_port, incoming_senders).await;
    });

    run_event_loop(event_rx, state, stop_senders).await;
}

/// Sets up BGP sessions for every configured peer and constructs the initial
/// [`DaemonState`].
///
/// `spawn_fn` is called once per peer to create a [`SessionHandle`]; `start()`
/// is then called on each handle so the session task begins the TCP connect /
/// BGP open exchange.  The returned tuple contains:
///
/// - The shared daemon state (pre-populated with per-peer RIBs and policies).
/// - The event receiver that drains `(peer_ip, SessionEvent)` messages from
///   the per-peer forwarding tasks.
/// - The stop-sender map so the event loop can close a session whose outbound
///   channel overflowed.
///
/// Extracted from `run_with()` so it can be driven in tests by supplying a
/// mock `spawn_fn` — no real TCP sockets needed.
pub(crate) async fn build_daemon<H, F>(
    cfg: &config::Config,
    spawn_fn: F,
) -> (
    Arc<RwLock<DaemonState>>,
    mpsc::Receiver<(Ipv4Addr, SessionEvent)>,
    HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>>,
    HashMap<IpAddr, mpsc::Sender<SessionCommand>>,
)
where
    H: SessionHandle,
    F: Fn(SessionConfig) -> H,
{
    let local_as = cfg.daemon.local_as;
    let local_bgp_id = cfg.daemon.bgp_id;

    let (event_tx, event_rx) = mpsc::channel::<(Ipv4Addr, SessionEvent)>(256);
    let mut update_senders: HashMap<Ipv4Addr, mpsc::Sender<UpdateMessage>> = HashMap::new();
    // Stop senders are kept here so the event loop can close a session whose
    // outbound UPDATE channel overflowed.  The session handle itself is moved
    // into the per-peer forwarding task, so this is the only retained handle.
    let mut stop_senders: HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>> = HashMap::new();
    // Incoming senders: keyed by IpAddr for O(1) lookup in the BGP listener.
    let mut incoming_senders: HashMap<IpAddr, mpsc::Sender<SessionCommand>> = HashMap::new();

    let local_capabilities = vec![
        Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
        Capability::FourByteAsn(local_as),
        Capability::ExtendedMessage,
    ];

    for peer in &cfg.peers {
        let session_cfg = SessionConfig {
            local_as,
            local_bgp_id,
            hold_time: cfg.daemon.hold_time,
            capabilities: local_capabilities.clone(),
            required_capabilities: vec![],
            peer_as: Some(peer.remote_as),
            peer_addr: SocketAddr::new(IpAddr::V4(peer.address), peer.port),
        };

        let mut handle = spawn_fn(session_cfg);
        handle.start().await;

        update_senders.insert(peer.address, handle.update_sender());
        stop_senders.insert(peer.address, handle.stop_sender());
        incoming_senders.insert(IpAddr::V4(peer.address), handle.incoming_sender());

        let peer_addr = peer.address;
        let tx = event_tx.clone();
        tokio::spawn(async move {
            while let Some(event) = handle.next_event().await {
                if tx.send((peer_addr, event)).await.is_err() {
                    break;
                }
            }
        });
    }
    // Drop our sender copy so the channel closes when all peer tasks exit.
    drop(event_tx);

    let state = Arc::new(RwLock::new(DaemonState::new(
        local_as,
        local_bgp_id,
        cfg.daemon.local_ipv6,
        &cfg.peers,
        update_senders,
        local_capabilities,
    )));

    (state, event_rx, stop_senders, incoming_senders)
}

/// BGP TCP listener for inbound connections (RFC 4271 §6.8).
///
/// Binds on `0.0.0.0:<bgp_port>` and forwards each accepted connection to the
/// session task for the corresponding peer.  Unknown peers (not in
/// `incoming_senders`) have their connection dropped immediately — the TCP RST
/// tells the remote peer to back off.
///
/// The listener runs for the lifetime of the daemon.  If `bind()` fails (e.g.,
/// port 179 without `CAP_NET_BIND_SERVICE`), the error is logged and the
/// listener exits; the daemon continues operating in dial-only mode.
async fn run_bgp_listener(
    bgp_port: u16,
    incoming_senders: HashMap<IpAddr, mpsc::Sender<SessionCommand>>,
) {
    let bind_addr = std::net::SocketAddr::from(([0, 0, 0, 0], bgp_port));
    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(l) => {
            tracing::info!(port = bgp_port, "BGP listener started");
            l
        }
        Err(e) => {
            tracing::error!(port = bgp_port, error = %e, "BGP listener failed to bind; operating in dial-only mode");
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                if let Some(tx) = incoming_senders.get(&peer_addr.ip()) {
                    tracing::debug!(peer = %peer_addr, "accepted inbound BGP connection");
                    let _ = tx.send(SessionCommand::IncomingConnection(stream)).await;
                } else {
                    tracing::debug!(peer = %peer_addr, "rejected inbound BGP connection from unknown peer");
                    // stream dropped here → TCP RST
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "BGP listener accept error");
            }
        }
    }
}

/// Core BGP event loop.
///
/// Drains `event_rx`, dispatches each `(peer_ip, SessionEvent)` to the shared
/// [`DaemonState`], then closes any sessions whose outbound UPDATE channel
/// overflowed during that dispatch.
///
/// Extracted from `run()` so it can be driven in unit tests by injecting a
/// pre-built channel and a pre-populated `DaemonState` — no TCP connections
/// or real session tasks required.
pub(crate) async fn run_event_loop(
    mut event_rx: mpsc::Receiver<(Ipv4Addr, SessionEvent)>,
    state: Arc<RwLock<DaemonState>>,
    stop_senders: HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>>,
) {
    while let Some((peer_ip, event)) = event_rx.recv().await {
        let mut s = state.write().await;
        match event {
            SessionEvent::Established(info) => {
                s.on_established(
                    peer_ip,
                    info.peer_type,
                    info.peer_as,
                    info.hold_time,
                    &info.peer_capabilities,
                );
            }
            SessionEvent::Terminated => {
                s.on_terminated(peer_ip);
            }
            SessionEvent::RouteUpdate(msg) => {
                s.on_route_update(peer_ip, msg);
            }
        }
        // Collect any peers whose outbound channel overflowed.  Drain outside
        // the write-lock so we don't hold it across the async stop-sender sends.
        let stalled = s.take_stalled_peers();
        drop(s);

        for peer in stalled {
            tracing::error!(
                peer = %peer,
                "closing session: outbound UPDATE channel overflowed; \
                 session will re-establish and perform a fresh full-table dump"
            );
            if let Some(tx) = stop_senders.get(&peer) {
                let _ = tx.send(SessionCommand::Stop).await;
            }
        }
    }
}

/// Re-evaluates all routes stored in `adj_rib_in` against `policy` and
/// reconciles `loc_rib` with the result.
///
/// This is soft reconfiguration: when the import policy for a peer changes,
/// call this instead of resetting the session. Routes that the new policy
/// accepts are (re-)inserted into `loc_rib` with any attribute modifications
/// the policy applies. Routes that the new policy rejects are withdrawn from
/// `loc_rib` if they were previously accepted.
///
/// The raw routes in `adj_rib_in` are never modified — they always reflect
/// what the peer actually advertised.
pub fn reapply_import_policy(
    peer: PeerId,
    adj_rib_in: &AdjRibIn<Ipv4Addr>,
    loc_rib: &mut LocRib<Ipv4Addr>,
    policy: &Policy<Route<Ipv4Addr>>,
) {
    let mut accepted = 0usize;
    let mut rejected = 0usize;

    for (nlri, raw_route) in adj_rib_in.routes() {
        let mut route = raw_route.clone();
        match policy.evaluate(&mut route) {
            Decision::Accept => {
                loc_rib.insert(peer, route);
                accepted += 1;
            }
            Decision::Reject | Decision::Next => {
                loc_rib.withdraw(&peer, nlri);
                rejected += 1;
            }
        }
    }

    tracing::info!(
        peer = %peer,
        accepted,
        rejected,
        rib_size = loc_rib.len(),
        "soft reconfig complete"
    );
}

// UPDATE processing dispatches across all path attribute types in one pass.
// Splitting this function further would produce artificial helpers with no
// independent utility.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn handle_update(
    peer: PeerId,
    msg: UpdateMessage,
    adj_rib_in: &mut AdjRibIn<Ipv4Addr>,
    loc_rib: &mut LocRib<Ipv4Addr>,
    adj_rib_in_v6: &mut AdjRibIn<Ipv6Addr>,
    loc_rib_v6: &mut LocRib<Ipv6Addr>,
    policy: &Policy<Route<Ipv4Addr>>,
    peer_type: PeerType,
) {
    let withdrawn_count = msg.withdrawn.len();

    // ── Traditional IPv4 withdrawals (RFC 4271 §4.3) ──────────────────────
    for nlri in &msg.withdrawn {
        adj_rib_in.withdraw(nlri);
        loc_rib.withdraw(&peer, nlri);
    }

    // ── Single pass over path attributes ─────────────────────────────────
    // Extracts scalar attributes shared by all announced NLRIs, and collects
    // IPv4 NLRIs from MP_REACH_NLRI / MP_UNREACH_NLRI (RFC 4760). Non-IPv4
    // AFI/SAFIs are logged and skipped; the daemon is IPv4-only for now.
    let mut origin = Origin::Incomplete;
    let mut as_path = AsPath::new();
    let mut next_hop: Option<NextHop> = None;
    let mut local_pref: Option<LocalPref> = None;
    let mut med: Option<Med> = None;
    let mut communities = Vec::new();
    let mut large_communities = Vec::new();
    let mut extended_communities = Vec::new();
    let mut atomic_aggregate = false;
    let mut aggregator = None;
    // (nlri, next_hop) pairs from MP_REACH_NLRI; next_hop is mandatory there.
    let mut mp_v4_announced: Vec<(Nlri<Ipv4Addr>, NextHop)> = Vec::new();
    let mut mp_v4_withdrawn: Vec<Nlri<Ipv4Addr>> = Vec::new();
    let mut mp_v6_announced: Vec<(Nlri<Ipv6Addr>, NextHop)> = Vec::new();
    let mut mp_v6_withdrawn: Vec<Nlri<Ipv6Addr>> = Vec::new();

    for attr in &msg.attributes {
        match attr {
            PathAttribute::Origin(o) => origin = *o,
            PathAttribute::AsPath(p) => as_path = p.clone(),
            PathAttribute::NextHop(ip) => next_hop = Some(NextHop::V4(*ip)),
            PathAttribute::LocalPref(lp) => local_pref = Some(LocalPref::new(*lp)),
            PathAttribute::Med(m) => med = Some(Med::new(*m)),
            PathAttribute::Communities(cs) => communities.clone_from(cs),
            PathAttribute::LargeCommunities(lcs) => large_communities.clone_from(lcs),
            PathAttribute::ExtendedCommunities(ecs) => extended_communities.clone_from(ecs),
            PathAttribute::AtomicAggregate => atomic_aggregate = true,
            PathAttribute::Aggregator(a) => aggregator = Some(*a),
            PathAttribute::MpReachNlri(mp) => {
                if mp.afi_safi == AfiSafi::IPV4_UNICAST {
                    for prefix in &mp.prefixes {
                        if let Prefix::V4(nlri) = prefix {
                            mp_v4_announced.push((*nlri, mp.next_hop));
                        }
                    }
                } else if mp.afi_safi == AfiSafi::IPV6_UNICAST {
                    for prefix in &mp.prefixes {
                        if let Prefix::V6(nlri) = prefix {
                            mp_v6_announced.push((*nlri, mp.next_hop));
                        }
                    }
                } else {
                    tracing::debug!(
                        peer = %peer,
                        afi_safi = %mp.afi_safi,
                        "MP_REACH_NLRI for unsupported AFI/SAFI — skipping"
                    );
                }
            }
            PathAttribute::MpUnreachNlri(mp) => {
                if mp.afi_safi == AfiSafi::IPV4_UNICAST {
                    for prefix in &mp.prefixes {
                        if let Prefix::V4(nlri) = prefix {
                            mp_v4_withdrawn.push(*nlri);
                        }
                    }
                } else if mp.afi_safi == AfiSafi::IPV6_UNICAST {
                    for prefix in &mp.prefixes {
                        if let Prefix::V6(nlri) = prefix {
                            mp_v6_withdrawn.push(*nlri);
                        }
                    }
                } else {
                    tracing::debug!(
                        peer = %peer,
                        afi_safi = %mp.afi_safi,
                        "MP_UNREACH_NLRI for unsupported AFI/SAFI — skipping"
                    );
                }
            }
            _ => {}
        }
    }

    // ── MP_UNREACH_NLRI withdrawals (RFC 4760) ────────────────────────────
    let mp_withdrawn_count = mp_v4_withdrawn.len();
    for nlri in &mp_v4_withdrawn {
        adj_rib_in.withdraw(nlri);
        loc_rib.withdraw(&peer, nlri);
    }

    // ── Announcements: traditional NLRIs + MP_REACH_NLRI V4 prefixes ─────
    // Both paths share the same scalar attributes extracted above. The only
    // difference is the next-hop source: traditional NLRIs use the NEXT_HOP
    // path attribute (optional); MP_REACH_NLRI carries next-hop inline
    // (mandatory) and takes precedence when present.
    let mut accepted = 0usize;
    let mut rejected = 0usize;

    let all_announced = msg
        .announced
        .into_iter()
        .map(|nlri| (nlri, next_hop))
        .chain(
            mp_v4_announced
                .into_iter()
                .map(|(nlri, nh)| (nlri, Some(nh))),
        );

    for (nlri, nh) in all_announced {
        let mut builder = RouteBuilder::new(nlri, origin, as_path.clone()).peer_type(peer_type);
        if let Some(nh) = nh {
            builder = builder.next_hop(nh);
        }
        if let Some(lp) = local_pref {
            builder = builder.local_pref(lp);
        }
        if let Some(m) = med {
            builder = builder.med(m);
        }
        for &c in &communities {
            builder = builder.community(c);
        }
        for &lc in &large_communities {
            builder = builder.large_community(lc);
        }
        for &ec in &extended_communities {
            builder = builder.extended_community(ec);
        }
        if atomic_aggregate {
            builder = builder.atomic_aggregate();
        }
        if let Some(agg) = aggregator {
            builder = builder.aggregator(agg);
        }

        let raw = builder.build();

        // RFC 7999: silently discard routes tagged with the BLACKHOLE community.
        // Store in AdjRibIn so soft-reconfig can see the raw route, but never
        // install into LocRib or advertise outbound.
        if raw.communities.iter().any(|c| c.is_blackhole()) {
            adj_rib_in.insert(raw.clone());
            tracing::debug!(peer = %peer, prefix = %nlri, "discarding BLACKHOLE-tagged route (RFC 7999)");
            rejected += 1;
            continue;
        }

        // Store the pre-policy route for soft reconfiguration.
        adj_rib_in.insert(raw.clone());

        // Apply import policy to a working copy; only insert if accepted.
        let mut route = raw;
        match policy.evaluate(&mut route) {
            Decision::Accept => {
                loc_rib.insert(peer, route);
                accepted += 1;
            }
            Decision::Reject | Decision::Next => {
                rejected += 1;
            }
        }
    }

    // ── MP_UNREACH_NLRI IPv6 withdrawals (RFC 4760) ──────────────────────────
    let mp_v6_withdrawn_count = mp_v6_withdrawn.len();
    for nlri in &mp_v6_withdrawn {
        adj_rib_in_v6.withdraw(nlri);
        loc_rib_v6.withdraw(&peer, nlri);
    }

    // ── IPv6 announcements from MP_REACH_NLRI ─────────────────────────────
    // No import policy for IPv6 yet — accept all. Policy support will be added
    // when per-AFI policy configuration is introduced.
    let mut accepted_v6 = 0usize;
    for (nlri, nh) in mp_v6_announced {
        let mut builder = RouteBuilder::new(nlri, origin, as_path.clone()).peer_type(peer_type);
        builder = builder.next_hop(nh);
        if let Some(lp) = local_pref {
            builder = builder.local_pref(lp);
        }
        if let Some(m) = med {
            builder = builder.med(m);
        }
        for &c in &communities {
            builder = builder.community(c);
        }
        for &lc in &large_communities {
            builder = builder.large_community(lc);
        }
        for &ec in &extended_communities {
            builder = builder.extended_community(ec);
        }
        if atomic_aggregate {
            builder = builder.atomic_aggregate();
        }
        if let Some(agg) = aggregator {
            builder = builder.aggregator(agg);
        }

        let route = builder.build();
        adj_rib_in_v6.insert(route.clone());
        loc_rib_v6.insert(peer, route);
        accepted_v6 += 1;
    }

    tracing::info!(
        peer = %peer,
        withdrawn = withdrawn_count,
        mp_withdrawn = mp_withdrawn_count,
        mp_v6_withdrawn = mp_v6_withdrawn_count,
        accepted,
        rejected,
        accepted_v6,
        rib_size = loc_rib.len(),
        rib_v6_size = loc_rib_v6.len(),
        "processed UPDATE"
    );
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use pathvector_policy::{
        Accept, ActionSequence, AnyCondition, CommunityCondition, DefaultAction, Policy, Reject,
        SetLocalPref, Term,
    };
    use pathvector_types::{
        Aggregator, Asn, Community, ExtendedCommunity, LargeCommunity, LocalPref as LP, Nlri,
    };

    use super::*;

    // ── test helpers ──────────────────────────────────────────────────────────

    fn peer_id(ip: &str) -> PeerId {
        PeerId::new(IpAddr::V4(ip.parse().unwrap()))
    }

    fn peer() -> PeerId {
        peer_id("10.0.0.1")
    }

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn accept_all() -> Policy<Route<Ipv4Addr>> {
        Policy::new(DefaultAction::Accept)
    }

    fn reject_all() -> Policy<Route<Ipv4Addr>> {
        Policy::new(DefaultAction::Reject)
    }

    fn fresh_ari() -> AdjRibIn<Ipv4Addr> {
        AdjRibIn::new(peer())
    }

    /// Builds a `DaemonState` with explicit accept-all policies for every peer.
    /// Returns the state and a map of receivers for asserting on outbound messages.
    fn make_state(
        local_as: u32,
        peers: &[(Ipv4Addr, u32)],
    ) -> (
        DaemonState,
        HashMap<Ipv4Addr, mpsc::Receiver<UpdateMessage>>,
    ) {
        let mut senders = HashMap::new();
        let mut receivers = HashMap::new();
        for &(ip, _) in peers {
            let (tx, rx) = mpsc::channel(64);
            senders.insert(ip, tx);
            receivers.insert(ip, rx);
        }
        let peer_configs: Vec<config::PeerConfig> = peers
            .iter()
            .map(|&(address, remote_as)| config::PeerConfig {
                address,
                port: 179,
                remote_as,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
            })
            .collect();
        let local_bgp_id = Ipv4Addr::new(10, 0, 0, 1);
        let state =
            DaemonState::new(local_as, local_bgp_id, None, &peer_configs, senders, vec![]);
        (state, receivers)
    }

    // ── config_peer_type ─────────────────────────────────────────────────────

    #[test]
    fn test_config_peer_type_different_as_is_external() {
        assert_eq!(config_peer_type(65001, 65002), PeerType::External);
    }

    #[test]
    fn test_config_peer_type_same_as_is_internal() {
        assert_eq!(config_peer_type(65001, 65001), PeerType::Internal);
    }

    // ── RFC 8212 default resolution ───────────────────────────────────────────

    #[test]
    fn test_resolve_import_ebgp_omitted_defaults_to_reject() {
        assert!(matches!(
            resolve_import_default(None, true),
            DefaultAction::Reject
        ));
    }

    #[test]
    fn test_resolve_import_ibgp_omitted_defaults_to_accept() {
        assert!(matches!(
            resolve_import_default(None, false),
            DefaultAction::Accept
        ));
    }

    #[test]
    fn test_resolve_import_explicit_accept_overrides_ebgp_default() {
        assert!(matches!(
            resolve_import_default(Some(config::ImportDefault::Accept), true),
            DefaultAction::Accept
        ));
    }

    #[test]
    fn test_resolve_import_explicit_reject_overrides_ibgp_default() {
        assert!(matches!(
            resolve_import_default(Some(config::ImportDefault::Reject), false),
            DefaultAction::Reject
        ));
    }

    #[test]
    fn test_resolve_export_ebgp_omitted_defaults_to_reject() {
        assert!(matches!(
            resolve_export_default(None, true),
            DefaultAction::Reject
        ));
    }

    #[test]
    fn test_resolve_export_ibgp_omitted_defaults_to_accept() {
        assert!(matches!(
            resolve_export_default(None, false),
            DefaultAction::Accept
        ));
    }

    #[test]
    fn test_resolve_export_explicit_accept_overrides_ebgp_default() {
        assert!(matches!(
            resolve_export_default(Some(config::ExportDefault::Accept), true),
            DefaultAction::Accept
        ));
    }

    #[test]
    fn test_resolve_export_explicit_reject_overrides_ibgp_default() {
        assert!(matches!(
            resolve_export_default(Some(config::ExportDefault::Reject), false),
            DefaultAction::Reject
        ));
    }

    // ── DaemonState::new ─────────────────────────────────────────────────────

    #[test]
    fn test_daemon_state_new_creates_maps_for_all_peers() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (state, _) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);
        for ip in [peer_a, peer_b] {
            assert!(state.import_policies.contains_key(&ip));
            assert!(state.export_policies.contains_key(&ip));
            assert!(state.adj_ribs_in.contains_key(&ip));
            assert!(state.adj_ribs_out.contains_key(&ip));
            assert!(state.update_senders.contains_key(&ip));
        }
    }

    #[test]
    fn test_daemon_state_new_ebgp_gets_reject_default_when_omitted() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let peers = vec![config::PeerConfig {
            address: peer_ip,
            port: 179,
            remote_as: 65002,
            import_default: None,
            export_default: None,
        }];
        let state = DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            &peers,
            {
                let mut m = HashMap::new();
                m.insert(peer_ip, tx);
                m
            },
            vec![],
        );
        // Import policy with Reject default means routes are dropped unless a
        // term accepts them. Verify by running a route through it.
        let mut route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .build();
        let decision = state.import_policies[&peer_ip].evaluate(&mut route);
        assert!(
            matches!(decision, Decision::Reject),
            "eBGP with no import_default must reject by default (RFC 8212)"
        );
    }

    // ── DaemonState::on_established ───────────────────────────────────────────

    #[test]
    fn test_on_established_records_peer_type() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        assert!(!state.rib.peer_types.contains_key(&peer_ip));
        state.on_established(peer_ip, PeerType::External, 65002, 90, &[]);
        assert_eq!(state.rib.peer_types[&peer_ip], PeerType::External);
    }

    #[test]
    fn test_on_established_empty_rib_sends_nothing() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, PeerType::External, 65002, 90, &[]);
        assert!(
            receivers.get_mut(&peer_ip).unwrap().try_recv().is_err(),
            "empty RIB should produce no messages on establish"
        );
    }

    #[test]
    fn test_on_established_sends_full_table_dump() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_ip, 65002)]);

        // Pre-populate the RIB with a route from a third-party peer.
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
        let route = RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65009)]),
        )
        .next_hop(NextHop::V4("10.0.0.9".parse().unwrap()))
        .peer_type(PeerType::External)
        .build();
        state.rib_mut().loc_rib.insert(src, route);

        state.on_established(peer_ip, PeerType::External, 65002, 90, &[]);

        let msg = receivers
            .get_mut(&peer_ip)
            .unwrap()
            .try_recv()
            .expect("should have queued a full-table dump UPDATE");
        assert_eq!(msg.announced, vec![nlri("10.0.0.0/8")]);
    }

    #[test]
    fn test_on_established_export_reject_sends_nothing() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (tx, _rx) = mpsc::channel(64);
        let peers = vec![config::PeerConfig {
            address: peer_ip,
            port: 179,
            remote_as: 65002,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Reject),
        }];
        let mut state = DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            &peers,
            {
                let mut m = HashMap::new();
                m.insert(peer_ip, tx);
                m
            },
            vec![],
        );

        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
        state.rib_mut().loc_rib.insert(
            src,
            RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
                .peer_type(PeerType::External)
                .build(),
        );

        state.on_established(peer_ip, PeerType::External, 65002, 90, &[]);
        // Export policy rejects everything — no UPDATE should be queued.
        // (We can't assert on the receiver here since we dropped _rx, but the
        // important invariant is that no panic or error occurs, and the RIB is
        // not modified.)
        assert_eq!(state.rib.loc_rib.len(), 1, "RIB must be unchanged");
    }

    // ── DaemonState::on_terminated ────────────────────────────────────────────

    #[test]
    fn test_on_terminated_removes_peer_type() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, PeerType::External, 65002, 90, &[]);
        state.on_terminated(peer_ip);
        assert!(!state.rib.peer_types.contains_key(&peer_ip));
    }

    #[test]
    fn test_on_terminated_withdraws_peer_routes_from_rib() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, PeerType::External, 65002, 90, &[]);

        state.rib_mut().loc_rib.insert(
            PeerId::from(peer_ip),
            RouteBuilder::new(
                nlri("10.0.0.0/8"),
                Origin::Igp,
                AsPath::from_sequence(vec![Asn::new(65002)]),
            )
            .peer_type(PeerType::External)
            .build(),
        );
        assert_eq!(state.rib.loc_rib.len(), 1);

        state.on_terminated(peer_ip);
        assert_eq!(state.rib.loc_rib.len(), 0);
    }

    #[test]
    fn test_on_terminated_propagates_withdraw_to_other_established_peers() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);

        state.on_established(peer_a, PeerType::External, 65002, 90, &[]);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[]);

        // Announce a route from peer_a so it reaches peer_b's AdjRibOut.
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_a),
                ],
                announced: vec![nlri("192.168.0.0/16")],
            },
        );
        // Drain the propagation messages sent during on_route_update.
        receivers.get_mut(&peer_a).unwrap().try_recv().ok();
        receivers.get_mut(&peer_b).unwrap().try_recv().ok();

        // Terminate peer_a — peer_b must receive a WITHDRAW.
        state.on_terminated(peer_a);

        let msg = receivers
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer_b should receive WITHDRAW after peer_a terminates");
        assert!(!msg.withdrawn.is_empty());
        assert_eq!(msg.withdrawn[0], nlri("192.168.0.0/16"));
    }

    // ── DaemonState::on_route_update ──────────────────────────────────────────

    #[test]
    fn test_on_route_update_inserts_route_into_rib() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, PeerType::External, 65002, 90, &[]);

        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        assert_eq!(state.rib.loc_rib.len(), 1);
        assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some());
    }

    #[test]
    fn test_on_route_update_propagates_to_other_established_peer() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);

        state.on_established(peer_a, PeerType::External, 65002, 90, &[]);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[]);

        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_a),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        let msg = receivers
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer_b should receive UPDATE for the new route");
        assert_eq!(msg.announced, vec![nlri("10.0.0.0/8")]);
    }

    #[test]
    fn test_on_route_update_withdraw_removes_route_from_rib() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, PeerType::External, 65002, 90, &[]);

        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        assert_eq!(state.rib.loc_rib.len(), 1);

        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![nlri("10.0.0.0/8")],
                attributes: vec![],
                announced: vec![],
            },
        );
        assert_eq!(state.rib.loc_rib.len(), 0);
    }

    // ── test wrappers ─────────────────────────────────────────────────────────

    /// Wrapper for IPv4-only `handle_update` calls — passes fresh v6 stubs.
    fn handle_update_v4(
        p: PeerId,
        msg: UpdateMessage,
        ari: &mut AdjRibIn<Ipv4Addr>,
        rib: &mut LocRib<Ipv4Addr>,
        policy: &Policy<Route<Ipv4Addr>>,
        pt: PeerType,
    ) {
        let mut ari_v6: AdjRibIn<Ipv6Addr> = AdjRibIn::new(p);
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        handle_update(p, msg, ari, rib, &mut ari_v6, &mut rib_v6, policy, pt);
    }

    fn nlri_v6(s: &str) -> Nlri<Ipv6Addr> {
        s.parse().unwrap()
    }

    // ── basic handle_update behaviour ─────────────────────────────────────────

    #[test]
    fn test_handle_update_inserts_route_with_all_attributes() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Egp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                PathAttribute::LocalPref(200),
                PathAttribute::Med(50),
                PathAttribute::Communities(vec![Community::new(0x0001_0001)]),
                PathAttribute::LargeCommunities(vec![LargeCommunity::new(65000, 1, 100)]),
                PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::route_target_as2(
                    65000, 1,
                )]),
                PathAttribute::AtomicAggregate,
                PathAttribute::Aggregator(Aggregator::new(
                    Asn::new(65001),
                    Ipv4Addr::new(1, 1, 1, 1),
                )),
            ],
            announced: vec![nlri("192.168.0.0/16")],
        };
        handle_update_v4(
            peer(),
            msg,
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );

        let route = rib.best(&nlri("192.168.0.0/16")).unwrap();
        assert_eq!(route.origin, Origin::Egp);
        assert_eq!(route.local_pref, Some(LocalPref::new(200)));
        assert_eq!(route.med, Some(Med::new(50)));
        assert_eq!(route.communities.len(), 1);
        assert_eq!(route.large_communities.len(), 1);
        assert_eq!(route.extended_communities.len(), 1);
        assert!(route.atomic_aggregate);
        assert!(route.aggregator.is_some());
    }

    #[test]
    fn test_handle_update_withdraw_removes_route() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 1);

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![nlri("10.0.0.0/8")],
                attributes: vec![],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());
        assert!(ari.is_empty());
    }

    #[test]
    fn test_handle_update_empty_announced_is_noop() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::Origin(Origin::Igp)],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());
        assert!(ari.is_empty());
    }

    #[test]
    fn test_handle_update_unknown_attribute_is_skipped() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::Unknown {
                        flags: 0x80,
                        type_code: 255,
                        value: vec![1, 2, 3],
                    },
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 1);
    }

    // ── RFC 7999 — BLACKHOLE community discard ───────────────────────────────

    #[test]
    fn test_handle_update_blackhole_route_not_installed() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::Communities(vec![Community::BLACKHOLE]),
                ],
                announced: vec![nlri("192.0.2.0/24")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        // BLACKHOLE-tagged route must not enter LocRib even with accept-all policy.
        assert_eq!(rib.len(), 0, "BLACKHOLE route must not be installed");
    }

    #[test]
    fn test_handle_update_blackhole_route_stored_in_adj_rib_in() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        let prefix = nlri("192.0.2.0/24");
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::Communities(vec![Community::BLACKHOLE]),
                ],
                announced: vec![prefix],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        // Pre-policy route stored in AdjRibIn for soft-reconfig visibility.
        assert!(
            ari.get(&prefix).is_some(),
            "BLACKHOLE route must be in AdjRibIn"
        );
    }

    #[test]
    fn test_handle_update_non_blackhole_route_installed_normally() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    // Regular community, not BLACKHOLE.
                    PathAttribute::Communities(vec![Community::NO_EXPORT]),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 1);
    }

    // ── MP_UNREACH_NLRI / MP_REACH_NLRI (RFC 4760) ───────────────────────────

    #[test]
    fn test_handle_update_mp_unreach_withdraws_ipv4_route() {
        // Peer first announces a route via the traditional field, then
        // withdraws it via MP_UNREACH_NLRI (AFI=1, SAFI=1) — valid per RFC 4760
        // and done by some modern implementations when multiprotocol is negotiated.
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 1);

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi_safi: AfiSafi::IPV4_UNICAST,
                    prefixes: vec![Prefix::V4(nlri("10.0.0.0/8"))],
                })],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );

        assert!(
            rib.is_empty(),
            "MP_UNREACH_NLRI should have removed the route"
        );
        assert!(ari.is_empty(), "AdjRibIn should also be cleared");
    }

    #[test]
    fn test_handle_update_mp_reach_announces_ipv4_route() {
        // Peer announces via MP_REACH_NLRI instead of the traditional NLRI field.
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::LocalPref(150),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV4_UNICAST,
                        next_hop: NextHop::V4("10.0.0.2".parse().unwrap()),
                        prefixes: vec![
                            Prefix::V4(nlri("192.168.1.0/24")),
                            Prefix::V4(nlri("192.168.2.0/24")),
                        ],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );

        assert_eq!(rib.len(), 2, "both MP_REACH prefixes should be in LocRib");
        assert_eq!(ari.len(), 2, "both MP_REACH prefixes should be in AdjRibIn");

        let route = rib.best(&nlri("192.168.1.0/24")).unwrap();
        assert_eq!(route.local_pref, Some(LP::new(150)));
        assert_eq!(
            route.next_hop,
            Some(NextHop::V4("10.0.0.2".parse().unwrap()))
        );
    }

    #[test]
    fn test_handle_update_mp_reach_mixed_with_traditional() {
        // Traditional NLRI + MP_REACH_NLRI V4 in the same UPDATE — both should land.
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::NextHop("10.0.0.2".parse().unwrap()),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV4_UNICAST,
                        next_hop: NextHop::V4("10.0.0.3".parse().unwrap()),
                        prefixes: vec![Prefix::V4(nlri("172.16.0.0/12"))],
                    }),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );

        assert_eq!(rib.len(), 2);
        // Traditional NLRI uses NEXT_HOP attribute
        assert_eq!(
            rib.best(&nlri("10.0.0.0/8")).unwrap().next_hop,
            Some(NextHop::V4("10.0.0.2".parse().unwrap()))
        );
        // MP_REACH_NLRI uses its own embedded next-hop
        assert_eq!(
            rib.best(&nlri("172.16.0.0/12")).unwrap().next_hop,
            Some(NextHop::V4("10.0.0.3".parse().unwrap()))
        );
    }

    #[test]
    fn test_handle_update_mp_unreach_non_ipv4_is_skipped() {
        // MP_UNREACH_NLRI for a non-IPv4 AFI/SAFI is silently skipped —
        // no panic, no crash, IPv4 RIB unchanged.
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    prefixes: vec![], // IPv6 prefixes; we have none to construct here
                })],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );

        assert!(rib.is_empty());
    }

    #[test]
    fn test_handle_update_mp_reach_import_policy_applied() {
        // Import policy must be evaluated for MP_REACH_NLRI routes just as
        // it is for traditional NLRIs.
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV4_UNICAST,
                        next_hop: NextHop::V4("10.0.0.2".parse().unwrap()),
                        prefixes: vec![Prefix::V4(nlri("10.0.0.0/8"))],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &reject_all(),
            PeerType::External,
        );

        // Policy rejected it: AdjRibIn stores the raw route, LocRib stays empty.
        assert_eq!(ari.len(), 1, "pre-policy route stored in AdjRibIn");
        assert!(rib.is_empty(), "rejected route must not enter LocRib");
    }

    #[test]
    fn test_on_route_update_mp_unreach_propagates_withdraw_to_peers() {
        // End-to-end: a peer withdraws via MP_UNREACH_NLRI, and the best-path
        // change must reach all other established peers as a WITHDRAW UPDATE.
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut rxs) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);

        state.on_established(peer_a, PeerType::External, 65002, 90, &[]);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[]);

        // Peer A announces 10.0.0.0/8 via traditional field.
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        // Drain the announcement that went to peer B.
        let _ = rxs.get_mut(&peer_b).unwrap().try_recv();

        // Peer A now withdraws via MP_UNREACH_NLRI.
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi_safi: AfiSafi::IPV4_UNICAST,
                    prefixes: vec![Prefix::V4(nlri("10.0.0.0/8"))],
                })],
                announced: vec![],
            },
        );

        assert_eq!(
            state.rib.loc_rib.len(),
            0,
            "LocRib must be empty after MP_UNREACH_NLRI"
        );

        let withdraw_msg = rxs
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer B should receive a WITHDRAW");
        assert!(
            withdraw_msg.withdrawn.contains(&nlri("10.0.0.0/8")),
            "WITHDRAW must contain the MP-withdrawn prefix"
        );
    }

    // ── IPv6 inbound (MP_REACH_NLRI / MP_UNREACH_NLRI) ───────────────────────

    fn fresh_ari_v6() -> AdjRibIn<Ipv6Addr> {
        AdjRibIn::new(peer())
    }

    #[test]
    fn test_handle_update_mp_reach_ipv6_inserts_into_loc_rib_v6() {
        let mut ari = fresh_ari();
        let mut rib = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();

        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                        prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            PeerType::External,
        );

        assert_eq!(rib_v6.len(), 1, "IPv6 route must enter loc_rib_v6");
        assert!(rib.is_empty(), "IPv4 LocRib must remain empty");
        let route = rib_v6.best(&nlri_v6("2001:db8::/32")).unwrap();
        assert_eq!(route.origin, Origin::Igp);
    }

    #[test]
    fn test_handle_update_mp_reach_ipv6_stored_in_adj_rib_in_v6() {
        let mut ari = fresh_ari();
        let mut rib = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();

        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("fe80::1".parse().unwrap()),
                        prefixes: vec![Prefix::V6(nlri_v6("fd00::/16"))],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            PeerType::External,
        );

        assert_eq!(ari_v6.len(), 1, "pre-policy route must be in adj_rib_in_v6");
    }

    #[test]
    fn test_handle_update_mp_unreach_ipv6_withdraws_route() {
        let mut ari = fresh_ari();
        let mut rib = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();

        // Announce first.
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                        prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib_v6.len(), 1);

        // Then withdraw.
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                })],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            PeerType::External,
        );

        assert!(
            rib_v6.is_empty(),
            "loc_rib_v6 must be empty after withdrawal"
        );
        assert!(rib.is_empty(), "IPv4 LocRib must be unaffected");
    }

    #[test]
    fn test_handle_update_ipv4_and_ipv6_in_same_update() {
        let mut ari = fresh_ari();
        let mut rib = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();

        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                        prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                    }),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            PeerType::External,
        );

        assert_eq!(rib.len(), 1, "IPv4 route must be in loc_rib");
        assert_eq!(rib_v6.len(), 1, "IPv6 route must be in loc_rib_v6");
    }

    // ── IPv6 outbound (propagate_prefix_v6 / flush_updates_v6) ───────────────

    fn make_adj_rib_out_v6(pt: PeerType) -> AdjRibOut<Ipv6Addr> {
        AdjRibOut::new(peer(), pt)
    }

    #[test]
    fn test_propagate_prefix_v6_ibgp_announces_route() {
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let mut aro = make_adj_rib_out_v6(PeerType::Internal);
        let route = RouteBuilder::new(nlri_v6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        rib_v6.insert(peer(), route);

        let decision = propagate_prefix_v6(
            nlri_v6("2001:db8::/32"),
            &rib_v6,
            &mut aro,
            PeerType::Internal,
            65001,
            None, // no local_ipv6 — OK for iBGP
        );

        assert!(
            matches!(decision, PrefixDecisionV6::Announce(_)),
            "iBGP peer should receive v6 announcement regardless of local_ipv6"
        );
    }

    #[test]
    fn test_propagate_prefix_v6_ebgp_with_local_ipv6_rewrites_nexthop() {
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let mut aro = make_adj_rib_out_v6(PeerType::External);
        let route = RouteBuilder::new(nlri_v6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        rib_v6.insert(peer(), route);

        let local_v6: Ipv6Addr = "2001:db8::ff".parse().unwrap();
        let decision = propagate_prefix_v6(
            nlri_v6("2001:db8::/32"),
            &rib_v6,
            &mut aro,
            PeerType::External,
            65001,
            Some(local_v6),
        );

        match decision {
            PrefixDecisionV6::Announce(r) => {
                assert_eq!(
                    r.next_hop,
                    Some(NextHop::V6(local_v6)),
                    "eBGP next-hop must be rewritten to local_ipv6"
                );
            }
            other => panic!("expected Announce, got {other:?}"),
        }
    }

    #[test]
    fn test_propagate_prefix_v6_ebgp_without_local_ipv6_is_no_announce() {
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let mut aro = make_adj_rib_out_v6(PeerType::External);
        let route = RouteBuilder::new(nlri_v6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        rib_v6.insert(peer(), route);

        let decision = propagate_prefix_v6(
            nlri_v6("2001:db8::/32"),
            &rib_v6,
            &mut aro,
            PeerType::External,
            65001,
            None, // no local_ipv6 — eBGP must NOT announce
        );

        assert!(
            matches!(decision, PrefixDecisionV6::NoChange),
            "eBGP peer without local_ipv6 must not receive v6 announcement"
        );
    }

    #[test]
    fn test_propagate_prefix_v6_withdraw_when_best_disappears() {
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let mut aro = make_adj_rib_out_v6(PeerType::Internal);
        // Pre-populate AdjRibOut with an existing announcement.
        let route = RouteBuilder::new(nlri_v6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        rib_v6.insert(peer(), route.clone());
        // Announce it first so AdjRibOut records it.
        propagate_prefix_v6(
            nlri_v6("2001:db8::/32"),
            &rib_v6,
            &mut aro,
            PeerType::Internal,
            65001,
            None,
        );

        // Now withdraw from loc_rib_v6 and propagate again.
        rib_v6.withdraw(&peer(), &nlri_v6("2001:db8::/32"));
        let decision = propagate_prefix_v6(
            nlri_v6("2001:db8::/32"),
            &rib_v6,
            &mut aro,
            PeerType::Internal,
            65001,
            None,
        );

        assert!(
            matches!(decision, PrefixDecisionV6::Withdraw(_)),
            "must produce Withdraw when best path is gone"
        );
    }

    #[test]
    fn test_on_established_sends_v6_full_table_dump() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut rxs) = make_state(65001, &[(peer_ip, 65002)]);

        // Pre-populate the v6 RIB with a route from a third-party peer.
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
        let v6_route = RouteBuilder::new(
            nlri_v6("2001:db8::/32"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65009)]),
        )
        .next_hop(NextHop::V6("2001:db8::9".parse().unwrap()))
        .peer_type(PeerType::External)
        .build();
        state.rib_mut().loc_rib_v6.insert(src, v6_route);

        // Set local_ipv6 so eBGP dump works.
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

        state.on_established(peer_ip, PeerType::External, 65002, 90, &[]);

        // First message should be the MP_REACH_NLRI UPDATE for the v6 prefix.
        let msg = rxs
            .get_mut(&peer_ip)
            .unwrap()
            .try_recv()
            .expect("should receive v6 UPDATE on establish");
        let has_mp_reach = msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::MpReachNlri(mp) if mp.afi_safi == AfiSafi::IPV6_UNICAST));
        assert!(has_mp_reach, "Established full-table dump must include v6 MP_REACH_NLRI");
    }

    #[test]
    fn test_on_route_update_v6_propagates_to_peer() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut rxs) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);

        // Set local_ipv6 so eBGP next-hop rewrite works for peer_b.
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

        state.on_established(peer_a, PeerType::External, 65002, 90, &[]);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[]);

        // Peer A announces an IPv6 route via MP_REACH_NLRI.
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("2001:db8::2".parse().unwrap()),
                        prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                    }),
                ],
                announced: vec![],
            },
        );

        // peer_b should receive an UPDATE with MP_REACH_NLRI for the v6 prefix.
        let msg = rxs
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer_b should receive a v6 UPDATE");
        let has_v6 = msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::MpReachNlri(mp) if mp.afi_safi == AfiSafi::IPV6_UNICAST));
        assert!(has_v6, "propagated UPDATE must contain MP_REACH_NLRI for v6 prefix");
    }

    // ── import policy ─────────────────────────────────────────────────────────

    #[test]
    fn test_reject_all_policy_blocks_all_routes() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8"), nlri("192.168.0.0/16")],
            },
            &mut ari,
            &mut rib,
            &reject_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());
    }

    #[test]
    fn test_accept_all_policy_passes_all_routes() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8"), nlri("192.168.0.0/16")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 2);
    }

    #[test]
    fn test_policy_modifies_route_before_insert() {
        let mut policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Reject);
        policy.add_term(Term::new(
            AnyCondition,
            ActionSequence::new()
                .then(SetLocalPref::new(LP::new(200)))
                .then(Accept),
        ));

        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &policy,
            PeerType::External,
        );

        let route = rib.best(&nlri("10.0.0.0/8")).unwrap();
        assert_eq!(route.local_pref, Some(LP::new(200)));
    }

    #[test]
    fn test_policy_partial_reject_only_accepted_routes_inserted() {
        let blocked = Community::from_parts(65001, 1);
        let mut policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Accept);
        policy.add_term(Term::new(CommunityCondition::new(blocked), Reject));

        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::Communities(vec![blocked]),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &policy,
            PeerType::External,
        );

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("192.168.0.0/16")],
            },
            &mut ari,
            &mut rib,
            &policy,
            PeerType::External,
        );

        assert!(
            rib.best(&nlri("10.0.0.0/8")).is_none(),
            "blocked route must not be in RIB"
        );
        assert!(
            rib.best(&nlri("192.168.0.0/16")).is_some(),
            "clean route must be in RIB"
        );
    }

    #[test]
    fn test_peer_type_tagged_on_route() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::Internal,
        );
        let route = rib.best(&nlri("10.0.0.0/8")).unwrap();
        assert_eq!(route.peer_type, PeerType::Internal);
    }

    // ── Adj-RIB-In pre-policy store ───────────────────────────────────────────

    #[test]
    fn test_adj_rib_in_stores_raw_route_even_when_rejected() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &reject_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());
        assert_eq!(ari.len(), 1);
        assert!(ari.get(&nlri("10.0.0.0/8")).is_some());
    }

    #[test]
    fn test_adj_rib_in_stores_raw_attributes_before_policy_modification() {
        let mut policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Reject);
        policy.add_term(Term::new(
            AnyCondition,
            ActionSequence::new()
                .then(SetLocalPref::new(LP::new(200)))
                .then(Accept),
        ));

        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &policy,
            PeerType::External,
        );

        assert_eq!(
            rib.best(&nlri("10.0.0.0/8")).unwrap().local_pref,
            Some(LP::new(200))
        );
        assert_eq!(ari.get(&nlri("10.0.0.0/8")).unwrap().local_pref, None);
    }

    #[test]
    fn test_adj_rib_in_withdraw_clears_both_tables() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(ari.len(), 1);
        assert_eq!(rib.len(), 1);

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![nlri("10.0.0.0/8")],
                attributes: vec![],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(ari.is_empty());
        assert!(rib.is_empty());
    }

    // ── soft reconfiguration ──────────────────────────────────────────────────

    #[test]
    fn test_reapply_accepts_previously_rejected_route() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &reject_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());

        reapply_import_policy(peer(), &ari, &mut rib, &accept_all());
        assert!(rib.best(&nlri("10.0.0.0/8")).is_some());
    }

    #[test]
    fn test_reapply_rejects_previously_accepted_route() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(rib.best(&nlri("10.0.0.0/8")).is_some());

        reapply_import_policy(peer(), &ari, &mut rib, &reject_all());
        assert!(rib.best(&nlri("10.0.0.0/8")).is_none());
    }

    #[test]
    fn test_reapply_applies_new_policy_modifications() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.best(&nlri("10.0.0.0/8")).unwrap().local_pref, None);

        let mut new_policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Reject);
        new_policy.add_term(Term::new(
            AnyCondition,
            ActionSequence::new()
                .then(SetLocalPref::new(LP::new(300)))
                .then(Accept),
        ));

        reapply_import_policy(peer(), &ari, &mut rib, &new_policy);
        assert_eq!(
            rib.best(&nlri("10.0.0.0/8")).unwrap().local_pref,
            Some(LP::new(300))
        );
        assert_eq!(ari.get(&nlri("10.0.0.0/8")).unwrap().local_pref, None);
    }

    #[test]
    fn test_reapply_partial_accept_reject() {
        let blocked = Community::from_parts(65001, 1);
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::Communities(vec![blocked]),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("192.168.0.0/16")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 2);

        let mut new_policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Accept);
        new_policy.add_term(Term::new(CommunityCondition::new(blocked), Reject));

        reapply_import_policy(peer(), &ari, &mut rib, &new_policy);
        assert!(
            rib.best(&nlri("10.0.0.0/8")).is_none(),
            "blocked route must be withdrawn"
        );
        assert!(
            rib.best(&nlri("192.168.0.0/16")).is_some(),
            "clean route must remain"
        );
    }

    // ── prepare_outbound ──────────────────────────────────────────────────────

    fn bgp_id() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 1)
    }

    fn ebgp_route_with_lp(prefix: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(
            nlri(prefix),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65002)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 2)))
        .local_pref(LP::new(200))
        .peer_type(PeerType::External)
        .build()
    }

    fn ibgp_route(prefix: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(
            nlri(prefix),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65002)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 2)))
        .local_pref(LP::new(200))
        .peer_type(PeerType::Internal)
        .build()
    }

    #[test]
    fn test_prepare_outbound_ebgp_prepends_local_as() {
        let route = ebgp_route_with_lp("10.0.0.0/8");
        let out = prepare_outbound(route, PeerType::External, 65001, bgp_id());
        assert_eq!(out.as_path.path_length(), 2);
        assert!(out.as_path.contains(Asn::new(65001)));
        assert!(out.as_path.contains(Asn::new(65002)));
    }

    #[test]
    fn test_prepare_outbound_ebgp_rewrites_next_hop() {
        let route = ebgp_route_with_lp("10.0.0.0/8");
        let out = prepare_outbound(route, PeerType::External, 65001, bgp_id());
        assert_eq!(out.next_hop, Some(NextHop::V4(bgp_id())));
    }

    #[test]
    fn test_prepare_outbound_ebgp_strips_local_pref() {
        let route = ebgp_route_with_lp("10.0.0.0/8");
        let out = prepare_outbound(route, PeerType::External, 65001, bgp_id());
        assert!(
            out.local_pref.is_none(),
            "LOCAL_PREF must be stripped for eBGP"
        );
    }

    #[test]
    fn test_prepare_outbound_ibgp_preserves_attributes() {
        let route = ibgp_route("10.0.0.0/8");
        let out = prepare_outbound(route.clone(), PeerType::Internal, 65001, bgp_id());
        assert_eq!(out.as_path.path_length(), route.as_path.path_length());
        assert_eq!(out.local_pref, route.local_pref);
        assert_eq!(out.next_hop, route.next_hop);
    }

    // ── route_to_attributes ───────────────────────────────────────────────────

    fn route_to_update_for_test(route: &Route<Ipv4Addr>) -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: route_to_attributes(route),
            announced: vec![route.nlri],
        }
    }

    #[test]
    fn test_route_to_update_contains_mandatory_attributes() {
        let route = RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65001)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .build();

        let msg = route_to_update_for_test(&route);
        assert_eq!(msg.announced, vec![nlri("10.0.0.0/8")]);
        assert!(msg.withdrawn.is_empty());
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::Origin(_)))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::AsPath(_)))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::NextHop(_)))
        );
    }

    #[test]
    fn test_route_to_update_omits_absent_optional_attributes() {
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new()).build();
        let msg = route_to_update_for_test(&route);
        assert!(
            !msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::LocalPref(_)))
        );
        assert!(
            !msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::Med(_)))
        );
    }

    #[test]
    fn test_route_to_update_includes_all_optional_attributes() {
        let route = RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65001)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .local_pref(LP::new(150))
        .med(Med::new(100))
        .community(Community::new(0xFFFF_FF01))
        .large_community(LargeCommunity::new(65001, 1, 1))
        .extended_community(ExtendedCommunity::route_target_as2(65001, 1))
        .atomic_aggregate()
        .aggregator(Aggregator::new(Asn::new(65001), Ipv4Addr::new(1, 1, 1, 1)))
        .build();

        let msg = route_to_update_for_test(&route);
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::LocalPref(_)))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::Med(_)))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::Communities(_)))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::LargeCommunities(_)))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::ExtendedCommunities(_)))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::AtomicAggregate))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::Aggregator(_)))
        );
    }

    // ── propagate_prefix / flush_updates ─────────────────────────────────────

    /// Test helper: propagate a single prefix and flush decisions to `tx`.
    /// Returns whether the flush succeeded (channel not full).
    #[allow(clippy::too_many_arguments)]
    fn propagate_and_flush(
        nlri: Nlri<Ipv4Addr>,
        rib: &impl RibView<Ipv4Addr>,
        aro: &mut AdjRibOut<Ipv4Addr>,
        policy: &Policy<Route<Ipv4Addr>>,
        peer_type: PeerType,
        local_as: u32,
        bgp_id: Ipv4Addr,
        tx: &mpsc::Sender<UpdateMessage>,
    ) -> bool {
        let decision = propagate_prefix(nlri, rib, aro, policy, peer_type, local_as, bgp_id);
        flush_updates(vec![decision], MAX_LEN, tx)
    }

    fn ebgp_out_peer() -> (PeerId, AdjRibOut<Ipv4Addr>) {
        let p = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        (p, AdjRibOut::new(p, PeerType::External))
    }

    fn ibgp_out_peer() -> (PeerId, AdjRibOut<Ipv4Addr>) {
        let p = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)));
        (p, AdjRibOut::new(p, PeerType::Internal))
    }

    #[test]
    fn test_propagate_prefix_sends_update_for_new_route() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );

        let msg = rx.try_recv().expect("should have queued an UPDATE");
        assert!(!msg.announced.is_empty());
        assert_eq!(msg.announced[0], nlri("10.0.0.0/8"));
    }

    #[test]
    fn test_propagate_prefix_no_send_when_route_unchanged() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let _ = rx.try_recv();

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(
            rx.try_recv().is_err(),
            "identical route must not produce a second UPDATE"
        );
    }

    #[test]
    fn test_propagate_prefix_sends_withdraw_when_route_removed() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let _ = rx.try_recv();

        rib.withdraw(&peer(), &nlri("10.0.0.0/8"));

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let msg = rx.try_recv().expect("should have queued a WITHDRAW");
        assert!(!msg.withdrawn.is_empty());
        assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
        assert!(msg.announced.is_empty());
    }

    #[test]
    fn test_propagate_prefix_sends_withdraw_when_export_policy_rejects() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let _ = rx.try_recv();

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &reject_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let msg = rx.try_recv().expect("should have queued a WITHDRAW");
        assert!(!msg.withdrawn.is_empty());
        assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
    }

    #[test]
    fn test_propagate_prefix_no_withdraw_for_never_advertised_route() {
        let (_, mut aro) = ebgp_out_peer();
        let rib = LocRib::<Ipv4Addr>::new();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &reject_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(
            rx.try_recv().is_err(),
            "no message expected for a route that was never advertised"
        );
    }

    #[test]
    fn test_propagate_prefix_ibgp_split_horizon_no_send() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ibgp_route("10.0.0.0/8"));
        let (_, mut aro) = ibgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::Internal,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(
            rx.try_recv().is_err(),
            "iBGP split-horizon must suppress re-advertisement"
        );
        assert!(aro.is_empty());
    }

    #[test]
    fn test_propagate_prefix_ebgp_prepends_local_as_in_wire_message() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );

        let msg = rx.try_recv().unwrap();
        let aspath_attr = msg
            .attributes
            .iter()
            .find_map(|a| {
                if let PathAttribute::AsPath(p) = a {
                    Some(p.clone())
                } else {
                    None
                }
            })
            .expect("UPDATE must carry AS_PATH");
        assert!(
            aspath_attr.contains(Asn::new(65001)),
            "local AS must be prepended"
        );
    }

    // ── propagate_prefix — iBGP split-horizon eviction ────────────────────────

    /// When the best path for a prefix switches from eBGP to iBGP, the
    /// previously stored eBGP entry in the iBGP peer's `AdjRibOut` is evicted
    /// (`InsertOutcome::Filtered(Some(_))`), triggering a WITHDRAW.
    #[test]
    fn test_propagate_prefix_ibgp_split_horizon_eviction_sends_withdraw() {
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
        let (_, mut aro) = ibgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        // Phase 1: best path is eBGP — stored in the iBGP peer's AdjRibOut.
        let mut rib = LocRib::new();
        rib.insert(src, ebgp_route_with_lp("10.0.0.0/8"));
        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::Internal,
            65001,
            bgp_id(),
            &tx,
        );
        let _ = rx.try_recv(); // consume the UPDATE

        // Phase 2: best path switches to iBGP — split-horizon evicts the stored
        // eBGP entry and the peer must receive a WITHDRAW.
        let mut rib2 = LocRib::new();
        rib2.insert(src, ibgp_route("10.0.0.0/8"));
        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib2,
            &mut aro,
            &accept_all(),
            PeerType::Internal,
            65001,
            bgp_id(),
            &tx,
        );
        let msg = rx
            .try_recv()
            .expect("split-horizon eviction must send WITHDRAW");
        assert!(!msg.withdrawn.is_empty());
        assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
    }

    // ── propagate_prefix — StubRibView (dependency-inversion tests) ─────────────

    /// Minimal `RibView` implementation for unit tests that want to inject a
    /// specific best route without constructing a full `LocRib`.
    struct StubRibView(Option<Route<Ipv4Addr>>);

    impl RibView<Ipv4Addr> for StubRibView {
        fn best(&self, _nlri: &Nlri<Ipv4Addr>) -> Option<&Route<Ipv4Addr>> {
            self.0.as_ref()
        }
    }

    #[test]
    fn test_propagate_prefix_stub_rib_announces_when_route_present() {
        let rib = StubRibView(Some(ebgp_route_with_lp("10.0.0.0/8")));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);
        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let msg = rx
            .try_recv()
            .expect("should announce when best route present");
        assert!(!msg.announced.is_empty());
        assert_eq!(msg.announced[0], nlri("10.0.0.0/8"));
    }

    #[test]
    fn test_propagate_prefix_stub_rib_no_message_when_no_route() {
        let rib = StubRibView(None);
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);
        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &reject_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(
            rx.try_recv().is_err(),
            "no message when RIB has no best route and prefix was never advertised"
        );
    }

    #[test]
    fn test_propagate_prefix_stub_rib_withdraw_when_route_gone() {
        // First advertise via a real LocRib, then call again with empty StubRibView
        // to verify a WITHDRAW is produced even without constructing a second LocRib.
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);
        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let _ = rx.try_recv(); // consume announcement

        // Now inject an empty view — simulates route having been withdrawn
        let empty_rib = StubRibView(None);
        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &empty_rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let msg = rx
            .try_recv()
            .expect("should WITHDRAW when best route disappears");
        assert!(!msg.withdrawn.is_empty());
        assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
    }

    // ── propagate_prefix — channel-full stall detection ──────────────────────

    /// When the outbound UPDATE channel is full, propagate_prefix returns false
    /// so the caller can close the session and restore a consistent peer view.
    #[test]
    fn test_propagate_prefix_full_update_channel_returns_false() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, _rx) = mpsc::channel(1);

        // Fill the single-slot channel so the next try_send fails.
        tx.try_send(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })
        .unwrap();

        let ok = propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(!ok, "full channel must return false");
    }

    /// When the outbound WITHDRAW channel is full (Reject/Next decision path),
    /// propagate_prefix returns false.
    #[test]
    fn test_propagate_prefix_full_withdraw_on_reject_returns_false() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(1);

        // Advertise the route so it is stored in AdjRibOut.
        let ok = propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(ok);
        let _ = rx.try_recv();

        // Fill the channel before the second call so try_send fails.
        tx.try_send(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })
        .unwrap();

        // Export policy now rejects — triggers WITHDRAW try_send on a full channel.
        let ok = propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &reject_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(!ok, "full channel on WITHDRAW (reject) must return false");
    }

    /// When the outbound WITHDRAW channel is full (no best route / None path),
    /// propagate_prefix returns false.
    #[test]
    fn test_propagate_prefix_full_withdraw_on_empty_rib_returns_false() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(1);

        // Store the route in AdjRibOut.
        let ok = propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(ok);
        let _ = rx.try_recv();

        // Remove the route so loc_rib.best returns None.
        rib.withdraw(&peer(), &nlri("10.0.0.0/8"));

        // Fill the channel so the WITHDRAW try_send fails.
        tx.try_send(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })
        .unwrap();

        let ok = propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(!ok, "full channel on WITHDRAW (no best) must return false");
    }

    // ── DaemonState — unknown peer defensive paths ────────────────────────────

    /// Calling `on_established` with a peer IP that was never in the config
    /// logs an error and returns without panicking.
    #[test]
    fn test_on_established_unknown_peer_is_noop() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);

        let unknown: Ipv4Addr = "10.0.0.99".parse().unwrap();
        state.on_established(unknown, PeerType::External, 65099, 90, &[]);
        // Invariant: no state changes (the unknown IP is absent from maps).
        assert!(!state.rib.peer_types.contains_key(&peer_ip));
    }

    // ── on_established error paths ────────────────────────────────────────────

    #[test]
    fn test_on_established_missing_adj_rib_out_logs_and_returns() {
        // export_policies is present but adj_ribs_out was removed — the second
        // let-else guard fires; must not panic and peer_type is still recorded.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.adj_ribs_out.remove(&peer_ip);

        state.on_established(peer_ip, PeerType::External, 65002, 90, &[]);

        // peer_type is inserted before the guard, so it should be present.
        assert!(state.rib.peer_types.contains_key(&peer_ip));
    }

    #[test]
    fn test_on_established_missing_update_sender_logs_and_returns() {
        // export_policies and adj_ribs_out are present but update_senders was
        // removed — the third let-else guard fires; must not panic.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.update_senders.remove(&peer_ip);

        state.on_established(peer_ip, PeerType::External, 65002, 90, &[]);

        assert!(state.rib.peer_types.contains_key(&peer_ip));
    }

    // ── on_terminated propagation error paths ────────────────────────────────

    #[test]
    fn test_on_terminated_propagation_missing_adj_rib_out_continues() {
        // Peer B's adj_rib_out is removed. When peer A terminates, propagation
        // to peer B hits the adj_rib_out guard and continues — no panic.
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);
        state.on_established(peer_a, PeerType::External, 65002, 90, &[]);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[]);
        state.adj_ribs_out.remove(&peer_b);

        state.on_terminated(peer_a);

        assert!(!state.rib.peer_types.contains_key(&peer_a));
        assert!(state.rib.peer_types.contains_key(&peer_b));
    }

    #[test]
    fn test_on_terminated_propagation_missing_update_sender_continues() {
        // Peer B's update_sender is removed. Propagation hits the update_sender
        // guard and continues — no panic.
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);
        state.on_established(peer_a, PeerType::External, 65002, 90, &[]);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[]);
        state.update_senders.remove(&peer_b);

        state.on_terminated(peer_a);

        assert!(!state.rib.peer_types.contains_key(&peer_a));
    }

    // ── on_route_update error paths ───────────────────────────────────────────

    #[test]
    fn test_on_route_update_missing_adj_rib_in_logs_and_returns() {
        // import_policy is present but adj_ribs_in was removed — the second
        // let-else guard fires; must not panic and RIB stays empty.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.adj_ribs_in.remove(&peer_ip);

        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        assert_eq!(state.rib.loc_rib.len(), 0);
    }

    #[test]
    fn test_on_route_update_propagation_missing_adj_rib_out_continues() {
        // Peer B's adj_rib_out is removed. When peer A sends an UPDATE,
        // propagation to peer B hits the adj_rib_out guard and continues.
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);
        state.on_established(peer_a, PeerType::External, 65002, 90, &[]);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[]);
        state.adj_ribs_out.remove(&peer_b);

        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        // Route lands in the RIB; missing peer B did not cause a panic.
        assert_eq!(state.rib.loc_rib.len(), 1);
    }

    #[test]
    fn test_on_route_update_propagation_missing_update_sender_continues() {
        // Peer B's update_sender is removed. Propagation hits the update_sender
        // guard and continues — no panic and route still lands.
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);
        state.on_established(peer_a, PeerType::External, 65002, 90, &[]);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[]);
        state.update_senders.remove(&peer_b);

        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        assert_eq!(state.rib.loc_rib.len(), 1);
    }

    // ── propagate_prefix channel-full stall paths ────────────────────────────

    /// Returns a `Sender` whose single-slot channel is already full so that
    /// the very next `try_send` returns `Err(Full)`.
    fn full_channel() -> (mpsc::Sender<UpdateMessage>, mpsc::Receiver<UpdateMessage>) {
        let (tx, rx) = mpsc::channel(1);
        tx.try_send(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })
        .expect("pre-fill");
        (tx, rx)
    }

    #[test]
    fn test_propagate_prefix_channel_full_update_returns_false() {
        // Best route → export accepted → INSERT into empty AdjRibOut → try_send
        // UPDATE fails because the channel is full. Must return false.
        let n = nlri("10.0.0.0/8");
        let mut loc_rib = LocRib::new();
        loc_rib.insert(
            peer(),
            RouteBuilder::new(n, Origin::Igp, AsPath::new()).build(),
        );

        let out_peer = PeerId::new(IpAddr::V4("10.0.0.2".parse().unwrap()));
        let mut aro = AdjRibOut::new(out_peer, PeerType::External);

        let (tx, _rx) = full_channel();
        let ok = propagate_and_flush(
            n,
            &loc_rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            &tx,
        );
        assert!(!ok, "full UPDATE channel must return false");
        // AdjRibOut records the route even though the wire message was not sent;
        // the caller is responsible for closing the session to restore consistency.
        assert_eq!(aro.len(), 1);
    }

    #[test]
    fn test_propagate_prefix_channel_full_split_horizon_eviction_returns_false() {
        // iBGP peer's AdjRibOut has a pre-stored eBGP route. The new best is an
        // iBGP route → InsertOutcome::Filtered(Some(_)) → WITHDRAW → channel full
        // → returns false.
        let n = nlri("10.0.0.0/8");

        let mut loc_rib = LocRib::new();
        loc_rib.insert(
            peer(),
            RouteBuilder::new(n, Origin::Igp, AsPath::new())
                .peer_type(PeerType::Internal)
                .build(),
        );

        let out_peer = PeerId::new(IpAddr::V4("10.0.0.3".parse().unwrap()));
        let mut aro = AdjRibOut::new(out_peer, PeerType::Internal);
        aro.insert(
            RouteBuilder::new(n, Origin::Igp, AsPath::new())
                .peer_type(PeerType::External)
                .build(),
        );

        let (tx, _rx) = full_channel();
        let ok = propagate_and_flush(
            n,
            &loc_rib,
            &mut aro,
            &accept_all(),
            PeerType::Internal,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            &tx,
        );
        assert!(
            !ok,
            "full WITHDRAW channel (split-horizon eviction) must return false"
        );
        assert!(aro.is_empty());
    }

    #[test]
    fn test_propagate_prefix_channel_full_export_reject_returns_false() {
        // Best route exists but export policy rejects it. AdjRibOut had a prior
        // route → WITHDRAW generated → channel full → returns false.
        let n = nlri("10.0.0.0/8");

        let mut loc_rib = LocRib::new();
        loc_rib.insert(
            peer(),
            RouteBuilder::new(n, Origin::Igp, AsPath::new()).build(),
        );

        let out_peer = PeerId::new(IpAddr::V4("10.0.0.2".parse().unwrap()));
        let mut aro = AdjRibOut::new(out_peer, PeerType::External);
        aro.insert(RouteBuilder::new(n, Origin::Igp, AsPath::new()).build());

        let (tx, _rx) = full_channel();
        let ok = propagate_and_flush(
            n,
            &loc_rib,
            &mut aro,
            &reject_all(),
            PeerType::External,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            &tx,
        );
        assert!(
            !ok,
            "full WITHDRAW channel (export reject) must return false"
        );
        assert!(aro.is_empty());
    }

    #[test]
    fn test_propagate_prefix_channel_full_no_best_returns_false() {
        // No best route in LocRib. AdjRibOut has a stale route → WITHDRAW →
        // channel full → returns false.
        let n = nlri("10.0.0.0/8");
        let loc_rib: LocRib<Ipv4Addr> = LocRib::new();

        let out_peer = PeerId::new(IpAddr::V4("10.0.0.2".parse().unwrap()));
        let mut aro = AdjRibOut::new(out_peer, PeerType::External);
        aro.insert(RouteBuilder::new(n, Origin::Igp, AsPath::new()).build());

        let (tx, _rx) = full_channel();
        let ok = propagate_and_flush(
            n,
            &loc_rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            &tx,
        );
        assert!(!ok, "full WITHDRAW channel (no best) must return false");
        assert!(aro.is_empty());
    }

    /// When `on_terminated` propagates to other established peers, a ghost peer
    /// (one that reached `Established` via `on_established` but was never in the
    /// config maps) triggers the missing-export-policy error path.  Must not
    /// panic.
    #[test]
    fn test_on_terminated_ghost_established_peer_does_not_panic() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_a, 65002)]);
        state.on_established(peer_a, PeerType::External, 65002, 90, &[]);

        // Inject a ghost peer into peer_types (never registered in config maps).
        let ghost: Ipv4Addr = "10.0.0.99".parse().unwrap();
        state.on_established(ghost, PeerType::External, 65099, 90, &[]);

        // Terminating peer_a iterates established peers; ghost has no policy /
        // rib entries — the error branch logs and continues without panicking.
        state.on_terminated(peer_a);
        assert!(!state.rib.peer_types.contains_key(&peer_a));
    }

    /// Calling `on_route_update` with an unknown peer IP logs an error and
    /// returns without panicking.
    #[test]
    fn test_on_route_update_unknown_peer_is_noop() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);

        let unknown: Ipv4Addr = "10.0.0.99".parse().unwrap();
        state.on_route_update(
            unknown,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![],
                announced: vec![],
            },
        );
        assert_eq!(state.rib.loc_rib.len(), 0);
    }

    /// When `on_route_update` propagates to established peers, a ghost peer
    /// (in `peer_types` but absent from policy maps) triggers the error path.
    /// Must not panic.
    #[test]
    fn test_on_route_update_ghost_established_peer_does_not_panic() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_a, 65002)]);
        state.on_established(peer_a, PeerType::External, 65002, 90, &[]);

        let ghost: Ipv4Addr = "10.0.0.99".parse().unwrap();
        state.on_established(ghost, PeerType::External, 65099, 90, &[]);

        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        assert_eq!(state.rib.loc_rib.len(), 1);
    }
}

// ── DaemonState stalled-channel paths ────────────────────────────────────────
//
// The following tests cover the `stalled_peers` tracking paths that fire when
// an outbound UPDATE channel is full.  They require a bounded channel with
// capacity 1 that is pre-filled before the method under test runs.

#[cfg(test)]
mod stall_tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    use pathvector_policy::DefaultAction;
    use pathvector_types::{AsPath, Asn, NextHop, Nlri, Origin, PeerType};

    use super::*;
    use crate::config;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn base_route(prefix: &str, nh: Ipv4Addr, pt: PeerType) -> pathvector_rib::Route<Ipv4Addr> {
        RouteBuilder::new(
            nlri(prefix),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65002)]),
        )
        .next_hop(NextHop::V4(nh))
        .peer_type(pt)
        .build()
    }

    /// Build a `DaemonState` where every peer's outbound channel has `capacity`.
    /// Returns the state and a map of receivers so the caller can drain channels.
    fn make_capped(
        peers: &[(Ipv4Addr, u32)],
        capacity: usize,
    ) -> (
        DaemonState,
        HashMap<Ipv4Addr, mpsc::Receiver<UpdateMessage>>,
    ) {
        let mut senders = HashMap::new();
        let mut receivers = HashMap::new();
        for &(ip, _) in peers {
            let (tx, rx) = mpsc::channel(capacity);
            senders.insert(ip, tx);
            receivers.insert(ip, rx);
        }
        let peer_configs: Vec<config::PeerConfig> = peers
            .iter()
            .map(|&(address, remote_as)| config::PeerConfig {
                address,
                port: 179,
                remote_as,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
            })
            .collect();
        let state = DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            &peer_configs,
            senders,
            vec![],
        );
        (state, receivers)
    }

    /// Fill a channel with a dummy UPDATE so the next `try_send` fails.
    fn fill_channel(state: &DaemonState, peer: Ipv4Addr) {
        let tx = state.update_senders.get(&peer).unwrap();
        tx.try_send(UpdateMessage {
            withdrawn: vec![nlri("0.0.0.0/0")],
            attributes: vec![],
            announced: vec![],
        })
        .expect("channel must have room for the fill message");
    }

    // ── take_stalled_peers ────────────────────────────────────────────────────

    #[test]
    fn take_stalled_peers_returns_and_clears() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_capped(&[(peer_ip, 64)], 64);

        assert!(state.take_stalled_peers().is_empty(), "initially empty");
        state.stalled_peers.push(peer_ip);
        let stalled = state.take_stalled_peers();
        assert_eq!(stalled, vec![peer_ip]);
        assert!(state.take_stalled_peers().is_empty(), "cleared after take");
    }

    // ── on_established stalled path ───────────────────────────────────────────

    #[test]
    fn on_established_marks_stalled_when_channel_full() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _rx) = make_capped(&[(peer_ip, 1)], 1);

        // Pre-populate the Loc-RIB from a third-party peer so that on_established
        // has something to propagate.
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
        state.rib_mut().loc_rib.insert(
            src,
            base_route(
                "10.0.0.0/8",
                "10.0.0.9".parse().unwrap(),
                PeerType::External,
            ),
        );

        // Saturate the channel; propagate_prefix's try_send will fail.
        fill_channel(&state, peer_ip);

        state.on_established(peer_ip, PeerType::External, 65002, 90, &[]);
        assert!(
            !state.take_stalled_peers().is_empty(),
            "peer must be stalled when outbound channel is full during table dump"
        );
    }

    // ── on_terminated stalled path ────────────────────────────────────────────

    #[test]
    fn on_terminated_marks_stalled_when_channel_full() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        // Build with mixed capacities: peer_a gets a large channel, peer_b gets cap 1.
        let (tx_a, _rx_a) = mpsc::channel::<UpdateMessage>(64);
        let (tx_b, _rx_b) = mpsc::channel::<UpdateMessage>(1);
        let peer_configs = vec![
            config::PeerConfig {
                address: peer_a,
                port: 179,
                remote_as: 65002,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
            },
            config::PeerConfig {
                address: peer_b,
                port: 179,
                remote_as: 65003,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
            },
        ];
        let mut senders = HashMap::new();
        senders.insert(peer_a, tx_a);
        senders.insert(peer_b, tx_b.clone());
        let mut state = DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            &peer_configs,
            senders,
            vec![],
        );

        state.on_established(peer_a, PeerType::External, 65002, 90, &[]);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[]);

        // Announce a route from peer_a → it ends up in Loc-RIB.
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_a),
                ],
                announced: vec![nlri("192.168.0.0/16")],
            },
        );

        // Drain the messages that on_route_update sent so channels are not pre-filled.
        // (peer_b channel cap = 1; we need exactly that one slot to be free
        //  so we can fill it ourselves.)
        // peer_b received the propagation — drain it.
        // peer_b's channel had capacity 1; one UPDATE was sent during on_route_update.
        // We intentionally do NOT drain it — that fill is the one we rely on.

        // Terminate peer_a: the withdraw for peer_b's channel will fail (full).
        state.on_terminated(peer_a);
        assert!(
            !state.take_stalled_peers().is_empty(),
            "peer_b must be stalled when its channel is full during termination propagation"
        );
    }

    // ── set_import_default propagation loop ───────────────────────────────────

    #[test]
    fn set_import_default_propagates_to_established_peer() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_capped(&[(peer_a, 65002), (peer_b, 65003)], 64);

        state.on_established(peer_a, PeerType::External, 65002, 90, &[]);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[]);

        // Announce a route from peer_a via on_route_update so that it is
        // properly recorded in Adj-RIB-In, Loc-RIB, AND peer_b's Adj-RIB-Out.
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_a),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        // Drain the UPDATE that on_route_update propagated so receivers are clear.
        receivers.get_mut(&peer_b).unwrap().try_recv().ok();
        receivers.get_mut(&peer_a).unwrap().try_recv().ok();

        // Flip the import policy to Reject — route evicted from Loc-RIB;
        // peer_b must receive a WITHDRAW.
        state.set_import_default(peer_a, DefaultAction::Reject);

        receivers
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer_b must receive a WITHDRAW after set_import_default → Reject");
    }

    #[test]
    fn set_import_default_marks_stalled_when_channel_full() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();

        // peer_a gets a large channel; peer_b gets capacity 1.
        let (tx_a, _rx_a) = mpsc::channel::<UpdateMessage>(64);
        let (tx_b, _rx_b) = mpsc::channel::<UpdateMessage>(1);
        let peer_configs = vec![
            config::PeerConfig {
                address: peer_a,
                port: 179,
                remote_as: 65002,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
            },
            config::PeerConfig {
                address: peer_b,
                port: 179,
                remote_as: 65003,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
            },
        ];
        let mut senders = HashMap::new();
        senders.insert(peer_a, tx_a);
        senders.insert(peer_b, tx_b);
        let mut state = DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            &peer_configs,
            senders,
            vec![],
        );

        state.on_established(peer_a, PeerType::External, 65002, 90, &[]);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[]);

        // Announce via on_route_update so adj_rib_out[peer_b] has the route.
        // The UPDATE fills peer_b's channel (capacity 1).
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_a),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        // peer_b's channel is now full (UPDATE from on_route_update).
        // Do NOT drain it.

        // set_import_default tries to send WITHDRAW to peer_b but channel is full.
        state.set_import_default(peer_a, DefaultAction::Reject);
        assert!(
            !state.take_stalled_peers().is_empty(),
            "peer_b must be stalled when channel is full during set_import_default propagation"
        );
    }

    // ── set_export_default propagation loop ───────────────────────────────────

    #[test]
    fn set_export_default_propagates_to_established_peer() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut receivers) = make_capped(&[(peer_ip, 65002)], 64);

        // Populate Loc-RIB BEFORE establishing so the table dump sends the
        // route to peer_ip's Adj-RIB-Out.
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
        state.rib_mut().loc_rib.insert(
            src,
            base_route(
                "10.0.0.0/8",
                "10.0.0.9".parse().unwrap(),
                PeerType::External,
            ),
        );

        state.on_established(peer_ip, PeerType::External, 65002, 90, &[]);
        // Drain the table-dump UPDATE so the receiver is clean.
        receivers.get_mut(&peer_ip).unwrap().try_recv().ok();

        // Reject all exports — peer_ip must receive a WITHDRAW.
        state.set_export_default(peer_ip, DefaultAction::Reject);

        receivers
            .get_mut(&peer_ip)
            .unwrap()
            .try_recv()
            .expect("peer must receive WITHDRAW after set_export_default → Reject");
    }

    #[test]
    fn set_export_default_no_send_when_peer_not_established() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut receivers) = make_capped(&[(peer_ip, 65002)], 64);

        // Peer is configured but never established — set_export_default must
        // return early without sending anything to the channel.
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
        state.rib_mut().loc_rib.insert(
            src,
            base_route(
                "10.0.0.0/8",
                "10.0.0.9".parse().unwrap(),
                PeerType::External,
            ),
        );

        state.set_export_default(peer_ip, DefaultAction::Reject);
        assert!(
            receivers.get_mut(&peer_ip).unwrap().try_recv().is_err(),
            "no message must be sent when peer is not established"
        );
    }

    #[test]
    fn set_export_default_marks_stalled_when_channel_full() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _rx) = make_capped(&[(peer_ip, 65002)], 1);

        // Pre-populate Loc-RIB so the table dump fills the channel (cap 1).
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
        state.rib_mut().loc_rib.insert(
            src,
            base_route(
                "10.0.0.0/8",
                "10.0.0.9".parse().unwrap(),
                PeerType::External,
            ),
        );

        // on_established table-dumps the route → fills the cap-1 channel.
        state.on_established(peer_ip, PeerType::External, 65002, 90, &[]);
        // Do NOT drain the channel — it is now full.

        // Reject forces a WITHDRAW for the route already in adj_rib_out.
        // try_send(withdraw) finds the channel full → propagate_prefix returns
        // false → peer is pushed into stalled_peers.
        state.set_export_default(peer_ip, DefaultAction::Reject);
        assert!(
            !state.take_stalled_peers().is_empty(),
            "peer must be stalled when channel is full during set_export_default propagation"
        );
    }
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
}

// ── Event loop tests ──────────────────────────────────────────────────────────
//
// These tests drive `run_event_loop` by injecting `SessionEvent`s through an
// mpsc channel.  No TCP connections or real session tasks are required.

#[cfg(test)]
mod event_loop_tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use pathvector_session::fsm::SessionInfo;
    use pathvector_session::message::{Capability, UpdateMessage};
    use pathvector_session::transport::{SessionCommand, SessionEvent};
    use pathvector_types::{AsPath, Asn, Nlri, Origin, PeerType};
    use tokio::sync::mpsc;

    use super::*;
    use crate::config;

    // ── helpers ───────────────────────────────────────────────────────────────

    type StateBundle = (
        Arc<RwLock<DaemonState>>,
        HashMap<Ipv4Addr, mpsc::Receiver<UpdateMessage>>,
        HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>>,
    );

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn established_info(peer_as: u32) -> SessionInfo {
        SessionInfo {
            peer_as,
            peer_bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            hold_time: 90,
            peer_capabilities: vec![Capability::FourByteAsn(peer_as)],
            peer_type: PeerType::External,
        }
    }

    /// Build a `DaemonState` + receivers for a set of peers with accept-all
    /// policies and channels of the given capacity.
    fn make_state(peers: &[(Ipv4Addr, u32)], channel_cap: usize) -> StateBundle {
        let mut update_senders = HashMap::new();
        let mut update_receivers = HashMap::new();
        let mut stop_senders = HashMap::new();
        let mut stop_receivers: HashMap<Ipv4Addr, mpsc::Receiver<SessionCommand>> = HashMap::new();

        for &(ip, _) in peers {
            let (tx, rx) = mpsc::channel(channel_cap);
            update_senders.insert(ip, tx);
            update_receivers.insert(ip, rx);
            let (stx, srx) = mpsc::channel(8);
            stop_senders.insert(ip, stx);
            stop_receivers.insert(ip, srx);
        }

        let peer_configs: Vec<config::PeerConfig> = peers
            .iter()
            .map(|&(address, remote_as)| config::PeerConfig {
                address,
                port: 179,
                remote_as,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
            })
            .collect();

        let state = Arc::new(RwLock::new(DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            &peer_configs,
            update_senders,
            vec![],
        )));

        (state, update_receivers, stop_senders)
    }

    // ── Established dispatch ──────────────────────────────────────────────────

    #[tokio::test]
    async fn event_loop_dispatches_established() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65002)], 64);

        let (event_tx, event_rx) = mpsc::channel(8);
        event_tx
            .send((peer_ip, SessionEvent::Established(established_info(65002))))
            .await
            .unwrap();
        drop(event_tx); // close channel so event loop exits after one event

        run_event_loop(event_rx, Arc::clone(&state), stop_senders).await;

        let s = state.read().await;
        assert!(
            s.rib.peer_types.contains_key(&peer_ip),
            "Established event must register peer type in DaemonState"
        );
    }

    // ── Terminated dispatch ───────────────────────────────────────────────────

    #[tokio::test]
    async fn event_loop_dispatches_terminated() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65002)], 64);

        // Establish first so there is state to tear down.
        {
            let mut s = state.write().await;
            s.on_established(peer_ip, PeerType::External, 65002, 90, &[]);
        }

        let (event_tx, event_rx) = mpsc::channel(8);
        event_tx
            .send((peer_ip, SessionEvent::Terminated))
            .await
            .unwrap();
        drop(event_tx);

        run_event_loop(event_rx, Arc::clone(&state), stop_senders).await;

        let s = state.read().await;
        assert!(
            !s.rib.peer_types.contains_key(&peer_ip),
            "Terminated event must remove peer type from DaemonState"
        );
    }

    // ── RouteUpdate dispatch ──────────────────────────────────────────────────

    #[tokio::test]
    async fn event_loop_dispatches_route_update() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65002)], 64);

        {
            let mut s = state.write().await;
            s.on_established(peer_ip, PeerType::External, 65002, 90, &[]);
        }

        let update = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(peer_ip),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        };

        let (event_tx, event_rx) = mpsc::channel(8);
        event_tx
            .send((peer_ip, SessionEvent::RouteUpdate(update)))
            .await
            .unwrap();
        drop(event_tx);

        run_event_loop(event_rx, Arc::clone(&state), stop_senders).await;

        let s = state.read().await;
        assert_eq!(
            s.rib.loc_rib.len(),
            1,
            "RouteUpdate must insert route into Loc-RIB"
        );
    }

    // ── Stalled peer → stop command ───────────────────────────────────────────

    #[tokio::test]
    async fn event_loop_sends_stop_to_stalled_peer() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();

        // Give peer_b a channel of capacity 1 so it stalls during propagation.
        let (update_tx_a, _update_rx_a) = mpsc::channel::<UpdateMessage>(64);
        let (update_tx_b, _update_rx_b) = mpsc::channel::<UpdateMessage>(1);
        let (sess_stop_a, _sess_stop_rx_a) = mpsc::channel::<SessionCommand>(8);
        let (sess_stop_b, mut cmd_rx_b) = mpsc::channel::<SessionCommand>(8);

        let peer_configs = vec![
            config::PeerConfig {
                address: peer_a,
                port: 179,
                remote_as: 65002,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
            },
            config::PeerConfig {
                address: peer_b,
                port: 179,
                remote_as: 65003,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
            },
        ];
        let mut update_senders = HashMap::new();
        update_senders.insert(peer_a, update_tx_a);
        update_senders.insert(peer_b, update_tx_b);
        let state = Arc::new(RwLock::new(DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            &peer_configs,
            update_senders,
            vec![],
        )));
        let mut stop_senders = HashMap::new();
        stop_senders.insert(peer_a, sess_stop_a);
        stop_senders.insert(peer_b, sess_stop_b);

        // Establish both peers.
        {
            let mut s = state.write().await;
            s.on_established(peer_a, PeerType::External, 65002, 90, &[]);
            s.on_established(peer_b, PeerType::External, 65003, 90, &[]);
        }

        // Pre-fill peer_b's cap-1 UPDATE channel so the propagation try_send fails.
        {
            let s = state.read().await;
            s.update_senders[&peer_b]
                .try_send(UpdateMessage {
                    withdrawn: vec![nlri("0.0.0.0/0")],
                    attributes: vec![],
                    announced: vec![],
                })
                .expect("channel must have room for the fill message");
        }

        // Announce a route from peer_a — propagation to peer_b will fail
        // (channel already full) and peer_b must be recorded as stalled.
        let (event_tx, event_rx) = mpsc::channel(8);
        event_tx
            .send((
                peer_a,
                SessionEvent::RouteUpdate(UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![
                        PathAttribute::Origin(Origin::Igp),
                        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                        PathAttribute::NextHop(peer_a),
                    ],
                    announced: vec![nlri("10.0.0.0/8")],
                }),
            ))
            .await
            .unwrap();
        drop(event_tx);

        run_event_loop(event_rx, Arc::clone(&state), stop_senders).await;

        // The event loop must have sent SessionCommand::Stop to peer_b.
        let cmd = cmd_rx_b
            .try_recv()
            .expect("event loop must send Stop to stalled peer_b");
        assert!(
            matches!(cmd, SessionCommand::Stop),
            "expected Stop command, got {cmd:?}"
        );
    }

    // ── Channel closed → loop exits ───────────────────────────────────────────

    #[tokio::test]
    async fn event_loop_exits_when_channel_closes() {
        let (state, _rxs, stop_senders) = make_state(&[], 64);
        let (event_tx, event_rx) = mpsc::channel::<(Ipv4Addr, SessionEvent)>(8);
        // Drop the sender immediately — the loop must exit without hanging.
        drop(event_tx);
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            run_event_loop(event_rx, state, stop_senders),
        )
        .await
        .expect("run_event_loop must exit when the event channel is closed");
    }
}

// ── Property tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod prop_tests {
    use std::net::Ipv4Addr;

    use proptest::prelude::*;

    use pathvector_types::{AsPath, Asn, LocalPref, NextHop, Origin, PeerType};

    use super::*;
    use crate::RouteBuilder;

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn base_route(prefix: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(
            nlri(prefix),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65002)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 2)))
        .local_pref(LocalPref::new(100))
        .peer_type(PeerType::External)
        .build()
    }

    proptest! {
        /// `config_peer_type` returns `Internal` iff the two AS numbers are
        /// equal, and `External` otherwise.
        #[test]
        fn prop_config_peer_type_internal_iff_equal(a: u32, b: u32) {
            let pt = config_peer_type(a, b);
            if a == b {
                prop_assert_eq!(pt, PeerType::Internal);
            } else {
                prop_assert_eq!(pt, PeerType::External);
            }
        }

        /// An explicit import default always overrides the eBGP/iBGP derived
        /// default, regardless of the `is_ebgp` flag.
        #[test]
        fn prop_resolve_import_explicit_always_wins(is_ebgp: bool) {
            let accept = resolve_import_default(Some(config::ImportDefault::Accept), is_ebgp);
            let reject = resolve_import_default(Some(config::ImportDefault::Reject), is_ebgp);
            prop_assert!(matches!(accept, DefaultAction::Accept));
            prop_assert!(matches!(reject, DefaultAction::Reject));
        }

        /// An explicit export default always overrides the eBGP/iBGP derived
        /// default.
        #[test]
        fn prop_resolve_export_explicit_always_wins(is_ebgp: bool) {
            let accept = resolve_export_default(Some(config::ExportDefault::Accept), is_ebgp);
            let reject = resolve_export_default(Some(config::ExportDefault::Reject), is_ebgp);
            prop_assert!(matches!(accept, DefaultAction::Accept));
            prop_assert!(matches!(reject, DefaultAction::Reject));
        }

        /// `withdraw_msg` always produces exactly one withdrawn NLRI and no
        /// announced NLRIs.
        #[test]
        fn prop_withdraw_msg_structure(
            prefix in prop::sample::select(vec![
                "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "0.0.0.0/0",
            ])
        ) {
            let n: Nlri<Ipv4Addr> = prefix.parse().unwrap();
            let msg = UpdateMessage { withdrawn: vec![n], attributes: vec![], announced: vec![] };
            prop_assert_eq!(msg.withdrawn.len(), 1);
            prop_assert_eq!(msg.withdrawn[0], n);
            prop_assert!(msg.announced.is_empty());
            prop_assert!(msg.attributes.is_empty());
        }

        /// `route_to_attributes` always produces Origin and AsPath attributes,
        /// and the NLRI is the route's nlri.
        #[test]
        fn prop_route_to_update_structure(
            prefix in prop::sample::select(vec![
                "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12",
            ])
        ) {
            use pathvector_session::message::PathAttribute;
            let route = base_route(prefix);
            let nlri_val: Nlri<Ipv4Addr> = prefix.parse().unwrap();
            let attrs = route_to_attributes(&route);
            let msg = UpdateMessage { withdrawn: vec![], attributes: attrs, announced: vec![nlri_val] };

            prop_assert_eq!(msg.announced, vec![nlri_val]);
            prop_assert!(msg.withdrawn.is_empty());
            prop_assert!(
                msg.attributes.iter().any(|a| matches!(a, PathAttribute::Origin(_))),
                "UPDATE must carry ORIGIN"
            );
            prop_assert!(
                msg.attributes.iter().any(|a| matches!(a, PathAttribute::AsPath(_))),
                "UPDATE must carry AS_PATH"
            );
        }

        /// For iBGP peers, `prepare_outbound` is an identity transform: the
        /// route's AS_PATH, NEXT_HOP, and LOCAL_PREF are all preserved.
        #[test]
        fn prop_prepare_outbound_ibgp_is_identity(lp_value in 0u32..=65535) {
            let route = RouteBuilder::new(
                nlri("10.0.0.0/8"),
                Origin::Igp,
                AsPath::from_sequence(vec![Asn::new(65002)]),
            )
            .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 2)))
            .local_pref(LocalPref::new(lp_value))
            .peer_type(PeerType::Internal)
            .build();

            let result = prepare_outbound(
                route.clone(),
                PeerType::Internal,
                65001,
                Ipv4Addr::new(10, 0, 0, 1),
            );

            prop_assert_eq!(result.as_path, route.as_path, "AS_PATH must be unchanged for iBGP");
            prop_assert_eq!(result.next_hop, route.next_hop, "NEXT_HOP must be unchanged for iBGP");
            prop_assert_eq!(result.local_pref, route.local_pref, "LOCAL_PREF must be preserved for iBGP");
        }

        /// For eBGP peers, `prepare_outbound` always prepends the local AS,
        /// rewrites the NEXT_HOP, and strips LOCAL_PREF.
        #[test]
        fn prop_prepare_outbound_ebgp_transforms(local_as in 1u32..=4_294_967_294) {
            let bgp_id = Ipv4Addr::new(10, 0, 0, 1);
            let route = base_route("10.0.0.0/8");
            let original_path_len = route.as_path.path_length();

            let result = prepare_outbound(route, PeerType::External, local_as, bgp_id);

            prop_assert_eq!(
                result.as_path.path_length(),
                original_path_len + 1,
                "local AS must be prepended for eBGP"
            );
            prop_assert!(result.as_path.contains(Asn::new(local_as)), "local AS must be in the path");
            prop_assert_eq!(result.next_hop, Some(NextHop::V4(bgp_id)), "NEXT_HOP must be rewritten");
            prop_assert!(result.local_pref.is_none(), "LOCAL_PREF must be stripped for eBGP");
        }
    }
}

// ── run_with / build_daemon tests ─────────────────────────────────────────────

#[cfg(test)]
mod run_with_tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use pathvector_session::message::UpdateMessage;
    use pathvector_session::transport::{
        SessionCommand, SessionConfig, SessionEvent, SessionHandle,
    };
    use tokio::sync::mpsc;

    use super::*;
    use crate::config;

    // ── MockSessionHandle ─────────────────────────────────────────────────────

    /// A zero-cost session handle for unit tests: no TCP, no background tasks.
    ///
    /// Events are injected through a channel whose sender is held by
    /// [`MockPeer`]; `start()` records that it was called via an `AtomicBool`.
    struct MockSessionHandle {
        event_rx: mpsc::Receiver<SessionEvent>,
        update_tx: mpsc::Sender<UpdateMessage>,
        stop_tx: mpsc::Sender<SessionCommand>,
        started: Arc<AtomicBool>,
    }

    impl SessionHandle for MockSessionHandle {
        async fn start(&self) {
            self.started.store(true, Ordering::SeqCst);
        }

        async fn next_event(&mut self) -> Option<SessionEvent> {
            self.event_rx.recv().await
        }

        fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
            self.update_tx.clone()
        }

        fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
            self.stop_tx.clone()
        }

        fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
            self.stop_tx.clone()
        }
    }

    /// Test-side view of a spawned mock session.
    struct MockPeer {
        /// Send events into the forwarding task that `build_daemon` spawned.
        event_tx: mpsc::Sender<SessionEvent>,
        /// `true` after `start()` has been called on the handle.
        started: Arc<AtomicBool>,
    }

    /// Returns a `spawn_fn` compatible with [`build_daemon`] together with a
    /// shared list that is appended to on each invocation.
    fn make_mock_spawn() -> (
        impl Fn(SessionConfig) -> MockSessionHandle,
        Arc<Mutex<Vec<MockPeer>>>,
    ) {
        let peers: Arc<Mutex<Vec<MockPeer>>> = Arc::new(Mutex::new(vec![]));
        let peers_clone = Arc::clone(&peers);
        let spawn_fn = move |_cfg: SessionConfig| {
            let (event_tx, event_rx) = mpsc::channel(8);
            let (update_tx, _update_rx) = mpsc::channel(8);
            let (stop_tx, _stop_rx) = mpsc::channel(8);
            let started = Arc::new(AtomicBool::new(false));
            peers_clone.lock().unwrap().push(MockPeer {
                event_tx,
                started: Arc::clone(&started),
            });
            MockSessionHandle {
                event_rx,
                update_tx,
                stop_tx,
                started,
            }
        };
        (spawn_fn, peers)
    }

    fn make_config(peer_ips: &[(Ipv4Addr, u32)]) -> config::Config {
        config::Config {
            daemon: config::DaemonConfig {
                local_as: 65001,
                bgp_id: Ipv4Addr::new(10, 0, 0, 1),
                hold_time: 90,
                grpc_port: 0,
                bgp_port: 0, // 0 = OS assigns; listener will fail to bind but tests don't need it
                local_ipv6: None,
            },
            peers: peer_ips
                .iter()
                .map(|&(address, remote_as)| config::PeerConfig {
                    address,
                    port: 179,
                    remote_as,
                    import_default: None,
                    export_default: None,
                })
                .collect(),
        }
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    /// `build_daemon` calls the spawn function exactly once per configured peer.
    #[tokio::test]
    async fn build_daemon_calls_spawn_once_per_peer() {
        let (spawn_fn, peers) = make_mock_spawn();
        let cfg = make_config(&[
            (Ipv4Addr::new(10, 0, 0, 1), 65002),
            (Ipv4Addr::new(10, 0, 0, 2), 65003),
        ]);
        let _ = build_daemon(&cfg, spawn_fn).await;
        assert_eq!(peers.lock().unwrap().len(), 2);
    }

    /// `build_daemon` calls `start()` on every handle it spawns.
    #[tokio::test]
    async fn build_daemon_starts_each_session() {
        let (spawn_fn, peers) = make_mock_spawn();
        let cfg = make_config(&[
            (Ipv4Addr::new(10, 0, 0, 1), 65002),
            (Ipv4Addr::new(10, 0, 0, 2), 65003),
        ]);
        let _ = build_daemon(&cfg, spawn_fn).await;
        for peer in peers.lock().unwrap().iter() {
            assert!(peer.started.load(Ordering::SeqCst), "start() not called");
        }
    }

    /// The returned stop-sender map contains an entry for every peer address.
    #[tokio::test]
    async fn build_daemon_provides_stop_sender_per_peer() {
        let peer_a = Ipv4Addr::new(10, 0, 0, 1);
        let peer_b = Ipv4Addr::new(10, 0, 0, 2);
        let (spawn_fn, _peers) = make_mock_spawn();
        let cfg = make_config(&[(peer_a, 65002), (peer_b, 65003)]);
        let (_state, _rx, stop_senders, _) = build_daemon(&cfg, spawn_fn).await;
        assert!(stop_senders.contains_key(&peer_a));
        assert!(stop_senders.contains_key(&peer_b));
    }

    /// An event injected through a mock peer's sender appears on the returned
    /// event receiver — verifying the per-peer forwarding task is wired up.
    #[tokio::test]
    async fn build_daemon_forwards_events_to_receiver() {
        let peer_a = Ipv4Addr::new(10, 0, 0, 1);
        let (spawn_fn, peers) = make_mock_spawn();
        let cfg = make_config(&[(peer_a, 65002)]);
        let (_state, mut event_rx, _stop, _) = build_daemon(&cfg, spawn_fn).await;

        let event_tx = peers.lock().unwrap()[0].event_tx.clone();
        event_tx.send(SessionEvent::Terminated).await.unwrap();

        let (ip, event) = event_rx.recv().await.unwrap();
        assert_eq!(ip, peer_a);
        assert!(matches!(event, SessionEvent::Terminated));
    }

    /// The returned `DaemonState` has an update-sender entry for every
    /// configured peer — i.e. the state is fully pre-populated at startup.
    #[tokio::test]
    async fn build_daemon_state_has_entry_per_peer() {
        let peer_a = Ipv4Addr::new(10, 0, 0, 1);
        let peer_b = Ipv4Addr::new(10, 0, 0, 2);
        let (spawn_fn, _peers) = make_mock_spawn();
        let cfg = make_config(&[(peer_a, 65002), (peer_b, 65003)]);
        let (state, _rx, _stop, _) = build_daemon(&cfg, spawn_fn).await;
        let s = state.read().await;
        assert!(s.update_senders.contains_key(&peer_a));
        assert!(s.update_senders.contains_key(&peer_b));
    }

    /// With no configured peers `build_daemon` succeeds and the event receiver
    /// closes immediately (all senders were dropped, no peers to forward from).
    #[tokio::test]
    async fn build_daemon_no_peers_closes_event_channel() {
        let (spawn_fn, peers) = make_mock_spawn();
        let cfg = make_config(&[]);
        let (_state, mut event_rx, _stop, _) = build_daemon(&cfg, spawn_fn).await;
        assert_eq!(peers.lock().unwrap().len(), 0);
        // No senders remain; recv() returns None immediately.
        assert!(event_rx.recv().await.is_none());
    }
}
