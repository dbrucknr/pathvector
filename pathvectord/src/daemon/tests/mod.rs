//! Daemon tests that drive [`DaemonState`] and the event loop, grouped by topic.
//!
//! This file holds the fixtures the topic modules share.

mod as_path_checks;
mod blackhole_discard;
mod coalescing;
mod dynamic_peer_props;
mod eor_receive;
mod error_paths;
mod event_loop_batches;
mod fib_notifications;
mod gr_peer_capability;
mod gr_phase2;
mod handle_update_basics;
mod import_policy;
mod import_reject_metric;
mod ipv6_outbound;
mod ipv6_peer_identity;
mod local_capabilities;
mod max_prefix;
mod missing_mandatory_attributes;
mod mp_nlri;
mod mrai_timer;
mod next_hop_validation;
mod otc_roles;
mod outbound_attributes;
mod peering_rules;
mod propagation;
mod rfc8538;
mod rib_consistency_props;
mod route_reflection;
mod rpki_rov;
mod run_with;
mod selection_deferral_timer;
mod session_lifecycle;
mod stall;
mod state_props;

use std::net::{IpAddr, Ipv4Addr};

use pathvector_policy::{
    Accept, ActionSequence, AnyCondition, CommunityCondition, DefaultAction, Policy, Reject,
    SetLocalPref, Term,
};
use pathvector_types::{
    Aggregator, Asn, Community, ExtendedCommunity, LargeCommunity, LocalPref as LP, Nlri,
};

use metrics_util::debugging::{DebugValue, DebuggingRecorder};

use super::*;
use crate::outbound::{propagate_prefix, propagate_prefix_v6, route_to_attributes};
use pathvector_rib::{RibView, outbound::prepare_outbound};

/// `(metric_name, sorted_labels) -> DebugValue`, as returned by `capture`.
type MetricsSnapshot = std::collections::HashMap<(String, Vec<(String, String)>), DebugValue>;

/// Runs `f` against a fresh, isolated recorder and returns every emitted
/// metric. Duplicated from `metrics.rs`'s private `capture()` —
/// `metrics-util` is already a workspace dev-dependency, and this is
/// simpler than exporting a private test helper across module boundaries.
fn capture(f: impl FnOnce()) -> MetricsSnapshot {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, f);
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .map(|(composite_key, _unit, _desc, value)| {
            let key = composite_key.key();
            let mut labels: Vec<(String, String)> = key
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            labels.sort();
            ((key.name().to_string(), labels), value)
        })
        .collect()
}

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

fn route_v4(prefix: &str) -> Route<Ipv4Addr> {
    RouteBuilder::new(nlri(prefix), Origin::Igp, AsPath::new())
        .peer_type(PeerType::External)
        .build()
}

fn route_v6(prefix: &str) -> Route<Ipv6Addr> {
    RouteBuilder::new(nlri_v6(prefix), Origin::Igp, AsPath::new())
        .peer_type(PeerType::External)
        .build()
}

/// Gate for tests that exercise policy only: no confederation, no local
/// addresses, and a local AS that no test route carries.
fn test_gate() -> IngressGate {
    IngressGate::new(64999, None, None, None)
}

fn accept_all() -> Policy<Route<Ipv4Addr>> {
    Policy::new(DefaultAction::Accept)
}

fn accept_all_v6() -> Policy<Route<Ipv6Addr>> {
    Policy::new(DefaultAction::Accept)
}

fn reject_all() -> Policy<Route<Ipv4Addr>> {
    Policy::new(DefaultAction::Reject)
}

fn reject_all_v6() -> Policy<Route<Ipv6Addr>> {
    Policy::new(DefaultAction::Reject)
}

fn fresh_ari() -> AdjRibIn<Ipv4Addr> {
    AdjRibIn::new(peer())
}

/// Builds a `DaemonState` with explicit accept-all policies for every peer.
/// Returns the state and a map of receivers for asserting on outbound messages.
pub(super) fn make_state(
    local_as: u32,
    peers: &[(IpAddr, u32)],
) -> (DaemonState, HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>) {
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
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
            confederation_member: false,
            blackhole_authorized_prefixes: None,
        })
        .collect();
    let local_bgp_id = Ipv4Addr::new(10, 0, 0, 1);
    let state = DaemonState::new(
        local_as,
        local_bgp_id,
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &peer_configs,
        senders,
        vec![],
    );
    (state, receivers)
}

use pathvector_rib::BestPathChange;
use std::sync::Mutex;

/// Shared test double: records every `apply_v4/v6` call without touching the
/// kernel. Inject via `state.fib_manager = Some(Arc::new(RecordingFib::new()))`.
pub(super) struct RecordingFib {
    pub(super) v4: Mutex<Vec<BestPathChange<Ipv4Addr>>>,
    pub(super) v6: Mutex<Vec<BestPathChange<Ipv6Addr>>>,
    pub(super) blackhole_v4: Mutex<Vec<(Nlri<Ipv4Addr>, bool)>>, // (nlri, announced)
    pub(super) blackhole_v6: Mutex<Vec<(Nlri<Ipv6Addr>, bool)>>,
}
impl RecordingFib {
    pub(super) fn new() -> Self {
        Self {
            v4: Mutex::new(Vec::new()),
            v6: Mutex::new(Vec::new()),
            blackhole_v4: Mutex::new(Vec::new()),
            blackhole_v6: Mutex::new(Vec::new()),
        }
    }
    pub(super) fn v4_changes(&self) -> Vec<BestPathChange<Ipv4Addr>> {
        self.v4.lock().unwrap().clone()
    }
}
impl crate_fib::ApplyFibChange for RecordingFib {
    fn apply_v4(&self, change: BestPathChange<Ipv4Addr>) {
        self.v4.lock().unwrap().push(change);
    }
    fn apply_v6(&self, change: BestPathChange<Ipv6Addr>) {
        self.v6.lock().unwrap().push(change);
    }
    fn apply_blackhole_v4(&self, nlri: Nlri<Ipv4Addr>) {
        self.blackhole_v4.lock().unwrap().push((nlri, true));
    }
    fn withdraw_blackhole_v4(&self, nlri: Nlri<Ipv4Addr>) {
        self.blackhole_v4.lock().unwrap().push((nlri, false));
    }
    fn apply_blackhole_v6(&self, nlri: Nlri<Ipv6Addr>) {
        self.blackhole_v6.lock().unwrap().push((nlri, true));
    }
    fn withdraw_blackhole_v6(&self, nlri: Nlri<Ipv6Addr>) {
        self.blackhole_v6.lock().unwrap().push((nlri, false));
    }
}
pub(super) fn with_recording_fib(state: &mut DaemonState) -> Arc<RecordingFib> {
    let fib = Arc::new(RecordingFib::new());
    state.fib_manager = Some(Arc::clone(&fib) as Arc<dyn crate_fib::ApplyFibChange>);
    fib
}

/// Drain all messages currently queued in every receiver.
///
/// Call this after `on_established` in tests that don't care about the
/// EOR marker the session setup now sends (RFC 4724 §2).  Tests that
/// specifically verify the EOR shape should NOT call this helper — they
/// should assert on the message content directly.
fn drain_all(receivers: &mut HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>) {
    for rx in receivers.values_mut() {
        while rx.try_recv().is_ok() {}
    }
}

// ── test wrappers ─────────────────────────────────────────────────────────

/// Wrapper for IPv4-only `handle_update` calls — passes fresh v6 stubs.
fn handle_update_v4(
    p: PeerId,
    mut msg: UpdateMessage,
    ari: &mut AdjRibIn<Ipv4Addr>,
    rib: &mut LocRib<Ipv4Addr>,
    policy: &Policy<Route<Ipv4Addr>>,
    pt: PeerType,
) {
    // Ensure tests with IPv4 announces satisfy mandatory-attribute validation
    // (RFC 4271 §6.3) so they don't get rejected before reaching the logic
    // under test. Supply defaults when mandatory attributes are absent.
    if !msg.announced.is_empty() {
        let has_origin = msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::Origin(_)));
        let has_as_path = msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::AsPath(_)));
        let has_next_hop = msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::NextHop(_)));
        if !has_origin {
            msg.attributes.push(PathAttribute::Origin(Origin::Igp));
        }
        if !has_as_path {
            msg.attributes
                .push(PathAttribute::AsPath(AsPath::from_sequence(vec![
                    Asn::new(65009),
                ])));
        }
        if !has_next_hop {
            msg.attributes
                .push(PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)));
        }
    }
    let mut ari_v6: AdjRibIn<Ipv6Addr> = AdjRibIn::new(p);
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    let policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(DefaultAction::Accept);
    handle_update(
        p,
        msg,
        ari,
        rib,
        &mut ari_v6,
        &mut rib_v6,
        policy,
        &policy_v6,
        pt,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        None, // confederation_id
        None,
        None,
    );
}

fn nlri_v6(s: &str) -> Nlri<Ipv6Addr> {
    s.parse().unwrap()
}

// ── Route Reflection (RFC 4456) ───────────────────────────────────────────

/// Builds a DaemonState acting as an RR for the given clients.
/// `clients` and `non_clients` are all iBGP peers (same `local_as`).
pub(super) fn make_rr_state(
    local_as: u32,
    cluster_id: u32,
    clients: &[Ipv4Addr],
    non_clients: &[Ipv4Addr],
) -> (DaemonState, HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>) {
    let mut senders = HashMap::new();
    let mut receivers = HashMap::new();
    for &ip in clients.iter().chain(non_clients.iter()) {
        let (tx, rx) = mpsc::channel(64);
        senders.insert(IpAddr::V4(ip), tx);
        receivers.insert(IpAddr::V4(ip), rx);
    }
    let peer_configs: Vec<config::PeerConfig> = clients
        .iter()
        .map(|&address| config::PeerConfig {
            address: IpAddr::V4(address),
            port: 179,
            remote_as: local_as,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
            md5_password: None,
            is_rr_client: true,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
            confederation_member: false,
            blackhole_authorized_prefixes: None,
        })
        .chain(non_clients.iter().map(|&address| config::PeerConfig {
            address: IpAddr::V4(address),
            port: 179,
            remote_as: local_as,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
            confederation_member: false,
            blackhole_authorized_prefixes: None,
        }))
        .collect();
    let local_bgp_id = Ipv4Addr::new(10, 0, 0, 1);
    let state = DaemonState::new(
        local_as,
        local_bgp_id,
        None,
        Some(cluster_id),
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &peer_configs,
        senders,
        vec![],
    );
    (state, receivers)
}

fn update_announce(prefix: &str) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::new()),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 1, 1)),
        ],
        announced: vec![nlri(prefix)],
    }
}

// ── IPv6 inbound (MP_REACH_NLRI / MP_UNREACH_NLRI) ───────────────────────

fn fresh_ari_v6() -> AdjRibIn<Ipv6Addr> {
    AdjRibIn::new(peer())
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
    let peer_ip = aro.peer().ip();
    let decision = propagate_prefix(
        nlri,
        rib,
        aro,
        &std::collections::HashSet::new(),
        policy,
        peer_type,
        local_as,
        local_as,
        bgp_id,
        false,
        false,
    );
    flush_updates(peer_ip, vec![decision], MAX_LEN, tx, peer_type, true)
}

/// Extracts the IPv4 address from a test fixture's `IpAddr`. Every peer
/// address literal in the daemon's test modules is IPv4; this exists only to
/// bridge the peer-identity `IpAddr` type to APIs (e.g. `on_established`'s
/// `peer_bgp_id`) that require an `Ipv4Addr` specifically.
pub(super) fn must_v4(addr: IpAddr) -> Ipv4Addr {
    match addr {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => panic!("test fixture address must be IPv4"),
    }
}
