//! Self-contained domain types returned by [`PathvectorClient`].
//!
//! These types mirror the proto schema but are independent of any internal
//! pathvector crates, so this library can be published and consumed without
//! pulling in the full BGP implementation stack.
//!
//! [`PathvectorClient`]: crate::PathvectorClient

use std::net::IpAddr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// ── Enumerations ──────────────────────────────────────────────────────────────

/// BGP FSM session state for a configured peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum SessionState {
    /// Session is not established (Idle / Connect / Active / OpenSent /
    /// OpenConfirm).
    Idle,
    /// Session has reached the Established state.
    Established,
}

/// Source classification of a BGP route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum PeerType {
    /// eBGP — route learned from a peer in a different autonomous system.
    External,
    /// iBGP — route learned from a peer in the same autonomous system.
    Internal,
    /// Locally originated — injected via the origination API.
    Local,
}

/// BGP ORIGIN path attribute (RFC 4271 §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum Origin {
    /// Interior Gateway Protocol — the route was originated inside the AS.
    Igp,
    /// Exterior Gateway Protocol — legacy, rarely seen.
    Egp,
    /// Incomplete — origin cannot be determined (e.g. redistributed).
    Incomplete,
}

/// Type of a single AS_PATH segment (RFC 4271 §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum AsSegmentType {
    /// Ordered list of ASes — the common case.
    Sequence,
    /// Unordered set of ASes — produced by aggregation.
    Set,
    /// Ordered confederation sequence (RFC 5065).
    ConfedSequence,
    /// Unordered confederation set (RFC 5065).
    ConfedSet,
}

// ── Compound types ────────────────────────────────────────────────────────────

/// One segment of the AS_PATH attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AsSegment {
    /// Whether this is a sequence, set, or confederation variant.
    pub kind: AsSegmentType,
    /// The AS numbers in this segment, in order.
    pub asns: Vec<u32>,
}

/// RFC 8092 LARGE_COMMUNITY — three 4-byte unsigned integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LargeCommunity {
    pub global_admin: u32,
    pub local_data1: u32,
    pub local_data2: u32,
}

/// AGGREGATOR attribute — the router that created an aggregate route.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Aggregator {
    /// AS number of the aggregating router.
    pub asn: u32,
    /// BGP router-id of the aggregating router.
    pub address: IpAddr,
}

// ── Top-level domain objects ──────────────────────────────────────────────────

/// Operational state of a single BGP peer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PeerState {
    /// Configured peer IP address.
    pub address: IpAddr,
    /// Remote AS number from configuration.
    pub remote_as: u32,
    /// Local AS number.
    pub local_as: u32,
    /// Current BGP FSM state.
    pub session_state: SessionState,
    /// Peer relationship type; [`None`] when the session is not established.
    pub peer_type: Option<PeerType>,
    /// Negotiated hold-timer in seconds; 0 if not established.
    pub hold_time: u32,
    /// Seconds since the session reached Established; 0 if not established.
    pub uptime_seconds: u64,
    /// Routes in Adj-RIB-In (all prefixes received from this peer).
    pub prefixes_received: u32,
    /// Routes from this peer that are the current best path in Loc-RIB.
    pub prefixes_accepted: u32,
    /// Routes currently being advertised to this peer (Adj-RIB-Out size).
    pub prefixes_advertised: u32,
}

/// A single BGP route with all path attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Route {
    /// Advertised prefix in CIDR notation, e.g. `"10.0.0.0/8"`.
    pub prefix: String,
    /// IP address of the peer that sent this route, or [`None`] for locally
    /// originated routes (injected via the `OriginationService` gRPC API).
    pub peer_address: Option<IpAddr>,
    /// Whether the peer is iBGP or eBGP.
    pub peer_type: PeerType,
    /// Forwarding next-hop; [`None`] if the attribute was absent.
    pub next_hop: Option<IpAddr>,
    /// `AS_PATH` segments in order; empty for locally originated routes.
    pub as_path: Vec<AsSegment>,
    /// ORIGIN attribute.
    pub origin: Origin,
    /// `LOCAL_PREF` (RFC 4271 §5.1.5); present for iBGP routes.
    pub local_pref: Option<u32>,
    /// `MULTI_EXIT_DISC` (RFC 4271 §5.1.4); absent if the peer did not send it.
    pub med: Option<u32>,
    /// Standard BGP communities (RFC 1997) as raw `u32` values.
    ///
    /// Decode as `high_16 = asn`, `low_16 = value`.
    pub communities: Vec<u32>,
    /// Large communities (RFC 8092).
    pub large_communities: Vec<LargeCommunity>,
    /// Extended communities (RFC 4360), each serialised as exactly 8 bytes.
    pub extended_communities: Vec<[u8; 8]>,
    /// Whether the `ATOMIC_AGGREGATE` attribute is present (RFC 4271 §5.1.6).
    pub atomic_aggregate: bool,
    /// AGGREGATOR attribute (RFC 4271 §5.1.7); absent if not set.
    pub aggregator: Option<Aggregator>,
}

// ── Origination ───────────────────────────────────────────────────────────────

/// Parameters for a single locally originated route.
///
/// Pass to [`PathvectorClient::originate_route`] or collect into a `Vec` for
/// [`PathvectorClient::originate_routes`].
///
/// [`PathvectorClient::originate_route`]: crate::PathvectorClient::originate_route
/// [`PathvectorClient::originate_routes`]: crate::PathvectorClient::originate_routes
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OriginateRouteParams {
    /// Prefix in CIDR notation, e.g. `"1.2.3.4/32"`.
    pub prefix: String,
    /// Forwarding next-hop in dotted-decimal notation.
    pub next_hop: String,
    /// ORIGIN attribute.
    pub origin: Origin,
    /// Standard BGP communities (RFC 1997) as raw `u32` values.
    pub communities: Vec<u32>,
    /// Large communities (RFC 8092).
    pub large_communities: Vec<LargeCommunity>,
    /// Extended communities (RFC 4360), each exactly 8 bytes.
    pub extended_communities: Vec<[u8; 8]>,
    /// `LOCAL_PREF`; absent means unset (not advertised to eBGP peers).
    pub local_pref: Option<u32>,
    /// `MULTI_EXIT_DISC`; absent means unset.
    pub med: Option<u32>,
}

// ── Streaming watch events ────────────────────────────────────────────────────

/// Discriminant for events on the [`WatchRoutes`] stream.
///
/// [`WatchRoutes`]: crate::PathvectorClient::watch_routes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum RouteEventType {
    /// Snapshot phase: the current best route for one prefix.
    Current,
    /// Snapshot complete; live deltas follow.
    EndInitial,
    /// A prefix was announced or its best-path changed.
    Announced,
    /// A prefix was withdrawn from the Loc-RIB.
    Withdrawn,
}

/// A single event on the [`WatchRoutes`] stream.
///
/// [`WatchRoutes`]: crate::PathvectorClient::watch_routes
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RouteEvent {
    pub event_type: RouteEventType,
    /// Present for [`RouteEventType::Current`] and [`RouteEventType::Announced`].
    pub route: Option<Route>,
    /// Present for [`RouteEventType::Withdrawn`].
    pub withdrawn_prefix: Option<String>,
}

/// Discriminant for events on the [`WatchPeers`] stream.
///
/// [`WatchPeers`]: crate::PathvectorClient::watch_peers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum PeerEventType {
    /// Snapshot phase: the current state of one peer.
    Current,
    /// Snapshot complete; live deltas follow.
    EndInitial,
    /// A peer's session state changed.
    Changed,
}

/// A single event on the [`WatchPeers`] stream.
///
/// [`WatchPeers`]: crate::PathvectorClient::watch_peers
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PeerEvent {
    pub event_type: PeerEventType,
    /// Present for [`PeerEventType::Current`] and [`PeerEventType::Changed`].
    pub peer: Option<PeerState>,
}
