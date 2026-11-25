use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use pathvector_policy::DefaultAction;
use pathvector_session::transport::tcp_md5::{Md5Enforcement, TcpMd5Key, TcpMd5KeyError};
use pathvector_types::SpeakerAsn;
use serde::{Deserialize, Serialize};

/// Top-level daemon configuration.
///
/// ```toml
/// [daemon]
/// local_as     = 65002
/// bgp_id       = "127.0.0.2"
/// hold_time    = 90          # optional, default 90 s
/// grpc_port    = 50051       # optional, default 50051
/// bgp_port     = 179         # optional, default 179 (use 1179+ without CAP_NET_BIND_SERVICE)
/// metrics_port = 9179        # optional; omit to disable Prometheus scrape endpoint
///
/// [[peers]]
/// address   = "127.0.0.1"
/// port      = 179         # optional, default 179
/// remote_as = 65001
/// ```
#[derive(Deserialize)]
pub struct Config {
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    /// Path to the dynamic-peer sidecar file.  Not present in TOML — set by
    /// the caller (e.g. `main`) after parsing so the daemon can persist peers
    /// added via `add_peer` across restarts.
    #[serde(skip)]
    pub sidecar_path: Option<PathBuf>,
}

#[derive(Deserialize)]
pub struct DaemonConfig {
    /// This speaker's AS number. AS 0 is refused (RFC 7607).
    #[serde(deserialize_with = "speaker_as")]
    pub local_as: u32,
    pub bgp_id: Ipv4Addr,
    #[serde(default = "default_hold_time")]
    pub hold_time: u16,
    /// TCP port on which the gRPC management API listens.
    ///
    /// Binds on all interfaces (`0.0.0.0:<grpc_port>`).  Set to `0` to
    /// disable the API entirely (not yet implemented — the server always
    /// starts when the daemon runs).
    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,
    /// TCP port for the Prometheus `/metrics` scrape endpoint.
    ///
    /// When set, pathvectord binds an HTTP listener on `0.0.0.0:<metrics_port>`
    /// that serves standard Prometheus text format.  Omit (or set to `None`) to
    /// disable the endpoint entirely.
    ///
    /// The conventional port for BGP exporters is `9179`.
    ///
    /// ```toml
    /// [daemon]
    /// local_as     = 65001
    /// bgp_id       = "10.0.0.1"
    /// metrics_port = 9179
    /// ```
    #[serde(default)]
    pub metrics_port: Option<u16>,
    /// TCP port on which pathvectord listens for inbound BGP connections.
    ///
    /// Peers that also dial out will trigger RFC 4271 §6.8 collision detection.
    /// Defaults to `179`.  Set to a non-privileged port (e.g. `1179`) for
    /// development or testing without `CAP_NET_BIND_SERVICE`.
    #[serde(default = "default_bgp_listen_port")]
    pub bgp_port: u16,
    /// Local IPv6 address used as `NEXT_HOP` when advertising IPv6 routes to
    /// eBGP peers (RFC 4760 §4.3).
    ///
    /// When absent, IPv6 routes are still received and stored in the local RIB
    /// but are only propagated to iBGP peers (where NEXT_HOP is passed through
    /// unchanged). Set this to enable full dual-stack eBGP.
    ///
    /// ```toml
    /// [daemon]
    /// local_as   = 65001
    /// bgp_id     = "10.0.0.1"
    /// local_ipv6 = "2001:db8::1"
    /// ```
    #[serde(default)]
    pub local_ipv6: Option<Ipv6Addr>,
    /// Route Reflector cluster identifier (RFC 4456).
    ///
    /// When any peer has `is_rr_client = true`, this daemon acts as a Route
    /// Reflector. The `cluster_id` is prepended to `CLUSTER_LIST` on every
    /// reflected route and used for loop detection. When omitted, defaults to
    /// the 32-bit representation of `bgp_id`.
    ///
    /// **Multi-cluster deployments:** if you run more than one independent RR
    /// cluster in the same AS, each cluster MUST have a distinct `cluster_id`.
    /// Without explicit configuration every cluster's `cluster_id` equals its
    /// RR's BGP ID — if two RRs share a BGP ID (unusual but possible), or if
    /// you rely on CLUSTER_LIST loop detection across clusters, set this field
    /// explicitly to a unique value per cluster. Using the same `cluster_id` in
    /// multiple clusters causes CLUSTER_LIST loop detection to fire incorrectly,
    /// dropping routes that should be accepted.
    ///
    /// ```toml
    /// [daemon]
    /// local_as   = 65001
    /// bgp_id     = "10.0.0.1"
    /// cluster_id = 1    # must be unique per cluster in multi-cluster setups
    /// ```
    #[serde(default)]
    pub cluster_id: Option<u32>,
    /// BGP Confederation Identifier (RFC 5065).
    ///
    /// When set, `local_as` is reinterpreted as this daemon's private
    /// Member-AS Number, and `confederation_id` becomes the AS number this
    /// speaker presents to the outside world: it is prepended into
    /// `AS_SEQUENCE` toward peers outside the confederation (instead of
    /// `local_as`), while `local_as` continues to be prepended into
    /// `AS_CONFED_SEQUENCE` toward peers marked `confederation_member = true`
    /// (see [`PeerConfig::confederation_member`]). Omit to disable
    /// confederation support entirely (the default) — existing pass-through
    /// interop with someone else's confederation is unaffected either way.
    ///
    /// ```toml
    /// [daemon]
    /// local_as         = 65001   # this router's private Member-AS Number
    /// bgp_id           = "10.0.0.1"
    /// confederation_id = 64500    # AS number advertised to the outside world
    /// ```
    #[serde(default, deserialize_with = "optional_speaker_as")]
    pub confederation_id: Option<u32>,
    /// Linux routing table into which BGP routes are installed (default: 254 = main).
    ///
    /// Set to a non-default value (e.g. 100) to keep BGP routes in a separate
    /// table and use policy routing (`ip rule`) to select them.
    ///
    /// ```toml
    /// [daemon]
    /// local_as  = 65001
    /// bgp_id    = "10.0.0.1"
    /// fib_table = 100
    /// ```
    #[serde(default = "default_fib_table")]
    pub fib_table: u32,
    /// Metric assigned to installed BGP routes (default: 20).
    ///
    /// Lower values are preferred. Choose a value higher than connected and
    /// static routes so BGP routes do not shadow them.
    ///
    /// ```toml
    /// [daemon]
    /// local_as   = 65001
    /// bgp_id     = "10.0.0.1"
    /// fib_metric = 200
    /// ```
    #[serde(default = "default_fib_metric")]
    pub fib_metric: u32,
    /// RFC 4724 §3: how long (in seconds) peers should hold our routes if our
    /// BGP session drops unexpectedly.
    ///
    /// When non-zero, pathvectord advertises the GracefulRestart capability with
    /// this restart time and marks IPv4/IPv6 unicast families as
    /// `forwarding_preserved`. The upstream peer will retain our routes for up to
    /// this many seconds after an unclean session loss, giving pathvectord time to
    /// reconnect and re-announce without causing a route flap.
    ///
    /// Set to `0` (the default) to disable forwarding-state advertisement.  Peers
    /// will still receive the GracefulRestart capability (required for EOR
    /// signalling) but will withdraw our routes immediately on session loss.
    ///
    /// The RFC 4724 maximum encodable value is 4095 seconds; larger values are
    /// silently clamped. Recommended range for DDoS blackhole use: 120–300.
    ///
    /// ```toml
    /// [daemon]
    /// local_as              = 65001
    /// bgp_id                = "10.0.0.1"
    /// graceful_restart_time = 120
    /// ```
    #[serde(default)]
    pub graceful_restart_time: u16,
    /// RFC 4724 §3: set the Restart State (R) bit in OPEN messages to signal
    /// that this daemon is the restarting speaker.
    ///
    /// Set this to `true` when restarting pathvectord during an active BGP
    /// session (e.g., during a planned upgrade or after a crash) so that peers
    /// stop their stale-route timers immediately when the session re-establishes.
    /// Leave `false` (the default) on normal first-time startup.
    ///
    /// Ignored when `graceful_restart_time = 0`.
    ///
    /// # Example
    ///
    /// ```toml
    /// [daemon]
    /// local_as              = 65001
    /// bgp_id                = "10.0.0.1"
    /// graceful_restart_time = 120
    /// restarting            = true   # set only when restarting; remove after
    /// ```
    #[serde(default)]
    pub restarting: bool,
    /// RFC 4724 §4.1: how long (in seconds) to defer outbound route
    /// advertisement after this daemon starts, giving peers time to
    /// re-send their full routing tables before we propagate anything
    /// based on a possibly-incomplete view.
    ///
    /// Applies the "Restarting Speaker" deferral to **outbound
    /// advertisement only** — Loc-RIB/FIB computation stays immediate, as
    /// today. This matches how BIRD implements graceful restart recovery
    /// (deferring export while tables repopulate normally), rather than
    /// the RFC's literal text of deferring route selection itself.
    ///
    /// While deferred, each address family (IPv4 unicast, IPv6 unicast)
    /// independently releases as soon as either (a) every currently- or
    /// eventually-established peer that advertises the GracefulRestart
    /// capability (and isn't itself restarting) has sent its End-of-RIB
    /// marker for that family, or (b) this timer expires — whichever
    /// comes first. Once released, a family never re-defers, even if a
    /// peer later disconnects.
    ///
    /// Unlike `restarting`, this applies on **every** startup when
    /// non-zero — it is not gated behind the `restarting` flag, since it
    /// protects against advertising based on incomplete peer state
    /// regardless of whether this restart was planned.
    ///
    /// Set to `0` (the default) to disable — outbound advertisement is
    /// never deferred.
    ///
    /// ```toml
    /// [daemon]
    /// local_as                = 65001
    /// bgp_id                  = "10.0.0.1"
    /// selection_deferral_time = 120
    /// ```
    #[serde(default)]
    pub selection_deferral_time: u16,
    /// RPKI Route Origin Validation via the RTR protocol (RFC 8210 / RFC 6810).
    ///
    /// When present, pathvectord connects to an external RPKI validator
    /// (Routinator, rpki-client, OctoRPKI, Cloudflare gortr, etc.) and
    /// maintains a live ROA validity cache. Connection failures are logged
    /// and retried in the background — they never prevent the daemon from
    /// starting or processing BGP sessions. Omit this table to disable RPKI
    /// support (the default).
    ///
    /// Phase 1: read-only cache queryable via gRPC/CLI. Does not affect
    /// route acceptance or best-path selection.
    ///
    /// ```toml
    /// [daemon.rpki]
    /// host = "127.0.0.1"
    /// port = 3323
    /// ```
    #[serde(default)]
    pub rpki: Option<RpkiConfig>,
    /// What to do when a peer has `md5_password` but this host cannot
    /// enforce TCP MD5 (kernel built without `CONFIG_TCP_MD5SIG`, a non-Linux
    /// build, or an IPv6 peer).
    ///
    /// - `"required"` (default): the session does not connect, and the
    ///   connect error is logged. RFC 5925 §8: an endpoint configured to
    ///   require TCP MD5 must sign all outgoing segments and validate all
    ///   incoming ones.
    /// - `"best-effort"`: the session connects **without authentication** and
    ///   a warning is logged on every connection attempt. Meant for
    ///   development hosts such as Docker Desktop, whose kernel lacks TCP MD5.
    ///
    /// ```toml
    /// [daemon]
    /// local_as            = 65001
    /// bgp_id              = "10.0.0.1"
    /// tcp_md5_enforcement = "best-effort"   # development only
    /// ```
    #[serde(default)]
    pub tcp_md5_enforcement: TcpMd5EnforcementConfig,
}

/// A configured AS number that identifies a BGP speaker: AS 0 is refused
/// (RFC 7607 §2, via [`SpeakerAsn`]), since no session could use it.
fn speaker_as<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
    SpeakerAsn::try_from(u32::deserialize(d)?)
        .map(SpeakerAsn::as_u32)
        .map_err(serde::de::Error::custom)
}

/// [`speaker_as`] for an optional field.
fn optional_speaker_as<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u32>, D::Error> {
    speaker_as(d).map(Some)
}

/// RTR server connection settings for RPKI Route Origin Validation.
#[derive(Deserialize, Clone)]
pub struct RpkiConfig {
    pub host: String,
    /// TCP port of the RTR server. Defaults to `3323`, Routinator's default
    /// `--rtr` listen port (confirmed against `nlnetlabs/routinator`'s
    /// published Docker image, which exposes `3323/tcp` for RTR and
    /// `8323/tcp` for its HTTP status/metrics API — an earlier default of
    /// `8323` here was a mix-up between the two).
    #[serde(default = "default_rtr_port")]
    pub port: u16,
    /// Reject routes whose RFC 6811 validity is `Invalid` — a covering ROA
    /// exists but names a different origin AS, or the announcement is more
    /// specific than the ROA's max length allows. `Valid` and `NotFound`
    /// routes are unaffected. Matches RFC 7115 / BIRD / FRR default
    /// convention. Applied to every configured peer's import policy, IPv4
    /// and IPv6. Set to `false` to run RPKI in monitoring-only mode (cache
    /// still queryable via `pathvector rpki status`/`validate`, but nothing
    /// is filtered).
    #[serde(default = "default_true")]
    pub reject_invalid: bool,
}

fn default_rtr_port() -> u16 {
    3323
}

fn default_true() -> bool {
    true
}

fn default_fib_table() -> u32 {
    254
}

fn default_fib_metric() -> u32 {
    20
}

fn default_hold_time() -> u16 {
    90
}

fn default_grpc_port() -> u16 {
    50051
}

fn default_bgp_listen_port() -> u16 {
    179
}

/// TOML representation of the import policy default action for a peer.
///
/// Controls what happens to routes that do not match any import policy term.
/// When omitted, eBGP peers default to `"reject"` (RFC 8212) and iBGP peers
/// default to `"accept"`.
///
/// ```toml
/// [[peers]]
/// address        = "10.0.0.1"
/// remote_as      = 65001
/// import_default = "accept"   # explicit opt-in for an eBGP peer
/// ```
#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum ImportDefault {
    /// Accept routes that matched no term.
    Accept,
    /// Reject routes that matched no term.
    Reject,
}

impl From<ImportDefault> for DefaultAction {
    fn from(d: ImportDefault) -> Self {
        match d {
            ImportDefault::Accept => DefaultAction::Accept,
            ImportDefault::Reject => DefaultAction::Reject,
        }
    }
}

/// TOML representation of the export policy default action for a peer.
///
/// Controls what happens to best routes that do not match any export policy
/// term before they are advertised to this peer.  When omitted, eBGP peers
/// default to `"reject"` (RFC 8212) and iBGP peers default to `"accept"`.
///
/// ```toml
/// [[peers]]
/// address        = "10.0.0.2"
/// remote_as      = 65002
/// export_default = "accept"   # explicit opt-in for an eBGP peer
/// ```
#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum ExportDefault {
    /// Re-advertise routes that matched no term.
    Accept,
    /// Suppress routes that matched no term.
    Reject,
}

impl From<ExportDefault> for DefaultAction {
    fn from(d: ExportDefault) -> Self {
        match d {
            ExportDefault::Accept => DefaultAction::Accept,
            ExportDefault::Reject => DefaultAction::Reject,
        }
    }
}

/// TOML representation of a peer's RFC 9234 BGP Role.
///
/// Declares the local speaker's role *on this specific session* — not a
/// property of the AS itself. The same AS can be a `provider` on one session
/// and a `customer` on another. When set, pathvectord advertises the BGP
/// Role capability and enforces RFC 9234's `ONLY_TO_CUSTOMER` route-leak
/// prevention for this peer; when omitted, neither happens (matches the
/// RFC's own non-strict default of not requiring Role at all).
///
/// ```toml
/// [[peers]]
/// address   = "10.0.0.1"
/// remote_as = 65001
/// role      = "customer"   # this peer is our customer — we are their provider
/// ```
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PeerRole {
    /// We provide transit to this peer.
    Provider,
    /// We operate a route server (typically at an IXP) and this peer is a
    /// participant, not our route-server-client.
    #[serde(rename = "rs")]
    RouteServer,
    /// This peer is a route-server-client of ours.
    #[serde(rename = "rs_client")]
    RsClient,
    /// This peer provides transit to us.
    Customer,
    /// Lateral peering — neither side provides transit to the other.
    Peer,
}

impl From<PeerRole> for pathvector_types::Role {
    fn from(r: PeerRole) -> Self {
        match r {
            PeerRole::Provider => Self::Provider,
            PeerRole::RouteServer => Self::RouteServer,
            PeerRole::RsClient => Self::RsClient,
            PeerRole::Customer => Self::Customer,
            PeerRole::Peer => Self::Peer,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PeerConfig {
    /// The peer's address — either IPv4 or IPv6. Determines which TCP
    /// transport family the session dials/accepts over; independent of
    /// which NLRI address families (IPv4/IPv6 unicast) are actually
    /// exchanged once established (see RFC 4760).
    pub address: IpAddr,
    #[serde(default = "default_bgp_port")]
    pub port: u16,
    #[serde(deserialize_with = "speaker_as")]
    pub remote_as: u32,
    /// Default action when no import policy term matches for IPv4 routes.
    ///
    /// When omitted: eBGP peers default to `"reject"` (RFC 8212 compliance);
    /// iBGP peers default to `"accept"`. Set explicitly to override.
    #[serde(default)]
    pub import_default: Option<ImportDefault>,
    /// Default action when no import policy term matches for IPv6 routes.
    ///
    /// When omitted, falls back to `import_default`. This lets operators
    /// accept IPv4 routes while still applying RFC 8212 reject semantics to
    /// IPv6, or vice-versa.
    ///
    /// ```toml
    /// [[peers]]
    /// address           = "198.51.100.1"
    /// remote_as         = 64496
    /// import_default    = "accept"    # accept IPv4
    /// import_default_v6 = "reject"    # but reject IPv6 from this peer
    /// ```
    #[serde(default)]
    pub import_default_v6: Option<ImportDefault>,
    /// Default action when no export policy term matches.
    ///
    /// When omitted: eBGP peers default to `"reject"` (RFC 8212 compliance);
    /// iBGP peers default to `"accept"`. Set explicitly to override.
    #[serde(default)]
    pub export_default: Option<ExportDefault>,
    /// RFC 2385 TCP MD5 authentication key shared with this peer.
    ///
    /// When set, the kernel signs every TCP segment pathvectord sends to this
    /// peer and drops segments from it that are unsigned or wrongly signed.
    /// The peer must be configured with the same key. Must be 1 to 80 bytes:
    /// an empty or longer value is a config error (Linux would read an empty
    /// key as "delete the key", and rejects keys over 80 bytes). Omit to
    /// disable MD5 (default).
    ///
    /// If the host cannot enforce the key (a kernel without
    /// `CONFIG_TCP_MD5SIG`, a non-Linux build, or an IPv6 peer), the session
    /// does not connect unless `[daemon] tcp_md5_enforcement = "best-effort"`.
    ///
    /// Currently applied to outbound connections only; inbound listener keys
    /// are tracked in issue #66.
    ///
    /// ```toml
    /// [[peers]]
    /// address      = "198.51.100.1"
    /// remote_as    = 64496
    /// md5_password = "secret"
    /// ```
    #[serde(default)]
    pub md5_password: Option<Md5Password>,
    /// Whether this peer is a Route Reflector client (RFC 4456).
    ///
    /// When `true`, the daemon acts as a Route Reflector for this peer:
    /// routes received from this client are reflected to all other clients and
    /// to non-client iBGP peers (with `ORIGINATOR_ID` and `CLUSTER_LIST`
    /// attributes set). Routes from non-client iBGP peers are reflected to
    /// this client. Defaults to `false`.
    ///
    /// The `daemon.cluster_id` setting must also be set (or defaults to
    /// `bgp_id`) for the reflector to operate correctly.
    ///
    /// ```toml
    /// [[peers]]
    /// address      = "10.0.0.2"
    /// remote_as    = 65001
    /// is_rr_client = true
    /// ```
    #[serde(default)]
    pub is_rr_client: bool,
    /// Force the NEXT_HOP attribute to the local router address when
    /// advertising routes to this peer over iBGP.
    ///
    /// Required when the route reflector is also an eBGP border router and
    /// its iBGP clients cannot reach the eBGP next-hop directly.  Has no
    /// effect on eBGP peers (NEXT_HOP is always rewritten for eBGP).
    ///
    /// ```toml
    /// [[peers]]
    /// address       = "10.0.0.2"
    /// remote_as     = 65001
    /// next_hop_self = true
    /// ```
    #[serde(default)]
    pub next_hop_self: bool,
    /// Per-peer BGP hold time in seconds, overriding `daemon.hold_time`.
    ///
    /// When omitted the peer inherits the daemon-level `hold_time` (default 90 s).
    /// Setting `0` disables the hold timer for this peer (keepalives are still
    /// sent but expiry is not checked). Must be ≥ 3 or exactly 0.
    ///
    /// ```toml
    /// [[peers]]
    /// address   = "10.0.0.2"
    /// remote_as = 65001
    /// hold_time = 30
    /// ```
    #[serde(default)]
    pub hold_time: Option<u16>,
    /// UTF-8 reason string sent in the CEASE/AdministrativeShutdown NOTIFICATION
    /// when this peer is administratively removed (RFC 9003).
    ///
    /// Truncated to 128 bytes at the wire layer per RFC 9003 §2.
    /// When omitted the CEASE carries no diagnostic payload.
    ///
    /// ```toml
    /// [[peers]]
    /// address          = "10.0.0.2"
    /// remote_as        = 65001
    /// shutdown_message = "going down for maintenance"
    /// ```
    #[serde(default)]
    pub shutdown_message: Option<String>,
    /// RFC 4271 §8.1 ConnectRetry timer in seconds.
    ///
    /// How long to wait before retrying a failed TCP connection to this peer.
    /// Defaults to 120 s per the RFC recommendation. Reduce for
    /// latency-sensitive deployments or test environments.
    ///
    /// ```toml
    /// [[peers]]
    /// address             = "10.0.0.2"
    /// remote_as           = 65001
    /// connect_retry_time  = 5
    /// ```
    #[serde(default)]
    pub connect_retry_time: Option<u16>,
    /// Maximum number of prefixes (IPv4 + IPv6 combined) accepted from this
    /// peer before the session is torn down with a CEASE/MaximumNumberOfPrefixes
    /// NOTIFICATION (RFC 4486 §4).
    ///
    /// When omitted no prefix limit is enforced. Setting this protects against
    /// misconfigured or misbehaving peers flooding the RIB.
    ///
    /// ```toml
    /// [[peers]]
    /// address      = "10.0.0.2"
    /// remote_as    = 65001
    /// max_prefixes = 500000
    /// ```
    /// Maximum IPv4 prefixes accepted from this peer (RFC 4486 §4).
    ///
    /// Checked against the IPv4 Adj-RIB-In size after each UPDATE.
    /// When exceeded, the session is torn down with a
    /// CEASE/MaximumNumberOfPrefixesReached NOTIFICATION.
    #[serde(default)]
    pub max_prefixes_v4: Option<u32>,
    /// Maximum IPv6 prefixes accepted from this peer (RFC 4486 §4).
    ///
    /// Checked independently of `max_prefixes_v4`. Either limit firing
    /// causes the session to be torn down.
    #[serde(default)]
    pub max_prefixes_v6: Option<u32>,
    /// Seconds to wait before reconnecting after a max-prefix CEASE.
    ///
    /// When either `max_prefixes_v4` or `max_prefixes_v6` is exceeded and
    /// the session is dropped, pathvectord waits this many seconds before
    /// allowing the peer to reconnect. Use this as a back-off to give
    /// operators time to investigate and correct a route leak before the
    /// peer floods the RIB again.
    ///
    /// `0` (the default) means reconnect immediately according to the
    /// normal `connect_retry_time`.
    ///
    /// ```toml
    /// [[peers]]
    /// address                = "10.0.0.2"
    /// remote_as              = 65001
    /// max_prefixes_v4        = 500000
    /// max_prefixes_v6        = 100000
    /// max_prefixes_restart   = 300
    /// ```
    #[serde(default)]
    pub max_prefixes_restart: Option<u16>,
    /// RFC 9234 BGP Role for this session. Omit to disable Role capability
    /// negotiation and OTC-based route-leak prevention entirely for this
    /// peer (the RFC's own non-strict default).
    ///
    /// ```toml
    /// [[peers]]
    /// address   = "10.0.0.1"
    /// remote_as = 65001
    /// role      = "customer"
    /// ```
    #[serde(default)]
    pub role: Option<PeerRole>,
    /// Whether this peer is a fellow Member-AS within the same BGP
    /// confederation (RFC 5065), rather than a genuine external peer.
    ///
    /// Requires `daemon.confederation_id` to also be set — a peer with
    /// `confederation_member = true` under an unconfigured confederation is
    /// treated as a plain eBGP peer (with a warning), the same
    /// graceful-degradation pattern used by [`PeerConfig::role`] for
    /// iBGP-configured Role. When both are set, this session is classified
    /// as [`pathvector_types::PeerType::ConfedMember`]: AS_PATH is prepended
    /// into `AS_CONFED_SEQUENCE` (not `AS_SEQUENCE`), LOCAL_PREF and MED are
    /// passed through unchanged, and best-path preference matches `Internal`.
    ///
    /// ```toml
    /// [[peers]]
    /// address              = "10.0.0.2"
    /// remote_as            = 64501
    /// confederation_member = true
    /// ```
    #[serde(default)]
    pub confederation_member: bool,
    /// RFC 7999 BLACKHOLE: the prefixes this peer is authorized to blackhole
    /// on this session. **Setting it is the agreement to honor BLACKHOLE here.**
    ///
    /// RFC 7999 §3.3: "BGP speakers in a bilateral peering relationship using
    /// the BLACKHOLE community MUST only accept and honor BGP announcements
    /// carrying the BLACKHOLE community under the two following conditions:
    /// the announced prefix is covered by an equal or shorter prefix that the
    /// neighboring network is authorized to advertise; the receiving party
    /// agreed to honor the BLACKHOLE community on the particular BGP session."
    ///
    /// **Omitted (the default): denied.** RFC 7999 §4: without an explicit
    /// directive "network elements SHOULD NOT discard traffic destined towards
    /// IP prefixes that are tagged with the BLACKHOLE community." A
    /// BLACKHOLE-tagged announcement on a denied session is ignored — no null
    /// route, no Loc-RIB entry, nothing exported — whatever the import
    /// defaults say.
    ///
    /// When set, a BLACKHOLE-tagged announcement whose prefix is covered by one
    /// of these (equal or shorter; `/32` and `/128` host routes inside an
    /// authorized `/24` or `/48` are covered) programs a kernel null route. It
    /// is honored **instead of** the session's import policy, so origin
    /// validation (RFC 6811) and `import_default = "reject"` cannot block it
    /// (RFC 7999 §3.3: "An operator MUST ensure that origin validation
    /// techniques … do not inadvertently block legitimate announcements
    /// carrying the BLACKHOLE community"). An RFC 9234 route leak is still
    /// rejected. Authorized blackholes are never added to the Loc-RIB and so
    /// are never advertised to other peers (RFC 7999 §3.2).
    ///
    /// Must be a non-empty list of IPv4/IPv6 prefixes in canonical (no host
    /// bits) CIDR form. Dynamic peers added over gRPC have no blackhole
    /// agreement.
    ///
    /// ```toml
    /// [[peers]]
    /// address                       = "198.51.100.1"
    /// remote_as                     = 64496
    /// blackhole_authorized_prefixes = ["192.0.2.0/24", "2001:db8:100::/40"]
    /// ```
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blackhole_authorized_prefixes: Option<crate::blackhole::BlackholeScope>,
}

fn default_bgp_port() -> u16 {
    179
}

// ── TCP MD5 ───────────────────────────────────────────────────────────────────

/// A peer's TCP MD5 password, validated when it is parsed.
///
/// Holds the text as written (so the dynamic-peer sidecar can store it again)
/// and the [`TcpMd5Key`] built from it. Construction fails for an empty value
/// or one longer than 80 bytes; see [`TcpMd5Key`]. `Debug` hides the value.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(into = "String")]
pub struct Md5Password {
    text: String,
    key: TcpMd5Key,
}

impl Md5Password {
    /// The validated key.
    pub fn key(&self) -> &TcpMd5Key {
        &self.key
    }
}

impl TryFrom<String> for Md5Password {
    type Error = TcpMd5KeyError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let key = TcpMd5Key::try_from(text.as_str())?;
        Ok(Self { text, key })
    }
}

impl std::str::FromStr for Md5Password {
    type Err = TcpMd5KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl From<Md5Password> for String {
    fn from(p: Md5Password) -> Self {
        p.text
    }
}

/// Hand-written so that no error ever contains the value: serde's default
/// "invalid type" errors quote non-string input (an unquoted numeric
/// password, say), and those errors end up in logs.
impl<'de> Deserialize<'de> for Md5Password {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = Md5Password;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a TCP MD5 password string")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Md5Password, E> {
                Md5Password::try_from(v.to_owned()).map_err(E::custom)
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Md5Password, E> {
                Md5Password::try_from(v).map_err(E::custom)
            }

            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Md5Password, E> {
                Err(E::custom(NOT_A_STRING))
            }

            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Md5Password, E> {
                Err(E::custom(NOT_A_STRING))
            }

            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Md5Password, E> {
                Err(E::custom(NOT_A_STRING))
            }

            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Md5Password, E> {
                Err(E::custom(NOT_A_STRING))
            }
        }

        const NOT_A_STRING: &str = "md5_password must be a quoted string";
        d.deserialize_str(Visitor)
    }
}

impl std::fmt::Debug for Md5Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Md5Password(<redacted>)")
    }
}

/// `[daemon] tcp_md5_enforcement`: `"required"` (default) or `"best-effort"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TcpMd5EnforcementConfig {
    /// Refuse to connect when a configured key cannot be enforced.
    #[default]
    Required,
    /// Connect unauthenticated, with a warning, when a configured key cannot
    /// be enforced.
    BestEffort,
}

impl From<TcpMd5EnforcementConfig> for Md5Enforcement {
    fn from(c: TcpMd5EnforcementConfig) -> Self {
        match c {
            TcpMd5EnforcementConfig::Required => Self::Required,
            TcpMd5EnforcementConfig::BestEffort => Self::BestEffort,
        }
    }
}

// ── Dynamic peer persistence ──────────────────────────────────────────────────

/// Internal sidecar file format: a flat `[[peers]]` list, kept as raw TOML
/// tables so one entry that fails validation cannot take the others with it.
#[derive(Serialize, Deserialize, Default)]
struct SidecarFile {
    #[serde(default)]
    peers: Vec<toml::Table>,
}

/// A sidecar read from disk: the entries that are valid peers, and the raw
/// entries that are not (kept so a write never discards them).
#[derive(Default)]
struct LoadedSidecar {
    peers: Vec<PeerConfig>,
    rejected: Vec<toml::Table>,
}

/// Why the sidecar could not be read at all. Holds a description that never
/// quotes the file (see [`describe_toml_error`]).
struct SidecarUnreadable(String);

/// Persists dynamically-added peers to a TOML sidecar file so they survive
/// daemon restarts.
///
/// The sidecar lives next to the static config file (or at an explicit path)
/// and uses the same `[[peers]]` format, making it easy to inspect or edit
/// manually.  Writes are atomic: the new content is written to a `.tmp` file
/// then `rename`d over the target, so a crash mid-write never corrupts the
/// sidecar.
///
/// An entry that is not a valid peer (for example an `md5_password` that is
/// empty or longer than 80 bytes, which older versions accepted) is logged,
/// skipped at load, and written back unchanged, so the operator can fix it.
/// A file that cannot be read or parsed as TOML at all is never overwritten:
/// writes are refused (and logged) until it is fixed or removed.
pub struct DynamicPeerStore {
    path: PathBuf,
}

impl DynamicPeerStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load all valid persisted dynamic peers.  Returns an empty vec if the
    /// sidecar does not exist yet (first run) or cannot be parsed (logged).
    pub fn load(&self) -> Vec<PeerConfig> {
        match Self::load_sync(&self.path) {
            Ok(loaded) => loaded.peers,
            Err(SidecarUnreadable(why)) => {
                tracing::error!(
                    path = %self.path.display(),
                    "dynamic peer sidecar unreadable, no dynamic peers loaded \
                     and the file will not be modified: {why}"
                );
                vec![]
            }
        }
    }

    /// Upsert a peer into the sidecar (replace by address if already present).
    pub async fn upsert(&self, peer: PeerConfig) {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            Self::modify_sync(&path, |s| {
                s.peers.retain(|p| p.address != peer.address);
                s.rejected
                    .retain(|t| raw_address(t) != Some(peer.address.to_string()));
                s.peers.push(peer);
            });
        })
        .await
        .ok();
    }

    /// Remove a peer from the sidecar by address.
    pub async fn remove(&self, address: IpAddr) {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            Self::modify_sync(&path, |s| s.peers.retain(|p| p.address != address));
        })
        .await
        .ok();
    }

    /// Loads, applies `change`, and writes back — unless the file could not
    /// be read, in which case nothing is written.
    fn modify_sync(path: &Path, change: impl FnOnce(&mut LoadedSidecar)) {
        match Self::load_sync(path) {
            Ok(mut loaded) => {
                change(&mut loaded);
                Self::write_sync(path, &loaded);
            }
            Err(SidecarUnreadable(why)) => tracing::error!(
                path = %path.display(),
                "not persisting dynamic peer change: the sidecar is unreadable \
                 and will not be overwritten ({why}); fix or remove the file"
            ),
        }
    }

    fn load_sync(path: &Path) -> Result<LoadedSidecar, SidecarUnreadable> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LoadedSidecar::default());
            }
            Err(e) => return Err(SidecarUnreadable(e.to_string())),
        };
        let file: SidecarFile = toml::from_str(&text)
            .map_err(|e| SidecarUnreadable(describe_toml_error(&e, Some(&text))))?;

        let mut loaded = LoadedSidecar::default();
        for table in file.peers {
            match toml::Value::Table(table.clone()).try_into::<PeerConfig>() {
                Ok(peer) => loaded.peers.push(peer),
                Err(e) => {
                    tracing::error!(
                        path = %path.display(),
                        peer = raw_address(&table).as_deref().unwrap_or("<no address>"),
                        "skipping invalid dynamic peer (kept in the file): {}",
                        describe_toml_error(&e, None)
                    );
                    loaded.rejected.push(table);
                }
            }
        }
        Ok(loaded)
    }

    fn write_sync(path: &Path, sidecar: &LoadedSidecar) {
        let mut peers = Vec::with_capacity(sidecar.peers.len() + sidecar.rejected.len());
        for peer in &sidecar.peers {
            match toml::Table::try_from(peer) {
                Ok(table) => peers.push(table),
                Err(e) => {
                    tracing::warn!("failed to serialise dynamic peers: {e}");
                    return;
                }
            }
        }
        peers.extend(sidecar.rejected.iter().cloned());
        let text = match toml::to_string(&SidecarFile { peers }) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("failed to serialise dynamic peers: {e}");
                return;
            }
        };
        let tmp = path.with_extension("tmp");
        if let Err(e) =
            std::fs::write(&tmp, text.as_bytes()).and_then(|()| std::fs::rename(&tmp, path))
        {
            tracing::warn!(path = %path.display(), "failed to persist dynamic peers: {e}");
        }
    }
}

/// The `address` of a raw sidecar entry, for logs and de-duplication.
fn raw_address(table: &toml::Table) -> Option<String> {
    table.get("address")?.as_str().map(str::to_owned)
}

/// Describes a TOML error without quoting the input.
///
/// `toml::de::Error`'s `Display` prints the offending source line, which can
/// contain an `md5_password`. This returns only the parser's message and,
/// when `text` is given, the line number.
pub fn describe_toml_error(err: &toml::de::Error, text: Option<&str>) -> String {
    let message = err.message().trim_end();
    match (err.span(), text) {
        (Some(span), Some(text)) => {
            let line = text
                .get(..span.start)
                .map_or(0, |before| before.matches('\n').count())
                + 1;
            format!("{message} (line {line})")
        }
        _ => message.to_owned(),
    }
}

#[cfg(test)]
mod sidecar_tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn peer(octet: u8, remote_as: u32) -> PeerConfig {
        PeerConfig {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet)),
            port: 179,
            remote_as,
            import_default: None,
            import_default_v6: None,
            export_default: None,
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
        }
    }

    /// Runs `body` as the test `name` in a child process of its own: the
    /// test binary is run again, filtered to that one test, and must pass.
    ///
    /// For the tests that check what `tracing` logs. tracing-core caches
    /// each callsite's interest process-wide, and while only one scoped
    /// subscriber is alive it registers a callsite against the default of
    /// whichever thread reaches it first, without a lock. A test running
    /// in parallel with no subscriber (`invalid_entry_does_not_drop_valid_peers`
    /// logs through the same callsite) can then cache it as never enabled,
    /// and the capturing test sees no output. In the child, nothing else
    /// runs.
    fn in_own_process(name: &str, body: impl FnOnce()) {
        const CHILD: &str = "PATHVECTORD_ISOLATED_TEST";
        let module = module_path!();
        let module = module.split_once("::").map_or(module, |(_, m)| m);
        let test = format!("{module}::{name}");
        if std::env::var(CHILD).is_ok_and(|v| v == test) {
            body();
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([test.as_str(), "--exact", "--test-threads=1"])
            .env(CHILD, &test)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "{test} failed in its own process:\n{stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("1 passed"),
            "{test} did not run in its own process:\n{stdout}\n{stderr}"
        );
    }

    /// Captures what `f` logs through `tracing`, as plain text. Call it only
    /// inside [`in_own_process`].
    fn capture_logs<R>(f: impl FnOnce() -> R) -> (R, String) {
        #[derive(Clone, Default)]
        struct Buf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
            type Writer = Buf;
            fn make_writer(&'a self) -> Buf {
                self.clone()
            }
        }
        let buf = Buf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let out = tracing::subscriber::with_default(subscriber, f);
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        (out, text)
    }

    const SECRET: &str = "review-valid-secret";

    /// PR #124 review: `toml::de::Error`'s `Display` quotes the offending
    /// source line, so logging it would print a password that sits next to
    /// a syntax error. Diagnostics must not echo the file.
    #[test]
    fn unparseable_sidecar_log_does_not_reveal_passwords() {
        in_own_process("unparseable_sidecar_log_does_not_reveal_passwords", || {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("dynamic_peers.toml");
            std::fs::write(
                &path,
                format!(
                    "[[peers]]\naddress = \"10.0.0.1\"\nremote_as = 65001\nmd5_password = \"{SECRET}\" oops\n"
                ),
            )
            .unwrap();

            let (peers, logs) = capture_logs(|| DynamicPeerStore::new(path).load());
            assert!(peers.is_empty());
            assert!(!logs.is_empty(), "the failure must still be logged");
            assert!(!logs.contains(SECRET), "password leaked into logs: {logs}");
        });
    }

    /// Same for a password the validator rejects (over 80 bytes): the
    /// rejection is logged, the password is not.
    #[test]
    fn rejected_sidecar_password_is_not_logged() {
        in_own_process("rejected_sidecar_password_is_not_logged", || {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("dynamic_peers.toml");
            let long = format!("{SECRET}-{}", "x".repeat(80));
            std::fs::write(
                &path,
                format!(
                    "[[peers]]\naddress = \"10.0.0.1\"\nremote_as = 65001\nmd5_password = \"{long}\"\n"
                ),
            )
            .unwrap();

            let (_, logs) = capture_logs(|| DynamicPeerStore::new(path).load());
            assert!(
                logs.contains("too long"),
                "rejection must be logged: {logs}"
            );
            assert!(!logs.contains(SECRET), "password leaked into logs: {logs}");
        });
    }

    /// PR #124 review: a sidecar written before passwords were validated can
    /// hold an entry that no longer parses. That entry must not take the
    /// valid peers down with it, at load or at the next write.
    #[tokio::test]
    async fn invalid_entry_does_not_drop_valid_peers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dynamic_peers.toml");
        std::fs::write(
            &path,
            "[[peers]]\naddress = \"10.0.0.1\"\nremote_as = 65001\n\n\
             [[peers]]\naddress = \"10.0.0.2\"\nremote_as = 65002\nmd5_password = \"\"\n",
        )
        .unwrap();
        let store = DynamicPeerStore::new(path.clone());

        let loaded = store.load();
        assert_eq!(loaded.len(), 1, "the valid peer must still load");
        assert_eq!(loaded[0].address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        store.upsert(peer(3, 65003)).await;

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("10.0.0.1"),
            "valid peer lost on write:\n{text}"
        );
        assert!(
            text.contains("10.0.0.2"),
            "rejected entry must be kept for the operator:\n{text}"
        );
        assert!(
            text.contains("10.0.0.3"),
            "new peer must be written:\n{text}"
        );
        let addrs: Vec<IpAddr> = store.load().iter().map(|p| p.address).collect();
        assert_eq!(
            addrs,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            ]
        );
    }

    /// A sidecar that is not valid TOML at all cannot be split into entries,
    /// so writes must leave it untouched rather than replace it.
    #[tokio::test]
    async fn unparseable_sidecar_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dynamic_peers.toml");
        let original = "[[peers]]\naddress = \"10.0.0.1\"\nremote_as = 65001 garbage\n";
        std::fs::write(&path, original).unwrap();
        let store = DynamicPeerStore::new(path.clone());

        store.upsert(peer(3, 65003)).await;
        store.remove(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;

        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    #[tokio::test]
    async fn load_returns_empty_when_file_absent() {
        let dir = tempfile::tempdir().unwrap();
        let store = DynamicPeerStore::new(dir.path().join("dynamic_peers.toml"));
        assert!(store.load().is_empty());
    }

    #[tokio::test]
    async fn upsert_persists_peer() {
        let dir = tempfile::tempdir().unwrap();
        let store = DynamicPeerStore::new(dir.path().join("dynamic_peers.toml"));

        store.upsert(peer(1, 65001)).await;

        let loaded = store.load();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].address, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(loaded[0].remote_as, 65001);
    }

    #[tokio::test]
    async fn upsert_is_idempotent_by_address() {
        let dir = tempfile::tempdir().unwrap();
        let store = DynamicPeerStore::new(dir.path().join("dynamic_peers.toml"));

        store.upsert(peer(1, 65001)).await;
        store.upsert(peer(1, 65002)).await; // same address, different AS

        let loaded = store.load();
        assert_eq!(loaded.len(), 1, "upsert must replace, not append");
        assert_eq!(loaded[0].remote_as, 65002, "latest value must win");
    }

    #[tokio::test]
    async fn remove_deletes_peer() {
        let dir = tempfile::tempdir().unwrap();
        let store = DynamicPeerStore::new(dir.path().join("dynamic_peers.toml"));

        store.upsert(peer(1, 65001)).await;
        store.upsert(peer(2, 65002)).await;
        store.remove(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;

        let loaded = store.load();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].address, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[tokio::test]
    async fn remove_unknown_address_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let store = DynamicPeerStore::new(dir.path().join("dynamic_peers.toml"));

        store.upsert(peer(1, 65001)).await;
        store.remove(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99))).await; // not in sidecar

        assert_eq!(store.load().len(), 1);
    }

    #[tokio::test]
    async fn sidecar_round_trips_all_fields() {
        let dir = tempfile::tempdir().unwrap();
        let store = DynamicPeerStore::new(dir.path().join("dynamic_peers.toml"));

        let full_peer = PeerConfig {
            address: "10.0.0.1".parse().unwrap(),
            port: 1179,
            remote_as: 65001,
            import_default: Some(ImportDefault::Accept),
            import_default_v6: Some(ImportDefault::Reject),
            export_default: Some(ExportDefault::Accept),
            md5_password: Some("s3cr3t".parse().unwrap()),
            is_rr_client: true,
            next_hop_self: false,
            hold_time: Some(60),
            shutdown_message: Some("planned maintenance".into()),
            connect_retry_time: Some(5),
            max_prefixes_v4: Some(500_000),
            max_prefixes_v6: Some(100_000),
            max_prefixes_restart: Some(300),
            role: Some(PeerRole::Provider),
            confederation_member: true,
            blackhole_authorized_prefixes: Some(
                crate::blackhole::BlackholeScope::new(["192.0.2.0/24", "2001:db8:100::/40"])
                    .unwrap(),
            ),
        };
        store.upsert(full_peer.clone()).await;

        let loaded = store.load();
        let got = &loaded[0];
        assert_eq!(got.port, 1179);
        assert!(matches!(got.import_default, Some(ImportDefault::Accept)));
        assert!(matches!(got.import_default_v6, Some(ImportDefault::Reject)));
        assert!(matches!(got.export_default, Some(ExportDefault::Accept)));
        assert_eq!(got.md5_password, Some("s3cr3t".parse().unwrap()));
        assert!(got.is_rr_client);
        assert_eq!(got.hold_time, Some(60));
        assert_eq!(got.shutdown_message.as_deref(), Some("planned maintenance"));
        assert_eq!(
            got.max_prefixes_v4,
            Some(500_000),
            "max_prefixes_v4 must round-trip"
        );
        assert_eq!(
            got.max_prefixes_v6,
            Some(100_000),
            "max_prefixes_v6 must round-trip"
        );
        assert_eq!(
            got.max_prefixes_restart,
            Some(300),
            "max_prefixes_restart must round-trip"
        );
        assert_eq!(got.role, Some(PeerRole::Provider), "role must round-trip");
        assert!(
            got.confederation_member,
            "confederation_member must round-trip"
        );
        assert_eq!(
            got.blackhole_authorized_prefixes, full_peer.blackhole_authorized_prefixes,
            "blackhole_authorized_prefixes must round-trip"
        );
    }

    #[tokio::test]
    async fn write_is_atomic_tmp_file_cleaned_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dynamic_peers.toml");
        let store = DynamicPeerStore::new(path.clone());

        store.upsert(peer(1, 65001)).await;

        // After a successful write, no .tmp file should remain.
        let tmp = path.with_extension("tmp");
        assert!(
            !tmp.exists(),
            ".tmp file must be cleaned up after atomic rename"
        );
        assert!(path.exists(), "sidecar file must exist after upsert");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_grpc_port_defaults_to_50051() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.daemon.grpc_port, 50051);
    }

    #[test]
    fn test_config_grpc_port_explicit() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"
grpc_port = 9090
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.daemon.grpc_port, 9090);
    }

    #[test]
    fn test_config_defaults_hold_time_and_port() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"

[[peers]]
address = "10.0.0.2"
remote_as = 65002
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.daemon.hold_time, 90);
        assert_eq!(cfg.peers[0].port, 179);
    }

    #[test]
    fn test_config_explicit_hold_time_and_port() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"
hold_time = 180

[[peers]]
address = "10.0.0.2"
port = 1179
remote_as = 65002
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.daemon.hold_time, 180);
        assert_eq!(cfg.peers[0].port, 1179);
    }

    #[test]
    fn test_config_no_peers_defaults_to_empty() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.peers.is_empty());
    }

    #[test]
    fn test_config_import_default_omitted_is_none() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"

[[peers]]
address = "10.0.0.2"
remote_as = 65002
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.peers[0].import_default.is_none());
    }

    #[test]
    fn test_config_import_default_reject() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"

[[peers]]
address = "10.0.0.2"
remote_as = 65002
import_default = "reject"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            cfg.peers[0].import_default,
            Some(ImportDefault::Reject)
        ));
    }

    #[test]
    fn test_config_import_default_explicit_accept() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"

[[peers]]
address = "10.0.0.2"
remote_as = 65002
import_default = "accept"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            cfg.peers[0].import_default,
            Some(ImportDefault::Accept)
        ));
    }

    #[test]
    fn test_import_default_converts_to_default_action() {
        use pathvector_policy::DefaultAction;
        assert!(matches!(
            DefaultAction::from(ImportDefault::Accept),
            DefaultAction::Accept
        ));
        assert!(matches!(
            DefaultAction::from(ImportDefault::Reject),
            DefaultAction::Reject
        ));
    }

    #[test]
    fn test_export_default_omitted_is_none() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"

[[peers]]
address = "10.0.0.2"
remote_as = 65002
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.peers[0].export_default.is_none());
    }

    #[test]
    fn test_export_default_reject() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"

[[peers]]
address = "10.0.0.2"
remote_as = 65002
export_default = "reject"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            cfg.peers[0].export_default,
            Some(ExportDefault::Reject)
        ));
    }

    #[test]
    fn test_export_default_explicit_accept() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"

[[peers]]
address = "10.0.0.2"
remote_as = 65002
export_default = "accept"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            cfg.peers[0].export_default,
            Some(ExportDefault::Accept)
        ));
    }

    #[test]
    fn test_md5_password_omitted_is_none() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"

[[peers]]
address = "10.0.0.2"
remote_as = 65002
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.peers[0].md5_password.is_none());
    }

    #[test]
    fn test_md5_password_explicit() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"

[[peers]]
address = "10.0.0.2"
remote_as = 65002
md5_password = "s3cr3t"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.peers[0].md5_password, Some("s3cr3t".parse().unwrap()));
    }

    fn peer_with_md5(value: &str) -> String {
        format!(
            r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"

[[peers]]
address = "10.0.0.2"
remote_as = 65002
md5_password = "{value}"
"#
        )
    }

    /// Linux `tcp_v4_parse_md5_keys` reads a zero key length as "delete the
    /// key" (`tcp_md5_do_del`), so `md5_password = ""` would silently mean
    /// "no authentication". It must be a config error instead.
    #[test]
    fn test_md5_password_empty_is_rejected() {
        let err = toml::from_str::<Config>(&peer_with_md5(""))
            .err()
            .expect("must fail");
        assert!(err.to_string().contains("must not be empty"), "{err}");
    }

    /// `TCP_MD5SIG_MAXKEYLEN` is 80 (`include/uapi/linux/tcp.h`); the kernel
    /// returns `EINVAL` for longer keys, so reject them when parsing.
    #[test]
    fn test_md5_password_over_80_bytes_is_rejected() {
        let err = toml::from_str::<Config>(&peer_with_md5(&"x".repeat(81)))
            .err()
            .expect("must fail");
        assert!(err.to_string().contains("too long"), "{err}");
        let ok: Config = toml::from_str(&peer_with_md5(&"x".repeat(80))).unwrap();
        assert!(ok.peers[0].md5_password.is_some());
    }

    /// PR #124 review: startup config errors must not print the password.
    /// `toml::de::Error`'s `Display` quotes the source line;
    /// `describe_toml_error` (used by `main`) must not, whether the problem
    /// is a syntax error next to the password, an over-length password, or
    /// a password written as a bare (non-string) value.
    #[test]
    fn test_config_errors_do_not_reveal_md5_password() {
        let syntax =
            peer_with_md5("hunter2-secret").replace("hunter2-secret\"", "hunter2-secret\" x");
        let long = peer_with_md5(&format!("hunter2-secret{}", "x".repeat(80)));
        let bare = peer_with_md5("x").replace("\"x\"", "73556120071");
        for (text, secret) in [
            (syntax, "hunter2-secret"),
            (long, "hunter2-secret"),
            (bare, "73556120071"),
        ] {
            let err = toml::from_str::<Config>(&text).err().expect("must fail");
            let shown = describe_toml_error(&err, Some(&text));
            assert!(!shown.contains(secret), "password leaked: {shown}");
            assert!(shown.contains("(line "), "location expected: {shown}");
        }
    }

    #[test]
    fn test_md5_password_debug_is_redacted() {
        let p: Md5Password = "hunter2".parse().unwrap();
        assert_eq!(format!("{p:?}"), "Md5Password(<redacted>)");
    }

    /// Fail closed by default: without an explicit setting, a key the host
    /// cannot enforce stops the session.
    #[test]
    fn test_tcp_md5_enforcement_defaults_to_required() {
        let cfg: Config = toml::from_str(&peer_with_md5("k")).unwrap();
        assert_eq!(
            cfg.daemon.tcp_md5_enforcement,
            TcpMd5EnforcementConfig::Required
        );
        assert_eq!(
            Md5Enforcement::from(cfg.daemon.tcp_md5_enforcement),
            Md5Enforcement::Required
        );
    }

    #[test]
    fn test_tcp_md5_enforcement_values() {
        let parse = |v: &str| {
            toml::from_str::<Config>(&format!(
                "[daemon]\nlocal_as = 65001\nbgp_id = \"10.0.0.1\"\ntcp_md5_enforcement = \"{v}\"\n"
            ))
            .map(|c| c.daemon.tcp_md5_enforcement)
        };
        assert_eq!(
            parse("required").unwrap(),
            TcpMd5EnforcementConfig::Required
        );
        assert_eq!(
            parse("best-effort").unwrap(),
            TcpMd5EnforcementConfig::BestEffort
        );
        assert!(parse("off").is_err(), "unknown values must not parse");
    }

    #[test]
    fn test_config_import_default_v6_omitted_is_none() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"

[[peers]]
address = "10.0.0.2"
remote_as = 65002
import_default = "accept"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.peers[0].import_default_v6.is_none());
    }

    #[test]
    fn test_config_import_default_v6_accept() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"

[[peers]]
address = "10.0.0.2"
remote_as = 65002
import_default    = "reject"
import_default_v6 = "accept"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            cfg.peers[0].import_default_v6,
            Some(ImportDefault::Accept)
        ));
    }

    #[test]
    fn test_config_import_default_v6_reject() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"

[[peers]]
address = "10.0.0.2"
remote_as = 65002
import_default    = "accept"
import_default_v6 = "reject"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            cfg.peers[0].import_default_v6,
            Some(ImportDefault::Reject)
        ));
    }

    #[test]
    fn test_export_default_converts_to_default_action() {
        use pathvector_policy::DefaultAction;
        assert!(matches!(
            DefaultAction::from(ExportDefault::Accept),
            DefaultAction::Accept
        ));
        assert!(matches!(
            DefaultAction::from(ExportDefault::Reject),
            DefaultAction::Reject
        ));
    }

    // ── blackhole_authorized_prefixes (RFC 7999 §3.3) ────────────────────────

    fn peer_with_blackhole(line: &str) -> String {
        format!(
            r#"
[daemon]
local_as = 65002
bgp_id   = "10.0.0.2"

[[peers]]
address   = "10.0.0.1"
remote_as = 65001
{line}
"#
        )
    }

    /// RFC 7999 §4: no directive, no discard. Omitting the setting is the
    /// denied default.
    #[test]
    fn blackhole_agreement_defaults_to_denied() {
        let cfg: Config = toml::from_str(&peer_with_blackhole("")).unwrap();
        assert!(cfg.peers[0].blackhole_authorized_prefixes.is_none());
    }

    #[test]
    fn blackhole_authorized_prefixes_parse_both_families() {
        let cfg: Config = toml::from_str(&peer_with_blackhole(
            r#"blackhole_authorized_prefixes = ["192.0.2.0/24", "2001:db8:100::/40"]"#,
        ))
        .unwrap();
        let scope = cfg.peers[0].blackhole_authorized_prefixes.as_ref().unwrap();
        assert!(
            scope.covers(
                &"192.0.2.9/32"
                    .parse::<pathvector_types::Nlri<std::net::Ipv4Addr>>()
                    .unwrap()
            )
        );
        assert!(
            scope.covers(
                &"2001:db8:100::1/128"
                    .parse::<pathvector_types::Nlri<std::net::Ipv6Addr>>()
                    .unwrap()
            )
        );
    }

    /// Invalid agreements are config errors, never silently-empty scopes: an
    /// empty list, a host-bits prefix, and non-prefix text.
    #[test]
    fn invalid_blackhole_scopes_are_config_errors() {
        for bad in [
            "blackhole_authorized_prefixes = []",
            r#"blackhole_authorized_prefixes = ["192.0.2.5/24"]"#,
            r#"blackhole_authorized_prefixes = ["not-a-prefix"]"#,
            r#"blackhole_authorized_prefixes = "192.0.2.0/24""#,
        ] {
            assert!(
                toml::from_str::<Config>(&peer_with_blackhole(bad)).is_err(),
                "{bad} must be rejected"
            );
        }
    }
}

/// RFC 7607 §2: "A router MUST NOT initiate a connection claiming to be AS 0",
/// and AS 0 as a peer AS is Bad Peer AS — so AS 0 in a configuration could
/// never produce a session. It is refused when the file is read (issue #111).
#[cfg(test)]
mod as_zero_tests {
    use super::*;

    fn parse(daemon: &str, peer: &str) -> Result<(), String> {
        let text = format!(
            "[daemon]\nbgp_id = \"10.0.0.1\"\n{daemon}\n\n[[peers]]\naddress = \"10.0.0.2\"\n{peer}\n"
        );
        toml::from_str::<Config>(&text)
            .map(|_| ())
            .map_err(|e| describe_toml_error(&e, Some(&text)))
    }

    #[test]
    fn as_zero_is_refused_in_every_identity_field() {
        for (daemon, peer) in [
            ("local_as = 0", "remote_as = 65002"),
            (
                "local_as = 65001\nconfederation_id = 0",
                "remote_as = 65002",
            ),
            ("local_as = 65001", "remote_as = 0"),
        ] {
            let err = parse(daemon, peer).expect_err(daemon);
            assert!(err.contains("AS 0"), "{err}");
        }
    }

    #[test]
    fn non_zero_identities_parse() {
        parse(
            "local_as = 4294967295\nconfederation_id = 1",
            "remote_as = 131072",
        )
        .unwrap();
    }

    /// A persisted dynamic peer with AS 0 is not loaded, and the others are.
    #[test]
    fn sidecar_entry_with_as_zero_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dynamic_peers.toml");
        std::fs::write(
            &path,
            "[[peers]]\naddress = \"10.0.0.2\"\nremote_as = 0\n\n\
             [[peers]]\naddress = \"10.0.0.3\"\nremote_as = 65003\n",
        )
        .unwrap();
        let loaded = DynamicPeerStore::new(path).load();
        let addresses: Vec<_> = loaded.iter().map(|p| p.address.to_string()).collect();
        assert_eq!(addresses, ["10.0.0.3"]);
    }
}
