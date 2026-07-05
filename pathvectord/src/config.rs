use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use pathvector_policy::DefaultAction;
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
    /// When set, the kernel signs and verifies every TCP segment for this BGP
    /// session using HMAC-MD5. The peer must be configured with the same key.
    /// Maximum 80 bytes (Linux kernel limit). Omit to disable MD5 (default).
    ///
    /// ```toml
    /// [[peers]]
    /// address      = "198.51.100.1"
    /// remote_as    = 64496
    /// md5_password = "secret"
    /// ```
    #[serde(default)]
    pub md5_password: Option<String>,
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
}

fn default_bgp_port() -> u16 {
    179
}

// ── Dynamic peer persistence ──────────────────────────────────────────────────

/// Internal sidecar file format — a flat list of peer configs.
#[derive(Serialize, Deserialize, Default)]
struct SidecarFile {
    #[serde(default)]
    peers: Vec<PeerConfig>,
}

/// Persists dynamically-added peers to a TOML sidecar file so they survive
/// daemon restarts.
///
/// The sidecar lives next to the static config file (or at an explicit path)
/// and uses the same `[[peers]]` format, making it easy to inspect or edit
/// manually.  Writes are atomic: the new content is written to a `.tmp` file
/// then `rename`d over the target, so a crash mid-write never corrupts the
/// sidecar.
pub struct DynamicPeerStore {
    path: PathBuf,
}

impl DynamicPeerStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load all persisted dynamic peers.  Returns an empty vec if the sidecar
    /// does not exist yet (first run).
    pub fn load(&self) -> Vec<PeerConfig> {
        Self::load_sync(&self.path)
    }

    /// Upsert a peer into the sidecar (replace by address if already present).
    pub async fn upsert(&self, peer: PeerConfig) {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut peers = Self::load_sync(&path);
            peers.retain(|p| p.address != peer.address);
            peers.push(peer);
            Self::write_sync(&path, &peers);
        })
        .await
        .ok();
    }

    /// Remove a peer from the sidecar by address.
    pub async fn remove(&self, address: IpAddr) {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut peers = Self::load_sync(&path);
            peers.retain(|p| p.address != address);
            Self::write_sync(&path, &peers);
        })
        .await
        .ok();
    }

    fn load_sync(path: &Path) -> Vec<PeerConfig> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                toml::from_str::<SidecarFile>(&text)
                    .unwrap_or_default()
                    .peers
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
            Err(e) => {
                tracing::warn!(path = %path.display(), "failed to read dynamic peer sidecar: {e}");
                vec![]
            }
        }
    }

    fn write_sync(path: &Path, peers: &[PeerConfig]) {
        let sidecar = SidecarFile {
            peers: peers.to_vec(),
        };
        let text = match toml::to_string(&sidecar) {
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
        }
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
            md5_password: Some("s3cr3t".into()),
            is_rr_client: true,
            next_hop_self: false,
            hold_time: Some(60),
            shutdown_message: Some("planned maintenance".into()),
            connect_retry_time: Some(5),
            max_prefixes_v4: Some(500_000),
            max_prefixes_v6: Some(100_000),
            max_prefixes_restart: Some(300),
            role: Some(PeerRole::Provider),
        };
        store.upsert(full_peer.clone()).await;

        let loaded = store.load();
        let got = &loaded[0];
        assert_eq!(got.port, 1179);
        assert!(matches!(got.import_default, Some(ImportDefault::Accept)));
        assert!(matches!(got.import_default_v6, Some(ImportDefault::Reject)));
        assert!(matches!(got.export_default, Some(ExportDefault::Accept)));
        assert_eq!(got.md5_password.as_deref(), Some("s3cr3t"));
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
        assert_eq!(cfg.peers[0].md5_password.as_deref(), Some("s3cr3t"));
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
}
