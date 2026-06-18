use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use pathvector_policy::DefaultAction;
use serde::{Deserialize, Serialize};

/// Top-level daemon configuration.
///
/// ```toml
/// [daemon]
/// local_as  = 65002
/// bgp_id    = "127.0.0.2"
/// hold_time = 90          # optional, default 90 s
/// grpc_port = 50051       # optional, default 50051
/// bgp_port  = 179         # optional, default 179 (use 1179+ without CAP_NET_BIND_SERVICE)
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
    /// ```toml
    /// [daemon]
    /// local_as   = 65001
    /// bgp_id     = "10.0.0.1"
    /// cluster_id = 1
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

#[derive(Serialize, Deserialize, Clone)]
pub struct PeerConfig {
    pub address: Ipv4Addr,
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
    pub async fn remove(&self, address: Ipv4Addr) {
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
            Ok(text) => toml::from_str::<SidecarFile>(&text)
                .unwrap_or_default()
                .peers,
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
        if let Err(e) = std::fs::write(&tmp, text.as_bytes())
            .and_then(|()| std::fs::rename(&tmp, path))
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
            address: Ipv4Addr::new(10, 0, 0, octet),
            port: 179,
            remote_as,
            import_default: None,
            import_default_v6: None,
            export_default: None,
            md5_password: None,
            is_rr_client: false,
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
        store.remove(Ipv4Addr::new(10, 0, 0, 1)).await;

        let loaded = store.load();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].address, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[tokio::test]
    async fn remove_unknown_address_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let store = DynamicPeerStore::new(dir.path().join("dynamic_peers.toml"));

        store.upsert(peer(1, 65001)).await;
        store.remove(Ipv4Addr::new(10, 0, 0, 99)).await; // not in sidecar

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
    }

    #[tokio::test]
    async fn write_is_atomic_tmp_file_cleaned_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dynamic_peers.toml");
        let store = DynamicPeerStore::new(path.clone());

        store.upsert(peer(1, 65001)).await;

        // After a successful write, no .tmp file should remain.
        let tmp = path.with_extension("tmp");
        assert!(!tmp.exists(), ".tmp file must be cleaned up after atomic rename");
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
