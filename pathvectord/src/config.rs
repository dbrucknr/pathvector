use std::net::{Ipv4Addr, Ipv6Addr};

use pathvector_policy::DefaultAction;
use serde::Deserialize;

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
#[derive(Deserialize, Clone, Copy)]
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
#[derive(Deserialize, Clone, Copy)]
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

#[derive(Deserialize)]
pub struct PeerConfig {
    pub address: Ipv4Addr,
    #[serde(default = "default_bgp_port")]
    pub port: u16,
    pub remote_as: u32,
    /// Default action when no import policy term matches.
    ///
    /// When omitted: eBGP peers default to `"reject"` (RFC 8212 compliance);
    /// iBGP peers default to `"accept"`. Set explicitly to override.
    #[serde(default)]
    pub import_default: Option<ImportDefault>,
    /// Default action when no export policy term matches.
    ///
    /// When omitted: eBGP peers default to `"reject"` (RFC 8212 compliance);
    /// iBGP peers default to `"accept"`. Set explicitly to override.
    #[serde(default)]
    pub export_default: Option<ExportDefault>,
}

fn default_bgp_port() -> u16 {
    179
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
