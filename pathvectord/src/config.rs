use std::net::Ipv4Addr;

use pathvector_policy::DefaultAction;
use serde::Deserialize;

/// Top-level daemon configuration.
///
/// ```toml
/// [daemon]
/// local_as  = 65002
/// bgp_id    = "127.0.0.2"
/// hold_time = 90          # optional, default 90 s
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
}

fn default_hold_time() -> u16 {
    90
}

/// TOML representation of the import policy default action for a peer.
///
/// Controls what happens to routes that do not match any import policy term.
/// Defaults to `"accept"` if not specified, preserving the previous behaviour
/// of installing every received route unconditionally.
///
/// ```toml
/// [[peers]]
/// address        = "10.0.0.1"
/// remote_as      = 65001
/// import_default = "reject"   # block all routes unless a term accepts them
/// ```
#[derive(Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum ImportDefault {
    /// Accept routes that matched no term.
    #[default]
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

#[derive(Deserialize)]
pub struct PeerConfig {
    pub address: Ipv4Addr,
    #[serde(default = "default_bgp_port")]
    pub port: u16,
    pub remote_as: u32,
    /// Default action when no import policy term matches.
    ///
    /// Defaults to `"accept"` so the daemon behaves as before when
    /// `import_default` is omitted.
    #[serde(default)]
    pub import_default: ImportDefault,
}

fn default_bgp_port() -> u16 {
    179
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_config_import_default_omitted_is_accept() {
        let toml = r#"
[daemon]
local_as = 65001
bgp_id = "10.0.0.1"

[[peers]]
address = "10.0.0.2"
remote_as = 65002
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(matches!(cfg.peers[0].import_default, ImportDefault::Accept));
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
        assert!(matches!(cfg.peers[0].import_default, ImportDefault::Reject));
    }

    #[test]
    fn test_import_default_converts_to_default_action() {
        use pathvector_policy::DefaultAction;
        assert!(matches!(DefaultAction::from(ImportDefault::Accept), DefaultAction::Accept));
        assert!(matches!(DefaultAction::from(ImportDefault::Reject), DefaultAction::Reject));
    }
}
