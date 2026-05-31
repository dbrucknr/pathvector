use std::net::Ipv4Addr;

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

#[derive(Deserialize)]
pub struct PeerConfig {
    pub address: Ipv4Addr,
    #[serde(default = "default_bgp_port")]
    pub port: u16,
    pub remote_as: u32,
}

fn default_bgp_port() -> u16 {
    179
}
