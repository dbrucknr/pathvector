//! Topology and `pathvectord` configuration for the load harness, plus the
//! preflight check for the loopback source addresses it needs.

use std::{
    fmt::Write as _,
    net::{Ipv4Addr, SocketAddr, TcpListener},
};

/// One simulated peer: the source address it connects *from* (which is how
/// `pathvectord` identifies it) and the AS it claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerSpec {
    pub addr: Ipv4Addr,
    pub remote_as: u32,
}

/// The fixed shape of a harness run: N full-table loaders plus one quiet
/// control peer with an aggressive hold timer.
#[derive(Debug, Clone)]
pub struct Topology {
    pub loaders: Vec<PeerSpec>,
    pub control: PeerSpec,
    /// Hold time (seconds) the control peer negotiates. The daemon sends a
    /// KEEPALIVE every `hold/3`, so this sets both the expected cadence and
    /// the deadline whose breach the harness reports as a hold-timer miss.
    pub control_hold: u16,
    pub bgp_port: u16,
    pub grpc_port: u16,
    pub metrics_port: u16,
}

pub const DAEMON_AS: u32 = 65002;
pub const CONTROL_AS: u32 = 65100;
const LOADER_AS_BASE: u32 = 65101;

impl Topology {
    /// Loaders take `<prefix>.2`, `<prefix>.3`, …; the control peer takes the
    /// next address after them. `prefix` is the first three octets, e.g.
    /// `[127, 0, 0]`.
    #[must_use]
    pub fn new(prefix: [u8; 3], loaders: u8, control_hold: u16) -> Self {
        let addr = |n: u8| Ipv4Addr::new(prefix[0], prefix[1], prefix[2], n);
        let loaders_specs = (0..loaders)
            .map(|i| PeerSpec {
                addr: addr(2 + i),
                remote_as: LOADER_AS_BASE + u32::from(i),
            })
            .collect();
        Self {
            loaders: loaders_specs,
            control: PeerSpec {
                addr: addr(2 + loaders),
                remote_as: CONTROL_AS,
            },
            control_hold,
            bgp_port: 11_790,
            grpc_port: 59_381,
            metrics_port: 19_181,
        }
    }

    /// Builds a topology from explicit source addresses: all but the last are
    /// loaders, the last is the control peer. For hosts where a `127.0.0.x`
    /// range isn't available (macOS without `lo0` aliases) or when real
    /// interface addresses should be used.
    ///
    /// # Panics
    ///
    /// Panics if fewer than two addresses are given (one loader plus the
    /// control peer is the minimum).
    #[must_use]
    pub fn from_addrs(addrs: &[Ipv4Addr], control_hold: u16) -> Self {
        assert!(
            addrs.len() >= 2,
            "need at least one loader and a control address"
        );
        let (control, loaders) = addrs.split_last().expect("non-empty");
        Self {
            loaders: loaders
                .iter()
                .enumerate()
                .map(|(i, &addr)| PeerSpec {
                    addr,
                    remote_as: LOADER_AS_BASE + u32::try_from(i).expect("few loaders"),
                })
                .collect(),
            control: PeerSpec {
                addr: *control,
                remote_as: CONTROL_AS,
            },
            control_hold,
            bgp_port: 11_790,
            grpc_port: 59_381,
            metrics_port: 19_181,
        }
    }

    /// Every source address the run binds.
    #[must_use]
    pub fn all_addrs(&self) -> Vec<Ipv4Addr> {
        self.loaders
            .iter()
            .map(|l| l.addr)
            .chain(std::iter::once(self.control.addr))
            .collect()
    }

    /// `pathvectord` config. Every peer accepts imports (RFC 8212 makes eBGP
    /// reject-by-default, so this is explicit) and rejects exports, so
    /// steady-state outbound traffic is just KEEPALIVEs — isolating the
    /// inbound/lock path. The export-policy scenario flips one loader to
    /// `accept` at runtime over gRPC.
    #[must_use]
    pub fn daemon_toml(&self) -> String {
        let mut s = format!(
            "[daemon]\nlocal_as = {DAEMON_AS}\nbgp_id = \"10.255.255.2\"\n\
             bgp_port = {}\ngrpc_port = {}\nmetrics_port = {}\n",
            self.bgp_port, self.grpc_port, self.metrics_port
        );
        for l in &self.loaders {
            let _ = write!(
                s,
                "\n[[peers]]\naddress = \"{}\"\nremote_as = {}\n\
                 connect_retry_time = 3\nimport_default = \"accept\"\nexport_default = \"reject\"\n",
                l.addr, l.remote_as
            );
        }
        let _ = write!(
            s,
            "\n[[peers]]\naddress = \"{}\"\nremote_as = {}\nhold_time = {}\n\
             import_default = \"accept\"\nexport_default = \"reject\"\n",
            self.control.addr, self.control.remote_as, self.control_hold
        );
        s
    }
}

/// Verifies every address in `addrs` can be bound as a local source address.
///
/// Linux treats all of `127.0.0.0/8` as loopback; macOS only configures
/// `127.0.0.1`, so extra addresses need an explicit `lo0` alias. Returns an
/// actionable error — including the exact commands to add and later remove
/// the aliases — rather than failing mid-run with an opaque `EADDRNOTAVAIL`.
///
/// # Errors
///
/// Returns a human-readable message listing the addresses that failed.
pub fn preflight(addrs: &[Ipv4Addr]) -> Result<(), String> {
    let missing: Vec<Ipv4Addr> = addrs
        .iter()
        .copied()
        .filter(|a| TcpListener::bind(SocketAddr::from((*a, 0))).is_err())
        .collect();
    if missing.is_empty() {
        return Ok(());
    }

    let mut msg = format!(
        "cannot bind source address(es): {}\n\
         pathvectord identifies peers by source IP, so each simulated peer needs its own.\n",
        missing
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
    if cfg!(target_os = "macos") {
        msg.push_str("\nOn macOS, add loopback aliases (needs sudo):\n");
        for a in &missing {
            let _ = writeln!(msg, "  sudo ifconfig lo0 alias {a} up");
        }
        msg.push_str("\nRemove them afterwards:\n");
        for a in &missing {
            let _ = writeln!(msg, "  sudo ifconfig lo0 -alias {a}");
        }
    } else {
        msg.push_str(
            "\nOn Linux, `127.0.0.0/8` is normally all loopback; check `ip addr show lo`.\n",
        );
    }
    Err(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_sequential_and_distinct() {
        let t = Topology::new([127, 0, 0], 2, 9);
        assert_eq!(t.loaders[0].addr, Ipv4Addr::new(127, 0, 0, 2));
        assert_eq!(t.loaders[1].addr, Ipv4Addr::new(127, 0, 0, 3));
        assert_eq!(t.control.addr, Ipv4Addr::new(127, 0, 0, 4));
        let all = t.all_addrs();
        let mut dedup = all.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(
            dedup.len(),
            all.len(),
            "peer source addresses must be unique"
        );
        let asns: Vec<u32> = t
            .loaders
            .iter()
            .map(|l| l.remote_as)
            .chain([t.control.remote_as])
            .collect();
        let mut d = asns.clone();
        d.sort_unstable();
        d.dedup();
        assert_eq!(d.len(), asns.len(), "peer ASNs must be unique");
    }

    /// The generated config must be valid TOML with the peer shape
    /// `pathvectord` expects: one `[[peers]]` per simulated peer, loaders
    /// import-accept/export-reject, and only the control peer carrying a
    /// per-peer hold time.
    #[test]
    fn daemon_toml_has_expected_peers_and_policies() {
        let t = Topology::new([127, 0, 0], 2, 9);
        let toml = t.daemon_toml();
        assert_eq!(toml.matches("[[peers]]").count(), 3);
        assert_eq!(toml.matches("import_default = \"accept\"").count(), 3);
        assert_eq!(toml.matches("export_default = \"reject\"").count(), 3);
        assert_eq!(
            toml.matches("hold_time").count(),
            1,
            "only the control peer overrides hold time"
        );
        assert!(toml.contains("address = \"127.0.0.4\"\nremote_as = 65100\nhold_time = 9"));
        assert!(toml.contains("metrics_port = 19181"));
        assert_eq!(
            toml.matches("connect_retry_time = 3").count(),
            2,
            "loaders (not the control peer) get a short ConnectRetry so reconnect scenarios don't wait 120 s"
        );
    }

    /// Explicit addresses: the last is the control peer, the rest are loaders
    /// with distinct ASNs, and the daemon config reflects that split.
    #[test]
    fn from_addrs_makes_last_address_the_control_peer() {
        let a = Ipv4Addr::LOCALHOST;
        let b = Ipv4Addr::new(192, 168, 1, 50);
        let t = Topology::from_addrs(&[a, b], 9);
        assert_eq!(t.loaders.len(), 1);
        assert_eq!(t.loaders[0].addr, a);
        assert_eq!(t.control.addr, b);
        assert_eq!(t.all_addrs(), vec![a, b]);
        assert!(
            t.daemon_toml()
                .contains("address = \"192.168.1.50\"\nremote_as = 65100\nhold_time = 9")
        );
    }

    #[test]
    fn preflight_passes_for_loopback_and_names_unbindable_addresses() {
        assert!(preflight(&[Ipv4Addr::LOCALHOST]).is_ok());
        // TEST-NET-1 is never a local interface address.
        let err = preflight(&[Ipv4Addr::LOCALHOST, Ipv4Addr::new(192, 0, 2, 77)]).unwrap_err();
        assert!(err.contains("192.0.2.77"), "{err}");
        assert!(
            !err.contains("127.0.0.1,"),
            "bindable address must not be listed as failing: {err}"
        );
    }
}
