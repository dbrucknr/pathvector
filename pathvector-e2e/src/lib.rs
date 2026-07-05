//! Test harness for pathvector end-to-end tests.
//!
//! Each test creates a [`Harness`], which:
//!
//! 1. Creates an isolated Docker bridge network for this test.
//! 2. Starts a `gobgpd` container on that network, listening for BGP on
//!    port 179 (the standard well-known port — privileged inside a container).
//! 3. Inspects the container to learn gobgpd's IP on the network.
//! 4. Starts a `pathvectord` container on the same network, configured to
//!    dial gobgpd's IP on port 179.
//! 5. Polls [`PathvectorClient::get_peer`] until the session reaches
//!    `Established`.
//!
//! **Why Docker containers (not native subprocesses)?**
//!
//! GoBGP's upstream releases only ship Linux binaries; there are no macOS
//! prebuilts.  Running both services as containers on the same Docker bridge
//! network means BGP traffic is **container-to-container** — it never touches
//! the macOS Docker Desktop TCP proxy that was causing OPENCONFIRM to stall.
//! Only pathvectord's gRPC management port is mapped to the host (for
//! [`PathvectorClient`]), and HTTP/2 is unaffected by the proxy.
//!
//! **Image names**
//!
//! `just e2e` builds four images before running the suite:
//! - `pathvector-gobgpd-test:latest` — GoBGP from `e2e/Dockerfile`
//! - `pathvector-bird-test:latest`   — BIRD from `e2e/Dockerfile.bird`
//! - `pathvector-frr-test:latest`    — FRRRouting from `e2e/Dockerfile.frr`
//! - `pathvector-e2e:latest`         — pathvectord from `e2e/Dockerfile.pathvectord`

use std::{
    io::Write as _,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use pathvector_client::{
    DaemonClient, PathvectorClient,
    types::{Route, SessionState},
};
use tempfile::NamedTempFile;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{ContainerPort, Mount, WaitFor, wait::HealthWaitStrategy},
    runners::AsyncRunner,
};

// ── Docker image names ────────────────────────────────────────────────────────

/// GoBGP image built by `just e2e` from `e2e/Dockerfile`.
pub const GOBGPD_IMAGE: &str = "pathvector-gobgpd-test";

/// pathvectord image built by `just e2e` from `e2e/Dockerfile.pathvectord`.
pub const PATHVECTORD_IMAGE: &str = "pathvector-e2e";

/// Mock RTR server image built by `just e2e` from `e2e/Dockerfile.mock-rtr`,
/// used by [`RpkiHarness`]. See `src/bin/mock_rtr_server.rs` for the fixed
/// ROA scenario it serves.
pub const MOCK_RTR_IMAGE: &str = "pathvector-mock-rtr-test";

/// Mock BGP peer image built by `just e2e` from
/// `e2e/Dockerfile.mock-bgp-peer`, used by [`RoleHarness`]. See
/// `src/bin/mock_bgp_peer.rs` for the fixed RFC 9234 leak scenario it sends.
pub const MOCK_BGP_PEER_IMAGE: &str = "pathvector-mock-bgp-peer-test";

/// Mock BGP dialer image built by `just e2e` from
/// `e2e/Dockerfile.mock-bgp-dialer`, used by [`Ipv6AcceptHarness`]. See
/// `src/bin/mock_bgp_dialer.rs` — the mirror image of `mock_bgp_peer`, dials
/// out instead of listening.
pub const MOCK_BGP_DIALER_IMAGE: &str = "pathvector-mock-bgp-dialer-test";

// ── Fixed container-internal ports ───────────────────────────────────────────

/// BGP listen port inside the gobgpd container.
pub const GOBGPD_BGP_PORT: u16 = 179;

/// RTR listen port inside the mock RTR server container (RFC 8210 default).
pub const MOCK_RTR_PORT: u16 = 3323;

/// gRPC management port inside the pathvectord container.
pub const PATHVECTORD_GRPC_PORT: u16 = 51_200;

/// Prometheus metrics port inside the pathvectord container, used by
/// [`MetricsHarness`]. Distinct from the gRPC port range so both can be
/// published to the host simultaneously.
pub const PATHVECTORD_METRICS_PORT: u16 = 51_300;

// ── Port / ID allocation ──────────────────────────────────────────────────────

/// Per-test unique ID — used to name Docker networks and containers, and to
/// derive per-test subnets (see `fib_test_subnet` and friends below), so
/// concurrent (or back-to-back) tests never collide.
///
/// This is a per-*process* counter, which matters: nextest runs many test
/// binaries concurrently as separate OS processes (unlike `cargo test`,
/// which runs one integration-test binary at a time), so each process gets
/// its own independent copy of this static, all starting at 0. Without the
/// PID-based offset in `alloc_test_id` below, two concurrently-running test
/// binaries would both allocate test_id 0 and collide on the same Docker
/// network name / subnet — this happened in practice switching to nextest.
static NEXT_TEST_ID: AtomicU32 = AtomicU32::new(0);

pub fn alloc_test_id() -> u32 {
    let counter = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    // Fold in the OS PID (unique among concurrently-running processes on
    // this host) so different *processes* get disjoint id sequences instead
    // of every process starting at the same 0, 1, 2, ... Multiplying by a
    // large odd constant before XOR-ing spreads the PID across the full u32
    // range, so callers that mask down to 8 or 16 bits (fib_test_subnet's
    // `% 256`, the IPv6 subnet's `& 0xffff`) still see good separation
    // between processes, not just the low few bits of a raw PID. XOR with a
    // fixed per-process value is a bijection, so sequential counter values
    // within one process (0, 1, 2, ...) still map to distinct ids — only
    // the mapping is process-specific, not the guarantee of within-process
    // uniqueness.
    let pid_component = std::process::id().wrapping_mul(2_654_435_761);
    pid_component ^ counter
}

/// Asks the OS for a genuinely free TCP port by binding to port 0 and
/// reading back what the kernel assigned, then immediately releasing it.
///
/// This replaced a static incrementing counter for the same reason
/// `alloc_test_id` now folds in the PID: a counter that always starts at
/// 51_200 (or 59_300) in every process nextest spawns guarantees a
/// collision the moment two test binaries run concurrently — this happened
/// in practice ("port is already allocated" in CI). Querying the OS's live
/// port table instead means two concurrent processes essentially never get
/// told the same port. There's a small window between this check and
/// Docker actually binding the port where another process could grab it —
/// an accepted, standard tradeoff for this pattern (the same one used by
/// most "give me a free port" test helpers); a collision here is now a
/// rare, transient race rather than a guaranteed failure.
fn alloc_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("OS must be able to bind an ephemeral port")
        .local_addr()
        .expect("bound socket must have a local address")
        .port()
}

#[must_use]
pub fn alloc_grpc_port() -> u16 {
    alloc_free_port()
}

#[must_use]
pub fn alloc_metrics_port() -> u16 {
    alloc_free_port()
}

// ── Binary / workspace paths ──────────────────────────────────────────────────

/// Returns the workspace root (parent of `e2e/`).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("e2e/ must be inside a workspace")
        .to_owned()
}

/// Resolves the path to the `target/` directory, honouring `CARGO_TARGET_DIR`.
fn target_dir() -> PathBuf {
    std::env::var("CARGO_TARGET_DIR")
        .map_or_else(|_| workspace_root().join("target"), PathBuf::from)
}

/// Resolves the path to the `pathvectord` binary built by the host toolchain.
///
/// Used only to verify that the binary was built before Docker image creation.
#[must_use]
pub fn daemon_binary() -> PathBuf {
    target_dir().join("debug").join("pathvectord")
}

// ── Docker network management ─────────────────────────────────────────────────

/// A Docker bridge network that is removed on drop.
///
/// Placed **last** in [`Harness`] so it is dropped after the containers that
/// use it.
pub struct DockerNetwork {
    name: String,
}

impl DockerNetwork {
    /// Create a new Docker bridge network with the given name.
    ///
    /// # Panics
    ///
    /// Panics if `docker network create` fails.
    #[must_use]
    pub fn create(name: String) -> Self {
        let status = Command::new("docker")
            .args(["network", "create", &name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("docker network create");
        assert!(
            status.success(),
            "docker network create {name} failed: {status}"
        );
        Self { name }
    }

    /// Create a Docker bridge network with both IPv4 and IPv6 enabled.
    ///
    /// Uses the supplied ULA prefix as the IPv6 subnet.  Containers on this
    /// network receive link-local (`fe80::`) addresses automatically, which is
    /// required for IPv6 BGP next-hop tests.
    ///
    /// # Panics
    ///
    /// Panics if `docker network create` fails.
    #[must_use]
    pub fn create_with_ipv6(name: String, ipv6_subnet: &str) -> Self {
        let status = Command::new("docker")
            .args([
                "network",
                "create",
                "--ipv6",
                "--subnet",
                ipv6_subnet,
                &name,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("docker network create --ipv6");
        assert!(
            status.success(),
            "docker network create --ipv6 {name} failed: {status}"
        );
        Self { name }
    }

    /// Create a new Docker bridge network with a specific subnet.
    ///
    /// Useful when container IPs must be known before the containers start
    /// (e.g. TCP MD5SIG tests where each side is pre-configured with the
    /// other's IP).
    ///
    /// # Panics
    ///
    /// Panics if `docker network create` fails.
    #[must_use]
    pub fn create_with_subnet(name: String, subnet: &str) -> Self {
        let status = Command::new("docker")
            .args(["network", "create", "--subnet", subnet, &name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("docker network create --subnet");
        assert!(
            status.success(),
            "docker network create {name} --subnet {subnet} failed: {status}"
        );
        Self { name }
    }

    /// The network name — pass to `docker run --network`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

// ── Raw-CLI container guard ───────────────────────────────────────────────────

/// RAII guard for a Docker container started via the CLI (not testcontainers).
///
/// The container is forcibly removed (`docker rm -f`) when this guard drops.
/// Unlike [`ContainerAsync`], this supports options that testcontainers does
/// not expose — in particular `--ip` (fixed IP assignment on a custom subnet)
/// and `--cap-add` (Linux capability grants needed for `TCP_MD5SIG`).
pub struct ContainerGuard(pub String);

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        Command::new("docker")
            .args(["rm", "-f", &self.0])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok();
    }
}

impl Drop for DockerNetwork {
    fn drop(&mut self) {
        Command::new("docker")
            .args(["network", "rm", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok();
    }
}

// ── Container IP lookup ───────────────────────────────────────────────────────

/// Returns the IP address assigned to `container_id` on `network`.
///
/// Runs `docker inspect` synchronously and parses the `IPAddress` field.
/// This is a quick, one-shot CLI call so blocking is acceptable.
///
/// # Panics
///
/// Panics if `docker inspect` fails or the output is not a valid IPv4 address.
#[must_use]
pub fn container_network_ip(container_id: &str, network: &str) -> Ipv4Addr {
    let fmt = format!(r#"{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}"#);
    let output = Command::new("docker")
        .args(["inspect", container_id, "--format", &fmt])
        .output()
        .expect("docker inspect");
    let ip_str = std::str::from_utf8(&output.stdout)
        .expect("docker inspect output is UTF-8")
        .trim()
        .to_owned();
    ip_str
        .parse()
        .unwrap_or_else(|_| panic!("docker inspect returned non-IPv4 address: {ip_str:?}"))
}

/// Returns the global-scope IPv6 address assigned to `container_id` on
/// `network`.
///
/// Only meaningful for a network created with [`DockerNetwork::create_with_ipv6`]
/// and an explicit `--subnet`: Docker assigns a routable address in that
/// subnet (`GlobalIPv6Address`) in addition to the kernel-autoconfigured
/// `fe80::` link-local address that every container on an `--ipv6` bridge
/// gets regardless of subnet config (see [`Harness::gobgp_link_local_v6`]).
/// Use this address (not the link-local one) as a peer's transport address —
/// dialing a link-local destination requires a zone/interface index that a
/// plain `TcpStream::connect` can't express.
///
/// # Panics
///
/// Panics if `docker inspect` fails or the output is not a valid IPv6 address.
#[must_use]
pub fn container_network_ipv6(container_id: &str, network: &str) -> Ipv6Addr {
    let fmt = format!(r#"{{{{(index .NetworkSettings.Networks "{network}").GlobalIPv6Address}}}}"#);
    let output = Command::new("docker")
        .args(["inspect", container_id, "--format", &fmt])
        .output()
        .expect("docker inspect");
    let ip_str = std::str::from_utf8(&output.stdout)
        .expect("docker inspect output is UTF-8")
        .trim()
        .to_owned();
    ip_str
        .parse()
        .unwrap_or_else(|_| panic!("docker inspect returned non-IPv6 address: {ip_str:?}"))
}

// ── Config generation ─────────────────────────────────────────────────────────

/// Writes the gobgpd config file for the test container.
///
/// The container uses port 179 (default; no `port =` key needed).
/// gRPC defaults to `0.0.0.0:50051` which is accessible via `docker exec`.
/// Two dynamic-neighbor prefixes are configured — `0.0.0.0/0` and `::/0` —
/// so GoBGP accepts a dial-in from pathvectord regardless of which address
/// family the connection arrives over; this is what lets a native-IPv6-
/// transport session (see `container_network_ipv6`) reach Established
/// alongside every existing IPv4-transport test using this same config.
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_gobgp_config() -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp gobgp config");
    write!(
        f,
        r#"
[global.config]
  as        = 65001
  router-id = "1.0.0.1"

[[peer-groups]]
  [peer-groups.config]
    peer-group-name = "pathvector-peers"
    peer-as         = 65002
  [peer-groups.timers.config]
    hold-time          = 9
    keepalive-interval = 3
  [peer-groups.transport.config]
    passive-mode = true

  # RFC 4724: enable graceful restart so GoBGP sends End-of-RIB markers
  # after its initial table dump.  pathvectord parses but defers the stale-
  # route timer; enabling this on GoBGP's side is harmless for all tests.
  [peer-groups.graceful-restart.config]
    enabled      = true
    restart-time = 120

  [[peer-groups.afi-safis]]
    [peer-groups.afi-safis.config]
      afi-safi-name = "ipv4-unicast"

  [[peer-groups.afi-safis]]
    [peer-groups.afi-safis.config]
      afi-safi-name = "ipv6-unicast"

[[dynamic-neighbors]]
  [dynamic-neighbors.config]
    prefix     = "0.0.0.0/0"
    peer-group = "pathvector-peers"

[[dynamic-neighbors]]
  [dynamic-neighbors.config]
    prefix     = "::/0"
    peer-group = "pathvector-peers"
"#
    )
    .expect("write gobgp config");
    f
}

/// Like [`write_gobgp_config`] but with a configurable local AS.
///
/// Needed whenever a test topology has pathvectord re-advertise a route
/// between two GoBGP peers: if both peers ran the hardcoded AS 65001,
/// the receiving peer's own AS_PATH loop-prevention would (correctly, per
/// RFC 4271 §9.1.2) discard the re-advertised route, since the AS_PATH
/// already contains 65001 from the originating hop.
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_gobgp_config_with_as(as_number: u32) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp gobgp config");
    write!(
        f,
        r#"
[global.config]
  as        = {as_number}
  router-id = "1.0.0.1"

[[peer-groups]]
  [peer-groups.config]
    peer-group-name = "pathvector-peers"
    peer-as         = 65002
  [peer-groups.timers.config]
    hold-time          = 9
    keepalive-interval = 3
  [peer-groups.transport.config]
    passive-mode = true

  # RFC 4724: enable graceful restart so GoBGP sends End-of-RIB markers
  # after its initial table dump.  pathvectord parses but defers the stale-
  # route timer; enabling this on GoBGP's side is harmless for all tests.
  [peer-groups.graceful-restart.config]
    enabled      = true
    restart-time = 120

  [[peer-groups.afi-safis]]
    [peer-groups.afi-safis.config]
      afi-safi-name = "ipv4-unicast"

  [[peer-groups.afi-safis]]
    [peer-groups.afi-safis.config]
      afi-safi-name = "ipv6-unicast"

[[dynamic-neighbors]]
  [dynamic-neighbors.config]
    prefix     = "0.0.0.0/0"
    peer-group = "pathvector-peers"
"#
    )
    .expect("write gobgp config with custom AS");
    f
}

/// Like [`write_gobgp_config`] but with a configurable `restart-time`.
///
/// Use a short `restart_secs` (e.g. `10`) for Phase 2 tests so the GR window
/// expires quickly without waiting the full 120 s default.
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_gobgp_config_with_restart_time(restart_secs: u16) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp gobgp config");
    write!(
        f,
        r#"
[global.config]
  as        = 65001
  router-id = "1.0.0.1"

[[peer-groups]]
  [peer-groups.config]
    peer-group-name = "pathvector-peers"
    peer-as         = 65002
  [peer-groups.timers.config]
    hold-time          = 9
    keepalive-interval = 3
  [peer-groups.transport.config]
    passive-mode = true

  [peer-groups.graceful-restart.config]
    enabled      = true
    restart-time = {restart_secs}

  [[peer-groups.afi-safis]]
    [peer-groups.afi-safis.config]
      afi-safi-name = "ipv4-unicast"

  [[peer-groups.afi-safis]]
    [peer-groups.afi-safis.config]
      afi-safi-name = "ipv6-unicast"

[[dynamic-neighbors]]
  [dynamic-neighbors.config]
    prefix     = "0.0.0.0/0"
    peer-group = "pathvector-peers"
"#
    )
    .expect("write gobgp config");
    f
}

/// Like [`write_gobgp_config_with_restart_time`] but also sets
/// `notification-enabled = true` in the GracefulRestart config block.
///
/// This causes GoBGP to advertise the RFC 8538 N-bit (0x04) in its
/// `GracefulRestart` capability, enabling notification-mode GR on both sides
/// when pathvectord is also configured with `graceful_restart_time > 0`.
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_gobgp_config_with_notification_and_restart_time(restart_secs: u16) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp gobgp config");
    write!(
        f,
        r#"
[global.config]
  as        = 65001
  router-id = "1.0.0.1"

[[peer-groups]]
  [peer-groups.config]
    peer-group-name = "pathvector-peers"
    peer-as         = 65002
  [peer-groups.timers.config]
    hold-time          = 9
    keepalive-interval = 3
  [peer-groups.transport.config]
    passive-mode = true

  [peer-groups.graceful-restart.config]
    enabled              = true
    restart-time         = {restart_secs}
    notification-enabled = true

  [[peer-groups.afi-safis]]
    [peer-groups.afi-safis.config]
      afi-safi-name = "ipv4-unicast"

  [[peer-groups.afi-safis]]
    [peer-groups.afi-safis.config]
      afi-safi-name = "ipv6-unicast"

[[dynamic-neighbors]]
  [dynamic-neighbors.config]
    prefix     = "0.0.0.0/0"
    peer-group = "pathvector-peers"
"#
    )
    .expect("write gobgp config");
    f
}

/// Writes the gobgpd config for a **route-source** container (AS 65003).
///
/// This is used in two-peer outbound tests: the source announces prefixes to
/// pathvectord, which then propagates them to the sink (AS 65001).
fn write_gobgp_source_config() -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp gobgp source config");
    write!(
        f,
        r#"
[global.config]
  as        = 65003
  router-id = "1.0.0.3"

[[peer-groups]]
  [peer-groups.config]
    peer-group-name = "pathvector-peers"
    peer-as         = 65002
  [peer-groups.timers.config]
    hold-time          = 9
    keepalive-interval = 3
  [peer-groups.transport.config]
    passive-mode = true

[[dynamic-neighbors]]
  [dynamic-neighbors.config]
    prefix     = "0.0.0.0/0"
    peer-group = "pathvector-peers"
"#
    )
    .expect("write gobgp source config");
    f
}

/// Writes the pathvectord config file for the test container.
///
/// `peers` is a list of `(address, remote_as)` pairs for every BGP peer
/// pathvectord should dial.  Every peer gets `import_default = "accept"` and
/// `export_default = "accept"` so that routes flow freely in both directions.
/// Use [`write_daemon_config_no_policy`] or [`write_daemon_config_import_only`]
/// when testing RFC 8212 default-reject semantics.
fn write_daemon_config(peers: &[(Ipv4Addr, u32)]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord config");
    write!(
        f,
        r#"
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
hold_time = 9
grpc_port = {PATHVECTORD_GRPC_PORT}
"#
    )
    .expect("write pathvectord config header");

    for (ip, remote_as) in peers {
        write!(
            f,
            r#"
[[peers]]
address        = "{ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {remote_as}
import_default = "accept"
export_default = "accept"
"#
        )
        .expect("write pathvectord peer config");
    }
    f
}

/// Writes a pathvectord config with `metrics_port` set, for
/// [`MetricsHarness`]. Otherwise identical to [`write_daemon_config`].
fn write_daemon_config_with_metrics(peers: &[(Ipv4Addr, u32)]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord config");
    write!(
        f,
        r#"
[daemon]
local_as     = 65002
bgp_id       = "10.0.0.2"
hold_time    = 9
grpc_port    = {PATHVECTORD_GRPC_PORT}
metrics_port = {PATHVECTORD_METRICS_PORT}
"#
    )
    .expect("write pathvectord config header");

    for (ip, remote_as) in peers {
        write!(
            f,
            r#"
[[peers]]
address        = "{ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {remote_as}
import_default = "accept"
export_default = "accept"
"#
        )
        .expect("write pathvectord peer config");
    }
    f
}

/// Writes a pathvectord config with `[daemon.rpki]` pointed at `rpki_host`
/// (the mock RTR server's container IP), for [`RpkiHarness`]. `reject_invalid`
/// defaults to `true` — exactly the behavior under test. Otherwise identical
/// to [`write_daemon_config`].
fn write_daemon_config_rpki(peers: &[(Ipv4Addr, u32)], rpki_host: Ipv4Addr) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord config");
    write!(
        f,
        r#"
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
hold_time = 9
grpc_port = {PATHVECTORD_GRPC_PORT}

[daemon.rpki]
host = "{rpki_host}"
port = {MOCK_RTR_PORT}
"#
    )
    .expect("write pathvectord config header");

    for (ip, remote_as) in peers {
        write!(
            f,
            r#"
[[peers]]
address        = "{ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {remote_as}
import_default = "accept"
export_default = "accept"
"#
        )
        .expect("write pathvectord peer config");
    }
    f
}

/// Writes a pathvectord config with `role = "provider"` on the single
/// configured peer, for [`RoleHarness`]. The peer (the mock BGP peer
/// container) is thus treated as our Customer — RFC 9234 §5 ingress leak
/// detection applies. Otherwise identical to [`write_daemon_config`].
fn write_daemon_config_role(peer_ip: Ipv4Addr, peer_as: u32) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord config");
    write!(
        f,
        r#"
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
hold_time = 9
grpc_port = {PATHVECTORD_GRPC_PORT}

[[peers]]
address        = "{peer_ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {peer_as}
import_default = "accept"
export_default = "accept"
role           = "provider"
"#
    )
    .expect("write pathvectord config");
    f
}

/// Writes a pathvectord config with `local_ipv6` set for eBGP IPv6 next-hop
/// rewrite.  All other settings are identical to [`write_daemon_config`].
fn write_daemon_config_v6(peers: &[(Ipv4Addr, u32)]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord config");
    write!(
        f,
        r#"
[daemon]
local_as   = 65002
bgp_id     = "10.0.0.2"
local_ipv6 = "2001:db8::2"
hold_time  = 9
grpc_port  = {PATHVECTORD_GRPC_PORT}
"#
    )
    .expect("write pathvectord config header");

    for (ip, remote_as) in peers {
        write!(
            f,
            r#"
[[peers]]
address        = "{ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {remote_as}
import_default = "accept"
export_default = "accept"
"#
        )
        .expect("write pathvectord peer config");
    }
    f
}

/// Writes a pathvectord config whose peer's `address` is itself an IPv6
/// literal — the peer's TCP transport address, not just an NLRI/next-hop
/// value carried over a v4 session (contrast with [`write_daemon_config_v6`]).
/// Used by [`Ipv6TransportHarness`] to prove pathvectord actually dials a BGP
/// session over IPv6.
fn write_daemon_config_v6_transport(peer: Ipv6Addr, remote_as: u32) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord v6-transport config");
    write!(
        f,
        r#"
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
hold_time = 9
grpc_port = {PATHVECTORD_GRPC_PORT}

[[peers]]
address        = "{peer}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {remote_as}
import_default = "accept"
export_default = "accept"
"#
    )
    .expect("write pathvectord v6-transport config");
    f
}

/// Writes a pathvectord config with **no** import or export policy on any peer.
///
/// For eBGP peers this activates the RFC 8212 defaults: both import and export
/// default to `Reject`.  No routes are accepted into the Loc-RIB and no routes
/// are advertised to peers unless an explicit policy term matches.
fn write_daemon_config_no_policy(peers: &[(Ipv4Addr, u32)]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord config");
    write!(
        f,
        r#"
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
hold_time = 9
grpc_port = {PATHVECTORD_GRPC_PORT}
"#
    )
    .expect("write pathvectord config header");

    for (ip, remote_as) in peers {
        write!(
            f,
            r#"
[[peers]]
address   = "{ip}"
port      = {GOBGPD_BGP_PORT}
remote_as = {remote_as}
"#
        )
        .expect("write pathvectord peer config");
    }
    f
}

/// Writes a pathvectord config with `import_default = "accept"` but **no**
/// `export_default` on any peer.
///
/// Routes are accepted into the Loc-RIB but not re-advertised to any peer:
/// for eBGP peers the RFC 8212 export default is `Reject`.
fn write_daemon_config_import_only(peers: &[(Ipv4Addr, u32)]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord config");
    write!(
        f,
        r#"
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
hold_time = 9
grpc_port = {PATHVECTORD_GRPC_PORT}
"#
    )
    .expect("write pathvectord config header");

    for (ip, remote_as) in peers {
        write!(
            f,
            r#"
[[peers]]
address        = "{ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {remote_as}
import_default = "accept"
"#
        )
        .expect("write pathvectord peer config");
    }
    f
}

/// Writes a pathvectord config where each peer accepts IPv4 but rejects IPv6.
///
/// `import_default = "accept"` / `import_default_v6 = "reject"` lets us test
/// that the two per-AFI defaults are independent: IPv4 routes from GoBGP are
/// installed while IPv6 routes are dropped at the import gate.
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_daemon_config_ipv4_accept_ipv6_reject(peers: &[(Ipv4Addr, u32)]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord config");
    write!(
        f,
        r#"
[daemon]
local_as   = 65002
bgp_id     = "10.0.0.2"
local_ipv6 = "2001:db8::2"
hold_time  = 9
grpc_port  = {PATHVECTORD_GRPC_PORT}
"#
    )
    .expect("write pathvectord config header");

    for (ip, remote_as) in peers {
        write!(
            f,
            r#"
[[peers]]
address           = "{ip}"
port              = {GOBGPD_BGP_PORT}
remote_as         = {remote_as}
import_default    = "accept"
import_default_v6 = "reject"
export_default    = "accept"
"#
        )
        .expect("write pathvectord per-peer config");
    }
    f
}

/// Writes a pathvectord config with `export_default = "reject"` and
/// `local_ipv6` set.
///
/// Regression coverage for the IPv6 export-policy fix (CHANGELOG.md
/// 2026-07-02): `propagate_prefix_v6` previously never consulted any export
/// policy at all, so `export_default = "reject"` correctly blocked IPv4
/// routes but had no effect on IPv6 routes. This config isolates the IPv6
/// export path so a real BGP session can prove the fix.
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_daemon_config_v6_export_reject(peers: &[(Ipv4Addr, u32)]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord v6-export-reject config");
    write!(
        f,
        r#"
[daemon]
local_as   = 65002
bgp_id     = "10.0.0.2"
local_ipv6 = "2001:db8::2"
hold_time  = 9
grpc_port  = {PATHVECTORD_GRPC_PORT}
"#
    )
    .expect("write pathvectord config header");

    for (ip, remote_as) in peers {
        write!(
            f,
            r#"
[[peers]]
address        = "{ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {remote_as}
import_default = "accept"
export_default = "reject"
"#
        )
        .expect("write pathvectord per-peer config");
    }
    f
}

/// Writes a GoBGP config with a **static neighbor** and TCP MD5 authentication.
///
/// Dynamic neighbors cannot be used with TCP MD5SIG: the Linux kernel requires
/// the key to be pre-installed on the listener for a specific peer IP before
/// the SYN arrives.  A static neighbor entry is the only correct approach.
///
/// The `pathvectord_ip` argument is the IP that pathvectord will dial from —
/// GoBGP configures `TCP_MD5SIG` on its listener for that address.
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_gobgp_config_md5(pathvectord_ip: &str, key: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp gobgp md5 config");
    write!(
        f,
        r#"
[global.config]
  as        = 65001
  router-id = "1.0.0.1"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "{pathvectord_ip}"
    peer-as          = 65002
    auth-password    = "{key}"
  [neighbors.timers.config]
    hold-time          = 9
    keepalive-interval = 3
  [neighbors.transport.config]
    passive-mode = true

  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-unicast"
"#
    )
    .expect("write gobgp md5 config");
    f
}

/// Writes a pathvectord config with `graceful_restart_time` set.
///
/// Identical to `write_daemon_config` but adds `graceful_restart_time` to the
/// `[daemon]` stanza so pathvectord advertises the GracefulRestart capability with
/// forwarding-preserved families.  Used to verify that upstream peers hold our
/// routes during the restart window (RFC 4724 §3 helper role).
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_daemon_config_gr(peers: &[(Ipv4Addr, u32)], restart_time: u16) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord GR config");
    write!(
        f,
        r#"
[daemon]
local_as              = 65002
bgp_id                = "10.0.0.2"
hold_time             = 9
grpc_port             = {PATHVECTORD_GRPC_PORT}
graceful_restart_time = {restart_time}
"#
    )
    .expect("write pathvectord GR config header");

    for (ip, remote_as) in peers {
        write!(
            f,
            r#"
[[peers]]
address        = "{ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {remote_as}
import_default = "accept"
export_default = "accept"
"#
        )
        .expect("write pathvectord GR peer config");
    }
    f
}

/// Writes a pathvectord config for [`GrIpv6ObserverHarness`]: two eBGP peers
/// (a GR-capable source and a plain observer) plus `local_ipv6` so IPv6 NLRI
/// can be exchanged with both.
///
/// Regression coverage for the `on_gr_deadline_expired` IPv6 fix
/// (CHANGELOG.md 2026-07-03): the source peer's restart window expiring
/// must produce a real BGP WITHDRAW to the observer peer, not just remove
/// the route from pathvectord's own Loc-RIB.
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_daemon_config_gr_v6_observer(
    source_ip: Ipv4Addr,
    source_as: u32,
    restart_time: u16,
    observer_ip: Ipv4Addr,
    observer_as: u32,
) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord GR v6 observer config");
    write!(
        f,
        r#"
[daemon]
local_as              = 65002
bgp_id                = "10.0.0.2"
local_ipv6            = "2001:db8::2"
hold_time             = 9
grpc_port             = {PATHVECTORD_GRPC_PORT}
graceful_restart_time = {restart_time}

[[peers]]
address        = "{source_ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {source_as}
import_default = "accept"
export_default = "accept"

[[peers]]
address        = "{observer_ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {observer_as}
import_default = "accept"
export_default = "accept"
"#
    )
    .expect("write pathvectord GR v6 observer config");
    f
}

/// Writes a pathvectord config with `connect_retry_time` set per-peer.
///
/// Identical to `write_daemon_config` except each peer has a
/// `connect_retry_time` override.  Use a short value (e.g. `2`) in tests that
/// kill and restart a peer and need pathvectord to reconnect quickly rather
/// than waiting the RFC-default 120 s.
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_daemon_config_fast_retry(
    peers: &[(Ipv4Addr, u32)],
    connect_retry_secs: u16,
) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord fast-retry config");
    write!(
        f,
        r#"
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
hold_time = 9
grpc_port = {PATHVECTORD_GRPC_PORT}
"#
    )
    .expect("write pathvectord fast-retry config header");

    for (ip, remote_as) in peers {
        write!(
            f,
            r#"
[[peers]]
address             = "{ip}"
port                = {GOBGPD_BGP_PORT}
remote_as           = {remote_as}
import_default      = "accept"
export_default      = "accept"
connect_retry_time  = {connect_retry_secs}
"#
        )
        .expect("write pathvectord fast-retry peer config");
    }
    f
}

/// Writes a pathvectord config with `graceful_restart_time` and `restarting = true`.
///
/// Identical to [`write_daemon_config_gr`] but also sets `restarting = true` so
/// pathvectord sets the RFC 4724 §3 Restart State (R) bit in the initial OPEN.
/// Used to verify that the R-bit is encoded and visible to the peer.
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_daemon_config_gr_restarting(
    peers: &[(Ipv4Addr, u32)],
    restart_time: u16,
) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord GR restarting config");
    write!(
        f,
        r#"
[daemon]
local_as              = 65002
bgp_id                = "10.0.0.2"
hold_time             = 9
grpc_port             = {PATHVECTORD_GRPC_PORT}
graceful_restart_time = {restart_time}
restarting            = true
"#
    )
    .expect("write pathvectord GR restarting config header");

    for (ip, remote_as) in peers {
        write!(
            f,
            r#"
[[peers]]
address        = "{ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {remote_as}
import_default = "accept"
export_default = "accept"
"#
        )
        .expect("write pathvectord GR restarting peer config");
    }
    f
}

/// Writes a pathvectord config with TCP MD5 authentication on every peer.
///
/// Identical to `write_daemon_config` but adds `md5_password = "<key>"`
/// to each peer stanza so pathvectord's outbound socket is keyed before
/// `connect()`.
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_daemon_config_md5(peers: &[(Ipv4Addr, u32)], key: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord md5 config");
    write!(
        f,
        r#"
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
hold_time = 9
grpc_port = {PATHVECTORD_GRPC_PORT}
"#
    )
    .expect("write pathvectord md5 config header");

    for (ip, remote_as) in peers {
        write!(
            f,
            r#"
[[peers]]
address        = "{ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {remote_as}
import_default = "accept"
export_default = "accept"
md5_password   = "{key}"
"#
        )
        .expect("write pathvectord md5 peer config");
    }
    f
}

// ── Low-level container helpers (CLI-based) ───────────────────────────────────

/// Start a Docker container via the CLI and return its container ID.
///
/// This is the escape hatch for features testcontainers does not expose:
/// `--ip` for fixed IP assignment and `--cap-add` for Linux capabilities.
/// Both are required for TCP MD5SIG tests.
///
/// # Panics
///
/// Panics if `docker run` exits non-zero.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn docker_start(
    name: &str,
    image: &str,
    network: &str,
    ip: Option<&str>,
    cap_net_admin: bool,
    volume_src: &str,
    volume_dst: &str,
    host_grpc_port: Option<u16>,
    cmd: Option<&str>,
) -> ContainerGuard {
    docker_start_with_caps(
        name,
        image,
        network,
        ip,
        cap_net_admin,
        false,
        volume_src,
        volume_dst,
        host_grpc_port,
        cmd,
    )
}

/// Like [`docker_start`] but with an optional `--privileged` flag for
/// containers that require capabilities beyond `CAP_NET_ADMIN` (e.g. FRR's
/// bgpd requires `CAP_SYS_ADMIN` for netlink operations on Linux).
///
/// # Panics
///
/// Panics if `docker run` exits non-zero.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn docker_start_with_caps(
    name: &str,
    image: &str,
    network: &str,
    ip: Option<&str>,
    cap_net_admin: bool,
    privileged: bool,
    volume_src: &str,
    volume_dst: &str,
    host_grpc_port: Option<u16>,
    cmd: Option<&str>,
) -> ContainerGuard {
    let mut args: Vec<String> = vec![
        "run".into(),
        "--detach".into(),
        format!("--name={name}"),
        format!("--network={network}"),
    ];
    if let Some(fixed_ip) = ip {
        args.push(format!("--ip={fixed_ip}"));
    }
    if cap_net_admin {
        args.push("--cap-add=NET_ADMIN".into());
    }
    if privileged {
        args.push("--privileged".into());
    }
    args.push(format!("--volume={volume_src}:{volume_dst}"));
    if let Some(host_port) = host_grpc_port {
        args.push(format!("--publish={host_port}:{PATHVECTORD_GRPC_PORT}"));
    }
    args.push(format!("{image}:latest"));
    if let Some(c) = cmd {
        args.push(c.into());
    }

    let output = Command::new("docker")
        .args(&args)
        .output()
        .expect("docker run");
    assert!(
        output.status.success(),
        "docker run {image} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let id = std::str::from_utf8(&output.stdout)
        .expect("docker run output is UTF-8")
        .trim()
        .to_owned();
    ContainerGuard(id)
}

/// Like [`docker_start`] but also publishes pathvectord's metrics port to the
/// host, for [`MetricsHarness`]. Kept as a separate function rather than
/// widening [`docker_start_with_caps`]'s already-long parameter list.
///
/// # Panics
///
/// Panics if `docker run` exits non-zero.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn docker_start_with_metrics(
    name: &str,
    image: &str,
    network: &str,
    volume_src: &str,
    volume_dst: &str,
    host_grpc_port: u16,
    host_metrics_port: u16,
    cmd: &str,
) -> ContainerGuard {
    let args: Vec<String> = vec![
        "run".into(),
        "--detach".into(),
        format!("--name={name}"),
        format!("--network={network}"),
        format!("--volume={volume_src}:{volume_dst}"),
        format!("--publish={host_grpc_port}:{PATHVECTORD_GRPC_PORT}"),
        format!("--publish={host_metrics_port}:{PATHVECTORD_METRICS_PORT}"),
        format!("{image}:latest"),
        cmd.into(),
    ];

    let output = Command::new("docker")
        .args(&args)
        .output()
        .expect("docker run");
    assert!(
        output.status.success(),
        "docker run {image} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let id = std::str::from_utf8(&output.stdout)
        .expect("docker run output is UTF-8")
        .trim()
        .to_owned();
    ContainerGuard(id)
}

/// Block (synchronously, with short sleeps) until the container's Docker
/// HEALTHCHECK reports `healthy`, or panic if `timeout` expires.
///
/// This is a blocking poll — acceptable in tests where the startup path is
/// already sequential and the wait is at most a few seconds.
///
/// # Panics
///
/// Panics if `docker inspect` fails or `timeout` expires before the container
/// reports `healthy`.
pub fn wait_container_healthy(container_id: &str, timeout: Duration) {
    use std::time::Instant;
    let deadline = Instant::now() + timeout;
    loop {
        let output = Command::new("docker")
            .args([
                "inspect",
                "--format",
                "{{.State.Health.Status}}",
                container_id,
            ])
            .output()
            .expect("docker inspect");
        let status = std::str::from_utf8(&output.stdout)
            .unwrap_or("")
            .trim()
            .to_owned();
        if status == "healthy" {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "container {container_id} did not become healthy within {timeout:?} (last status: {status:?})"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

// ── Md5Harness ────────────────────────────────────────────────────────────────

/// Per-test subnet and fixed container IPs for TCP MD5SIG tests, keyed by
/// `test_id` — both IPs must be known before either container starts (a
/// prerequisite for pre-configuring `TCP_MD5SIG` on both sides), but they
/// still need to vary per test/process the same way `bird_test_subnet` and
/// `fib_test_subnet` do. A shared, un-keyed constant here meant any two
/// concurrently-running MD5 tests (or an MD5 test overlapping with another
/// family sharing the same subnet range) would collide creating the Docker
/// network. Uses its own `172.29.x.x` range, distinct from `fib_test_subnet`
/// (172.30) and `bird_test_subnet` (172.31).
#[must_use]
pub fn md5_test_subnet(test_id: u32) -> String {
    let third = test_id % 256;
    format!("172.29.{third}.0/24")
}

#[must_use]
pub fn md5_gobgp_ip(test_id: u32) -> String {
    let third = test_id % 256;
    format!("172.29.{third}.10")
}

#[must_use]
pub fn md5_pathvectord_ip(test_id: u32) -> String {
    let third = test_id % 256;
    format!("172.29.{third}.20")
}

/// A test environment for RFC 2385 TCP MD5 authentication tests.
///
/// Uses a Docker subnet with **fixed container IPs** and grants `CAP_NET_ADMIN`
/// to both containers so the Linux kernel accepts the `setsockopt(TCP_MD5SIG)`
/// calls.  GoBGP is configured with a static neighbor (not dynamic) because
/// `TCP_MD5SIG` requires knowing the peer IP before the SYN arrives.
///
/// # Panics
///
/// [`Md5Harness::new`] panics if Docker is not running, either image is
/// missing, or the BGP session does not reach `Established` within 30 seconds.
pub struct Md5Harness {
    // Containers must drop before the network.
    _gobgpd: ContainerGuard,
    _pathvectord: ContainerGuard,
    _gobgpd_config: NamedTempFile,
    _pathvectord_config: NamedTempFile,
    pub client: PathvectorClient,
    /// The GoBGP container's IP on the shared network.
    pub gobgp_ip: Ipv4Addr,
    _network: DockerNetwork,
}

impl Md5Harness {
    /// Stand up both containers with the same MD5 key and wait for the session.
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new(key: &str) -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();
        let network_name = format!("pathvector-md5-test-{test_id}");
        let subnet = md5_test_subnet(test_id);
        let gobgp_ip_str = md5_gobgp_ip(test_id);
        let pathvectord_ip_str = md5_pathvectord_ip(test_id);

        let network = DockerNetwork::create_with_subnet(network_name.clone(), &subnet);

        // Both IPs are known before either container starts — write configs now.
        let gobgpd_config = write_gobgp_config_md5(&pathvectord_ip_str, key);
        let gobgpd_config_path = gobgpd_config.path().to_str().unwrap().to_owned();

        let pathvectord_config =
            write_daemon_config_md5(&[(gobgp_ip_str.parse().unwrap(), 65001)], key);
        let pathvectord_config_path = pathvectord_config.path().to_str().unwrap().to_owned();

        // Start GoBGP with a fixed IP and CAP_NET_ADMIN (needed for TCP_MD5SIG
        // on the listener socket).
        let gobgpd = docker_start(
            &format!("gobgpd-md5-{test_id}"),
            GOBGPD_IMAGE,
            &network_name,
            Some(&gobgp_ip_str),
            true,
            &gobgpd_config_path,
            "/etc/gobgp/gobgpd.conf",
            None,
            None,
        );

        // Wait for GoBGP's HEALTHCHECK before starting pathvectord — the MD5
        // key must be installed on the listener before pathvectord's SYN arrives.
        wait_container_healthy(&gobgpd.0, Duration::from_secs(30));

        // Start pathvectord with a fixed IP and CAP_NET_ADMIN (needed for
        // TCP_MD5SIG on the outbound socket before connect()).
        let pathvectord = docker_start(
            &format!("pathvectord-md5-{test_id}"),
            PATHVECTORD_IMAGE,
            &network_name,
            Some(&pathvectord_ip_str),
            true,
            &pathvectord_config_path,
            "/etc/pathvectord.toml",
            Some(grpc_host_port),
            Some("/etc/pathvectord.toml"),
        );

        let mut client = PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("connect PathvectorClient for Md5Harness");

        let gobgp_ip: Ipv4Addr = gobgp_ip_str.parse().unwrap();
        wait_for_established(&mut client, gobgp_ip, Duration::from_secs(30))
            .await
            .expect("MD5-authenticated BGP session did not reach Established within 30 s");

        Self {
            _gobgpd: gobgpd,
            _pathvectord: pathvectord,
            _gobgpd_config: gobgpd_config,
            _pathvectord_config: pathvectord_config,
            client,
            gobgp_ip,
            _network: network,
        }
    }
}

// ── FibHarness ───────────────────────────────────────────────────────────────

/// Per-test subnet for FIB integration tests. Uses the third octet to avoid
/// subnet collisions when tests run in parallel.
#[must_use]
pub fn fib_test_subnet(test_id: u32) -> String {
    let third = test_id % 256;
    format!("172.30.{third}.0/24")
}

#[must_use]
pub fn fib_pathvectord_ip(test_id: u32) -> String {
    let third = test_id % 256;
    format!("172.30.{third}.2")
}

#[must_use]
pub fn fib_gobgp_ip(test_id: u32) -> String {
    let third = test_id % 256;
    format!("172.30.{third}.3")
}

/// Test harness for FIB integration tests.
///
/// Starts pathvectord with `CAP_NET_ADMIN` so `FibWriter` can issue
/// `RTM_NEWROUTE` / `RTM_DELROUTE` via netlink. Uses fixed container IPs on a
/// dedicated subnet so the GoBGP peer address is known before either container
/// starts (required for fixed-IP routing).
///
/// # Panics
///
/// [`FibHarness::new`] panics if Docker is not running, either image is
/// missing, or the BGP session does not reach `Established` within 30 seconds.
pub struct FibHarness {
    _gobgpd: ContainerGuard,
    _pathvectord: ContainerGuard,
    _gobgpd_config: NamedTempFile,
    _pathvectord_config: NamedTempFile,
    pub client: PathvectorClient,
    /// GoBGP container ID — used for `gobgp_announce` / `gobgp_withdraw`.
    pub gobgpd_id: String,
    /// pathvectord container ID — used for `ip route` inspection.
    pub pathvectord_id: String,
    pub gobgp_ip: Ipv4Addr,
    _network: DockerNetwork,
}

impl FibHarness {
    /// Stand up GoBGP + pathvectord with `CAP_NET_ADMIN` and wait for the
    /// BGP session to reach `Established`.
    ///
    /// # Panics
    ///
    /// Panics if Docker is not running, either image is missing, or the BGP
    /// session does not reach `Established` within 30 seconds.
    pub async fn new() -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();
        let network_name = format!("pathvector-fib-test-{test_id}");

        let subnet = fib_test_subnet(test_id);
        let gobgp_ip_str = fib_gobgp_ip(test_id);
        let pathvectord_ip_str = fib_pathvectord_ip(test_id);

        let network = DockerNetwork::create_with_subnet(network_name.clone(), &subnet);

        let gobgp_ip: Ipv4Addr = gobgp_ip_str.parse().unwrap();

        let gobgpd_config = write_gobgp_config();
        let gobgpd_config_path = gobgpd_config.path().to_str().unwrap().to_owned();

        let pathvectord_config = write_daemon_config(&[(gobgp_ip, 65001)]);
        let pathvectord_config_path = pathvectord_config.path().to_str().unwrap().to_owned();

        let gobgpd = docker_start(
            &format!("gobgpd-fib-{test_id}"),
            GOBGPD_IMAGE,
            &network_name,
            Some(&gobgp_ip_str),
            false,
            &gobgpd_config_path,
            "/etc/gobgp/gobgpd.conf",
            None,
            None,
        );

        wait_container_healthy(&gobgpd.0, Duration::from_secs(30));

        // CAP_NET_ADMIN is required for FibWriter to issue RTM_NEWROUTE via netlink.
        let pathvectord = docker_start(
            &format!("pathvectord-fib-{test_id}"),
            PATHVECTORD_IMAGE,
            &network_name,
            Some(&pathvectord_ip_str),
            true,
            &pathvectord_config_path,
            "/etc/pathvectord.toml",
            Some(grpc_host_port),
            Some("/etc/pathvectord.toml"),
        );

        let gobgpd_id = gobgpd.0.clone();
        let pathvectord_id = pathvectord.0.clone();

        let mut client = PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("connect PathvectorClient for FibHarness");

        wait_for_established(&mut client, gobgp_ip, Duration::from_secs(30))
            .await
            .expect("BGP session did not reach Established within 30 s");

        Self {
            _gobgpd: gobgpd,
            _pathvectord: pathvectord,
            _gobgpd_config: gobgpd_config,
            _pathvectord_config: pathvectord_config,
            client,
            gobgpd_id,
            pathvectord_id,
            gobgp_ip,
            _network: network,
        }
    }

    /// Announce a prefix from GoBGP into pathvectord's RIB.
    ///
    /// # Panics
    ///
    /// Panics if `docker exec gobgp` fails or returns a non-zero exit status.
    pub fn gobgp_announce(&self, prefix: &str, nexthop: &str) {
        let status = Command::new("docker")
            .args(["exec", &self.gobgpd_id])
            .args([
                "gobgp", "global", "rib", "add", prefix, "nexthop", nexthop, "origin", "igp",
            ])
            .status()
            .expect("docker exec gobgp announce");
        assert!(status.success(), "gobgp announce {prefix} failed: {status}");
    }

    /// Withdraw a prefix from GoBGP's RIB.
    ///
    /// # Panics
    ///
    /// Panics if `docker exec gobgp` fails or returns a non-zero exit status.
    pub fn gobgp_withdraw(&self, prefix: &str) {
        let status = Command::new("docker")
            .args(["exec", &self.gobgpd_id])
            .args(["gobgp", "global", "rib", "del", prefix])
            .status()
            .expect("docker exec gobgp withdraw");
        assert!(status.success(), "gobgp withdraw {prefix} failed: {status}");
    }

    /// Announce a prefix tagged with the BLACKHOLE community (65535:666,
    /// RFC 7999) from GoBGP so pathvectord receives a BLACKHOLE UPDATE.
    ///
    /// # Panics
    ///
    /// Panics if `docker exec gobgp` fails or returns a non-zero exit status.
    pub fn gobgp_announce_blackhole(&self, prefix: &str) {
        let status = Command::new("docker")
            .args(["exec", &self.gobgpd_id])
            .args([
                "gobgp",
                "global",
                "rib",
                "add",
                prefix,
                "nexthop",
                &self.gobgp_ip.to_string(),
                "origin",
                "igp",
                "community",
                "65535:666",
            ])
            .status()
            .expect("docker exec gobgp announce blackhole");
        assert!(
            status.success(),
            "gobgp announce blackhole {prefix} failed: {status}"
        );
    }
}

// ── MetricsHarness ───────────────────────────────────────────────────────────

/// Test harness for the Prometheus `/metrics` endpoint (`pathvectord/src/metrics.rs`).
///
/// Starts pathvectord with `metrics_port` configured and publishes both the
/// gRPC and metrics ports to the host, so tests can assert on the *actual*
/// rendered Prometheus output — not just on the internal `metrics` crate
/// calls (which are covered separately by unit tests in
/// `pathvectord/src/metrics.rs`). This is what proves the event-loop hooks in
/// `daemon/mod.rs` (`on_session_established`, `on_route_update`, etc.) are
/// correctly wired, not just correct in isolation.
///
/// # Panics
///
/// [`MetricsHarness::new`] panics if Docker is not running, either image is
/// missing, or the BGP session does not reach `Established` within 30 seconds.
pub struct MetricsHarness {
    _gobgpd: ContainerGuard,
    _pathvectord: ContainerGuard,
    _gobgpd_config: NamedTempFile,
    _pathvectord_config: NamedTempFile,
    pub client: PathvectorClient,
    /// GoBGP container ID — used by `gobgp_announce`.
    pub gobgpd_id: String,
    /// IP address that gobgpd appears as to pathvectord on the shared network.
    pub gobgp_ip: Ipv4Addr,
    /// Host-mapped port for pathvectord's `/metrics` endpoint.
    pub metrics_host_port: u16,
    _network: DockerNetwork,
}

impl MetricsHarness {
    /// Stand up GoBGP + pathvectord (metrics enabled) and wait for the BGP
    /// session to reach `Established`.
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new() -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();
        let metrics_host_port = alloc_metrics_port();
        let network_name = format!("pathvector-metrics-test-{test_id}");

        let network = DockerNetwork::create(network_name.clone());

        let gobgpd_config = write_gobgp_config();
        let gobgpd_config_path = gobgpd_config.path().to_str().unwrap().to_owned();

        let gobgpd = docker_start(
            &format!("gobgpd-metrics-{test_id}"),
            GOBGPD_IMAGE,
            &network_name,
            None,
            false,
            &gobgpd_config_path,
            "/etc/gobgp/gobgpd.conf",
            None,
            None,
        );

        wait_container_healthy(&gobgpd.0, Duration::from_secs(30));

        let gobgpd_id = gobgpd.0.clone();
        let gobgp_ip = container_network_ip(&gobgpd_id, &network_name);

        let pathvectord_config = write_daemon_config_with_metrics(&[(gobgp_ip, 65001)]);
        let pathvectord_config_path = pathvectord_config.path().to_str().unwrap().to_owned();

        let pathvectord = docker_start_with_metrics(
            &format!("pathvectord-metrics-{test_id}"),
            PATHVECTORD_IMAGE,
            &network_name,
            &pathvectord_config_path,
            "/etc/pathvectord.toml",
            grpc_host_port,
            metrics_host_port,
            "/etc/pathvectord.toml",
        );

        let mut client = PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("connect PathvectorClient for MetricsHarness");

        wait_for_established(&mut client, gobgp_ip, Duration::from_secs(30))
            .await
            .expect("BGP session did not reach Established within 30 s");

        Self {
            _gobgpd: gobgpd,
            _pathvectord: pathvectord,
            _gobgpd_config: gobgpd_config,
            _pathvectord_config: pathvectord_config,
            client,
            gobgpd_id,
            gobgp_ip,
            metrics_host_port,
            _network: network,
        }
    }

    /// Announce a prefix from GoBGP into pathvectord's RIB.
    ///
    /// # Panics
    ///
    /// Panics if `docker exec gobgp` fails or returns a non-zero exit status.
    pub fn gobgp_announce(&self, prefix: &str, nexthop: &str) {
        let status = Command::new("docker")
            .args(["exec", &self.gobgpd_id])
            .args([
                "gobgp", "global", "rib", "add", prefix, "nexthop", nexthop, "origin", "igp",
            ])
            .status()
            .expect("docker exec gobgp announce");
        assert!(status.success(), "gobgp announce {prefix} failed: {status}");
    }
}

/// Stands up GoBGP + a mock RTR server + pathvectord (`[daemon.rpki]`
/// configured, default `reject_invalid = true`) and waits for both the BGP
/// session and the RTR sync to complete.
///
/// The mock RTR server ([`MOCK_RTR_IMAGE`], built from
/// `Dockerfile.mock-rtr`) serves a fixed, deterministic pair of ROAs over
/// the real RFC 8210 wire protocol — see `src/bin/mock_rtr_server.rs` for
/// the exact scenario. This proves pathvectord actually rejects an Invalid
/// route delivered over a real BGP session, not just that `pathvector rpki
/// validate` reports `INVALID` in isolation (which the mock-server-free
/// unit tests in `pathvectord`/`pathvector-policy` already cover).
///
/// A dedicated struct rather than another `Harness` constructor: `Harness`'s
/// shared constructors all funnel through `new_inner_with_gobgp_config`,
/// whose `make_cfg` closure signature has no way to carry the mock RTR
/// server's discovered IP — mirrors [`MetricsHarness`]'s existing precedent
/// of a separate struct for a scenario with a different container topology.
pub struct RpkiHarness {
    _gobgpd: ContainerAsync<GenericImage>,
    _mock_rtr: ContainerAsync<GenericImage>,
    _pathvectord: ContainerAsync<GenericImage>,
    pub gobgpd_id: String,
    _gobgpd_config: NamedTempFile,
    _pathvectord_config: NamedTempFile,
    pub client: PathvectorClient,
    pub peer: Ipv4Addr,
    _network: DockerNetwork,
}

impl RpkiHarness {
    /// # Panics
    ///
    /// Panics if any container fails to start, the BGP session doesn't
    /// reach `Established` within 30s, or the RTR sync doesn't complete
    /// within 15s.
    pub async fn new() -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();

        let network_name = format!("pathvector-rpki-test-{test_id}");
        let subnet = format!("10.{}.{}.0/24", (test_id >> 8) & 0xff, test_id & 0xff);
        let network = DockerNetwork::create_with_subnet(network_name.clone(), &subnet);

        let gobgpd_config = write_gobgp_config();
        let gobgpd_config_path = gobgpd_config.path().to_str().unwrap().to_owned();

        let gobgpd = GenericImage::new(GOBGPD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_network(&network_name)
            .with_container_name(format!("gobgpd-rpki-{test_id}"))
            .with_mount(Mount::bind_mount(
                gobgpd_config_path,
                "/etc/gobgp/gobgpd.conf",
            ))
            .start()
            .await
            .expect("start gobgpd container");
        let gobgpd_id = gobgpd.id().to_owned();
        let gobgpd_ip = container_network_ip(&gobgpd_id, &network_name);

        let mock_rtr = GenericImage::new(MOCK_RTR_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_network(&network_name)
            .with_container_name(format!("mock-rtr-{test_id}"))
            .start()
            .await
            .expect("start mock RTR server container");
        let mock_rtr_id = mock_rtr.id().to_owned();
        let mock_rtr_ip = container_network_ip(&mock_rtr_id, &network_name);

        let pathvectord_config = write_daemon_config_rpki(&[(gobgpd_ip, 65001)], mock_rtr_ip);
        let pathvectord_config_path = pathvectord_config.path().to_str().unwrap().to_owned();

        let pathvectord = GenericImage::new(PATHVECTORD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_cmd(["/etc/pathvectord.toml"])
            .with_network(&network_name)
            .with_container_name(format!("pathvectord-rpki-{test_id}"))
            .with_mapped_port(grpc_host_port, ContainerPort::Tcp(PATHVECTORD_GRPC_PORT))
            .with_mount(Mount::bind_mount(
                pathvectord_config_path,
                "/etc/pathvectord.toml",
            ))
            .start()
            .await
            .expect("start pathvectord container");

        let mut client = PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("connect PathvectorClient for RpkiHarness");

        wait_for_established(&mut client, gobgpd_ip, Duration::from_secs(30))
            .await
            .expect("BGP session did not reach Established within 30 s");
        wait_for_rpki_synced(&mut client, Duration::from_secs(15))
            .await
            .expect("RTR sync with the mock server did not complete within 15 s");

        Self {
            _gobgpd: gobgpd,
            _mock_rtr: mock_rtr,
            _pathvectord: pathvectord,
            gobgpd_id,
            _gobgpd_config: gobgpd_config,
            _pathvectord_config: pathvectord_config,
            client,
            peer: gobgpd_ip,
            _network: network,
        }
    }

    /// Announce a prefix from GoBGP into pathvectord's RIB.
    ///
    /// # Panics
    ///
    /// Panics if `docker exec gobgp` fails or returns a non-zero exit status.
    pub fn gobgp_announce(&self, prefix: &str, nexthop: &str) {
        let status = Command::new("docker")
            .args(["exec", &self.gobgpd_id])
            .args([
                "gobgp", "global", "rib", "add", prefix, "nexthop", nexthop, "origin", "igp",
            ])
            .status()
            .expect("docker exec gobgp announce");
        assert!(status.success(), "gobgp announce {prefix} failed: {status}");
    }
}

/// Harness for the RFC 9234 (BGP Role + `ONLY_TO_CUSTOMER`) route-leak
/// prevention e2e test — two containers, no `gobgpd`: pathvectord and a
/// custom mock BGP peer (see `src/bin/mock_bgp_peer.rs`) that speaks real
/// BGP and deliberately sends one leaked route and one clean route.
pub struct RoleHarness {
    _mock_peer: ContainerAsync<GenericImage>,
    _pathvectord: ContainerAsync<GenericImage>,
    _pathvectord_config: NamedTempFile,
    pub client: PathvectorClient,
    pub peer: Ipv4Addr,
    _network: DockerNetwork,
}

impl RoleHarness {
    /// # Panics
    ///
    /// Panics if either container fails to start, or the BGP session doesn't
    /// reach `Established` within 30s.
    pub async fn new() -> Self {
        const MOCK_PEER_AS: u32 = 65099;

        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();

        let network_name = format!("pathvector-role-test-{test_id}");
        let subnet = format!("10.{}.{}.0/24", (test_id >> 8) & 0xff, test_id & 0xff);
        let network = DockerNetwork::create_with_subnet(network_name.clone(), &subnet);

        let mock_peer = GenericImage::new(MOCK_BGP_PEER_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_network(&network_name)
            .with_container_name(format!("mock-bgp-peer-{test_id}"))
            .start()
            .await
            .expect("start mock BGP peer container");
        let mock_peer_id = mock_peer.id().to_owned();
        let mock_peer_ip = container_network_ip(&mock_peer_id, &network_name);

        let pathvectord_config = write_daemon_config_role(mock_peer_ip, MOCK_PEER_AS);
        let pathvectord_config_path = pathvectord_config.path().to_str().unwrap().to_owned();

        let pathvectord = GenericImage::new(PATHVECTORD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_cmd(["/etc/pathvectord.toml"])
            .with_network(&network_name)
            .with_container_name(format!("pathvectord-role-{test_id}"))
            .with_mapped_port(grpc_host_port, ContainerPort::Tcp(PATHVECTORD_GRPC_PORT))
            .with_mount(Mount::bind_mount(
                pathvectord_config_path,
                "/etc/pathvectord.toml",
            ))
            .start()
            .await
            .expect("start pathvectord container");

        let mut client = PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("connect PathvectorClient for RoleHarness");

        wait_for_established(&mut client, mock_peer_ip, Duration::from_secs(30))
            .await
            .expect("BGP session did not reach Established within 30 s");

        Self {
            _mock_peer: mock_peer,
            _pathvectord: pathvectord,
            _pathvectord_config: pathvectord_config,
            client,
            peer: mock_peer_ip,
            _network: network,
        }
    }
}

/// Polls until pathvectord reports its RTR session as connected and synced
/// (`roa_count > 0`).
///
/// # Errors
///
/// Returns `Err(String)` if `timeout` expires before the RTR sync completes.
pub async fn wait_for_rpki_synced(
    client: &mut PathvectorClient,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if tokio::time::Instant::now() > deadline {
            return Err("timed out waiting for RTR sync with the mock server".to_string());
        }
        if let Ok(status) = client.get_rpki_status().await
            && status.connected
            && status.roa_count > 0
        {
            return Ok(());
        }
    }
}

/// Fetches the Prometheus text-format response body from
/// `http://127.0.0.1:<port>/metrics`.
///
/// Uses a raw `std::net::TcpStream` HTTP/1.1 request rather than pulling in an
/// HTTP client crate — this is a single plaintext localhost GET in a test, not
/// production code.
///
/// # Panics
///
/// Panics if the connection fails or the response cannot be read as UTF-8.
#[must_use]
pub fn scrape_metrics_text(port: u16) -> String {
    use std::io::{Read, Write as _};

    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("connect to metrics endpoint on port {port}: {e}"));
    stream
        .write_all(
            format!("GET /metrics HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .expect("write metrics HTTP request");

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read metrics HTTP response");

    // Strip the HTTP headers — the caller only wants the Prometheus text body.
    response
        .split_once("\r\n\r\n")
        .map_or(response.as_str(), |(_headers, body)| body)
        .to_owned()
}

/// Polls [`scrape_metrics_text`] until `needle` appears in the response body,
/// or panics if `timeout` expires.
///
/// # Panics
///
/// Panics if `needle` does not appear within `timeout`.
pub async fn wait_for_metric(port: u16, needle: &str, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let body = scrape_metrics_text(port);
        if body.contains(needle) {
            return;
        }
        assert!(
            tokio::time::Instant::now() <= deadline,
            "timed out after {timeout:?} waiting for metric containing {needle:?}\n\
             full /metrics response:\n{body}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Polls `ip route show table 254 proto bgp` inside `container_id` until
/// `prefix` appears as a `blackhole` route.
///
/// The Linux kernel renders RTN_BLACKHOLE routes as:
/// `blackhole <prefix> proto bgp`
///
/// # Errors
///
/// Returns `Err(String)` if `timeout` expires before the blackhole route appears.
pub async fn wait_for_kernel_blackhole_route(
    container_id: &str,
    prefix: &str,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if tokio::time::Instant::now() > deadline {
            let full_table = Command::new("docker")
                .args(["exec", container_id, "ip", "route", "show", "table", "254"])
                .output()
                .map_or_else(
                    |e| format!("<ip route failed: {e}>"),
                    |o| String::from_utf8_lossy(&o.stdout).trim().to_owned(),
                );
            return Err(format!(
                "timed out waiting for kernel blackhole route {prefix} (proto bgp) in container {container_id}\nfull table:\n{full_table}"
            ));
        }
        let out = Command::new("docker")
            .args([
                "exec",
                container_id,
                "ip",
                "route",
                "show",
                "table",
                "254",
                "proto",
                "bgp",
            ])
            .output();
        if let Ok(out) = out {
            let text = String::from_utf8_lossy(&out.stdout);
            // The kernel renders RTN_BLACKHOLE as "blackhole <prefix> proto bgp"
            if text.contains("blackhole") && text.contains(prefix) {
                return Ok(());
            }
        }
    }
}

/// Polls `ip route show table 254 proto bgp` inside `container_id` until
/// `prefix` is absent.
///
/// Shared with both unicast and blackhole withdrawal assertions.
///
/// # Errors
///
/// Returns `Err(String)` if `timeout` expires before the prefix disappears.
pub async fn wait_for_kernel_blackhole_route_withdrawn(
    container_id: &str,
    prefix: &str,
    timeout: Duration,
) -> Result<(), String> {
    wait_for_kernel_route_withdrawn(container_id, prefix, timeout).await
}

/// Polls `ip route show table 254 proto bgp` inside `container_id` until
/// `prefix` appears.
///
/// # Errors
///
/// Returns `Err(String)` if `timeout` expires before the prefix appears.
pub async fn wait_for_kernel_route(
    container_id: &str,
    prefix: &str,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "timed out waiting for kernel route {prefix} (proto bgp) in container {container_id}"
            ));
        }
        let out = Command::new("docker")
            .args([
                "exec",
                container_id,
                "ip",
                "route",
                "show",
                "table",
                "254",
                "proto",
                "bgp",
            ])
            .output();
        if let Ok(out) = out {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.contains(prefix) {
                return Ok(());
            }
        }
    }
}

/// Polls `ip route show table 254 proto bgp` inside `container_id` until
/// `prefix` is absent.
///
/// # Errors
///
/// Returns `Err(String)` if `timeout` expires before the prefix disappears.
pub async fn wait_for_kernel_route_withdrawn(
    container_id: &str,
    prefix: &str,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if tokio::time::Instant::now() > deadline {
            let full_table = Command::new("docker")
                .args(["exec", container_id, "ip", "route", "show", "table", "254"])
                .output()
                .map_or_else(
                    |e| format!("<ip route failed: {e}>"),
                    |o| String::from_utf8_lossy(&o.stdout).trim().to_owned(),
                );

            let daemon_logs = Command::new("docker")
                .args(["logs", "--tail", "60", container_id])
                .output()
                .map_or_else(
                    |e| format!("<docker logs failed: {e}>"),
                    |o| {
                        let stdout = String::from_utf8_lossy(&o.stdout);
                        let stderr = String::from_utf8_lossy(&o.stderr);
                        format!("stdout:\n{stdout}\nstderr:\n{stderr}")
                    },
                );

            return Err(format!(
                "timed out waiting for kernel route {prefix} to be withdrawn in container {container_id}\n\
                 \n--- ip route show table 254 ---\n{full_table}\n\
                 \n--- daemon logs (last 60 lines) ---\n{daemon_logs}"
            ));
        }
        let out = Command::new("docker")
            .args([
                "exec",
                container_id,
                "ip",
                "route",
                "show",
                "table",
                "254",
                "proto",
                "bgp",
            ])
            .output();
        match out {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                if !text.contains(prefix) {
                    return Ok(());
                }
            }
            Err(_) => return Ok(()),
        }
    }
}

// ── Polling helpers ───────────────────────────────────────────────────────────

/// Polls until the BGP session with `peer` reaches `Established`.
///
/// Accepts either address family — `Ipv4Addr`/`Ipv6Addr`/`IpAddr` all
/// implement `Into<IpAddr>` — so this one function serves both IPv4-
/// transport tests and IPv6-transport tests without a separate helper.
///
/// Callers that treat a timeout as a test failure should call `.expect("…")`
/// on the return value.
///
/// # Errors
///
/// Returns `Err(String)` if `timeout` expires before the session reaches
/// `Established`.
pub async fn wait_for_established(
    client: &mut PathvectorClient,
    peer: impl Into<IpAddr>,
    timeout: Duration,
) -> Result<(), String> {
    let peer: IpAddr = peer.into();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "timed out waiting for BGP session to reach Established with {peer}"
            ));
        }
        if let Ok(p) = client.get_peer(peer).await
            && p.session_state == SessionState::Established
        {
            return Ok(());
        }
    }
}

/// Polls until the best route for `prefix` is present, then returns it.
///
/// Callers that treat a timeout as a test failure should call `.expect("…")`
/// on the return value.
///
/// # Errors
///
/// Returns `Err(String)` if `timeout` expires before the route appears in the
/// RIB.
pub async fn wait_for_route(
    client: &mut PathvectorClient,
    prefix: &str,
    timeout: Duration,
) -> Result<Route, String> {
    wait_for_route_with_diagnostics(client, prefix, timeout, None).await
}

/// Like [`wait_for_route`] but dumps the last 60 lines of `container_id`'s
/// stderr on timeout.  Use this for hard-to-diagnose e2e failures where the
/// daemon log is the only signal.
/// Like [`wait_for_route`] but dumps the last 80 lines of `container_id`'s
/// logs on timeout.  Use this for hard-to-diagnose e2e failures where the
/// daemon log is the only signal.
///
/// # Errors
///
/// Returns `Err(String)` if `timeout` expires before the route appears in the
/// RIB.
pub async fn wait_for_route_with_diagnostics(
    client: &mut PathvectorClient,
    prefix: &str,
    timeout: Duration,
    container_id: Option<&str>,
) -> Result<Route, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if tokio::time::Instant::now() > deadline {
            let diag = container_id.map(|id| {
                Command::new("docker")
                    .args(["logs", "--tail", "80", id])
                    .output()
                    .map_or_else(
                        |e| format!("<docker logs failed: {e}>"),
                        |o| {
                            let stdout = String::from_utf8_lossy(&o.stdout);
                            let stderr = String::from_utf8_lossy(&o.stderr);
                            format!("stdout:\n{stdout}\nstderr:\n{stderr}")
                        },
                    )
            });
            let msg = match diag {
                Some(logs) => format!(
                    "timed out waiting for route {prefix} to appear in RIB\n\n\
                     --- daemon logs (last 80 lines) ---\n{logs}"
                ),
                None => format!("timed out waiting for route {prefix} to appear in RIB"),
            };
            return Err(msg);
        }
        if let Ok(Some(route)) = client.get_best_route(prefix).await {
            return Ok(route);
        }
    }
}

/// Polls until the best route for `prefix` is absent (withdrawn).
///
/// Callers that treat a timeout as a test failure should call `.expect("…")`
/// on the return value.
///
/// # Errors
///
/// Returns `Err(String)` if `timeout` expires before the route is removed from
/// the RIB.
pub async fn wait_for_route_withdrawn(
    client: &mut PathvectorClient,
    prefix: &str,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "timed out waiting for route {prefix} to be withdrawn from RIB"
            ));
        }
        if let Ok(None) = client.get_best_route(prefix).await {
            return Ok(());
        }
    }
}

// ── Harness ───────────────────────────────────────────────────────────────────

/// A fully-wired test environment: isolated Docker network + `gobgpd`
/// container + `pathvectord` container + connected [`PathvectorClient`],
/// with the BGP session already `Established`.
///
/// All resources (containers, network) are cleaned up when `Harness` drops.
///
/// # Panics
///
/// [`Harness::new`] panics if:
/// - Docker is not running.
/// - Either image has not been built (run `just e2e`).
/// - The BGP session does not reach `Established` within 15 seconds.
pub struct Harness {
    // Containers must be dropped before the network.
    // Rust drops struct fields in declaration order (top to bottom), so
    // _gobgpd and _pathvectord drop first, then _network.
    _gobgpd: ContainerAsync<GenericImage>,
    _pathvectord: ContainerAsync<GenericImage>,
    /// Container ID of gobgpd — used by `gobgp_announce` / `gobgp_withdraw`
    /// and by `wait_for_gobgp_rib_entry` / `wait_for_gobgp_rib_withdrawn` in
    /// origination tests that inject routes from the pathvectord side.
    pub gobgpd_id: String,
    pub pathvectord_id: String,
    // Keep config files alive until the containers stop.
    _gobgpd_config: NamedTempFile,
    _pathvectord_config: NamedTempFile,
    pub client: PathvectorClient,
    /// IP address that gobgpd appears as to pathvectord (its container IP on
    /// the shared Docker network).  Used in tests that assert `route.peer_address`.
    pub peer: Ipv4Addr,
    /// IP address that pathvectord appears as to gobgpd (its container IP on
    /// the shared Docker network).  Used to query `gobgp neighbor <addr>` from
    /// inside the gobgpd container.
    pub pathvectord_ip: Ipv4Addr,
    /// Name of the isolated Docker bridge network for this test.  Exposed so
    /// tests can call `docker network disconnect/connect` to simulate link
    /// failures without stopping containers.
    pub network_name: String,
    // Dropped LAST so the network outlives the containers using it.
    _network: DockerNetwork,
}

impl Harness {
    /// Stand up the full environment and wait for the BGP session.
    ///
    /// pathvectord is configured with `import_default = "accept"` and
    /// `export_default = "accept"` on the GoBGP peer so that routes flow
    /// freely in both directions.
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new() -> Self {
        Self::new_inner(write_daemon_config).await
    }

    /// Same as [`Self::new`] but with `local_ipv6 = "2001:db8::2"` configured.
    ///
    /// Use this harness for IPv6 tests that require pathvectord to rewrite the
    /// NEXT_HOP in outbound MP_REACH_NLRI when advertising to an eBGP peer.
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new_v6() -> Self {
        Self::new_inner_v6(write_daemon_config_v6).await
    }

    /// Same as [`Self::new`] but with `import_default = "accept"` and
    /// `import_default_v6 = "reject"` on the peer.
    ///
    /// Use this harness to verify that the two per-AFI import defaults are
    /// independent: IPv4 routes from GoBGP are accepted into the Loc-RIB while
    /// IPv6 routes from the same peer are blocked at the import gate.
    ///
    /// `local_ipv6 = "2001:db8::2"` is included so the MP_REACH_NLRI next-hop
    /// rewrite works for outbound IPv6 advertisements (if any).
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new_v6_reject_policy() -> Self {
        Self::new_inner(write_daemon_config_ipv4_accept_ipv6_reject).await
    }

    /// Same as [`Self::new_v6`] but with `export_default = "reject"` on the peer.
    ///
    /// Regression coverage for the IPv6 export-policy fix (CHANGELOG.md
    /// 2026-07-02): use this harness to verify that `export_default = "reject"`
    /// actually blocks IPv6 route propagation over a real BGP session, not
    /// just at the unit-test level.
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new_v6_export_reject() -> Self {
        Self::new_inner_v6(write_daemon_config_v6_export_reject).await
    }

    /// Same as [`Self::new`] but with **no** import or export policy on the peer.
    ///
    /// For an eBGP peer this activates RFC 8212 defaults: both import and
    /// export default to `Reject`.  Use this harness to assert that routes
    /// are blocked when no policy explicitly permits them.
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new_rfc8212() -> Self {
        Self::new_inner(write_daemon_config_no_policy).await
    }

    /// Stand up pathvectord with `graceful_restart_time` set.
    ///
    /// Identical to [`Self::new`] except pathvectord advertises the
    /// GracefulRestart capability with `restart_time = restart_secs` and both
    /// IPv4/IPv6 unicast families marked `forwarding_preserved`.
    ///
    /// Use this harness for RFC 4724 §3 helper-role tests that verify the
    /// upstream peer holds our routes during a restart window.
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new_gr(restart_secs: u16) -> Self {
        Self::new_inner(move |peers| write_daemon_config_gr(peers, restart_secs)).await
    }

    /// Stand up pathvectord with `graceful_restart_time` set and `restarting = true`.
    ///
    /// Like [`Self::new_gr`] but also sets the RFC 4724 §3 Restart State (R) bit
    /// in the initial OPEN.  Use this to verify that GoBGP observes R=1 from us.
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new_gr_restarting(restart_secs: u16) -> Self {
        Self::new_inner(move |peers| write_daemon_config_gr_restarting(peers, restart_secs)).await
    }

    /// Stand up pathvectord with a GoBGP peer whose GR `restart-time` is set
    /// to `peer_restart_secs`.
    ///
    /// Pathvectord does **not** need its own `graceful_restart_time` configured
    /// for Phase 2 to work — only the peer's advertised capability matters.
    /// Use a short value (e.g. 10) so GR windows expire quickly in tests.
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new_gr_peer(peer_restart_secs: u16) -> Self {
        Self::new_inner_with_gobgp_config(
            move || write_gobgp_config_with_restart_time(peer_restart_secs),
            write_daemon_config,
        )
        .await
    }

    /// Like [`Self::new_gr_peer`] but pathvectord is also configured with a
    /// short `connect_retry_time` so it reconnects quickly after the peer
    /// disappears, rather than waiting the RFC-default 120 s.
    ///
    /// Use this for EOR-prune tests that simulate a peer restart: disconnect
    /// the peer from the network, mutate its RIB, reconnect, and wait for
    /// pathvectord to re-establish and process the EOR.
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new_gr_peer_fast_retry(peer_restart_secs: u16) -> Self {
        Self::new_inner_with_gobgp_config(
            move || write_gobgp_config_with_restart_time(peer_restart_secs),
            move |peers| write_daemon_config_fast_retry(peers, 2),
        )
        .await
    }

    /// Stand up a harness for RFC 8538 notification-mode GR testing.
    ///
    /// Both sides are configured with the N-bit:
    /// - GoBGP: `graceful-restart.enabled = true`, `notification-enabled = true`,
    ///   `restart-time = peer_restart_secs`
    /// - pathvectord: `graceful_restart_time = peer_restart_secs` (sets N-bit)
    ///
    /// Use a short `peer_restart_secs` (e.g. 10) so the GR window expires quickly
    /// in tests.  With this harness, `docker stop` (SIGTERM → CEASE NOTIFICATION)
    /// triggers a GR window instead of an immediate flush.
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new_rfc8538_gr(peer_restart_secs: u16) -> Self {
        Self::new_inner_with_gobgp_config(
            move || write_gobgp_config_with_notification_and_restart_time(peer_restart_secs),
            move |peers| write_daemon_config_gr(peers, peer_restart_secs),
        )
        .await
    }

    /// Disconnect the GoBGP container from the test network without stopping it.
    ///
    /// The TCP connection drops immediately, triggering an unclean termination
    /// in pathvectord.  The GoBGP process keeps running; its in-memory RIB is
    /// intact.  Call [`Self::reconnect_gobgp`] to restore network access with
    /// the same IP so pathvectord can reconnect.
    ///
    /// # Panics
    ///
    /// Panics if `docker network disconnect` fails.
    pub fn disconnect_gobgp(&self) {
        let status = Command::new("docker")
            .args(["network", "disconnect", &self.network_name, &self.gobgpd_id])
            .status()
            .expect("docker network disconnect gobgpd");
        assert!(
            status.success(),
            "docker network disconnect failed: {status}"
        );
    }

    /// Reconnect the GoBGP container to the test network with its original IP.
    ///
    /// Must be called after [`Self::disconnect_gobgp`].  Uses `--ip` to
    /// restore the same address, so pathvectord's peer config still matches.
    ///
    /// # Panics
    ///
    /// Panics if `docker network connect` fails.
    pub fn reconnect_gobgp(&self) {
        let status = Command::new("docker")
            .args([
                "network",
                "connect",
                "--ip",
                &self.peer.to_string(),
                &self.network_name,
                &self.gobgpd_id,
            ])
            .status()
            .expect("docker network connect gobgpd");
        assert!(status.success(), "docker network connect failed: {status}");
    }

    /// Internal constructor — spins up one GoBGP + one pathvectord container.
    ///
    /// `make_cfg` is the config-writing function (or closure) that produces the
    /// pathvectord TOML.  The caller chooses the policy / feature variant.
    async fn new_inner(make_cfg: impl Fn(&[(Ipv4Addr, u32)]) -> NamedTempFile) -> Self {
        Self::new_inner_with_gobgp_config(write_gobgp_config, make_cfg).await
    }

    /// Like [`new_inner`] but also accepts a `gobgpd_cfg_fn` for tests that
    /// need a non-default GoBGP configuration (e.g. a custom restart-time).
    async fn new_inner_with_gobgp_config(
        gobgpd_cfg_fn: impl Fn() -> NamedTempFile,
        make_cfg: impl Fn(&[(Ipv4Addr, u32)]) -> NamedTempFile,
    ) -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();

        // Create an isolated network for this test so containers from
        // different tests don't interfere.  Use an explicit subnet so that
        // `docker network connect --ip` works (Docker requires a user-configured
        // subnet for static IP assignment).
        let network_name = format!("pathvector-test-{test_id}");
        let subnet = format!("10.{}.{}.0/24", (test_id >> 8) & 0xff, test_id & 0xff);
        let network = DockerNetwork::create_with_subnet(network_name.clone(), &subnet);

        // Write gobgpd config.
        let gobgpd_config = gobgpd_cfg_fn();
        let gobgpd_config_path = gobgpd_config
            .path()
            .to_str()
            .expect("gobgpd config path is valid UTF-8")
            .to_owned();

        // Start gobgpd.  The HEALTHCHECK in the Dockerfile ensures `start()`
        // only returns once gobgpd's gRPC API is accepting connections.
        let gobgpd = GenericImage::new(GOBGPD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_network(&network_name)
            .with_container_name(format!("gobgpd-{test_id}"))
            .with_mount(Mount::bind_mount(
                gobgpd_config_path,
                "/etc/gobgp/gobgpd.conf",
            ))
            .start()
            .await
            .expect("start gobgpd container");

        let gobgpd_container_id = gobgpd.id().to_owned();

        // Discover gobgpd's IP on the shared network.  pathvectord's
        // PeerConfig.address is Ipv4Addr, so we need the real IP.
        let gobgpd_ip = container_network_ip(&gobgpd_container_id, &network_name);

        // Write pathvectord config referencing gobgpd's container IP.
        let pathvectord_config = make_cfg(&[(gobgpd_ip, 65001)]);
        let pathvectord_config_path = pathvectord_config
            .path()
            .to_str()
            .expect("pathvectord config path is valid UTF-8")
            .to_owned();

        // Start pathvectord.  Map its internal gRPC port to a fixed host port
        // using with_mapped_port so we bypass the PortNotExposed issue that
        // testcontainers exhibits on macOS (Docker Desktop returns HostIp=""
        // in port bindings, which the library cannot parse).
        let pathvectord = GenericImage::new(PATHVECTORD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_cmd(["/etc/pathvectord.toml"])
            .with_network(&network_name)
            .with_container_name(format!("pathvectord-{test_id}"))
            .with_mapped_port(grpc_host_port, ContainerPort::Tcp(PATHVECTORD_GRPC_PORT))
            .with_mount(Mount::bind_mount(
                pathvectord_config_path,
                "/etc/pathvectord.toml",
            ))
            .start()
            .await
            .expect("start pathvectord container");

        // Connect the management client to pathvectord's host-mapped gRPC port.
        let mut client = PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("connect PathvectorClient");

        // Wait for the BGP session.  gobgpd is passive (never initiates), so
        // pathvectord dials it.  Both containers are on the same bridge network
        // so the TCP connection goes container-to-container — no proxy involved.
        wait_for_established(&mut client, gobgpd_ip, Duration::from_secs(30))
            .await
            .expect("BGP session did not reach Established within 30 s");

        let pathvectord_container_id = pathvectord.id().to_owned();

        // Discover pathvectord's container IP so tests can reference it as a
        // GoBGP neighbor address (GoBGP keys its neighbor table by source IP).
        let pathvectord_ip = container_network_ip(&pathvectord_container_id, &network_name);

        Self {
            _gobgpd: gobgpd,
            _pathvectord: pathvectord,
            gobgpd_id: gobgpd_container_id,
            pathvectord_id: pathvectord_container_id,
            _gobgpd_config: gobgpd_config,
            _pathvectord_config: pathvectord_config,
            client,
            peer: gobgpd_ip,
            pathvectord_ip,
            network_name,
            _network: network,
        }
    }

    /// Like [`new_inner`] but creates the Docker network with `--ipv6` so that
    /// containers receive link-local IPv6 addresses.  Required for tests that
    /// use `gobgp_link_local_v6()` as a BGP next-hop.
    async fn new_inner_v6(make_cfg: impl Fn(&[(Ipv4Addr, u32)]) -> NamedTempFile) -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();

        let network_name = format!("pathvector-test-{test_id}");
        // Use a per-test ULA prefix so parallel tests don't collide.
        let ipv6_subnet = format!("fd00:{:x}::/48", test_id & 0xffff);
        let network = DockerNetwork::create_with_ipv6(network_name.clone(), &ipv6_subnet);

        let gobgpd_config = write_gobgp_config();
        let gobgpd_config_path = gobgpd_config
            .path()
            .to_str()
            .expect("gobgpd config path is valid UTF-8")
            .to_owned();

        let gobgpd = GenericImage::new(GOBGPD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_network(&network_name)
            .with_container_name(format!("gobgpd-v6-{test_id}"))
            .with_mount(Mount::bind_mount(
                gobgpd_config_path,
                "/etc/gobgp/gobgpd.conf",
            ))
            .start()
            .await
            .expect("start gobgpd container");

        let gobgpd_container_id = gobgpd.id().to_owned();
        let gobgpd_ip = container_network_ip(&gobgpd_container_id, &network_name);

        let pathvectord_config = make_cfg(&[(gobgpd_ip, 65001)]);
        let pathvectord_config_path = pathvectord_config
            .path()
            .to_str()
            .expect("pathvectord config path is valid UTF-8")
            .to_owned();

        let pathvectord = GenericImage::new(PATHVECTORD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_cmd(["/etc/pathvectord.toml"])
            .with_network(&network_name)
            .with_container_name(format!("pathvectord-v6-{test_id}"))
            .with_mapped_port(grpc_host_port, ContainerPort::Tcp(PATHVECTORD_GRPC_PORT))
            .with_mount(Mount::bind_mount(
                pathvectord_config_path,
                "/etc/pathvectord.toml",
            ))
            .start()
            .await
            .expect("start pathvectord container");

        let mut client = PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("connect PathvectorClient");

        wait_for_established(&mut client, gobgpd_ip, Duration::from_secs(30))
            .await
            .expect("BGP session did not reach Established within 30 s");

        let pathvectord_container_id = pathvectord.id().to_owned();
        let pathvectord_ip = container_network_ip(&pathvectord_container_id, &network_name);

        Self {
            _gobgpd: gobgpd,
            _pathvectord: pathvectord,
            gobgpd_id: gobgpd_container_id,
            pathvectord_id: pathvectord_container_id,
            _gobgpd_config: gobgpd_config,
            _pathvectord_config: pathvectord_config,
            client,
            peer: gobgpd_ip,
            pathvectord_ip,
            network_name,
            _network: network,
        }
    }

    /// Announce a prefix from GoBGP into pathvectord's RIB.
    ///
    /// Runs `gobgp global rib add <prefix> nexthop <nexthop>` inside the
    /// gobgpd container via `docker exec`.  GoBGP's gRPC API is never mapped
    /// to the host; all CLI access goes through the container directly.
    ///
    /// # Panics
    ///
    /// Panics if `docker exec` fails or the command exits non-zero.
    pub fn gobgp_announce(&self, prefix: &str, nexthop: &str) {
        // Pass `origin igp` explicitly: GoBGP defaults to INCOMPLETE for
        // manually injected routes, but the test suite validates IGP origin
        // handling throughout.
        let status = Command::new("docker")
            .args(["exec", &self.gobgpd_id])
            .args([
                "gobgp", "global", "rib", "add", prefix, "nexthop", nexthop, "origin", "igp",
            ])
            .status()
            .expect("docker exec gobgp announce");
        assert!(status.success(), "gobgp announce {prefix} failed: {status}");
    }

    /// Withdraw a prefix from GoBGP.
    ///
    /// # Panics
    ///
    /// Panics if `docker exec` fails or the command exits non-zero.
    pub fn gobgp_withdraw(&self, prefix: &str) {
        let status = Command::new("docker")
            .args(["exec", &self.gobgpd_id])
            .args(["gobgp", "global", "rib", "del", prefix])
            .status()
            .expect("docker exec gobgp withdraw");
        assert!(status.success(), "gobgp withdraw {prefix} failed: {status}");
    }

    /// Withdraw an IPv6 prefix from GoBGP's RIB (AFI/SAFI = ipv6-unicast).
    ///
    /// # Panics
    ///
    /// Panics if `docker exec` fails or the command exits non-zero.
    pub fn gobgp_withdraw_v6(&self, prefix: &str) {
        let status = Command::new("docker")
            .args(["exec", &self.gobgpd_id])
            .args(["gobgp", "global", "rib", "del", prefix, "-a", "ipv6"])
            .status()
            .expect("docker exec gobgp withdraw ipv6");
        assert!(
            status.success(),
            "gobgp withdraw_v6 {prefix} failed: {status}"
        );
    }

    /// Returns the link-local IPv6 address (`fe80::…`) of the GoBGP container's
    /// primary network interface.
    ///
    /// Docker containers always receive a link-local address via SLAAC even when
    /// IPv6 is not explicitly enabled on the Docker network.  This address is
    /// always on-link from pathvectord's perspective, making it the correct
    /// next-hop to use when testing IPv6 route reception over an IPv4 TCP session.
    ///
    /// # Panics
    ///
    /// Panics if the container has no link-local IPv6 address.
    pub fn gobgp_link_local_v6(&self) -> String {
        let out = Command::new("docker")
            .args([
                "exec",
                &self.gobgpd_id,
                "ip",
                "-6",
                "addr",
                "show",
                "scope",
                "link",
            ])
            .output()
            .expect("docker exec ip -6 addr show scope link");
        let text = String::from_utf8_lossy(&out.stdout);
        // Extract `fe80::…/64` then strip the prefix-length suffix.
        for token in text.split_whitespace() {
            if token.starts_with("fe80::") {
                return token
                    .split('/')
                    .next()
                    .expect("addr token has prefix-length")
                    .to_owned();
            }
        }
        panic!(
            "GoBGP container {id} has no link-local IPv6 address; ip -6 output:\n{text}",
            id = self.gobgpd_id
        );
    }

    /// Announce an IPv6 prefix into GoBGP's RIB (AFI/SAFI = ipv6-unicast).
    ///
    /// # Panics
    ///
    /// Panics if `docker exec` fails or the command exits non-zero.
    pub fn gobgp_announce_v6(&self, prefix: &str, nexthop: &str) {
        let status = Command::new("docker")
            .args(["exec", &self.gobgpd_id])
            .args([
                "gobgp", "global", "rib", "add", prefix, "nexthop", nexthop, "origin", "igp", "-a",
                "ipv6",
            ])
            .status()
            .expect("docker exec gobgp announce ipv6");
        assert!(
            status.success(),
            "gobgp announce_v6 {prefix} failed: {status}"
        );
    }
}

// ── Outbound advertisement helpers ────────────────────────────────────────────

/// Polls `gobgp global rib` inside `container_id` until `prefix` appears.
///
/// Used to verify that a prefix announced by pathvectord has been received
/// and installed by a GoBGP sink peer.
///
/// # Errors
///
/// Returns `Err(String)` if `timeout` expires before the prefix appears.
pub async fn wait_for_gobgp_rib_entry(
    container_id: &str,
    prefix: &str,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "timed out waiting for prefix {prefix} to appear in GoBGP global RIB"
            ));
        }
        let out = Command::new("docker")
            .args(["exec", container_id, "gobgp", "global", "rib"])
            .output();
        if let Ok(out) = out {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.contains(prefix) {
                return Ok(());
            }
        }
    }
}

/// Polls `gobgp global rib -a ipv6` inside `container_id` until `prefix` appears.
///
/// IPv6-specific variant of [`wait_for_gobgp_rib_entry`].
///
/// # Errors
///
/// Returns `Err(String)` if `timeout` expires before the prefix appears.
pub async fn wait_for_gobgp_rib_entry_v6(
    container_id: &str,
    prefix: &str,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "timed out waiting for IPv6 prefix {prefix} to appear in GoBGP global RIB"
            ));
        }
        let out = Command::new("docker")
            .args(["exec", container_id, "gobgp", "global", "rib", "-a", "ipv6"])
            .output();
        if let Ok(out) = out {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.contains(prefix) {
                return Ok(());
            }
        }
    }
}

/// Polls `gobgp global rib` until `prefix` is absent (withdrawn from the RIB).
///
/// # Errors
///
/// Returns `Err(String)` if `timeout` expires before the prefix disappears.
pub async fn wait_for_gobgp_rib_withdrawn(
    container_id: &str,
    prefix: &str,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "timed out waiting for prefix {prefix} to be withdrawn from GoBGP global RIB"
            ));
        }
        let out = Command::new("docker")
            .args(["exec", container_id, "gobgp", "global", "rib"])
            .output();
        match out {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                if !text.contains(prefix) {
                    return Ok(());
                }
            }
            Err(_) => return Ok(()), // container gone — route is certainly absent
        }
    }
}

/// Polls `gobgp global rib -a ipv6` until `prefix` is absent (withdrawn).
///
/// IPv6-specific variant of [`wait_for_gobgp_rib_withdrawn`].
///
/// # Errors
///
/// Returns `Err(String)` if `timeout` expires before the prefix disappears.
pub async fn wait_for_gobgp_rib_withdrawn_v6(
    container_id: &str,
    prefix: &str,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "timed out waiting for IPv6 prefix {prefix} to be withdrawn from GoBGP global RIB"
            ));
        }
        let out = Command::new("docker")
            .args(["exec", container_id, "gobgp", "global", "rib", "-a", "ipv6"])
            .output();
        match out {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                if !text.contains(prefix) {
                    return Ok(());
                }
            }
            Err(_) => return Ok(()), // container gone — route is certainly absent
        }
    }
}

// ── TwoPeerHarness ────────────────────────────────────────────────────────────

/// A two-peer test environment for verifying outbound advertisement:
///
/// ```text
/// GoBGP-source (AS 65003) ──BGP──► pathvectord (AS 65002) ──BGP──► GoBGP-sink (AS 65001)
/// ```
///
/// pathvectord dials both GoBGP containers on the same Docker bridge network.
/// Tests call [`TwoPeerHarness::source_announce`] to inject a route at the
/// source, then poll [`wait_for_gobgp_rib_entry`] on the sink container to
/// confirm pathvectord forwarded it.
///
/// # Panics
///
/// [`TwoPeerHarness::new`] panics if Docker is not running, either image is
/// missing, or either BGP session does not establish within 30 seconds.
pub struct TwoPeerHarness {
    _gobgpd_sink: ContainerAsync<GenericImage>,
    _gobgpd_source: ContainerAsync<GenericImage>,
    _pathvectord: ContainerAsync<GenericImage>,
    _sink_config: NamedTempFile,
    _source_config: NamedTempFile,
    _daemon_config: NamedTempFile,
    /// Container ID of GoBGP-source — used for `source_announce` / `source_withdraw`.
    pub source_id: String,
    /// Container ID of GoBGP-sink — pass to [`wait_for_gobgp_rib_entry`].
    pub sink_id: String,
    /// IP of the GoBGP-sink container (the `peer` address as seen by pathvectord).
    pub sink_peer: Ipv4Addr,
    /// pathvectord management client.
    pub client: PathvectorClient,
    _network: DockerNetwork,
}

impl TwoPeerHarness {
    /// Stand up the full two-peer environment and wait for both BGP sessions.
    ///
    /// pathvectord is configured with `import_default = "accept"` and
    /// `export_default = "accept"` on both peers so routes flow freely from
    /// source through to sink.
    ///
    /// # Panics
    ///
    /// Panics if Docker is not running, either image is missing, or either BGP
    /// session does not reach `Established` within 30 seconds.
    pub async fn new() -> Self {
        Self::new_inner(write_daemon_config).await
    }

    /// Same as [`Self::new`] but with `import_default = "accept"` and **no**
    /// `export_default` on either peer.
    ///
    /// Routes from GoBGP-source are accepted into pathvectord's Loc-RIB, but
    /// the RFC 8212 eBGP export default (`Reject`) prevents pathvectord from
    /// re-advertising them to GoBGP-sink.  Use this harness to assert that the
    /// export-policy default actually suppresses advertisements.
    ///
    /// # Panics
    ///
    /// Panics if Docker is not running, either image is missing, or either BGP
    /// session does not reach `Established` within 30 seconds.
    pub async fn new_no_export_policy() -> Self {
        Self::new_inner(write_daemon_config_import_only).await
    }

    /// Internal constructor — spins up GoBGP-sink + GoBGP-source + pathvectord.
    ///
    /// `make_cfg` is the config-writing function that produces the pathvectord
    /// TOML.  The caller chooses the policy variant.
    async fn new_inner(make_cfg: fn(&[(Ipv4Addr, u32)]) -> NamedTempFile) -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();

        let network_name = format!("pathvector-test-{test_id}");
        let network = DockerNetwork::create(network_name.clone());

        // ── GoBGP-sink (AS 65001) ─────────────────────────────────────────────
        let sink_config = write_gobgp_config();
        let sink_config_path = sink_config.path().to_str().unwrap().to_owned();

        let gobgpd_sink = GenericImage::new(GOBGPD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_network(&network_name)
            .with_container_name(format!("gobgpd-sink-{test_id}"))
            .with_mount(Mount::bind_mount(
                sink_config_path,
                "/etc/gobgp/gobgpd.conf",
            ))
            .start()
            .await
            .expect("start gobgpd-sink container");

        let sink_id = gobgpd_sink.id().to_owned();
        let sink_addr = container_network_ip(&sink_id, &network_name);

        // ── GoBGP-source (AS 65003) ───────────────────────────────────────────
        let source_config = write_gobgp_source_config();
        let source_config_path = source_config.path().to_str().unwrap().to_owned();

        let gobgpd_source = GenericImage::new(GOBGPD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_network(&network_name)
            .with_container_name(format!("gobgpd-source-{test_id}"))
            .with_mount(Mount::bind_mount(
                source_config_path,
                "/etc/gobgp/gobgpd.conf",
            ))
            .start()
            .await
            .expect("start gobgpd-source container");

        let source_id = gobgpd_source.id().to_owned();
        let source_addr = container_network_ip(&source_id, &network_name);

        // ── pathvectord (dials both peers) ────────────────────────────────────
        let daemon_config = make_cfg(&[(sink_addr, 65001), (source_addr, 65003)]);
        let daemon_config_path = daemon_config.path().to_str().unwrap().to_owned();

        let pathvectord = GenericImage::new(PATHVECTORD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_cmd(["/etc/pathvectord.toml"])
            .with_network(&network_name)
            .with_container_name(format!("pathvectord-{test_id}"))
            .with_mapped_port(grpc_host_port, ContainerPort::Tcp(PATHVECTORD_GRPC_PORT))
            .with_mount(Mount::bind_mount(
                daemon_config_path,
                "/etc/pathvectord.toml",
            ))
            .start()
            .await
            .expect("start pathvectord container");

        let mut client = PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("connect PathvectorClient");

        // Wait for both BGP sessions to establish.
        wait_for_established(&mut client, sink_addr, Duration::from_secs(30))
            .await
            .expect("BGP session with sink did not reach Established within 30 s");
        wait_for_established(&mut client, source_addr, Duration::from_secs(30))
            .await
            .expect("BGP session with source did not reach Established within 30 s");

        Self {
            _gobgpd_sink: gobgpd_sink,
            _gobgpd_source: gobgpd_source,
            _pathvectord: pathvectord,
            _sink_config: sink_config,
            _source_config: source_config,
            _daemon_config: daemon_config,
            source_id,
            sink_id,
            sink_peer: sink_addr,
            client,
            _network: network,
        }
    }

    /// Announce a prefix from GoBGP-source into pathvectord.
    ///
    /// # Panics
    ///
    /// Panics if `docker exec` fails or the command exits non-zero.
    pub fn source_announce(&self, prefix: &str, nexthop: &str) {
        let status = Command::new("docker")
            .args(["exec", &self.source_id])
            .args([
                "gobgp", "global", "rib", "add", prefix, "nexthop", nexthop, "origin", "igp",
            ])
            .status()
            .expect("docker exec gobgp source announce");
        assert!(
            status.success(),
            "gobgp source announce {prefix} failed: {status}"
        );
    }

    /// Withdraw a prefix from GoBGP-source.
    ///
    /// # Panics
    ///
    /// Panics if `docker exec` fails or the command exits non-zero.
    pub fn source_withdraw(&self, prefix: &str) {
        let status = Command::new("docker")
            .args(["exec", &self.source_id])
            .args(["gobgp", "global", "rib", "del", prefix])
            .status()
            .expect("docker exec gobgp source withdraw");
        assert!(
            status.success(),
            "gobgp source withdraw {prefix} failed: {status}"
        );
    }
}

// ── RrHarness ────────────────────────────────────────────────────────────────

/// Writes the gobgpd config for an **iBGP** peer of a route reflector.
///
/// The peer runs in AS 65002 (same as pathvectord) and uses passive-mode so
/// pathvectord dials it.  `router_id` distinguishes the two GoBGP instances.
fn write_gobgp_ibgp_config(router_id: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp gobgp ibgp config");
    write!(
        f,
        r#"
[global.config]
  as        = 65002
  router-id = "{router_id}"

[[peer-groups]]
  [peer-groups.config]
    peer-group-name = "pathvector-peers"
    peer-as         = 65002
  [peer-groups.timers.config]
    hold-time          = 9
    keepalive-interval = 3
  [peer-groups.transport.config]
    passive-mode = true

  [[peer-groups.afi-safis]]
    [peer-groups.afi-safis.config]
      afi-safi-name = "ipv4-unicast"

[[dynamic-neighbors]]
  [dynamic-neighbors.config]
    prefix     = "0.0.0.0/0"
    peer-group = "pathvector-peers"
"#
    )
    .expect("write gobgp ibgp config");
    f
}

/// Writes the pathvectord config for a route-reflector test.
///
/// `client_ip` is configured with `is_rr_client = true`; `non_client_ip` is a
/// plain iBGP peer (no `is_rr_client`).  Both peers use accept-all import and
/// export policy so routes flow freely through the reflector.
fn write_daemon_config_rr(
    client_ip: Ipv4Addr,
    non_client_ip: Ipv4Addr,
    grpc_port: u16,
) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord rr config");
    write!(
        f,
        r#"
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
hold_time = 9
grpc_port = {grpc_port}

[[peers]]
address        = "{client_ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = 65002
import_default = "accept"
export_default = "accept"
is_rr_client   = true

[[peers]]
address        = "{non_client_ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = 65002
import_default = "accept"
export_default = "accept"
"#
    )
    .expect("write pathvectord rr config");
    f
}

/// A route-reflector test environment.
///
/// ```text
/// GoBGP-client (AS 65002, RR client) ──iBGP──► pathvectord (AS 65002, RR)
///                                                       │
///                                              iBGP (non-client)
///                                                       │
///                                            GoBGP-non-client (AS 65002)
/// ```
///
/// pathvectord acts as the route reflector.  GoBGP-client has
/// `is_rr_client = true`; GoBGP-non-client does not.  RFC 4456 §8 requires
/// that routes received from a client are reflected to all other peers
/// (both clients and non-clients).
///
/// # Panics
///
/// [`RrHarness::new`] panics if Docker is not running, any image is missing,
/// or any BGP session does not reach `Established` within 30 seconds.
pub struct RrHarness {
    _gobgpd_client: ContainerAsync<GenericImage>,
    _gobgpd_non_client: ContainerAsync<GenericImage>,
    _pathvectord: ContainerAsync<GenericImage>,
    _client_config: NamedTempFile,
    _non_client_config: NamedTempFile,
    _daemon_config: NamedTempFile,
    /// Container ID of GoBGP-client — use to announce routes.
    pub client_id: String,
    /// Container ID of GoBGP-non-client — poll to verify reflected routes.
    pub non_client_id: String,
    /// IP of GoBGP-client as seen by pathvectord.
    pub client_peer: Ipv4Addr,
    /// IP of GoBGP-non-client as seen by pathvectord.
    pub non_client_peer: Ipv4Addr,
    /// IP of pathvectord on the Docker bridge — what peers see as pathvectord's
    /// address. This is the value that `next_hop_self` rewrites NEXT_HOP to.
    pub pathvectord_addr: Ipv4Addr,
    /// pathvectord management client.
    pub client: PathvectorClient,
    _network: DockerNetwork,
}

impl RrHarness {
    /// Stand up the route-reflector environment and wait for both iBGP sessions.
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new() -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();

        let network_name = format!("pathvector-test-rr-{test_id}");
        let network = DockerNetwork::create(network_name.clone());

        // ── GoBGP-client (iBGP RR client) ────────────────────────────────────
        let client_config = write_gobgp_ibgp_config("1.0.0.1");
        let client_config_path = client_config.path().to_str().unwrap().to_owned();

        let gobgpd_client = GenericImage::new(GOBGPD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_network(&network_name)
            .with_container_name(format!("gobgpd-rr-client-{test_id}"))
            .with_mount(Mount::bind_mount(
                client_config_path,
                "/etc/gobgp/gobgpd.conf",
            ))
            .start()
            .await
            .expect("start gobgpd-rr-client container");

        let client_id = gobgpd_client.id().to_owned();
        let client_addr = container_network_ip(&client_id, &network_name);

        // ── GoBGP-non-client (plain iBGP peer) ───────────────────────────────
        let non_client_config = write_gobgp_ibgp_config("1.0.0.3");
        let non_client_config_path = non_client_config.path().to_str().unwrap().to_owned();

        let gobgpd_non_client = GenericImage::new(GOBGPD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_network(&network_name)
            .with_container_name(format!("gobgpd-rr-non-client-{test_id}"))
            .with_mount(Mount::bind_mount(
                non_client_config_path,
                "/etc/gobgp/gobgpd.conf",
            ))
            .start()
            .await
            .expect("start gobgpd-rr-non-client container");

        let non_client_id = gobgpd_non_client.id().to_owned();
        let non_client_addr = container_network_ip(&non_client_id, &network_name);

        // ── pathvectord (route reflector) ─────────────────────────────────────
        let daemon_config =
            write_daemon_config_rr(client_addr, non_client_addr, PATHVECTORD_GRPC_PORT);
        let daemon_config_path = daemon_config.path().to_str().unwrap().to_owned();

        let pathvectord = GenericImage::new(PATHVECTORD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_cmd(["/etc/pathvectord.toml"])
            .with_network(&network_name)
            .with_container_name(format!("pathvectord-rr-{test_id}"))
            .with_mapped_port(grpc_host_port, ContainerPort::Tcp(PATHVECTORD_GRPC_PORT))
            .with_mount(Mount::bind_mount(
                daemon_config_path,
                "/etc/pathvectord.toml",
            ))
            .start()
            .await
            .expect("start pathvectord rr container");

        let pathvectord_id = pathvectord.id().to_owned();
        let pathvectord_addr = container_network_ip(&pathvectord_id, &network_name);

        let mut management =
            PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
                .expect("connect PathvectorClient");

        wait_for_established(&mut management, client_addr, Duration::from_secs(30))
            .await
            .expect("iBGP session with rr-client did not reach Established within 30 s");
        wait_for_established(&mut management, non_client_addr, Duration::from_secs(30))
            .await
            .expect("iBGP session with rr-non-client did not reach Established within 30 s");

        Self {
            _gobgpd_client: gobgpd_client,
            _gobgpd_non_client: gobgpd_non_client,
            _pathvectord: pathvectord,
            _client_config: client_config,
            _non_client_config: non_client_config,
            _daemon_config: daemon_config,
            client_id,
            non_client_id,
            client_peer: client_addr,
            non_client_peer: non_client_addr,
            pathvectord_addr,
            client: management,
            _network: network,
        }
    }

    /// Announce a prefix from GoBGP-client (the RR client) into pathvectord.
    ///
    /// # Panics
    ///
    /// Panics if `docker exec` fails or the command exits non-zero.
    pub fn client_announce(&self, prefix: &str, nexthop: &str) {
        let status = Command::new("docker")
            .args(["exec", &self.client_id])
            .args([
                "gobgp", "global", "rib", "add", prefix, "nexthop", nexthop, "origin", "igp",
            ])
            .status()
            .expect("docker exec gobgp client announce");
        assert!(
            status.success(),
            "gobgp rr-client announce {prefix} failed: {status}"
        );
    }

    /// Announce a prefix from GoBGP-non-client into pathvectord.
    ///
    /// # Panics
    ///
    /// Panics if `docker exec` fails or the command exits non-zero.
    pub fn non_client_announce(&self, prefix: &str, nexthop: &str) {
        let status = Command::new("docker")
            .args(["exec", &self.non_client_id])
            .args([
                "gobgp", "global", "rib", "add", prefix, "nexthop", nexthop, "origin", "igp",
            ])
            .status()
            .expect("docker exec gobgp non-client announce");
        assert!(
            status.success(),
            "gobgp rr-non-client announce {prefix} failed: {status}"
        );
    }
}

/// Returns the NEXT_HOP address that GoBGP stored for `prefix` in its global
/// RIB, or `None` if the prefix is absent or the output cannot be parsed.
///
/// Uses `gobgp global rib` inside the container, which prints one route per
/// line: `*> <prefix> <next-hop> …`.  The next-hop is the second field on the
/// prefix line, which is exactly what was written in the received UPDATE's
/// NEXT_HOP attribute.
#[must_use]
pub fn get_gobgp_next_hop(container_id: &str, prefix: &str) -> Option<std::net::Ipv4Addr> {
    let out = Command::new("docker")
        .args(["exec", container_id, "gobgp", "global", "rib"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        // Lines look like: `*> 10.100.0.0/16        172.16.0.1     …`
        if line.contains(prefix) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // fields[0] = "*>", fields[1] = prefix, fields[2] = next-hop
            if fields.len() >= 3 {
                return fields[2].parse().ok();
            }
        }
    }
    None
}

// ── GrIpv6ObserverHarness ─────────────────────────────────────────────────────

/// Test harness for RFC 4724 §4.2 IPv6 GR deadline-expiry re-propagation.
///
/// Topology:
///
/// ```text
/// GoBGP-source (AS 65001, GR-capable, restart_time=N) ──eBGP──► pathvectord (AS 65002)
///                                                                       │
///                                                                    eBGP
///                                                                       │
///                                                             GoBGP-observer (AS 65003)
/// ```
///
/// GoBGP-source announces an IPv6-only prefix; pathvectord installs it and
/// re-advertises it to GoBGP-observer over a real BGP session. When
/// GoBGP-source is killed uncleanly and its GR restart window expires,
/// pathvectord must send a real BGP WITHDRAW for that prefix to
/// GoBGP-observer — not just remove it from its own Loc-RIB (regression
/// coverage for the `on_gr_deadline_expired` IPv6 fix, CHANGELOG.md
/// 2026-07-03).
///
/// GoBGP-observer uses a distinct AS (65003, via [`write_gobgp_config_with_as`])
/// rather than reusing GoBGP-source's AS 65001. Both peers sharing 65001 was
/// tried first and produced a confusing failure: pathvectord correctly
/// re-advertised the route (confirmed via its own outbound decision and
/// `flush_pending` logs), but GoBGP-observer's own AS_PATH loop-prevention
/// silently discarded it on receipt, since the AS_PATH already contained
/// 65001 from the originating hop — RFC 4271 §9.1.2 working as designed, not
/// a pathvectord bug. A distinct AS avoids that entirely.
///
/// # Panics
///
/// [`GrIpv6ObserverHarness::new`] panics if Docker is not running, either
/// image is missing, or either BGP session does not reach `Established`
/// within 30 seconds.
pub struct GrIpv6ObserverHarness {
    _source: ContainerAsync<GenericImage>,
    _observer: ContainerAsync<GenericImage>,
    _pathvectord: ContainerAsync<GenericImage>,
    _source_config: NamedTempFile,
    _observer_config: NamedTempFile,
    _daemon_config: NamedTempFile,
    /// Container ID of GoBGP-source — killed with SIGKILL to trigger the GR window.
    pub source_id: String,
    /// Container ID of GoBGP-observer — polled to verify the real WITHDRAW.
    pub observer_id: String,
    /// IP of GoBGP-observer as seen by pathvectord — use with `get_peer` to
    /// query pathvectord's own view of that session.
    pub observer_addr: Ipv4Addr,
    /// Container ID of pathvectord — used to dump logs on test failure.
    pub pathvectord_id: String,
    pub client: PathvectorClient,
    _network: DockerNetwork,
}

impl GrIpv6ObserverHarness {
    /// Stand up both eBGP sessions and wait for both to reach Established.
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new(restart_secs: u16) -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();

        let network_name = format!("pathvector-gr-v6-obs-test-{test_id}");
        let ipv6_subnet = format!("fd00:{:x}::/48", test_id & 0xffff);
        let network = DockerNetwork::create_with_ipv6(network_name.clone(), &ipv6_subnet);

        // ── GoBGP-source (GR-capable, will be killed) ────────────────────────
        let source_config = write_gobgp_config_with_restart_time(restart_secs);
        let source_config_path = source_config
            .path()
            .to_str()
            .expect("source config path is valid UTF-8")
            .to_owned();

        let source = GenericImage::new(GOBGPD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_network(&network_name)
            .with_container_name(format!("gobgpd-gr-v6-source-{test_id}"))
            .with_mount(Mount::bind_mount(
                source_config_path,
                "/etc/gobgp/gobgpd.conf",
            ))
            .start()
            .await
            .expect("start gobgpd-gr-v6-source container");
        let source_id = source.id().to_owned();
        let source_addr = container_network_ip(&source_id, &network_name);

        // ── GoBGP-observer (distinct AS, observes the withdrawal) ────────────
        // AS 65003, not the source's 65001 — see struct docs for why sharing
        // an AS breaks this test via GoBGP's own AS_PATH loop-prevention.
        let observer_config = write_gobgp_config_with_as(65003);
        let observer_config_path = observer_config
            .path()
            .to_str()
            .expect("observer config path is valid UTF-8")
            .to_owned();

        let observer = GenericImage::new(GOBGPD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_network(&network_name)
            .with_container_name(format!("gobgpd-gr-v6-observer-{test_id}"))
            .with_mount(Mount::bind_mount(
                observer_config_path,
                "/etc/gobgp/gobgpd.conf",
            ))
            .start()
            .await
            .expect("start gobgpd-gr-v6-observer container");
        let observer_id = observer.id().to_owned();
        let observer_addr = container_network_ip(&observer_id, &network_name);

        // ── pathvectord ───────────────────────────────────────────────────────
        let daemon_config = write_daemon_config_gr_v6_observer(
            source_addr,
            65001,
            restart_secs,
            observer_addr,
            65003,
        );
        let daemon_config_path = daemon_config
            .path()
            .to_str()
            .expect("daemon config path is valid UTF-8")
            .to_owned();

        let pathvectord = GenericImage::new(PATHVECTORD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_cmd(["/etc/pathvectord.toml"])
            .with_network(&network_name)
            .with_container_name(format!("pathvectord-gr-v6-obs-{test_id}"))
            .with_mapped_port(grpc_host_port, ContainerPort::Tcp(PATHVECTORD_GRPC_PORT))
            .with_mount(Mount::bind_mount(
                daemon_config_path,
                "/etc/pathvectord.toml",
            ))
            .start()
            .await
            .expect("start pathvectord gr-v6-observer container");

        let pathvectord_id = pathvectord.id().to_owned();

        let mut client = PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("connect PathvectorClient for GrIpv6ObserverHarness");

        wait_for_established(&mut client, source_addr, Duration::from_secs(30))
            .await
            .expect("GR-source session did not reach Established within 30 s");
        wait_for_established(&mut client, observer_addr, Duration::from_secs(30))
            .await
            .expect("observer session did not reach Established within 30 s");

        Self {
            _source: source,
            _observer: observer,
            _pathvectord: pathvectord,
            pathvectord_id,
            _source_config: source_config,
            _observer_config: observer_config,
            _daemon_config: daemon_config,
            source_id,
            observer_id,
            observer_addr,
            client,
            _network: network,
        }
    }
}

/// Proves pathvectord dials a BGP session whose own TCP transport is IPv6 —
/// as opposed to [`Harness::new_v6`], which only carries IPv6 NLRI/next-hops
/// over what is still an IPv4-transport session with GoBGP.
///
/// A dedicated struct rather than widening the shared [`Harness`] — its
/// `peer`/`pathvectord_ip` fields are `Ipv4Addr` and referenced by ~30
/// existing v4-transport tests, not worth destabilizing for this one
/// scenario. Mirrors the shape of [`GrIpv6ObserverHarness`].
pub struct Ipv6TransportHarness {
    _gobgpd: ContainerAsync<GenericImage>,
    _pathvectord: ContainerAsync<GenericImage>,
    _gobgpd_config: NamedTempFile,
    _pathvectord_config: NamedTempFile,
    pub gobgpd_id: String,
    pub pathvectord_id: String,
    /// GoBGP's routable (global-scope ULA) IPv6 address on the test network —
    /// this is `PeerConfig.address` in pathvectord's config, and the address
    /// the real TCP SYN is sent to.
    pub peer_v6: Ipv6Addr,
    pub client: PathvectorClient,
    _network: DockerNetwork,
}

impl Ipv6TransportHarness {
    /// Stand up gobgpd and pathvectord on an `--ipv6` Docker network, with
    /// pathvectord's peer configured at GoBGP's global IPv6 address, and wait
    /// for the session to reach Established.
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new() -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();

        let network_name = format!("pathvector-v6-transport-test-{test_id}");
        // Use a per-test ULA prefix so parallel tests don't collide.
        let ipv6_subnet = format!("fd00:{:x}::/48", test_id & 0xffff);
        let network = DockerNetwork::create_with_ipv6(network_name.clone(), &ipv6_subnet);

        let gobgpd_config = write_gobgp_config();
        let gobgpd_config_path = gobgpd_config
            .path()
            .to_str()
            .expect("gobgpd config path is valid UTF-8")
            .to_owned();

        let gobgpd = GenericImage::new(GOBGPD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_network(&network_name)
            .with_container_name(format!("gobgpd-v6-transport-{test_id}"))
            .with_mount(Mount::bind_mount(
                gobgpd_config_path,
                "/etc/gobgp/gobgpd.conf",
            ))
            .start()
            .await
            .expect("start gobgpd container");

        let gobgpd_container_id = gobgpd.id().to_owned();
        // The global (ULA) address, not the auto-configured fe80:: link-local
        // one — see container_network_ipv6's doc comment for why.
        let peer_v6 = container_network_ipv6(&gobgpd_container_id, &network_name);

        let pathvectord_config = write_daemon_config_v6_transport(peer_v6, 65001);
        let pathvectord_config_path = pathvectord_config
            .path()
            .to_str()
            .expect("pathvectord config path is valid UTF-8")
            .to_owned();

        let pathvectord = GenericImage::new(PATHVECTORD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_cmd(["/etc/pathvectord.toml"])
            .with_network(&network_name)
            .with_container_name(format!("pathvectord-v6-transport-{test_id}"))
            .with_mapped_port(grpc_host_port, ContainerPort::Tcp(PATHVECTORD_GRPC_PORT))
            .with_mount(Mount::bind_mount(
                pathvectord_config_path,
                "/etc/pathvectord.toml",
            ))
            .start()
            .await
            .expect("start pathvectord container");

        let mut client = PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("connect PathvectorClient for Ipv6TransportHarness");

        wait_for_established(&mut client, peer_v6, Duration::from_secs(30))
            .await
            .expect("BGP session over IPv6 transport did not reach Established within 30 s");

        let pathvectord_container_id = pathvectord.id().to_owned();

        Self {
            _gobgpd: gobgpd,
            _pathvectord: pathvectord,
            gobgpd_id: gobgpd_container_id,
            pathvectord_id: pathvectord_container_id,
            _gobgpd_config: gobgpd_config,
            _pathvectord_config: pathvectord_config,
            peer_v6,
            client,
            _network: network,
        }
    }
}

/// Writes a pathvectord config whose peer's `address` is an IPv6 literal and
/// `port` is deliberately unreachable (the mock dialer never listens on any
/// port), so pathvectord's own outbound dial can never succeed. Used by
/// [`Ipv6AcceptHarness`] to force the accept path to be the only way the
/// session reaches Established.
fn write_daemon_config_v6_accept(peer: Ipv6Addr, remote_as: u32) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord v6-accept config");
    write!(
        f,
        r#"
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
hold_time = 9
grpc_port = {PATHVECTORD_GRPC_PORT}

[[peers]]
address        = "{peer}"
port           = 1
remote_as      = {remote_as}
import_default = "accept"
export_default = "accept"
"#
    )
    .expect("write pathvectord v6-accept config");
    f
}

/// Proves pathvectord's BGP *listener* accepts a real inbound IPv6-sourced
/// connection and completes the handshake to Established — the mirror image
/// of [`Ipv6TransportHarness`], which proves the outbound dial path.
///
/// pathvectord always actively dials every configured peer (there's no
/// "passive session" concept in `pathvector-session`), so simply pointing
/// GoBGP at pathvectord would race pathvectord's own dial against GoBGP's —
/// nondeterministic about which side's TCP connection actually wins RFC 4271
/// §6.8 collision detection. This harness sidesteps that: pathvectord's own
/// peer entry names the dialer's real address but a port nothing listens on
/// (see [`write_daemon_config_v6_accept`]), so pathvectord's outbound dial
/// can never succeed — `mock_bgp_dialer` actively connects to pathvectord's
/// *real* listening port instead, so the accept path is the only way
/// Established is ever reached.
///
/// Uses raw `docker run`/`docker rm` (not `testcontainers`) because both
/// containers need a *predictable* IPv6 address assigned before either
/// starts — pathvectord's config must name the dialer's address, and the
/// dialer's argv must name pathvectord's address, a mutual dependency plain
/// container-then-discover-IP can't satisfy. `docker run --ip6 <addr>` lets
/// both be chosen up front instead of discovered afterward.
pub struct Ipv6AcceptHarness {
    pathvectord_id: String,
    dialer_id: String,
    _network: DockerNetwork,
    _pathvectord_config: NamedTempFile,
    pub client: PathvectorClient,
    /// The dialer's static IPv6 address — `PeerConfig.address` in
    /// pathvectord's config, and the address its inbound TCP connection
    /// arrives from.
    pub peer_v6: Ipv6Addr,
}

impl Ipv6AcceptHarness {
    /// Stand up pathvectord and the mock dialer on an `--ipv6` Docker network
    /// with statically-assigned addresses, and wait for the session to reach
    /// Established via pathvectord's accept path.
    ///
    /// # Panics
    ///
    /// Panics if `docker run` fails for either container, or if the session
    /// does not reach Established within 30 s.
    #[must_use]
    pub async fn new() -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();

        let network_name = format!("pathvector-v6-accept-test-{test_id}");
        let subnet_prefix = format!("fd00:{:x}", test_id & 0xffff);
        let ipv6_subnet = format!("{subnet_prefix}::/48");
        let network = DockerNetwork::create_with_ipv6(network_name.clone(), &ipv6_subnet);

        let pathvectord_addr: Ipv6Addr = format!("{subnet_prefix}::10")
            .parse()
            .expect("valid IPv6 address");
        let dialer_addr: Ipv6Addr = format!("{subnet_prefix}::20")
            .parse()
            .expect("valid IPv6 address");

        let pathvectord_config = write_daemon_config_v6_accept(dialer_addr, 65099);
        let pathvectord_config_path = pathvectord_config
            .path()
            .to_str()
            .expect("pathvectord config path is valid UTF-8")
            .to_owned();
        let pathvectord_name = format!("pathvectord-v6-accept-{test_id}");

        let status = Command::new("docker")
            .args([
                "run",
                "-d",
                "--network",
                &network_name,
                "--ip6",
                &pathvectord_addr.to_string(),
                "--name",
                &pathvectord_name,
                "-p",
                &format!("{grpc_host_port}:{PATHVECTORD_GRPC_PORT}"),
                "-v",
                &format!("{pathvectord_config_path}:/etc/pathvectord.toml"),
                PATHVECTORD_IMAGE,
                "/etc/pathvectord.toml",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .expect("docker run pathvectord");
        assert!(status.success(), "docker run pathvectord failed");

        let dialer_name = format!("mock-bgp-dialer-{test_id}");
        let dial_target = format!("[{pathvectord_addr}]:{GOBGPD_BGP_PORT}");
        let status = Command::new("docker")
            .args([
                "run",
                "-d",
                "--network",
                &network_name,
                "--ip6",
                &dialer_addr.to_string(),
                "--name",
                &dialer_name,
                MOCK_BGP_DIALER_IMAGE,
                &dial_target,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .expect("docker run mock_bgp_dialer");
        assert!(status.success(), "docker run mock_bgp_dialer failed");

        let mut client = PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("connect PathvectorClient for Ipv6AcceptHarness");

        wait_for_established(&mut client, dialer_addr, Duration::from_secs(30))
            .await
            .expect("BGP session over the accept path did not reach Established within 30 s");

        Self {
            pathvectord_id: pathvectord_name,
            dialer_id: dialer_name,
            _network: network,
            _pathvectord_config: pathvectord_config,
            client,
            peer_v6: dialer_addr,
        }
    }
}

impl Drop for Ipv6AcceptHarness {
    fn drop(&mut self) {
        for id in [&self.pathvectord_id, &self.dialer_id] {
            Command::new("docker")
                .args(["rm", "-f", id])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .ok();
        }
        // `self.network`'s own Drop impl runs after this method returns
        // (containers must be gone before the network can be removed).
    }
}

fn write_daemon_config_rr_nhs(
    client_ip: Ipv4Addr,
    non_client_ip: Ipv4Addr,
    grpc_port: u16,
) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord rr nhs config");
    write!(
        f,
        r#"
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
hold_time = 9
grpc_port = {grpc_port}

[[peers]]
address        = "{client_ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = 65002
import_default = "accept"
export_default = "accept"
is_rr_client   = true
next_hop_self  = true

[[peers]]
address        = "{non_client_ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = 65002
import_default = "accept"
export_default = "accept"
next_hop_self  = true
"#
    )
    .expect("write pathvectord rr nhs config");
    f
}

impl RrHarness {
    /// Same as [`RrHarness::new`] but with `next_hop_self = true` on both
    /// peers.  Use this when testing that pathvectord rewrites NEXT_HOP to its
    /// own address before reflecting routes to iBGP peers.
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new_with_next_hop_self() -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();

        let network_name = format!("pathvector-test-rr-nhs-{test_id}");
        let network = DockerNetwork::create(network_name.clone());

        let client_config = write_gobgp_ibgp_config("1.0.0.1");
        let client_config_path = client_config.path().to_str().unwrap().to_owned();

        let gobgpd_client = GenericImage::new(GOBGPD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_network(&network_name)
            .with_container_name(format!("gobgpd-rr-nhs-client-{test_id}"))
            .with_mount(Mount::bind_mount(
                client_config_path,
                "/etc/gobgp/gobgpd.conf",
            ))
            .start()
            .await
            .expect("start gobgpd-rr-nhs-client container");

        let client_id = gobgpd_client.id().to_owned();
        let client_addr = container_network_ip(&client_id, &network_name);

        let non_client_config = write_gobgp_ibgp_config("1.0.0.3");
        let non_client_config_path = non_client_config.path().to_str().unwrap().to_owned();

        let gobgpd_non_client = GenericImage::new(GOBGPD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_network(&network_name)
            .with_container_name(format!("gobgpd-rr-nhs-non-client-{test_id}"))
            .with_mount(Mount::bind_mount(
                non_client_config_path,
                "/etc/gobgp/gobgpd.conf",
            ))
            .start()
            .await
            .expect("start gobgpd-rr-nhs-non-client container");

        let non_client_id = gobgpd_non_client.id().to_owned();
        let non_client_addr = container_network_ip(&non_client_id, &network_name);

        let daemon_config =
            write_daemon_config_rr_nhs(client_addr, non_client_addr, PATHVECTORD_GRPC_PORT);
        let daemon_config_path = daemon_config.path().to_str().unwrap().to_owned();

        let pathvectord = GenericImage::new(PATHVECTORD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_cmd(["/etc/pathvectord.toml"])
            .with_network(&network_name)
            .with_container_name(format!("pathvectord-rr-nhs-{test_id}"))
            .with_mapped_port(grpc_host_port, ContainerPort::Tcp(PATHVECTORD_GRPC_PORT))
            .with_mount(Mount::bind_mount(
                daemon_config_path,
                "/etc/pathvectord.toml",
            ))
            .start()
            .await
            .expect("start pathvectord rr-nhs container");

        let pathvectord_id = pathvectord.id().to_owned();
        let pathvectord_addr = container_network_ip(&pathvectord_id, &network_name);

        let mut management =
            PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
                .expect("connect PathvectorClient");

        wait_for_established(&mut management, client_addr, Duration::from_secs(30))
            .await
            .expect("iBGP session with rr-nhs-client did not reach Established within 30 s");
        wait_for_established(&mut management, non_client_addr, Duration::from_secs(30))
            .await
            .expect("iBGP session with rr-nhs-non-client did not reach Established within 30 s");

        Self {
            _gobgpd_client: gobgpd_client,
            _gobgpd_non_client: gobgpd_non_client,
            _pathvectord: pathvectord,
            _client_config: client_config,
            _non_client_config: non_client_config,
            _daemon_config: daemon_config,
            client_id,
            non_client_id,
            client_peer: client_addr,
            non_client_peer: non_client_addr,
            pathvectord_addr,
            client: management,
            _network: network,
        }
    }
}

// ── BirdHarness ──────────────────────────────────────────────────────────────

/// BIRD 2 image built by `just e2e-images` from `e2e/Dockerfile.bird`.
pub const BIRD_IMAGE: &str = "pathvector-bird-test";

/// Derives the per-test BIRD subnet and fixed IPs from `test_id`.
///
/// Each test gets an isolated /24 in `172.31.{id}.0/24` so multiple
/// BIRD tests can run concurrently without Docker rejecting duplicate
/// subnets.  The low octet assignments (`.10` / `.20`) are arbitrary but
/// must stay within the /24.
#[must_use]
pub fn bird_test_subnet(test_id: u32) -> String {
    let third = test_id % 256;
    format!("172.31.{third}.0/24")
}

#[must_use]
pub fn bird_ip(test_id: u32) -> String {
    let third = test_id % 256;
    format!("172.31.{third}.10")
}

#[must_use]
pub fn bird_pathvectord_ip(test_id: u32) -> String {
    let third = test_id % 256;
    format!("172.31.{third}.20")
}

/// Writes the pathvectord config for the BIRD interop harness.
///
/// Uses the standard `bgp_id = "10.0.0.2"` (the router ID, not the interface
/// address).  The eBGP NEXT_HOP is now set to the TCP session's local address
/// (the container's 172.31.50.0/24 interface IP) by `prepare_outbound`, so
/// BIRD 2's RFC 4271 §5.1.3 reachability check passes without conflating the
/// router ID with the NEXT_HOP.
fn write_daemon_config_bird(peers: &[(Ipv4Addr, u32)]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord bird config");
    write!(
        f,
        r#"
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
hold_time = 9
grpc_port = {PATHVECTORD_GRPC_PORT}
"#
    )
    .expect("write pathvectord bird config header");

    for (ip, remote_as) in peers {
        write!(
            f,
            r#"
[[peers]]
address        = "{ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {remote_as}
import_default = "accept"
export_default = "accept"
"#
        )
        .expect("write pathvectord bird peer config");
    }
    f
}

/// Writes a BIRD 2 config file.
///
/// - `routes`: prefixes BIRD announces to pathvectord via a `protocol static`
///   (blackhole, exported with `next hop self`).  Pass `&[]` for session-only
///   tests.
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_bird_config(routes: &[&str], pathvectord_ip: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp bird config");
    write!(
        f,
        r#"
log stderr all;

# Opaque router ID — does not need to match the container IP.
router id 1.0.0.1;

# Required for BIRD to discover its own interfaces and next-hops.
protocol device {{}}

protocol bgp pathvectord {{
    description "pathvectord peer";
    local as 65001;
    neighbor {pathvectord_ip} as 65002;

    # passive: wait for pathvectord to connect; do not dial out.
    # pathvectord is configured to dial BIRD's IP, so only one side initiates.
    passive;

    ipv4 {{
        import all;
        export where source = RTS_STATIC;
        next hop self;
    }};
}}

protocol static {{
    ipv4;
"#
    )
    .expect("write bird config header");

    for route in routes {
        writeln!(f, "    route {route} blackhole;").expect("write bird static route");
    }

    writeln!(f, "}}").expect("write bird config footer");
    f
}

/// Polls `birdc show route` inside `container_id` until `prefix` appears.
///
/// # Errors
///
/// Returns `Err(String)` if `timeout` expires before the prefix appears.
pub async fn wait_for_bird_rib_entry(
    container_id: &str,
    prefix: &str,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "timed out waiting for prefix {prefix} to appear in BIRD RIB"
            ));
        }
        // "show route protocol pathvectord" lists all routes learned from the
        // pathvectord BGP session — each token is a separate argv element since
        // there's no shell expansion in docker exec.
        let out = Command::new("docker")
            .args([
                "exec",
                container_id,
                "birdc",
                "show",
                "route",
                "protocol",
                "pathvectord",
            ])
            .output();
        if let Ok(out) = out {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.contains(prefix) {
                return Ok(());
            }
        }
    }
}

/// Returns the NEXT_HOP (`via`) address for `prefix` in BIRD's RIB as seen by
/// the `pathvectord` protocol, or `None` if the route is not present.
///
/// Runs `birdc show route all protocol pathvectord` and parses the
/// `BGP.next_hop: <IP>` line that BIRD 2 emits in the detailed attribute dump.
/// This is the value BIRD stored from the UPDATE's NEXT_HOP attribute — exactly
/// what RFC 4271 §5.1.3 requires to be the session's local interface address.
#[must_use]
pub fn get_bird_next_hop(container_id: &str, prefix: &str) -> Option<std::net::Ipv4Addr> {
    let out = Command::new("docker")
        .args([
            "exec",
            container_id,
            "birdc",
            "show",
            "route",
            "all",
            "protocol",
            "pathvectord",
        ])
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&out.stdout);

    // Only look at lines that belong to the target prefix block.
    // BIRD output groups lines under the prefix header; we scan for
    // `BGP.next_hop:` after we've seen the prefix header line.
    let mut in_prefix = false;
    for line in text.lines() {
        if line.contains(prefix) {
            in_prefix = true;
        }
        // A new non-indented line that doesn't start with whitespace signals
        // the start of a different prefix block.
        if in_prefix && !line.starts_with('\t') && !line.starts_with(' ') && !line.contains(prefix)
        {
            in_prefix = false;
        }
        if in_prefix {
            // `\tBGP.next_hop: 172.31.50.20`
            if let Some(rest) = line.trim().strip_prefix("BGP.next_hop:") {
                return rest.trim().parse().ok();
            }
        }
    }
    None
}

/// A fully-wired test environment: isolated Docker network + BIRD 2 container +
/// `pathvectord` container + connected [`PathvectorClient`], with the BGP
/// session already `Established`.
///
/// Both containers are assigned fixed IPs within a per-test subnet so
/// BIRD's config can name pathvectord's IP before either container starts.
///
/// All resources (containers, network) are cleaned up when `BirdHarness` drops.
///
/// # Panics
///
/// [`BirdHarness::new`] panics if:
/// - Docker is not running.
/// - Either image has not been built (run `just e2e-images`).
/// - The BGP session does not reach `Established` within 30 seconds.
pub struct BirdHarness {
    // Containers must drop before the network (declaration order = drop order).
    _bird: ContainerGuard,
    _pathvectord: ContainerGuard,
    _bird_config: NamedTempFile,
    _pathvectord_config: NamedTempFile,
    pub client: PathvectorClient,
    /// Container ID of the BIRD container — pass to [`wait_for_bird_rib_entry`].
    pub bird_id: String,
    /// The BIRD container's IP on the shared network.
    pub bird_ip: Ipv4Addr,
    /// The pathvectord container's IP on the shared network.
    /// This is the eBGP session-local address and therefore the NEXT_HOP
    /// pathvectord advertises to BIRD (RFC 4271 §5.1.3).
    pub pathvectord_ip: Ipv4Addr,
    _network: DockerNetwork,
}

impl BirdHarness {
    /// Stand up the environment with no pre-announced static routes.
    ///
    /// Use this for session-lifecycle tests that only need the handshake.
    pub async fn new() -> Self {
        Self::with_routes(&[]).await
    }

    /// Stand up the environment with BIRD pre-announcing `routes` to pathvectord.
    ///
    /// Each entry in `routes` is a CIDR prefix (e.g. `"10.100.0.0/24"`) that
    /// BIRD installs as a static blackhole route and exports to pathvectord via
    /// `next hop self`.
    ///
    /// # Panics
    ///
    /// Panics if Docker is not running, either image is missing (run `just
    /// e2e-images`), or the BGP session does not reach `Established` within 30 s.
    pub async fn with_routes(routes: &[&str]) -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();
        let network_name = format!("pathvector-bird-test-{test_id}");

        // Per-test IPs derived from test_id so concurrent tests get
        // non-overlapping subnets (Docker rejects duplicate subnets).
        let subnet = bird_test_subnet(test_id);
        let bird_ip_str = bird_ip(test_id);
        let pv_ip_str = bird_pathvectord_ip(test_id);

        let network = DockerNetwork::create_with_subnet(network_name.clone(), &subnet);

        // Write BIRD config — pathvectord's IP is known (fixed) before either
        // container starts, so we can set `neighbor <pv_ip>` now.
        let bird_config = write_bird_config(routes, &pv_ip_str);
        let bird_config_path = bird_config.path().to_str().unwrap().to_owned();

        // Start BIRD with its fixed IP and the config mounted.
        let bird = docker_start(
            &format!("bird-{test_id}"),
            BIRD_IMAGE,
            &network_name,
            Some(&bird_ip_str),
            false,
            &bird_config_path,
            "/etc/bird/bird.conf",
            None,
            None,
        );

        // Wait for BIRD's healthcheck (control socket live, `birdc show status` OK).
        wait_container_healthy(&bird.0, Duration::from_secs(30));

        // Write pathvectord config referencing BIRD's per-test IP.
        // bgp_id = pv_ip so the eBGP NEXT_HOP is directly reachable from BIRD.
        let pathvectord_config = write_daemon_config_bird(&[(bird_ip_str.parse().unwrap(), 65001)]);
        let pathvectord_config_path = pathvectord_config.path().to_str().unwrap().to_owned();

        // Start pathvectord with its fixed IP, mapping gRPC to the host.
        let pathvectord = docker_start(
            &format!("pathvectord-bird-{test_id}"),
            PATHVECTORD_IMAGE,
            &network_name,
            Some(&pv_ip_str),
            false,
            &pathvectord_config_path,
            "/etc/pathvectord.toml",
            Some(grpc_host_port),
            Some("/etc/pathvectord.toml"),
        );

        let mut client = PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("PathvectorClient::connect for BirdHarness");

        let bird_ip: Ipv4Addr = bird_ip_str.parse().unwrap();
        wait_for_established(&mut client, bird_ip, Duration::from_secs(30))
            .await
            .expect("BGP session with BIRD 2 did not reach Established within 30 s");

        let container_id = bird.0.clone();
        BirdHarness {
            _bird: bird,
            _pathvectord: pathvectord,
            _bird_config: bird_config,
            _pathvectord_config: pathvectord_config,
            client,
            bird_id: container_id,
            bird_ip,
            pathvectord_ip: pv_ip_str.parse().unwrap(),
            _network: network,
        }
    }
}

// ── FrrHarness ────────────────────────────────────────────────────────────────

/// FRRouting image built by `just e2e-images` from `e2e/Dockerfile.frr`.
pub const FRR_IMAGE: &str = "pathvector-frr-test";

/// Derives the per-test FRR subnet and fixed IPs from `test_id`.
///
/// Uses `172.31.{id % 256}.0/24` offset by 128 to avoid colliding with BIRD
/// test subnets when both harnesses run concurrently.
#[must_use]
pub fn frr_test_subnet(test_id: u32) -> String {
    let third = (test_id + 128) % 256;
    format!("172.31.{third}.0/24")
}

#[must_use]
pub fn frr_peer_ip(test_id: u32) -> String {
    let third = (test_id + 128) % 256;
    format!("172.31.{third}.10")
}

#[must_use]
pub fn frr_pathvectord_ip(test_id: u32) -> String {
    let third = (test_id + 128) % 256;
    format!("172.31.{third}.20")
}

/// Writes a minimal FRR bgpd config with Graceful Restart enabled.
///
/// Identical to [`write_frr_config`] but adds `neighbor X graceful-restart` so
/// that FRR actively parses and exposes the peer's GR capability state, including
/// the Restart State (R) bit, via `show bgp neighbors`.
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_frr_config_gr(pathvectord_ip: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp frr GR config");
    write!(
        f,
        "
frr defaults traditional

router bgp 65001
 bgp router-id 1.0.0.1
 no bgp ebgp-requires-policy
 no bgp network import-check
 neighbor {pathvectord_ip} remote-as 65002
 neighbor {pathvectord_ip} passive
 neighbor {pathvectord_ip} graceful-restart
 !
 address-family ipv4 unicast
  neighbor {pathvectord_ip} activate
  neighbor {pathvectord_ip} next-hop-self
 exit-address-family
exit
"
    )
    .expect("write frr GR config");
    f
}

/// Writes a minimal FRR bgpd config.
///
/// `routes`: prefixes FRR announces to pathvectord via `network` statements.
/// Pass `&[]` for session-only tests.
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_frr_config(routes: &[&str], pathvectord_ip: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp frr config");
    write!(
        f,
        "
frr defaults traditional

router bgp 65001
 bgp router-id 1.0.0.1
 no bgp ebgp-requires-policy
 no bgp network import-check
 neighbor {pathvectord_ip} remote-as 65002
 neighbor {pathvectord_ip} passive
 !
 address-family ipv4 unicast
  neighbor {pathvectord_ip} activate
  neighbor {pathvectord_ip} next-hop-self
"
    )
    .expect("write frr config header");

    for route in routes {
        writeln!(f, "  network {route}").expect("write frr network statement");
    }

    writeln!(f, " exit-address-family\nexit").expect("write frr config footer");
    f
}

/// Polls `vtysh -c "show bgp ipv4 unicast <prefix>"` until `prefix` appears.
///
/// # Errors
///
/// Returns `Err(String)` if `timeout` expires before the prefix appears.
pub async fn wait_for_frr_rib_entry(
    container_id: &str,
    prefix: &str,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "timed out waiting for prefix {prefix} to appear in FRR RIB"
            ));
        }
        let output = Command::new("docker")
            .args([
                "exec",
                container_id,
                "vtysh",
                "-c",
                &format!("show bgp ipv4 unicast {prefix}"),
            ])
            .output();
        if let Ok(o) = output {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if o.status.success() && stdout.contains(prefix) && !stdout.contains("not found") {
                return Ok(());
            }
        }
    }
}

/// Extracts the NEXT_HOP FRR stores for `prefix` from `vtysh show bgp` output.
///
/// Returns `None` if the prefix is absent or the next-hop line cannot be parsed.
#[must_use]
pub fn get_frr_next_hop(container_id: &str, prefix: &str) -> Option<std::net::Ipv4Addr> {
    let output = Command::new("docker")
        .args([
            "exec",
            container_id,
            "vtysh",
            "-c",
            &format!("show bgp ipv4 unicast {prefix}"),
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    // FRR's "show bgp ipv4 unicast <prefix>" output contains a line like:
    //   "    172.31.128.20 from 172.31.128.20 (10.0.0.2)"
    // The first token on the indented peer-path line is the NEXT_HOP.
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.contains(" from ") && !trimmed.starts_with("BGP") {
            let ip_str = trimmed.split_whitespace().next()?;
            if let Ok(addr) = ip_str.parse::<std::net::Ipv4Addr>() {
                // Skip 0.0.0.0 (locally originated routes have no real nexthop)
                if !addr.is_unspecified() {
                    return Some(addr);
                }
            }
        }
    }
    None
}

fn write_daemon_config_frr(peers: &[(Ipv4Addr, u32)]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord frr config");
    write!(
        f,
        r#"
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
hold_time = 9
grpc_port = {PATHVECTORD_GRPC_PORT}
"#
    )
    .expect("write pathvectord frr config header");

    for (ip, remote_as) in peers {
        write!(
            f,
            r#"
[[peers]]
address        = "{ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {remote_as}
import_default = "accept"
export_default = "accept"
"#
        )
        .expect("write pathvectord frr peer config");
    }
    f
}

/// Writes an FRR bgpd config with RFC 8538 N-bit (`graceful-restart notification`).
///
/// `routes`: prefixes FRR announces to pathvectord via `network` statements.
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_frr_config_gr_notification(
    routes: &[&str],
    pathvectord_ip: &str,
    restart_secs: u16,
) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp frr RFC8538 config");
    write!(
        f,
        "
frr defaults traditional

router bgp 65001
 bgp router-id 1.0.0.1
 no bgp ebgp-requires-policy
 no bgp network import-check
 bgp graceful-restart restart-time {restart_secs}
 neighbor {pathvectord_ip} remote-as 65002
 neighbor {pathvectord_ip} passive
 neighbor {pathvectord_ip} graceful-restart
 neighbor {pathvectord_ip} graceful-restart-notification
 !
 address-family ipv4 unicast
  neighbor {pathvectord_ip} activate
  neighbor {pathvectord_ip} next-hop-self
"
    )
    .expect("write frr RFC8538 config header");

    for route in routes {
        writeln!(f, "  network {route}").expect("write frr network statement");
    }

    writeln!(f, " exit-address-family\nexit").expect("write frr config footer");
    f
}

/// Pathvectord config with `graceful_restart_time` for FRR RFC 8538 tests.
///
/// # Panics
///
/// Panics if the temporary file cannot be created or written.
#[must_use]
pub fn write_daemon_config_frr_gr_notification(
    peers: &[(Ipv4Addr, u32)],
    restart_time: u16,
) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord FRR RFC8538 config");
    write!(
        f,
        r#"
[daemon]
local_as              = 65002
bgp_id                = "10.0.0.2"
hold_time             = 9
grpc_port             = {PATHVECTORD_GRPC_PORT}
graceful_restart_time = {restart_time}
"#
    )
    .expect("write pathvectord FRR RFC8538 config header");

    for (ip, remote_as) in peers {
        write!(
            f,
            r#"
[[peers]]
address        = "{ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {remote_as}
import_default = "accept"
export_default = "accept"
"#
        )
        .expect("write pathvectord FRR RFC8538 peer config");
    }
    f
}

fn write_daemon_config_frr_gr_restarting(
    peers: &[(Ipv4Addr, u32)],
    restart_time: u16,
) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp pathvectord frr GR restarting config");
    write!(
        f,
        r#"
[daemon]
local_as              = 65002
bgp_id                = "10.0.0.2"
hold_time             = 9
grpc_port             = {PATHVECTORD_GRPC_PORT}
graceful_restart_time = {restart_time}
restarting            = true
"#
    )
    .expect("write pathvectord frr GR restarting config header");

    for (ip, remote_as) in peers {
        write!(
            f,
            r#"
[[peers]]
address        = "{ip}"
port           = {GOBGPD_BGP_PORT}
remote_as      = {remote_as}
import_default = "accept"
export_default = "accept"
"#
        )
        .expect("write pathvectord frr GR restarting peer config");
    }
    f
}

/// A fully-wired test environment: isolated Docker network + FRR container +
/// `pathvectord` container + connected [`PathvectorClient`], with the BGP
/// session already `Established`.
///
/// All resources (containers, network) are cleaned up when `FrrHarness` drops.
pub struct FrrHarness {
    // Containers must drop before the network (declaration order = drop order).
    _frr: ContainerGuard,
    _pathvectord: ContainerGuard,
    _frr_config: NamedTempFile,
    _pathvectord_config: NamedTempFile,
    pub client: PathvectorClient,
    /// Container ID of the FRR container — pass to [`wait_for_frr_rib_entry`].
    pub frr_id: String,
    /// Container ID of the pathvectord container.
    pub pathvectord_id: String,
    /// The FRR container's IP on the shared network.
    pub frr_ip: Ipv4Addr,
    /// The pathvectord container's IP on the shared network.
    pub pathvectord_ip: Ipv4Addr,
    _network: DockerNetwork,
}

impl FrrHarness {
    /// Stand up the environment with no pre-announced routes.
    pub async fn new() -> Self {
        Self::with_routes(&[]).await
    }

    /// Both FRR and pathvectord configured with N-bit and `restart_time` for
    /// RFC 8538 notification-mode testing.
    ///
    /// FRR uses `neighbor X graceful-restart-notification` (RFC 8538 N-bit).
    /// pathvectord uses `graceful_restart_time = restart_secs` (sets N-bit too).
    ///
    /// # Panics
    ///
    /// Panics if any Docker or network setup step fails.
    pub async fn new_rfc8538_gr(routes: &'static [&'static str], restart_secs: u16) -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();
        let network_name = format!("pathvector-frr-rfc8538-{test_id}");

        let subnet = frr_test_subnet(test_id);
        let frr_ip_str = frr_peer_ip(test_id);
        let pv_ip_str = frr_pathvectord_ip(test_id);

        let network = DockerNetwork::create_with_subnet(network_name.clone(), &subnet);

        let frr_config = write_frr_config_gr_notification(routes, &pv_ip_str, restart_secs);
        let frr_config_path = frr_config.path().to_str().unwrap().to_owned();

        let frr = docker_start_with_caps(
            &format!("frr-rfc8538-{test_id}"),
            FRR_IMAGE,
            &network_name,
            Some(&frr_ip_str),
            true,
            true,
            &frr_config_path,
            "/etc/frr/frr.conf",
            None,
            None,
        );

        wait_container_healthy(&frr.0, Duration::from_secs(60));

        let pathvectord_config = {
            let frr_ip: Ipv4Addr = frr_ip_str.parse().unwrap();
            write_daemon_config_frr_gr_notification(&[(frr_ip, 65001)], restart_secs)
        };
        let pathvectord_config_path = pathvectord_config.path().to_str().unwrap().to_owned();

        let pathvectord = docker_start(
            &format!("pathvectord-frr-rfc8538-{test_id}"),
            PATHVECTORD_IMAGE,
            &network_name,
            Some(&pv_ip_str),
            false,
            &pathvectord_config_path,
            "/etc/pathvectord.toml",
            Some(grpc_host_port),
            Some("/etc/pathvectord.toml"),
        );

        let mut client = PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("PathvectorClient::connect for FrrHarness::new_rfc8538_gr");

        let frr_ip: Ipv4Addr = frr_ip_str.parse().unwrap();
        wait_for_established(&mut client, frr_ip, Duration::from_secs(30))
            .await
            .expect("BGP session with FRR (RFC 8538) did not reach Established within 30 s");

        let frr_container_id = frr.0.clone();
        let pv_container_id = pathvectord.0.clone();
        FrrHarness {
            _frr: frr,
            _pathvectord: pathvectord,
            _frr_config: frr_config,
            _pathvectord_config: pathvectord_config,
            client,
            frr_id: frr_container_id,
            pathvectord_id: pv_container_id,
            frr_ip,
            pathvectord_ip: pv_ip_str.parse().unwrap(),
            _network: network,
        }
    }

    /// Stand up pathvectord with `graceful_restart_time` set and `restarting = true`,
    /// against an FRR peer configured with `neighbor X graceful-restart`.
    ///
    /// FRR will actively parse pathvectord's GracefulRestart capability (including the
    /// Restart State R-bit) and expose it via `show bgp neighbors <addr>`.
    /// Use this harness to verify the R-bit reaches FRR correctly.
    ///
    /// # Panics
    ///
    /// Panics if Docker is not running, the images are missing, or the session does
    /// not reach `Established` within 30 s.
    pub async fn new_gr_restarting(restart_secs: u16) -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();
        let network_name = format!("pathvector-frr-gr-test-{test_id}");

        let subnet = frr_test_subnet(test_id);
        let frr_ip_str = frr_peer_ip(test_id);
        let pv_ip_str = frr_pathvectord_ip(test_id);

        let network = DockerNetwork::create_with_subnet(network_name.clone(), &subnet);

        let frr_config = write_frr_config_gr(&pv_ip_str);
        let frr_config_path = frr_config.path().to_str().unwrap().to_owned();

        let frr = docker_start_with_caps(
            &format!("frr-gr-{test_id}"),
            FRR_IMAGE,
            &network_name,
            Some(&frr_ip_str),
            true,
            true,
            &frr_config_path,
            "/etc/frr/frr.conf",
            None,
            None,
        );

        wait_container_healthy(&frr.0, Duration::from_secs(60));

        let pathvectord_config = {
            let frr_ip: Ipv4Addr = frr_ip_str.parse().unwrap();
            write_daemon_config_frr_gr_restarting(&[(frr_ip, 65001)], restart_secs)
        };
        let pathvectord_config_path = pathvectord_config.path().to_str().unwrap().to_owned();

        let pathvectord = docker_start(
            &format!("pathvectord-frr-gr-{test_id}"),
            PATHVECTORD_IMAGE,
            &network_name,
            Some(&pv_ip_str),
            false,
            &pathvectord_config_path,
            "/etc/pathvectord.toml",
            Some(grpc_host_port),
            Some("/etc/pathvectord.toml"),
        );

        let mut client = PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("PathvectorClient::connect for FrrHarness::new_gr_restarting");

        let frr_ip: Ipv4Addr = frr_ip_str.parse().unwrap();
        wait_for_established(&mut client, frr_ip, Duration::from_secs(30))
            .await
            .expect("BGP session with FRR (GR restarting) did not reach Established within 30 s");

        let frr_container_id = frr.0.clone();
        let pv_container_id = pathvectord.0.clone();
        FrrHarness {
            _frr: frr,
            _pathvectord: pathvectord,
            _frr_config: frr_config,
            _pathvectord_config: pathvectord_config,
            client,
            frr_id: frr_container_id,
            pathvectord_id: pv_container_id,
            frr_ip,
            pathvectord_ip: pv_ip_str.parse().unwrap(),
            _network: network,
        }
    }

    /// Stand up the environment with FRR pre-announcing `routes` to pathvectord.
    ///
    /// Each entry in `routes` is a CIDR prefix (e.g. `"10.100.0.0/24"`) that
    /// FRR announces via a `network` statement in its bgpd config.
    ///
    /// # Panics
    ///
    /// Panics if Docker is not running, the FRR image is missing (run `just
    /// e2e-images`), or the BGP session does not reach `Established` within 30 s.
    pub async fn with_routes(routes: &[&str]) -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();
        let network_name = format!("pathvector-frr-test-{test_id}");

        let subnet = frr_test_subnet(test_id);
        let frr_ip_str = frr_peer_ip(test_id);
        let pv_ip_str = frr_pathvectord_ip(test_id);

        let network = DockerNetwork::create_with_subnet(network_name.clone(), &subnet);

        let frr_config = write_frr_config(routes, &pv_ip_str);
        let frr_config_path = frr_config.path().to_str().unwrap().to_owned();

        let frr = docker_start_with_caps(
            &format!("frr-{test_id}"),
            FRR_IMAGE,
            &network_name,
            Some(&frr_ip_str),
            true, // NET_ADMIN for BGP socket binding
            true, // privileged: bgpd requires CAP_SYS_ADMIN for netlink
            &frr_config_path,
            "/etc/frr/frr.conf",
            None,
            None,
        );

        wait_container_healthy(&frr.0, Duration::from_secs(60));

        let pathvectord_config = write_daemon_config_frr(&[(frr_ip_str.parse().unwrap(), 65001)]);
        let pathvectord_config_path = pathvectord_config.path().to_str().unwrap().to_owned();

        let pathvectord = docker_start(
            &format!("pathvectord-frr-{test_id}"),
            PATHVECTORD_IMAGE,
            &network_name,
            Some(&pv_ip_str),
            false,
            &pathvectord_config_path,
            "/etc/pathvectord.toml",
            Some(grpc_host_port),
            Some("/etc/pathvectord.toml"),
        );

        let mut client = PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("PathvectorClient::connect for FrrHarness");

        let frr_ip: Ipv4Addr = frr_ip_str.parse().unwrap();
        wait_for_established(&mut client, frr_ip, Duration::from_secs(30))
            .await
            .expect("BGP session with FRR did not reach Established within 30 s");

        let frr_container_id = frr.0.clone();
        let pv_container_id = pathvectord.0.clone();
        FrrHarness {
            _frr: frr,
            _pathvectord: pathvectord,
            _frr_config: frr_config,
            _pathvectord_config: pathvectord_config,
            client,
            frr_id: frr_container_id,
            pathvectord_id: pv_container_id,
            frr_ip,
            pathvectord_ip: pv_ip_str.parse().unwrap(),
            _network: network,
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────
//
// These tests cover the pure path-calculation helpers that do not require
// Docker.  They are intentionally lightweight — just enough to execute the
// code paths that the e2e Docker harness is the only other caller of.
//
// Note: `std::env::set_var` / `remove_var` require `unsafe` on Rust 1.86+,
// and this crate forbids unsafe code.  The `CARGO_TARGET_DIR` override branch
// is therefore only exercised by the Docker harness itself, not here.

// ── DynamicPeerHarness ────────────────────────────────────────────────────────

/// A test environment where `pathvectord` starts with **no** statically
/// configured peers and a `gobgpd` container is available for dynamic
/// peer tests.
///
/// Unlike [`Harness`], no BGP session is pre-established — tests call
/// [`pathvector_client::DaemonClient::add_peer`] themselves and then poll
/// [`wait_for_established`] to confirm the session came up.
///
/// All resources are cleaned up on drop.
///
/// # Panics
///
/// [`DynamicPeerHarness::new`] panics if Docker is not running or either
/// image has not been built (`just e2e`).
pub struct DynamicPeerHarness {
    _gobgpd: ContainerAsync<GenericImage>,
    _pathvectord: ContainerAsync<GenericImage>,
    _gobgpd_config: NamedTempFile,
    _pathvectord_config: NamedTempFile,
    pub client: PathvectorClient,
    /// IP address that `gobgpd` occupies on the shared Docker bridge network.
    /// Pass this to `add_peer` as the peer address.
    pub gobgp_ip: Ipv4Addr,
    /// Container ID of `gobgpd` — used for `gobgp_announce` / `gobgp_withdraw`.
    pub gobgpd_id: String,
    _network: DockerNetwork,
}

impl DynamicPeerHarness {
    /// Stand up `gobgpd` (passive, AS 65001) and `pathvectord` (AS 65002)
    /// with **no** static peer configuration.
    ///
    /// Returns immediately once both containers are healthy — no BGP session
    /// is awaited.
    ///
    /// # Panics
    ///
    /// Panics if Docker is not running or either image is missing.
    pub async fn new() -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();

        let network_name = format!("pathvector-dynamic-test-{test_id}");
        let network = DockerNetwork::create(network_name.clone());

        let gobgpd_config = write_gobgp_config();
        let gobgpd_config_path = gobgpd_config.path().to_str().unwrap().to_owned();

        let gobgpd = GenericImage::new(GOBGPD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_network(&network_name)
            .with_container_name(format!("gobgpd-dynamic-{test_id}"))
            .with_mount(Mount::bind_mount(
                gobgpd_config_path,
                "/etc/gobgp/gobgpd.conf",
            ))
            .start()
            .await
            .expect("start gobgpd container for DynamicPeerHarness");

        let gobgpd_id = gobgpd.id().to_owned();
        let gobgp_ip = container_network_ip(&gobgpd_id, &network_name);

        // pathvectord config with no peers — dynamic adds will add them at runtime.
        let pathvectord_config = write_daemon_config(&[]);
        let pathvectord_config_path = pathvectord_config.path().to_str().unwrap().to_owned();

        let pathvectord = GenericImage::new(PATHVECTORD_IMAGE, "latest")
            .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::default()))
            .with_cmd(["/etc/pathvectord.toml"])
            .with_network(&network_name)
            .with_container_name(format!("pathvectord-dynamic-{test_id}"))
            .with_mapped_port(grpc_host_port, ContainerPort::Tcp(PATHVECTORD_GRPC_PORT))
            .with_mount(Mount::bind_mount(
                pathvectord_config_path,
                "/etc/pathvectord.toml",
            ))
            .start()
            .await
            .expect("start pathvectord container for DynamicPeerHarness");

        let client = PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("connect PathvectorClient for DynamicPeerHarness");

        Self {
            _gobgpd: gobgpd,
            _pathvectord: pathvectord,
            _gobgpd_config: gobgpd_config,
            _pathvectord_config: pathvectord_config,
            client,
            gobgp_ip,
            gobgpd_id,
            _network: network,
        }
    }

    /// Announce an IPv4 prefix from the GoBGP container into pathvectord's
    /// Adj-RIB-In.
    ///
    /// # Panics
    ///
    /// Panics if `docker exec` fails or the command exits non-zero.
    pub fn gobgp_announce(&self, prefix: &str, nexthop: &str) {
        let status = Command::new("docker")
            .args(["exec", &self.gobgpd_id])
            .args([
                "gobgp", "global", "rib", "add", prefix, "nexthop", nexthop, "origin", "igp",
            ])
            .status()
            .expect("docker exec gobgp announce");
        assert!(status.success(), "gobgp announce {prefix} failed: {status}");
    }

    /// Withdraw an IPv4 prefix from the GoBGP container's RIB.
    ///
    /// # Panics
    ///
    /// Panics if `docker exec` fails or the command exits non-zero.
    pub fn gobgp_withdraw(&self, prefix: &str) {
        let status = Command::new("docker")
            .args(["exec", &self.gobgpd_id])
            .args(["gobgp", "global", "rib", "del", prefix])
            .status()
            .expect("docker exec gobgp withdraw");
        assert!(status.success(), "gobgp withdraw {prefix} failed: {status}");
    }
}

/// Polls `list_peers` until the peer with `address` is absent (i.e., not
/// returned by the daemon), then returns `Ok(())`.
///
/// Use this after calling `remove_peer` to confirm teardown completed.
///
/// # Errors
///
/// Returns `Err(String)` if `timeout` expires before the peer disappears.
pub async fn wait_for_peer_absent(
    client: &mut PathvectorClient,
    address: Ipv4Addr,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "timed out waiting for peer {address} to be removed from list_peers"
            ));
        }
        if let Ok(peers) = client.list_peers().await {
            let target = IpAddr::V4(address);
            if !peers.iter().any(|p| p.address == target) {
                return Ok(());
            }
        }
        // gRPC call failed — daemon may be restarting; keep polling.
    }
}

#[cfg(test)]
mod tests {
    use super::{daemon_binary, target_dir, workspace_root};

    /// `workspace_root()` resolves `env!("CARGO_MANIFEST_DIR").parent()`, which
    /// must be the directory that owns the workspace `Cargo.toml`.
    #[test]
    fn workspace_root_contains_cargo_toml() {
        let root = workspace_root();
        assert!(
            root.join("Cargo.toml").exists(),
            "workspace root must contain Cargo.toml — got {root:?}"
        );
    }

    /// `target_dir()` returns a `PathBuf` whose last component is `target`
    /// when `CARGO_TARGET_DIR` is not set (the standard `cargo test` env).
    #[test]
    fn target_dir_has_target_component() {
        // In a normal `cargo test` run CARGO_TARGET_DIR is unset, so the
        // map_or_else Err-branch fires — covering the default path.
        // If CARGO_TARGET_DIR happens to be set, the Ok-branch fires instead;
        // either way the function executes and its lines are covered.
        let dir = target_dir();
        let has_target = dir.components().any(|c| c.as_os_str() == "target");
        let has_override = std::env::var("CARGO_TARGET_DIR").is_ok();
        assert!(
            has_target || has_override,
            "target_dir must contain a 'target' component unless overridden — got {dir:?}"
        );
    }

    /// `daemon_binary()` always appends `debug/pathvectord` to `target_dir()`.
    #[test]
    fn daemon_binary_ends_with_debug_pathvectord() {
        let bin = daemon_binary();
        assert!(
            bin.ends_with("debug/pathvectord"),
            "daemon_binary must end with debug/pathvectord — got {bin:?}"
        );
    }
}
