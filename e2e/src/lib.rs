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
//! `just e2e` builds two images before running the suite:
//! - `pathvector-gobgpd-test:latest` — GoBGP from `e2e/Dockerfile`
//! - `pathvector-e2e:latest`         — pathvectord from `e2e/Dockerfile.pathvectord`

use std::{
    io::Write as _,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU16, AtomicU32, Ordering},
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

// ── Fixed container-internal ports ───────────────────────────────────────────

/// BGP listen port inside the gobgpd container.
pub const GOBGPD_BGP_PORT: u16 = 179;

/// gRPC management port inside the pathvectord container.
pub const PATHVECTORD_GRPC_PORT: u16 = 51_200;

// ── Port / ID allocation ──────────────────────────────────────────────────────

/// Per-test unique ID — used to name Docker networks and containers so
/// concurrent (or back-to-back) tests never collide.
static NEXT_TEST_ID: AtomicU32 = AtomicU32::new(0);

/// Host-side port base for pathvectord's gRPC mapping.
static NEXT_GRPC_PORT: AtomicU16 = AtomicU16::new(51_200);

pub fn alloc_test_id() -> u32 {
    NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn alloc_grpc_port() -> u16 {
    NEXT_GRPC_PORT.fetch_add(1, Ordering::Relaxed)
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

// ── Config generation ─────────────────────────────────────────────────────────

/// Writes the gobgpd config file for the test container.
///
/// The container uses port 179 (default; no `port =` key needed).
/// gRPC defaults to `0.0.0.0:50051` which is accessible via `docker exec`.
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

/// Writes a pathvectord config with TCP MD5 authentication on every peer.
///
/// Identical to [`write_daemon_config`] but adds `md5_password = "<key>"`
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

/// Fixed container IPs for TCP MD5SIG tests.
///
/// A dedicated subnet is used so both IPs are known before either container
/// starts — a prerequisite for pre-configuring `TCP_MD5SIG` on both sides.
pub const MD5_TEST_SUBNET: &str = "172.31.42.0/24";
pub const MD5_GOBGP_IP: &str = "172.31.42.10";
pub const MD5_PATHVECTORD_IP: &str = "172.31.42.20";

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

        let network = DockerNetwork::create_with_subnet(network_name.clone(), MD5_TEST_SUBNET);

        // Both IPs are known before either container starts — write configs now.
        let gobgpd_config = write_gobgp_config_md5(MD5_PATHVECTORD_IP, key);
        let gobgpd_config_path = gobgpd_config.path().to_str().unwrap().to_owned();

        let pathvectord_config =
            write_daemon_config_md5(&[(MD5_GOBGP_IP.parse().unwrap(), 65001)], key);
        let pathvectord_config_path = pathvectord_config.path().to_str().unwrap().to_owned();

        // Start GoBGP with a fixed IP and CAP_NET_ADMIN (needed for TCP_MD5SIG
        // on the listener socket).
        let gobgpd = docker_start(
            &format!("gobgpd-md5-{test_id}"),
            GOBGPD_IMAGE,
            &network_name,
            Some(MD5_GOBGP_IP),
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
            Some(MD5_PATHVECTORD_IP),
            true,
            &pathvectord_config_path,
            "/etc/pathvectord.toml",
            Some(grpc_host_port),
            Some("/etc/pathvectord.toml"),
        );

        let mut client =
            PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
                .expect("connect PathvectorClient for Md5Harness");

        wait_for_established(
            &mut client,
            MD5_GOBGP_IP.parse().unwrap(),
            Duration::from_secs(30),
        )
        .await
        .expect("MD5-authenticated BGP session did not reach Established within 30 s");

        Self {
            _gobgpd: gobgpd,
            _pathvectord: pathvectord,
            _gobgpd_config: gobgpd_config,
            _pathvectord_config: pathvectord_config,
            client,
            gobgp_ip: MD5_GOBGP_IP.parse().unwrap(),
            _network: network,
        }
    }
}

// ── Polling helpers ───────────────────────────────────────────────────────────

/// Polls until the BGP session with `peer` reaches `Established`.
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
    peer: Ipv4Addr,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "timed out waiting for BGP session to reach Established with {peer}"
            ));
        }
        if let Ok(p) = client.get_peer(IpAddr::V4(peer)).await
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
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "timed out waiting for route {prefix} to appear in RIB"
            ));
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
        Self::new_inner(write_daemon_config_v6).await
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

    /// Internal constructor — spins up one GoBGP + one pathvectord container.
    ///
    /// `make_cfg` is the config-writing function that produces the pathvectord
    /// TOML.  The caller chooses the policy variant.
    async fn new_inner(make_cfg: fn(&[(Ipv4Addr, u32)]) -> NamedTempFile) -> Self {
        let test_id = alloc_test_id();
        let grpc_host_port = alloc_grpc_port();

        // Create an isolated network for this test so containers from
        // different tests don't interfere.
        let network_name = format!("pathvector-test-{test_id}");
        let network = DockerNetwork::create(network_name.clone());

        // Write gobgpd config.
        let gobgpd_config = write_gobgp_config();
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

        Self {
            _gobgpd: gobgpd,
            _pathvectord: pathvectord,
            gobgpd_id: gobgpd_container_id,
            pathvectord_id: pathvectord_container_id,
            _gobgpd_config: gobgpd_config,
            _pathvectord_config: pathvectord_config,
            client,
            peer: gobgpd_ip,
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

// ── Unit tests ────────────────────────────────────────────────────────────────
//
// These tests cover the pure path-calculation helpers that do not require
// Docker.  They are intentionally lightweight — just enough to execute the
// code paths that the e2e Docker harness is the only other caller of.
//
// Note: `std::env::set_var` / `remove_var` require `unsafe` on Rust 1.86+,
// and this crate forbids unsafe code.  The `CARGO_TARGET_DIR` override branch
// is therefore only exercised by the Docker harness itself, not here.

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
