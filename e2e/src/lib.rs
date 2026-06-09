//! Test harness for pathvector end-to-end tests.
//!
//! Each test creates a [`Harness`], which:
//!
//! 1. Starts a GoBGP container (via testcontainers) with a static config that
//!    accepts any incoming AS 65002 connection (dynamic neighbors).
//! 2. Spawns a `pathvectord` subprocess configured to dial the container's
//!    mapped BGP port on `127.0.0.1`.
//! 3. Polls [`PathvectorClient::get_peer`] until the session reaches
//!    `Established` — no fixed sleeps anywhere.
//!
//! Dropping a [`Harness`] kills the daemon subprocess and lets testcontainers
//! stop the container.

use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};

use pathvector_client::{
    PathvectorClient,
    types::{Route, SessionState},
};
use tempfile::NamedTempFile;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{ExecCommand, WaitFor},
    runners::AsyncRunner,
};

// ── Port allocation ───────────────────────────────────────────────────────────

/// Atomically-allocated gRPC port base.  Tests must run with `--test-threads=1`
/// to avoid races, but the counter provides a safety net.
static NEXT_GRPC_PORT: AtomicU16 = AtomicU16::new(51_200);

fn alloc_grpc_port() -> u16 {
    NEXT_GRPC_PORT.fetch_add(1, Ordering::Relaxed)
}

// ── Binary path ───────────────────────────────────────────────────────────────

/// Resolves the path to the `pathvectord` binary built by `just e2e`.
///
/// `just e2e` runs `cargo build -p pathvectord` before executing tests, so
/// `target/debug/pathvectord` is always up to date when this is called.
///
/// # Panics
///
/// Panics if `CARGO_MANIFEST_DIR` does not have a parent directory (which
/// would mean the `e2e/` crate is not inside a workspace).
pub fn daemon_binary() -> PathBuf {
    // CARGO_MANIFEST_DIR is e2e/ — go up one level to reach the workspace root.
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("e2e/ must be inside the workspace")
        .to_owned();

    // Respect CARGO_TARGET_DIR when set; otherwise use the default target/.
    let target =
        std::env::var("CARGO_TARGET_DIR").map_or_else(|_| workspace.join("target"), PathBuf::from);

    target.join("debug").join("pathvectord")
}

// ── GoBGP container ───────────────────────────────────────────────────────────

/// Path inside the container where GoBGP reads its config.
const GOBGP_CONFIG_PATH: &str = "/etc/gobgp/gobgpd.conf";

/// GoBGP Docker image.  Pin the digest in production; `latest` is fine for
/// local development and CI where we accept slow drift.
const GOBGP_IMAGE: &str = "osrg/gobgp";
const GOBGP_TAG: &str = "latest";

async fn start_gobgp() -> ContainerAsync<GenericImage> {
    let config_bytes = include_bytes!("../fixtures/gobgp.toml").to_vec();

    // `with_wait_for` and `with_exposed_port` are `GenericImage` methods and
    // must be called before the `ImageExt` methods (`with_copy_to`, `with_cmd`)
    // which consume `GenericImage` into `ContainerRequest<GenericImage>`.
    GenericImage::new(GOBGP_IMAGE, GOBGP_TAG)
        .with_wait_for(WaitFor::seconds(2))
        .with_copy_to(GOBGP_CONFIG_PATH, config_bytes)
        .with_cmd(["gobgpd", "-f", GOBGP_CONFIG_PATH, "--log-level", "warn"])
        .start()
        .await
        .expect("GoBGP container failed to start — is Docker running?")
}

// ── pathvectord subprocess ────────────────────────────────────────────────────

/// Writes a `pathvectord` config to a temporary file.
///
/// The returned [`NamedTempFile`] must be kept alive for the lifetime of the
/// `pathvectord` subprocess; dropping it removes the file from disk.
fn write_daemon_config(bgp_port: u16, grpc_port: u16) -> NamedTempFile {
    use std::io::Write as _;

    let mut f = NamedTempFile::new().expect("create temp config");
    write!(
        f,
        r#"
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
hold_time = 9
grpc_port = {grpc_port}

[[peers]]
address        = "127.0.0.1"
port           = {bgp_port}
remote_as      = 65001
import_default = "accept"
export_default = "accept"
"#
    )
    .expect("write config");
    f
}

/// A running `pathvectord` subprocess that is killed on drop.
pub struct DaemonProcess {
    child: Child,
    // Keep the temp file alive for as long as the subprocess runs.
    _config: NamedTempFile,
}

impl DaemonProcess {
    fn spawn(config: NamedTempFile) -> Self {
        let bin = daemon_binary();
        assert!(
            bin.exists(),
            "pathvectord binary not found at {} — run `just e2e` to build it first",
            bin.display()
        );

        let child = Command::new(&bin)
            .arg(config.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", bin.display()));

        Self {
            child,
            _config: config,
        }
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

// ── Polling helpers ───────────────────────────────────────────────────────────

/// Polls until the BGP session with `peer` reaches `Established`.
///
/// Polls every 200 ms.
///
/// # Panics
///
/// Panics if the session does not reach `Established` within `timeout`.
pub async fn wait_for_established(
    client: &mut PathvectorClient,
    peer: Ipv4Addr,
    timeout: Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            tokio::time::Instant::now() <= deadline,
            "timed out waiting for BGP session to reach Established with {peer}"
        );
        if let Ok(p) = client.get_peer(IpAddr::V4(peer)).await
            && p.session_state == SessionState::Established
        {
            return;
        }
    }
}

/// Polls until the best route for `prefix` is present, then returns it.
///
/// Polls every 200 ms.
///
/// # Panics
///
/// Panics if the route does not appear within `timeout`.
pub async fn wait_for_route(
    client: &mut PathvectorClient,
    prefix: &str,
    timeout: Duration,
) -> Route {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            tokio::time::Instant::now() <= deadline,
            "timed out waiting for route {prefix} to appear in RIB"
        );
        if let Ok(Some(route)) = client.get_best_route(prefix).await {
            return route;
        }
    }
}

/// Polls until the best route for `prefix` is absent (withdrawn).
///
/// Polls every 200 ms.
///
/// # Panics
///
/// Panics if the route is not withdrawn within `timeout`.
pub async fn wait_for_route_withdrawn(
    client: &mut PathvectorClient,
    prefix: &str,
    timeout: Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            tokio::time::Instant::now() <= deadline,
            "timed out waiting for route {prefix} to be withdrawn from RIB"
        );
        if let Ok(None) = client.get_best_route(prefix).await {
            return;
        }
    }
}

// ── Harness ───────────────────────────────────────────────────────────────────

/// A fully-wired test environment: GoBGP container + `pathvectord` subprocess +
/// connected [`PathvectorClient`], with the BGP session already `Established`.
///
/// All resources are cleaned up when the `Harness` is dropped.
///
/// # Panics
///
/// [`Harness::new`] panics if:
/// - Docker is not running.
/// - The `pathvectord` binary has not been built (run `just e2e`).
/// - The BGP session does not reach `Established` within 15 seconds.
pub struct Harness {
    gobgp: ContainerAsync<GenericImage>,
    _daemon: DaemonProcess,
    pub client: PathvectorClient,
    /// IPv4 address of the GoBGP peer as seen by `pathvectord`.
    pub peer: Ipv4Addr,
}

impl Harness {
    /// Stand up the full environment and wait for the BGP session.
    ///
    /// # Panics
    ///
    /// See the struct-level documentation.
    pub async fn new() -> Self {
        let grpc_port = alloc_grpc_port();

        // 1. Start GoBGP container; get its mapped BGP port.
        let gobgp = start_gobgp().await;
        let bgp_port = gobgp
            .get_host_port_ipv4(179)
            .await
            .expect("GoBGP container did not expose port 179");

        // 2. Write pathvectord config and spawn subprocess.
        let config = write_daemon_config(bgp_port, grpc_port);
        let daemon = DaemonProcess::spawn(config);

        // 3. Give the daemon a moment to bind its gRPC port.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // 4. Connect the management client.
        let mut client =
            PathvectorClient::connect(format!("http://127.0.0.1:{grpc_port}")).unwrap();

        // 5. Wait for the BGP session.
        let peer = Ipv4Addr::LOCALHOST;
        wait_for_established(&mut client, peer, Duration::from_secs(15)).await;

        Self {
            gobgp,
            _daemon: daemon,
            client,
            peer,
        }
    }

    /// Announce a route from GoBGP into `pathvectord`'s RIB.
    ///
    /// Equivalent to:
    /// ```text
    /// gobgp global rib add <prefix> nexthop <nexthop>
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the `docker exec` call fails.
    pub async fn gobgp_announce(&self, prefix: &str, nexthop: &str) {
        let cmd = ExecCommand::new(["gobgp", "global", "rib", "add", prefix, "nexthop", nexthop]);
        self.gobgp
            .exec(cmd)
            .await
            .expect("gobgp announce exec failed");
    }

    /// Withdraw a route from GoBGP.
    ///
    /// # Panics
    ///
    /// Panics if the `docker exec` call fails.
    pub async fn gobgp_withdraw(&self, prefix: &str) {
        let cmd = ExecCommand::new(["gobgp", "global", "rib", "del", prefix]);
        self.gobgp
            .exec(cmd)
            .await
            .expect("gobgp withdraw exec failed");
    }
}
