//! End-to-end tests for TCP MD5 authentication (RFC 2385).
//!
//! These tests verify that pathvectord correctly enforces TCP MD5SIG at the
//! kernel level.  Both containers run as Linux processes inside Docker and
//! require `CAP_NET_ADMIN` so the kernel accepts `setsockopt(TCP_MD5SIG)`.
//!
//! **CI note**: These tests run only in the `e2e` GitHub Actions job, which
//! builds the Docker images and provides a native Linux Docker environment
//! where `CAP_NET_ADMIN` works without additional configuration.
//!
//! **Docker Desktop cannot run them.** Its `LinuxKit` kernel is built without
//! `CONFIG_TCP_MD5SIG`, so `setsockopt(TCP_MD5SIG)` fails with `ENOPROTOOPT`.
//! Since issue #58 pathvectord treats that as "cannot enforce" and, with the
//! default `tcp_md5_enforcement = "required"`, refuses to connect instead of
//! running the session unauthenticated. All tests here therefore run only when
//! the `CI` environment variable is set (GitHub Actions sets it).

/// Returns `true` (after printing why) when this host cannot enforce TCP MD5.
fn skip_without_native_linux_md5(test: &str) -> bool {
    if std::env::var("CI").is_ok() {
        return false;
    }
    println!(
        "SKIP {test}: TCP_MD5SIG enforcement requires a native Linux Docker host \
         (Docker Desktop's kernel lacks CONFIG_TCP_MD5SIG). \
         Set CI=1 or run in GitHub Actions to enable."
    );
    true
}

use std::{net::IpAddr, time::Duration};

use pathvector_client::{DaemonClient, types::SessionState};
use pathvector_e2e::{
    DockerNetwork, GOBGPD_IMAGE, Md5Harness, Md5InboundHarness, PATHVECTORD_IMAGE, alloc_grpc_port,
    alloc_test_id, docker_start, wait_container_healthy, wait_for_established,
    write_daemon_config_md5, write_gobgp_config,
};

/// RFC 2385 §2.0 — when both sides share the same MD5 key the TCP connection
/// must complete and the BGP session must reach `Established`.
///
/// **Requires a native Linux Docker host** (see the module docs): with the
/// default `tcp_md5_enforcement = "required"`, pathvectord will not connect
/// on a kernel that cannot sign segments.
#[tokio::test]
async fn md5_matching_key_session_establishes() {
    if skip_without_native_linux_md5("md5_matching_key_session_establishes") {
        return;
    }
    let h = Md5Harness::new("bgp-test-key-2026").await;
    let mut c = h.client.clone();
    let peer = c
        .get_peer(IpAddr::V4(h.gobgp_ip))
        .await
        .expect("get_peer must succeed after Established");

    assert_eq!(
        peer.session_state,
        SessionState::Established,
        "BGP session must be Established when both sides share the same MD5 key"
    );
}

/// RFC 2385 §2.0 — when pathvectord is configured with an MD5 key but GoBGP is
/// not, pathvectord's kernel will add an MD5 option to every outbound TCP
/// segment.  GoBGP's kernel has no key for pathvectord's IP and will drop the
/// SYN.  The BGP session must never reach `Established`.
///
/// This test uses the **existing dynamic-neighbor GoBGP config** (no MD5) and
/// starts pathvectord with `md5_password` configured.  Only pathvectord needs
/// `CAP_NET_ADMIN` here — GoBGP's container runs with its normal privileges.
///
/// **Requires a native Linux Docker host** (see the module docs). On Docker
/// Desktop the session would also never establish, but because pathvectord
/// refuses to connect at all, which proves nothing about the peer's kernel
/// dropping signed segments.
#[tokio::test]
async fn md5_key_mismatch_session_never_establishes() {
    if skip_without_native_linux_md5("md5_key_mismatch_session_never_establishes") {
        return;
    }
    let test_id = alloc_test_id();
    let grpc_host_port = alloc_grpc_port();
    let network_name = format!("pathvector-md5-mismatch-test-{test_id}");

    // Isolated network — no subnet override needed; dynamic IPs are fine here
    // because GoBGP uses dynamic neighbors (no need to pre-configure a peer IP).
    let _network = DockerNetwork::create(network_name.clone());

    // GoBGP without MD5 — the standard dynamic-neighbor config.
    let gobgpd_config = write_gobgp_config();
    let gobgpd_config_path = gobgpd_config.path().to_str().unwrap().to_owned();

    let gobgpd = docker_start(
        &format!("gobgpd-mismatch-{test_id}"),
        GOBGPD_IMAGE,
        &network_name,
        None,  // No fixed IP — GoBGP uses dynamic neighbors, pathvectord's IP unknown at start.
        false, // GoBGP does not set TCP_MD5SIG — no CAP_NET_ADMIN needed.
        &gobgpd_config_path,
        "/etc/gobgp/gobgpd.conf",
        None,
        None,
    );
    wait_container_healthy(&gobgpd.0, Duration::from_secs(30));

    // Discover GoBGP's actual IP so pathvectord can dial it.
    let gobgpd_ip: std::net::Ipv4Addr = {
        let fmt =
            format!(r#"{{{{(index .NetworkSettings.Networks "{network_name}").IPAddress}}}}"#);
        let out = std::process::Command::new("docker")
            .args(["inspect", &gobgpd.0, "--format", &fmt])
            .output()
            .expect("docker inspect");
        std::str::from_utf8(&out.stdout)
            .unwrap()
            .trim()
            .parse()
            .expect("docker inspect returned non-IPv4 address")
    };

    // pathvectord configured with an MD5 key — GoBGP has none.
    // pathvectord's kernel will sign the SYN with MD5; GoBGP's kernel will
    // drop it because no key is configured for pathvectord's source IP.
    let pathvectord_config = write_daemon_config_md5(&[(gobgpd_ip, 65001)], "pathvector-only-key");
    let pathvectord_config_path = pathvectord_config.path().to_str().unwrap().to_owned();

    let _pathvectord = docker_start(
        &format!("pathvectord-mismatch-{test_id}"),
        PATHVECTORD_IMAGE,
        &network_name,
        None, // Auto-assigned IP; GoBGP uses dynamic neighbors.
        true, // CAP_NET_ADMIN required for setsockopt(TCP_MD5SIG).
        &pathvectord_config_path,
        "/etc/pathvectord.toml",
        Some(grpc_host_port),
        Some("/etc/pathvectord.toml"),
    );

    let mut client =
        pathvector_client::PathvectorClient::connect(format!("http://127.0.0.1:{grpc_host_port}"))
            .expect("connect PathvectorClient");

    // Allow 15 s — longer than a normal TCP retry but short enough for the
    // test suite to complete quickly.  If the session DOES establish, that is a
    // bug: MD5 enforcement failed.
    let result = wait_for_established(&mut client, gobgpd_ip, Duration::from_secs(15)).await;

    assert!(
        result.is_err(),
        "BGP session must NOT establish when pathvectord has an MD5 key but GoBGP does not"
    );
}

// ── Inbound connections (issue #66) ──────────────────────────────────────────
//
// In these tests only GoBGP initiates: pathvectord dials a port where nothing
// listens, so a session can only come up through pathvectord's BGP listener.
// RFC 5925 §8: required TCP MD5 must be "validated on all incoming segments";
// RFC 2385 §2.0: a failing segment is "dropped" with no response.

/// GoBGP dials pathvectord with the shared key: the listener has the key, so
/// the kernel accepts the signed handshake and the session establishes.
#[tokio::test]
async fn md5_inbound_matching_key_session_establishes() {
    if skip_without_native_linux_md5("md5_inbound_matching_key_session_establishes") {
        return;
    }
    let mut h = Md5InboundHarness::new("inbound-shared-key", Some("inbound-shared-key"));
    wait_for_established(&mut h.client, h.gobgp_ip, Duration::from_secs(30))
        .await
        .expect("inbound MD5 session with matching keys must reach Established");
}

/// Issue #66: GoBGP dials pathvectord **without** a key while pathvectord has
/// one for GoBGP's address. Before the fix the listener had no key, so this
/// unsigned connection was accepted and the session established
/// unauthenticated. Now the listener's kernel drops the unsigned SYN
/// (`TCP_MD5NOTFOUND`) and the session never establishes.
#[tokio::test]
async fn md5_inbound_unsigned_peer_never_establishes() {
    if skip_without_native_linux_md5("md5_inbound_unsigned_peer_never_establishes") {
        return;
    }
    let mut h = Md5InboundHarness::new("pathvector-only-key", None);
    let result = wait_for_established(&mut h.client, h.gobgp_ip, Duration::from_secs(15)).await;
    assert!(
        result.is_err(),
        "an unsigned inbound connection must not establish a session with an MD5 peer"
    );
}

/// GoBGP dials pathvectord with the wrong key: the digest check fails
/// (`TCP_MD5FAILURE`) and the session never establishes.
#[tokio::test]
async fn md5_inbound_wrong_key_never_establishes() {
    if skip_without_native_linux_md5("md5_inbound_wrong_key_never_establishes") {
        return;
    }
    let mut h = Md5InboundHarness::new("pathvector-key", Some("a-different-key"));
    let result = wait_for_established(&mut h.client, h.gobgp_ip, Duration::from_secs(15)).await;
    assert!(
        result.is_err(),
        "an inbound connection signed with the wrong key must not establish a session"
    );
}
