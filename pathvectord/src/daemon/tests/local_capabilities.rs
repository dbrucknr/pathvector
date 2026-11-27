//! ── build_local_capabilities — RFC 4724 §3 graceful restart advertisement ────

use crate::daemon::*;
use pathvector_session::message::{Capability, GracefulRestartFamily};
use pathvector_types::AfiSafi;

fn find_gr(caps: &[Capability]) -> Option<(u8, u16, Vec<GracefulRestartFamily>)> {
    caps.iter().find_map(|c| {
        if let Capability::GracefulRestart {
            restart_flags,
            restart_time,
            families,
        } = c
        {
            Some((*restart_flags, *restart_time, families.clone()))
        } else {
            None
        }
    })
}

#[test]
fn test_build_local_capabilities_gr_disabled() {
    let caps = build_local_capabilities(65001, 0, false, None);
    let (flags, time, families) =
        find_gr(&caps).expect("GracefulRestart capability must be present");
    assert_eq!(flags, 0);
    assert_eq!(time, 0, "restart_time must be 0 when GR is disabled");
    assert!(families.is_empty(), "no families when restart_time = 0");
}

#[test]
fn test_build_local_capabilities_gr_enabled() {
    let caps = build_local_capabilities(65001, 120, false, None);
    let (flags, time, families) =
        find_gr(&caps).expect("GracefulRestart capability must be present");
    // RFC 8538: N-bit (0x04) is set whenever gr_time > 0; R-bit (0x08) is not
    // set because we are not restarting.
    assert_eq!(
        flags, 0x04,
        "N-bit must be set, R-bit must be clear on normal startup"
    );
    assert_eq!(time, 120);
    assert_eq!(families.len(), 2);
    let v4 = families
        .iter()
        .find(|f| f.afi_safi == AfiSafi::IPV4_UNICAST)
        .expect("IPv4 unicast family must be present");
    assert!(
        v4.forwarding_preserved,
        "IPv4 must have forwarding_preserved=true"
    );
    let v6 = families
        .iter()
        .find(|f| f.afi_safi == AfiSafi::IPV6_UNICAST)
        .expect("IPv6 unicast family must be present");
    assert!(
        v6.forwarding_preserved,
        "IPv6 must have forwarding_preserved=true"
    );
}

#[test]
fn test_build_local_capabilities_gr_clamps_at_4095() {
    let caps = build_local_capabilities(65001, u16::MAX, false, None);
    let (_, time, _) = find_gr(&caps).expect("GracefulRestart capability must be present");
    assert_eq!(
        time, 4095,
        "restart_time must be clamped to RFC 4724 maximum of 4095"
    );
}

/// RFC 4724 §3: when restarting, F-bit must be false — our FIB was deleted on
/// startup before reconvergence.
#[test]
fn test_build_local_capabilities_f_bit_false_when_restarting() {
    let caps = build_local_capabilities(65001, 120, true, None);
    let (_, _, families) = find_gr(&caps).expect("GracefulRestart must be present");
    for fam in &families {
        assert!(
            !fam.forwarding_preserved,
            "forwarding_preserved must be false while restarting — FIB was wiped on startup"
        );
    }
}

/// RFC 4724 §3: when stable (not restarting), F-bit must be true — kernel
/// routes survive session loss on Linux.
#[test]
fn test_build_local_capabilities_f_bit_true_when_stable() {
    let caps = build_local_capabilities(65001, 120, false, None);
    let (_, _, families) = find_gr(&caps).expect("GracefulRestart must be present");
    for fam in &families {
        assert!(
            fam.forwarding_preserved,
            "forwarding_preserved must be true when not restarting — kernel FIB is intact"
        );
    }
}

/// RFC 4724 §3: when `restarting = true`, the R-bit (0x08 in restart_flags)
/// must be set so peers know to stop their stale-route timers on re-establishment.
#[test]
fn test_build_local_capabilities_r_bit_set_when_restarting() {
    let caps = build_local_capabilities(65001, 120, true, None);
    let (flags, _, _) = find_gr(&caps).expect("GracefulRestart capability must be present");
    assert_eq!(
        flags & 0x08,
        0x08,
        "R-bit must be set when restarting = true"
    );
}

/// RFC 4724 §3: when `restarting = false` (normal startup), the R-bit must
/// not be set — we are not signalling a restart to peers.
#[test]
fn test_build_local_capabilities_r_bit_clear_on_normal_startup() {
    let caps = build_local_capabilities(65001, 120, false, None);
    let (flags, _, _) = find_gr(&caps).expect("GracefulRestart capability must be present");
    assert_eq!(
        flags & 0x08,
        0x00,
        "R-bit must not be set on normal startup"
    );
}

/// RFC 4724 §3: R-bit must be ignored (stay 0x00) when `graceful_restart_time = 0`
/// even if `restarting = true` — there is no GR window to signal.
#[test]
fn test_build_local_capabilities_r_bit_ignored_when_gr_disabled() {
    let caps = build_local_capabilities(65001, 0, true, None);
    let (flags, _, _) = find_gr(&caps).expect("GracefulRestart capability must be present");
    assert_eq!(
        flags & 0x08,
        0x00,
        "R-bit must not be set when graceful_restart_time = 0"
    );
}

/// RFC 9234: when `role` is `Some`, `Capability::Role` must be present in
/// the output with the matching wire value.
#[test]
fn test_build_local_capabilities_includes_role_when_configured() {
    let caps = build_local_capabilities(65001, 0, false, Some(Role::Customer));
    assert!(
        caps.iter()
            .any(|c| matches!(c, Capability::Role(Role::Customer))),
        "Capability::Role(Customer) must be present when role is configured"
    );
}

/// RFC 9234's own non-strict default: omitting `role` must omit the
/// capability entirely, not send some default/placeholder role value.
#[test]
fn test_build_local_capabilities_omits_role_when_none() {
    let caps = build_local_capabilities(65001, 0, false, None);
    assert!(
        !caps.iter().any(|c| matches!(c, Capability::Role(_))),
        "Capability::Role must be absent when role is not configured"
    );
}

fn spawn_cfg(gr_time: u16, configured_restarting: bool, age: std::time::Duration) -> SpawnConfig {
    SpawnConfig {
        local_as: 65001,
        local_bgp_id: std::net::Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        graceful_restart_time: gr_time,
        configured_restarting,
        confederation_id: None,
        startup_instant: std::time::Instant::now().checked_sub(age).unwrap(),
        md5_enforcement: Md5Enforcement::Required,
    }
}

/// Within the restart window, SpawnConfig::capabilities() must set R=1.
#[test]
fn spawn_config_r_bit_set_within_restart_window() {
    let cfg = spawn_cfg(120, true, std::time::Duration::from_secs(10));
    let caps = cfg.capabilities(None, 65001);
    let (flags, _, _) = find_gr(&caps).expect("GracefulRestart must be present");
    assert_eq!(
        flags & 0x08,
        0x08,
        "R-bit must be set while within the 120 s restart window"
    );
}

/// After the restart window expires, SpawnConfig::capabilities() must clear R=0.
#[test]
fn spawn_config_r_bit_cleared_after_restart_window() {
    // Simulate 130 s elapsed for a 120 s window.
    let cfg = spawn_cfg(120, true, std::time::Duration::from_secs(130));
    let caps = cfg.capabilities(None, 65001);
    let (flags, _, _) = find_gr(&caps).expect("GracefulRestart must be present");
    assert_eq!(
        flags & 0x08,
        0x00,
        "R-bit must be cleared after the 120 s restart window expires"
    );
}

/// configured_restarting=false must always yield R=0, regardless of elapsed time.
#[test]
fn spawn_config_r_bit_not_set_when_not_configured_restarting() {
    let cfg = spawn_cfg(120, false, std::time::Duration::from_secs(5));
    let caps = cfg.capabilities(None, 65001);
    let (flags, _, _) = find_gr(&caps).expect("GracefulRestart must be present");
    assert_eq!(
        flags & 0x08,
        0x00,
        "R-bit must not be set when configured_restarting=false"
    );
}

/// RFC 9234: `SpawnConfig::capabilities()` — the same entry point used at
/// every session spawn, including on reconnect — must carry `role`
/// through to the output exactly like `build_local_capabilities` does.
/// This is the exact seam the reconnect capability-refresh fix touches
/// (`s.rib.peer_roles.get(&peer_ip).copied()` fed into this call); a
/// regression here would silently drop Role on every reconnect, the same
/// class of bug the R-bit lifetime fix (above) closed for GR.
#[test]
fn spawn_config_capabilities_includes_role_when_configured() {
    let cfg = spawn_cfg(0, false, std::time::Duration::from_secs(0));
    let caps = cfg.capabilities(Some(Role::Provider), 65001);
    assert!(
        caps.iter()
            .any(|c| matches!(c, Capability::Role(Role::Provider))),
        "Capability::Role(Provider) must be present"
    );
}
