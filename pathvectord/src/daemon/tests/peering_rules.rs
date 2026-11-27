use super::*;

// ── config_peer_type ─────────────────────────────────────────────────────

#[test]
fn test_config_peer_type_different_as_is_external() {
    assert_eq!(config_peer_type(65001, 65002, false), PeerType::External);
}

#[test]
fn test_config_peer_type_same_as_is_internal() {
    assert_eq!(config_peer_type(65001, 65001, false), PeerType::Internal);
}

#[test]
fn test_config_peer_type_confed_member() {
    // RFC 5065: a fellow confederation Member-AS is neither plain
    // Internal nor plain External.
    assert_eq!(config_peer_type(65001, 65002, true), PeerType::ConfedMember);
}

#[test]
fn test_config_peer_type_same_as_wins_over_confed_member() {
    // local_as == remote_as must classify Internal even if
    // confed_member is mistakenly also set — matches BIRD's
    // is_internal precedence.
    assert_eq!(config_peer_type(65001, 65001, true), PeerType::Internal);
}

// ── effective_session_as ─────────────────────────────────────────────────

#[test]
fn test_effective_session_as_external_uses_confederation_id() {
    // RFC 5065 §4: "MUST use its AS Confederation Identifier in all
    // transactions with peers that are not members of its confederation."
    assert_eq!(
        effective_session_as(65001, Some(64_500), PeerType::External),
        64_500
    );
}

#[test]
fn test_effective_session_as_internal_uses_member_as() {
    assert_eq!(
        effective_session_as(65001, Some(64_500), PeerType::Internal),
        65001
    );
}

#[test]
fn test_effective_session_as_confed_member_uses_member_as() {
    // RFC 5065 §4: "MUST use its Member-AS Number in all transactions
    // with peers that are members of the same confederation."
    assert_eq!(
        effective_session_as(65001, Some(64_500), PeerType::ConfedMember),
        65001
    );
}

#[test]
fn test_effective_session_as_external_falls_back_to_local_as_when_unconfigured() {
    // No confederation configured — behavior must be unchanged from
    // pre-RFC-5065 (always local_as).
    assert_eq!(effective_session_as(65001, None, PeerType::External), 65001);
}

// ── RFC 8212 default resolution ───────────────────────────────────────────

#[test]
fn test_resolve_import_ebgp_omitted_defaults_to_reject() {
    assert!(matches!(
        resolve_import_default(None, true),
        DefaultAction::Reject
    ));
}

#[test]
fn test_resolve_import_ibgp_omitted_defaults_to_accept() {
    assert!(matches!(
        resolve_import_default(None, false),
        DefaultAction::Accept
    ));
}

#[test]
fn test_resolve_import_explicit_accept_overrides_ebgp_default() {
    assert!(matches!(
        resolve_import_default(Some(config::ImportDefault::Accept), true),
        DefaultAction::Accept
    ));
}

#[test]
fn test_resolve_import_explicit_reject_overrides_ibgp_default() {
    assert!(matches!(
        resolve_import_default(Some(config::ImportDefault::Reject), false),
        DefaultAction::Reject
    ));
}

#[test]
fn test_resolve_export_ebgp_omitted_defaults_to_reject() {
    assert!(matches!(
        resolve_export_default(None, true),
        DefaultAction::Reject
    ));
}

#[test]
fn test_resolve_export_ibgp_omitted_defaults_to_accept() {
    assert!(matches!(
        resolve_export_default(None, false),
        DefaultAction::Accept
    ));
}

#[test]
fn test_resolve_export_explicit_accept_overrides_ebgp_default() {
    assert!(matches!(
        resolve_export_default(Some(config::ExportDefault::Accept), true),
        DefaultAction::Accept
    ));
}

#[test]
fn test_resolve_export_explicit_reject_overrides_ibgp_default() {
    assert!(matches!(
        resolve_export_default(Some(config::ExportDefault::Reject), false),
        DefaultAction::Reject
    ));
}

// ── RFC 9234 effective_role (eBGP-only guard) ─────────────────────────────

fn peer_with_role(remote_as: u32, role: Option<config::PeerRole>) -> config::PeerConfig {
    config::PeerConfig {
        address: "10.0.0.2".parse().unwrap(),
        port: 179,
        remote_as,
        import_default: None,
        export_default: None,
        import_default_v6: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: false,
        hold_time: None,
        shutdown_message: None,
        connect_retry_time: None,
        max_prefixes_v4: None,
        max_prefixes_v6: None,
        max_prefixes_restart: None,
        role,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    }
}

#[test]
fn test_effective_role_none_when_unconfigured() {
    let peer = peer_with_role(65002, None);
    assert_eq!(effective_role(&peer, 65001), None);
}

#[test]
fn test_effective_role_returns_role_for_ebgp_peer() {
    let peer = peer_with_role(65002, Some(config::PeerRole::Customer));
    assert_eq!(effective_role(&peer, 65001), Some(Role::Customer));
}

#[test]
fn test_effective_role_none_for_ibgp_peer_even_when_configured() {
    // remote_as == local_as: iBGP. RFC 9234 is eBGP-only by definition.
    let peer = peer_with_role(65001, Some(config::PeerRole::Provider));
    assert_eq!(
        effective_role(&peer, 65001),
        None,
        "role must be ignored for an iBGP peer, not just downgraded to a default"
    );
}
