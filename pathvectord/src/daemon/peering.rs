//! Domain rules that turn a peer's configuration into session semantics:
//! peer type, presented AS number, BGP Role, default policies and outbound
//! tables. Pure functions: no I/O, no async, no shared state.

use std::net::{Ipv4Addr, Ipv6Addr};

use pathvector_policy::{
    AnyCondition, BgpRoute, DefaultAction, OtcLeakCondition, OtcPropagationCondition, Policy,
    Reject, SetOtc, Term,
};
use pathvector_rib::{AdjRibOut, PeerId};
use pathvector_types::{Asn, PeerType, Role};

use super::blackhole::PeerBlackhole;
use crate::config;

/// Resolves the effective import default action for a peer (RFC 8212).
///
/// eBGP peers with no explicit setting default to `Reject`; iBGP peers default
/// to `Accept`. An explicit `import_default` in config always wins.
pub(super) fn resolve_import_default(
    opt: Option<config::ImportDefault>,
    is_ebgp: bool,
) -> DefaultAction {
    match opt {
        Some(d) => DefaultAction::from(d),
        None if is_ebgp => DefaultAction::Reject,
        None => DefaultAction::Accept,
    }
}

/// Resolves the effective export default action for a peer (RFC 8212).
///
/// eBGP peers with no explicit setting default to `Reject` — no routes are
/// advertised unless a policy term explicitly accepts them. iBGP peers default
/// to `Accept`. An explicit `export_default` in config always wins.
pub(super) fn resolve_export_default(
    opt: Option<config::ExportDefault>,
    is_ebgp: bool,
) -> DefaultAction {
    match opt {
        Some(d) => DefaultAction::from(d),
        None if is_ebgp => DefaultAction::Reject,
        None => DefaultAction::Accept,
    }
}

/// Derives the peer type (iBGP / eBGP / confederation Member-AS) from the
/// configured AS numbers and confederation membership.
///
/// `local_as == remote_as` is checked first regardless of `confed_member`:
/// a peer with matching AS numbers is definitionally same-AS iBGP even if
/// `confederation_member` was mistakenly also set (matches BIRD's
/// `is_internal`, which is likewise computed independently of confederation
/// state).
pub(super) fn config_peer_type(local_as: u32, remote_as: u32, confed_member: bool) -> PeerType {
    if local_as == remote_as {
        PeerType::Internal
    } else if confed_member {
        PeerType::ConfedMember
    } else {
        PeerType::External
    }
}

/// Resolves the AS number this daemon presents to a specific peer, in the
/// OPEN message's `my_as` field and the `FourByteAsn` capability.
///
/// RFC 5065 §4: "A member of a BGP confederation MUST use its AS
/// Confederation Identifier in all transactions with peers that are not
/// members of its confederation... this number is used in OPEN messages...
/// A member of a BGP confederation MUST use its Member-AS Number in all
/// transactions with peers that are members of the same confederation."
/// `local_as` is the private Member-AS Number; only `External` peers see
/// `confederation_id` instead. Falls back to `local_as` when no
/// confederation is configured, so behavior is unchanged for non-confederation
/// deployments.
pub(super) fn effective_session_as(
    local_as: u32,
    confederation_id: Option<u32>,
    peer_type: PeerType,
) -> u32 {
    match peer_type {
        PeerType::External => confederation_id.unwrap_or(local_as),
        PeerType::Internal | PeerType::ConfedMember | PeerType::Local => local_as,
    }
}

/// Creates a matched pair of `AdjRibOut` tables (IPv4 + IPv6) for one peer.
///
/// Both tables are created with identical reflecting/non-reflecting mode so they
/// can never diverge. When acting as a route reflector (`reflector_cluster_id`
/// is `Some`) and the peer is iBGP, both tables use
/// [`AdjRibOut::new_reflecting`]; otherwise both use [`AdjRibOut::new`].
///
/// All sites that construct outbound RIBs for a peer MUST use this function
/// instead of calling `AdjRibOut::new` / `new_reflecting` directly. This is the
/// single enforcement point for RFC 4456 §8 outbound-table invariant:
/// `adj_ribs_out[p].reflects() == adj_ribs_out_v6[p].reflects()` for every peer.
pub(super) fn make_adj_ribs_out_pair(
    peer_id: PeerId,
    peer_type: PeerType,
    reflector_cluster_id: Option<u32>,
) -> (AdjRibOut<Ipv4Addr>, AdjRibOut<Ipv6Addr>) {
    match reflector_cluster_id {
        Some(cluster_id) if peer_type == PeerType::Internal => (
            AdjRibOut::new_reflecting(peer_id, peer_type, cluster_id),
            AdjRibOut::new_reflecting(peer_id, peer_type, cluster_id),
        ),
        _ => (
            AdjRibOut::new(peer_id, peer_type),
            AdjRibOut::new(peer_id, peer_type),
        ),
    }
}

/// Resolves the effective RFC 9234 role for `peer`, or `None` if Role/OTC
/// must not apply to this session.
///
/// RFC 9234 is eBGP-only by definition (Provider/Customer/Peer/RS/RS-Client
/// relationships don't exist between routers in the same AS). Applying it to
/// an iBGP peer anyway would send a meaningless `Capability::Role` in OPEN
/// and, worse, could reject a route that legitimately carries OTC — attached
/// correctly by another border router's real eBGP session and reflected to
/// us over iBGP — as a false leak. Warns once (rather than failing startup)
/// so a config typo doesn't silently disable a peer, matching how other
/// eBGP-only features already degrade gracefully.
pub(super) fn effective_role(peer: &config::PeerConfig, local_as: u32) -> Option<Role> {
    let role = peer.role?;
    if peer.remote_as == local_as {
        tracing::warn!(
            peer = %peer.address,
            "role is configured but this is an iBGP peer (remote_as == local_as); \
             RFC 9234 is eBGP-only — ignoring role for this peer"
        );
        return None;
    }
    Some(role.into())
}

/// Resolves whether `peer` should be classified as a confederation
/// Member-AS (RFC 5065), or `false` if confederation membership must not
/// apply to this session.
///
/// Requires `confederation_id` to be configured — a peer with
/// `confederation_member = true` under an unconfigured confederation is
/// treated as a plain eBGP peer. Warns once (rather than failing startup)
/// so a config typo doesn't silently disable a peer, matching
/// [`effective_role`]'s graceful-degradation pattern. Takes the resolved
/// `confederation_id` scalar (rather than the whole `DaemonConfig`) to
/// match `effective_role`'s existing `local_as: u32` convention — callers
/// may only have `SpawnConfig`'s copy of it in scope, not the full config.
pub(super) fn effective_confederation_member(
    peer: &config::PeerConfig,
    confederation_id: Option<u32>,
) -> bool {
    if !peer.confederation_member {
        return false;
    }
    if confederation_id.is_none() {
        tracing::warn!(
            peer = %peer.address,
            "confederation_member is configured but daemon.confederation_id is unset; \
             ignoring confederation membership for this peer"
        );
        return false;
    }
    true
}

/// The BLACKHOLE agreement a peer's configuration describes (RFC 7999 §3.3):
/// denied unless `blackhole_authorized_prefixes` is set. A session with an
/// RFC 9234 role keeps leak detection in force for blackhole requests.
pub(super) fn peer_blackhole(peer: &config::PeerConfig, role: Option<Role>) -> PeerBlackhole {
    PeerBlackhole::from_config(
        peer.blackhole_authorized_prefixes.as_ref(),
        role.map(|r| (r, Asn::new(peer.remote_as))),
    )
}

/// RFC 9234 §5 ingress terms for a peer configured with `session_role`.
///
/// Always installs the leak-detection term (a no-op for roles it doesn't
/// apply to — see [`OtcLeakCondition`]'s doc comment). Additionally installs
/// the ingress-attach term (`OTC = peer_asn`) when `session_role` is
/// `Customer`, `Peer`, or `RsClient` — i.e. the route came from our
/// Provider/Peer/RS on this session.
pub(super) fn install_otc_import_term<R: BgpRoute>(
    policy: &mut Policy<R>,
    session_role: Role,
    peer_asn: Asn,
) {
    policy.add_term(Term::new(
        OtcLeakCondition::new(session_role, peer_asn),
        Reject,
    ));
    if matches!(session_role, Role::Customer | Role::Peer | Role::RsClient) {
        policy.add_term(Term::new(AnyCondition, SetOtc::new(peer_asn)));
    }
}

/// RFC 9234 §6 egress terms for a peer configured with `session_role`.
///
/// Installs the propagation-block term (reject routes that already carry
/// OTC) when `session_role` is `Customer`, `Peer`, or `RsClient` — i.e.
/// we're sending to our Provider/Peer/RS on this session. Installs the
/// egress-attach term (`OTC = local_asn`) when `session_role` is `Provider`,
/// `Peer`, or `RouteServer` — i.e. we're sending to our Customer/Peer/RS-Client.
pub(super) fn install_otc_export_term<R: BgpRoute>(
    policy: &mut Policy<R>,
    session_role: Role,
    local_asn: Asn,
) {
    if matches!(session_role, Role::Customer | Role::Peer | Role::RsClient) {
        policy.add_term(Term::new(OtcPropagationCondition, Reject));
    }
    if matches!(
        session_role,
        Role::Provider | Role::Peer | Role::RouteServer
    ) {
        policy.add_term(Term::new(AnyCondition, SetOtc::new(local_asn)));
    }
}

/// A peer's import policy as configured: the RFC 8212 default for its type,
/// plus the RFC 9234 ingress terms when it has a role.
pub(super) fn base_import_policy<R: BgpRoute>(
    default: Option<config::ImportDefault>,
    local_as: u32,
    remote_as: u32,
    role: Option<Role>,
) -> Policy<R> {
    let mut policy = Policy::new(resolve_import_default(default, remote_as != local_as));
    if let Some(role) = role {
        install_otc_import_term(&mut policy, role, Asn::new(remote_as));
    }
    policy
}

/// A peer's export policy as configured: the RFC 8212 default for its type,
/// plus the RFC 9234 egress terms when it has a role.
pub(super) fn base_export_policy<R: BgpRoute>(
    default: Option<config::ExportDefault>,
    local_as: u32,
    remote_as: u32,
    role: Option<Role>,
) -> Policy<R> {
    let mut policy = Policy::new(resolve_export_default(default, remote_as != local_as));
    if let Some(role) = role {
        install_otc_export_term(&mut policy, role, Asn::new(local_as));
    }
    policy
}
