//! RFC 9234 §5-§6 route-leak prevention via the `ONLY_TO_CUSTOMER` (OTC)
//! attribute.
//!
//! All three pieces here are keyed off `session_role` — the role the local
//! speaker plays *on this specific session* (configured per peer, not
//! per-AS). `session_role` describes *our* role; the peer's implied role is
//! always the complement (if we're `Provider`, the peer is our `Customer`;
//! if we're `Peer`, so are they). RFC 9234's own rule text is phrased in
//! terms of the peer's role ("route from Customer", "advertised to
//! Provider") — every doc comment below translates that into `session_role`
//! explicitly, since getting this backwards silently inverts the whole
//! leak-prevention mechanism.

use pathvector_types::{Asn, Role};

use crate::{action::Action, condition::Condition, outcome::Decision, route::BgpRoute};

/// RFC 9234 §5 ingress leak detection.
///
/// Matches (i.e. "this route is a leak, reject it") when:
/// - `session_role` is `Provider` or `RouteServer` (the route came from our
///   Customer or RS-Client) and OTC is present at all — a well-behaved
///   Customer/RS-Client never sends us a route carrying OTC.
/// - `session_role` is `Peer` (lateral peering) and OTC is present with a
///   value that isn't the peer's own ASN.
///
/// Every other combination (including "OTC absent" under any role, or OTC
/// present when `session_role` is `Customer`/`RsClient` — i.e. the route
/// came from our Provider/RS, which legitimately may already carry OTC)
/// does not match.
pub struct OtcLeakCondition {
    session_role: Role,
    peer_asn: Asn,
}

impl OtcLeakCondition {
    #[must_use]
    pub fn new(session_role: Role, peer_asn: Asn) -> Self {
        Self {
            session_role,
            peer_asn,
        }
    }
}

impl<R: BgpRoute> Condition<R> for OtcLeakCondition {
    fn matches(&self, route: &R) -> bool {
        match (self.session_role, route.otc()) {
            (Role::Provider | Role::RouteServer, Some(_)) => true,
            (Role::Peer, Some(otc)) => otc != self.peer_asn,
            _ => false,
        }
    }
}

/// RFC 9234 §6 egress leak prevention: a route that already carries OTC must
/// never be re-advertised to a Provider, Peer, or Route Server — only to a
/// Customer or RS-Client.
///
/// Deliberately role-agnostic (just "does this route carry OTC at all") —
/// the caller decides *whether* to install this term for a given session
/// based on `session_role`: install it only when `session_role` is
/// `Customer`, `Peer`, or `RsClient` (i.e. we're sending *to* a Provider,
/// Peer, or Route Server). A session where `session_role` is `Provider` or
/// `RouteServer` should never install this term — those destinations are
/// exactly the ones OTC is allowed to reach.
pub struct OtcPropagationCondition;

impl<R: BgpRoute> Condition<R> for OtcPropagationCondition {
    fn matches(&self, route: &R) -> bool {
        route.otc().is_some()
    }
}

/// Attaches `asn` as the `ONLY_TO_CUSTOMER` value if the route doesn't
/// already carry one. Idempotent — never overwrites an existing OTC value,
/// since RFC 9234 requires OTC be preserved unchanged once set.
///
/// Used at two call sites with different `asn` arguments, both installed
/// only for the `session_role`s where the RFC actually calls for attaching:
/// - **Ingress** (RFC 9234 §5, rule 3): `session_role` is `Customer`, `Peer`,
///   or `RsClient` (the route came from our Provider/Peer/RS) — attach
///   `asn = peer's ASN`.
/// - **Egress** (RFC 9234 §6, rule 1): `session_role` is `Provider`, `Peer`,
///   or `RouteServer` (we're sending to our Customer/Peer/RS-Client) —
///   attach `asn = local ASN`.
pub struct SetOtc {
    asn: Asn,
}

impl SetOtc {
    #[must_use]
    pub fn new(asn: Asn) -> Self {
        Self { asn }
    }
}

impl<R: BgpRoute> Action<R> for SetOtc {
    fn apply(&self, route: &mut R) -> Decision {
        if route.otc().is_none() {
            route.set_otc(Some(self.asn));
        }
        Decision::Next
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Reject, outcome::DefaultAction, term::PolicyBuilder, testutil::TestRoute};
    use pathvector_types::Nlri;
    use std::net::Ipv6Addr;

    fn route_with_otc(prefix: &str, otc: Option<u32>) -> TestRoute {
        let mut route = TestRoute::new(prefix);
        route.otc = otc.map(Asn::new);
        route
    }

    // ── OtcLeakCondition ─────────────────────────────────────────────────────

    #[test]
    fn provider_role_with_otc_present_is_a_leak_regardless_of_value() {
        let cond = OtcLeakCondition::new(Role::Provider, Asn::new(65002));
        // Any OTC value at all — a well-behaved Customer never sets OTC.
        assert!(cond.matches(&route_with_otc("10.0.0.0/8", Some(1))));
        assert!(cond.matches(&route_with_otc("10.0.0.0/8", Some(65002))));
    }

    #[test]
    fn route_server_role_with_otc_present_is_a_leak() {
        let cond = OtcLeakCondition::new(Role::RouteServer, Asn::new(65002));
        assert!(cond.matches(&route_with_otc("10.0.0.0/8", Some(1))));
    }

    #[test]
    fn provider_or_route_server_role_without_otc_is_not_a_leak() {
        // No OTC at all is never a leak — it's the "needs attaching" case,
        // handled separately by SetOtc, not by this condition.
        for role in [Role::Provider, Role::RouteServer] {
            let cond = OtcLeakCondition::new(role, Asn::new(65002));
            assert!(!cond.matches(&route_with_otc("10.0.0.0/8", None)));
        }
    }

    #[test]
    fn peer_role_with_matching_otc_asn_is_not_a_leak() {
        let cond = OtcLeakCondition::new(Role::Peer, Asn::new(65002));
        assert!(!cond.matches(&route_with_otc("10.0.0.0/8", Some(65002))));
    }

    #[test]
    fn peer_role_with_wrong_otc_asn_is_a_leak() {
        let cond = OtcLeakCondition::new(Role::Peer, Asn::new(65002));
        assert!(cond.matches(&route_with_otc("10.0.0.0/8", Some(99999))));
    }

    #[test]
    fn peer_role_without_otc_is_not_a_leak() {
        let cond = OtcLeakCondition::new(Role::Peer, Asn::new(65002));
        assert!(!cond.matches(&route_with_otc("10.0.0.0/8", None)));
    }

    #[test]
    fn customer_and_rs_client_roles_with_otc_present_are_not_flagged() {
        // The route came from our Provider/RS — it may legitimately already
        // carry OTC (attached by someone further upstream). Not our leak to
        // detect; RFC 9234 only requires *preserving* it, not rejecting it.
        for role in [Role::Customer, Role::RsClient] {
            let cond = OtcLeakCondition::new(role, Asn::new(65002));
            assert!(!cond.matches(&route_with_otc("10.0.0.0/8", Some(1))));
        }
    }

    // ── OtcPropagationCondition ──────────────────────────────────────────────

    #[test]
    fn propagation_condition_matches_iff_otc_present() {
        let cond = OtcPropagationCondition;
        assert!(cond.matches(&route_with_otc("10.0.0.0/8", Some(65001))));
        assert!(!cond.matches(&route_with_otc("10.0.0.0/8", None)));
    }

    // ── SetOtc ────────────────────────────────────────────────────────────────

    #[test]
    fn set_otc_attaches_when_absent() {
        let action = SetOtc::new(Asn::new(65001));
        let mut route = route_with_otc("10.0.0.0/8", None);
        assert_eq!(action.apply(&mut route), Decision::Next);
        assert_eq!(route.otc, Some(Asn::new(65001)));
    }

    #[test]
    fn set_otc_is_idempotent_never_overwrites_existing_value() {
        let action = SetOtc::new(Asn::new(65001));
        let mut route = route_with_otc("10.0.0.0/8", Some(99999));
        action.apply(&mut route);
        assert_eq!(
            route.otc,
            Some(Asn::new(99999)),
            "SetOtc must never overwrite an already-set OTC value"
        );
    }

    // ── End-to-end through a Policy ───────────────────────────────────────────

    #[test]
    fn ingress_policy_rejects_leak_accepts_and_attaches_otherwise() {
        // session_role = Provider: peer is our Customer. A route from them
        // carrying OTC is a leak; one without OTC is accepted (no OTC
        // attach needed on this ingress side per the RFC's rule set — the
        // attach-on-ingress case only applies when session_role is
        // Customer/Peer/RsClient, not Provider/RouteServer).
        let policy = PolicyBuilder::<TestRoute>::new(DefaultAction::Accept)
            .term(
                OtcLeakCondition::new(Role::Provider, Asn::new(65002)),
                Reject,
            )
            .build();

        let mut leaked = route_with_otc("10.0.0.0/8", Some(1));
        assert_eq!(policy.evaluate(&mut leaked), Decision::Reject);

        let mut clean = route_with_otc("10.0.0.0/8", None);
        assert_eq!(policy.evaluate(&mut clean), Decision::Accept);
        assert_eq!(clean.otc, None, "no attach expected on this ingress side");
    }

    #[test]
    fn ingress_policy_attaches_peer_asn_when_session_role_is_customer() {
        // session_role = Customer: peer is our Provider. No leak-detection
        // term applies (Customer isn't in OtcLeakCondition's trigger set) —
        // only the attach-if-absent term fires.
        let peer_asn = Asn::new(65002);
        let policy = PolicyBuilder::<TestRoute>::new(DefaultAction::Accept)
            .term(OtcLeakCondition::new(Role::Customer, peer_asn), Reject)
            .term(crate::AnyCondition, SetOtc::new(peer_asn))
            .build();

        let mut route = route_with_otc("10.0.0.0/8", None);
        assert_eq!(policy.evaluate(&mut route), Decision::Accept);
        assert_eq!(route.otc, Some(peer_asn));
    }

    #[test]
    fn egress_policy_blocks_propagation_to_provider_when_otc_already_set() {
        // session_role = Customer (we're sending to our Provider): a route
        // that already carries OTC must never reach them.
        let policy = PolicyBuilder::<TestRoute>::new(DefaultAction::Accept)
            .term(OtcPropagationCondition, Reject)
            .build();

        let mut leaked_onward = route_with_otc("10.0.0.0/8", Some(65001));
        assert_eq!(policy.evaluate(&mut leaked_onward), Decision::Reject);

        let mut clean = route_with_otc("10.0.0.0/8", None);
        assert_eq!(policy.evaluate(&mut clean), Decision::Accept);
    }

    #[test]
    fn egress_policy_attaches_local_asn_when_session_role_is_provider() {
        // session_role = Provider (we're sending to our Customer): attach
        // OTC = local ASN if not already present.
        let local_asn = Asn::new(65001);
        let policy = PolicyBuilder::<TestRoute>::new(DefaultAction::Accept)
            .term(crate::AnyCondition, SetOtc::new(local_asn))
            .build();

        let mut route = route_with_otc("10.0.0.0/8", None);
        policy.evaluate(&mut route);
        assert_eq!(route.otc, Some(local_asn));
    }

    // ── IPv6 sanity check ─────────────────────────────────────────────────────
    // OtcLeakCondition/SetOtc are generic over any BgpRoute impl — confirm
    // they work identically for an IPv6 route, not just the IPv4 TestRoute.

    struct V6Route {
        nlri: Nlri<Ipv6Addr>,
        otc: Option<Asn>,
    }

    impl BgpRoute for V6Route {
        type Addr = Ipv6Addr;
        fn nlri(&self) -> Nlri<Self::Addr> {
            self.nlri
        }
        fn origin(&self) -> pathvector_types::Origin {
            pathvector_types::Origin::Igp
        }
        fn local_pref(&self) -> Option<pathvector_types::LocalPref> {
            None
        }
        fn med(&self) -> Option<pathvector_types::Med> {
            None
        }
        fn as_path(&self) -> &pathvector_types::AsPath {
            static EMPTY: std::sync::OnceLock<pathvector_types::AsPath> =
                std::sync::OnceLock::new();
            EMPTY.get_or_init(pathvector_types::AsPath::new)
        }
        fn communities(&self) -> &[pathvector_types::Community] {
            &[]
        }
        fn large_communities(&self) -> &[pathvector_types::LargeCommunity] {
            &[]
        }
        fn extended_communities(&self) -> &[pathvector_types::ExtendedCommunity] {
            &[]
        }
        fn next_hop(&self) -> Option<pathvector_types::NextHop> {
            None
        }
        fn otc(&self) -> Option<Asn> {
            self.otc
        }
        fn set_origin(&mut self, _origin: pathvector_types::Origin) {}
        fn set_local_pref(&mut self, _lp: Option<pathvector_types::LocalPref>) {}
        fn set_med(&mut self, _med: Option<pathvector_types::Med>) {}
        fn set_as_path(&mut self, _path: pathvector_types::AsPath) {}
        fn set_communities(&mut self, _c: Vec<pathvector_types::Community>) {}
        fn set_large_communities(&mut self, _c: Vec<pathvector_types::LargeCommunity>) {}
        fn set_extended_communities(&mut self, _c: Vec<pathvector_types::ExtendedCommunity>) {}
        fn set_next_hop(&mut self, _nh: Option<pathvector_types::NextHop>) {}
        fn set_otc(&mut self, otc: Option<Asn>) {
            self.otc = otc;
        }
    }

    #[test]
    fn v6_leak_detection_and_attach_work_identically() {
        let cond = OtcLeakCondition::new(Role::Provider, Asn::new(65002));
        let leaked = V6Route {
            nlri: "2001:db8::/32".parse().unwrap(),
            otc: Some(Asn::new(1)),
        };
        assert!(cond.matches(&leaked));

        let action = SetOtc::new(Asn::new(65001));
        let mut clean = V6Route {
            nlri: "2001:db8::/32".parse().unwrap(),
            otc: None,
        };
        action.apply(&mut clean);
        assert_eq!(clean.otc, Some(Asn::new(65001)));
    }
}
