//! RFC 6811 Route Origin Validation as a policy [`Condition`].
//!
//! [`RoaValidityCondition`] matches routes whose ROA validity (computed by
//! `pathvector-rpki` from a live RTR cache) equals a target state — typically
//! paired with [`Reject`](crate::action::Reject) to build a "reject Invalid"
//! ROV policy, matching RFC 7115 / BIRD / FRR convention.

use std::net::{Ipv4Addr, Ipv6Addr};

use ipnetx::interfaces::IpAddress;
use pathvector_rpki::{RoaValidity, RtrHandle};
use pathvector_types::Asn;

use crate::{condition::Condition, route::BgpRoute};

/// Matches routes whose RFC 6811 ROA validity equals `target`.
///
/// Captures an [`RtrHandle`] at construction — the handle is cheap to clone
/// (`Arc`-backed) and never blocks on network I/O, so `matches` is safe to
/// call from the hot route-ingest path.
pub struct RoaValidityCondition<A: IpAddress> {
    rtr: RtrHandle,
    target: RoaValidity,
    /// The BGP speaker's own AS number — needed for RFC 6811 §2's Route
    /// Origin ASN derivation when a route's `AS_PATH` ends in a
    /// confederation segment. See [`pathvector_types::AsPath::origin_as`].
    local_as: Asn,
    _family: std::marker::PhantomData<A>,
}

impl<A: IpAddress> RoaValidityCondition<A> {
    /// Creates a condition that matches routes whose ROA validity equals
    /// `target`. Pair with [`Reject`](crate::action::Reject) and `target =
    /// RoaValidity::Invalid` for the common "reject hijacked/misoriginated
    /// routes" policy.
    #[must_use]
    pub fn new(rtr: RtrHandle, target: RoaValidity, local_as: Asn) -> Self {
        Self {
            rtr,
            target,
            local_as,
            _family: std::marker::PhantomData,
        }
    }
}

/// Sealed dispatch bridging the generic [`IpAddress`] bound to
/// [`RtrHandle`]'s two family-specific `validate_v4`/`validate_v6` methods.
/// Implemented only for `Ipv4Addr`/`Ipv6Addr` — the only two types that can
/// satisfy `ipnetx`'s sealed `IpAddress` trait — so `RoaValidityCondition<A>`
/// stays a single generic impl (mirroring [`PrefixListCondition`]'s style)
/// rather than two overlapping family-specific `Condition` impls.
///
/// [`PrefixListCondition`]: crate::condition::PrefixListCondition
trait RoaLookup: IpAddress {
    fn lookup(rtr: &RtrHandle, addr: Self, prefix_len: u8, asn: u32) -> RoaValidity;
}

impl RoaLookup for Ipv4Addr {
    fn lookup(rtr: &RtrHandle, addr: Self, prefix_len: u8, asn: u32) -> RoaValidity {
        rtr.validate_v4(addr, prefix_len, asn)
    }
}

impl RoaLookup for Ipv6Addr {
    fn lookup(rtr: &RtrHandle, addr: Self, prefix_len: u8, asn: u32) -> RoaValidity {
        rtr.validate_v6(addr, prefix_len, asn)
    }
}

impl<A, R> Condition<R> for RoaValidityCondition<A>
where
    A: RoaLookup + Send + Sync,
    R: BgpRoute<Addr = A>,
{
    fn matches(&self, route: &R) -> bool {
        // RFC 6811 §2: an AS_PATH ending in an AS_SET yields the
        // distinguished "NONE" origin. The RFC's own pseudo-code represents
        // this with ASN 0 ("no valid Route can have an Origin ASN of zero
        // [AS0] ... no Route can be Matched by a VRP whose ASN is zero") —
        // a value `RoaTable::validate` explicitly excludes from ever
        // Matching (see `table.rs`). Looking it up (rather than
        // short-circuiting to `false`) preserves the Invalid-vs-NotFound
        // distinction: a NONE-origin route covered by a VRP is Invalid, one
        // with no covering VRP is NotFound — neither is silently exempt
        // from ROV.
        let asn = route
            .as_path()
            .origin_as(self.local_as)
            .map_or(0, Asn::as_u32);
        let prefix = route.nlri().prefix();
        A::lookup(&self.rtr, prefix.ip(), prefix.mask(), asn) == self.target
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Reject,
        outcome::{Decision, DefaultAction},
        term::{PolicyBuilder, Term},
        testutil::TestRoute,
    };
    use pathvector_rpki::for_testing;
    use pathvector_types::{AsPath, Asn, Nlri};

    fn route_with_origin(prefix: &str, asn: u32) -> TestRoute {
        let mut route = TestRoute::new(prefix);
        route.as_path = AsPath::from_sequence(vec![Asn::new(asn)]);
        route
    }

    #[test]
    fn matches_when_roa_confirms_target_validity() {
        let rtr = for_testing(
            [(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 65001)],
            std::iter::empty(),
        );
        let route = route_with_origin("192.0.2.0/24", 65001);
        // ROA authorizes AS65001 for this exact prefix — validity is Valid,
        // not Invalid, so an "Invalid" condition should not match.
        let cond = RoaValidityCondition::<Ipv4Addr>::new(
            rtr.clone(),
            RoaValidity::Invalid,
            Asn::new(65000),
        );
        assert!(!cond.matches(&route));
        let cond = RoaValidityCondition::<Ipv4Addr>::new(rtr, RoaValidity::Valid, Asn::new(65000));
        assert!(cond.matches(&route));
    }

    #[test]
    fn matches_invalid_on_wrong_origin_asn() {
        let rtr = for_testing(
            [(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 65001)],
            std::iter::empty(),
        );
        // Same prefix, wrong origin AS — a covering ROA exists but doesn't
        // authorize this AS, so validity is Invalid.
        let route = route_with_origin("192.0.2.0/24", 99999);
        let cond =
            RoaValidityCondition::<Ipv4Addr>::new(rtr, RoaValidity::Invalid, Asn::new(65000));
        assert!(cond.matches(&route));
    }

    #[test]
    fn uncovered_prefix_is_not_found_not_invalid() {
        let rtr = for_testing(std::iter::empty(), std::iter::empty());
        let route = route_with_origin("203.0.113.0/24", 65001);
        let cond = RoaValidityCondition::<Ipv4Addr>::new(
            rtr.clone(),
            RoaValidity::Invalid,
            Asn::new(65000),
        );
        assert!(!cond.matches(&route));
        let cond =
            RoaValidityCondition::<Ipv4Addr>::new(rtr, RoaValidity::NotFound, Asn::new(65000));
        assert!(cond.matches(&route));
    }

    #[test]
    fn terminal_as_set_origin_none_is_invalid_when_covered_by_a_roa() {
        // RFC 6811 §2: a Route whose Origin ASN is "NONE" (terminal AS_SET)
        // "cannot be Matched by any VRP" — but a VRP still *Covers* the
        // prefix here, so per the Invalid definition ("At least one VRP
        // Covers the Route Prefix, but no VRP Matches it") this must be
        // Invalid, not silently exempted from ROV.
        let rtr = for_testing(
            [(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 65001)],
            std::iter::empty(),
        );
        let mut route = TestRoute::new("192.0.2.0/24");
        route.as_path =
            AsPath::from_segments(vec![pathvector_types::AsPathSegment::Set(vec![Asn::new(
                65001,
            )])]);
        let cond = RoaValidityCondition::<Ipv4Addr>::new(
            rtr.clone(),
            RoaValidity::Invalid,
            Asn::new(65000),
        );
        assert!(
            cond.matches(&route),
            "a terminal AS_SET origin is NONE, which can never Match a VRP; \
             since a VRP covers this prefix, the route must be Invalid"
        );
        let cond = RoaValidityCondition::<Ipv4Addr>::new(rtr, RoaValidity::Valid, Asn::new(65000));
        assert!(!cond.matches(&route));
    }

    #[test]
    fn terminal_as_set_origin_none_is_not_found_when_uncovered() {
        // Same "NONE" origin, but no VRP covers the prefix at all — must be
        // NotFound, not Invalid, preserving the coverage-vs-match distinction.
        let rtr = for_testing(std::iter::empty(), std::iter::empty());
        let mut route = TestRoute::new("203.0.113.0/24");
        route.as_path =
            AsPath::from_segments(vec![pathvector_types::AsPathSegment::Set(vec![Asn::new(
                65001,
            )])]);
        for target in [RoaValidity::Valid, RoaValidity::Invalid] {
            let cond = RoaValidityCondition::<Ipv4Addr>::new(rtr.clone(), target, Asn::new(65000));
            assert!(!cond.matches(&route));
        }
        let cond =
            RoaValidityCondition::<Ipv4Addr>::new(rtr, RoaValidity::NotFound, Asn::new(65000));
        assert!(cond.matches(&route));
    }

    #[test]
    fn empty_as_path_validates_against_local_as_not_never_matching() {
        // RFC 6811 §2: an empty AS_PATH substitutes the BGP speaker's own
        // AS number as the Route Origin ASN — a locally originated route
        // IS validated, against `local_as`, not silently exempted. This
        // deliberately does *not* assert "never matches": that was the
        // pre-fix behavior, and RFC 6811 doesn't actually call for it.
        let local_as = Asn::new(65000);
        let rtr = for_testing(
            [(Ipv4Addr::new(192, 0, 2, 0), 24, 24, local_as.as_u32())],
            std::iter::empty(),
        );
        let route = TestRoute::new("192.0.2.0/24"); // default: empty AS_PATH
        let cond = RoaValidityCondition::<Ipv4Addr>::new(rtr.clone(), RoaValidity::Valid, local_as);
        assert!(
            cond.matches(&route),
            "a VRP authorizing local_as for this prefix must make an \
             empty-AS_PATH route Valid, not exempt from validation"
        );
        let cond = RoaValidityCondition::<Ipv4Addr>::new(rtr, RoaValidity::Invalid, local_as);
        assert!(!cond.matches(&route));
    }

    #[test]
    fn empty_as_path_uncovered_prefix_is_not_found_and_never_panics() {
        // No VRP at all — an empty AS_PATH must not panic or spuriously
        // match Valid/Invalid; it resolves to NotFound like any other
        // uncovered prefix.
        let rtr = for_testing(std::iter::empty(), std::iter::empty());
        let route = TestRoute::new("192.0.2.0/24");
        for target in [RoaValidity::Valid, RoaValidity::Invalid] {
            let cond = RoaValidityCondition::<Ipv4Addr>::new(rtr.clone(), target, Asn::new(65000));
            assert!(!cond.matches(&route));
        }
        let cond =
            RoaValidityCondition::<Ipv4Addr>::new(rtr, RoaValidity::NotFound, Asn::new(65000));
        assert!(cond.matches(&route));
    }

    /// Minimal IPv6 `BgpRoute` used only in this module's tests — the shared
    /// `TestRoute` in `testutil.rs` is IPv4-only.
    struct V6Route {
        nlri: Nlri<Ipv6Addr>,
        as_path: AsPath,
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
        fn as_path(&self) -> &AsPath {
            &self.as_path
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
            None
        }
        fn set_origin(&mut self, _origin: pathvector_types::Origin) {}
        fn set_local_pref(&mut self, _lp: Option<pathvector_types::LocalPref>) {}
        fn set_med(&mut self, _med: Option<pathvector_types::Med>) {}
        fn set_as_path(&mut self, path: AsPath) {
            self.as_path = path;
        }
        fn set_communities(&mut self, _c: Vec<pathvector_types::Community>) {}
        fn set_large_communities(&mut self, _c: Vec<pathvector_types::LargeCommunity>) {}
        fn set_extended_communities(&mut self, _c: Vec<pathvector_types::ExtendedCommunity>) {}
        fn set_next_hop(&mut self, _nh: Option<pathvector_types::NextHop>) {}
        fn set_otc(&mut self, _otc: Option<Asn>) {}
    }

    #[test]
    fn v6_matches_invalid_on_wrong_origin_asn() {
        let rtr = for_testing(
            std::iter::empty(),
            [("2001:db8::".parse().unwrap(), 32, 32, 65001)],
        );
        let route = V6Route {
            nlri: "2001:db8::/32".parse().unwrap(),
            as_path: AsPath::from_sequence(vec![Asn::new(99999)]),
        };
        let cond =
            RoaValidityCondition::<Ipv6Addr>::new(rtr, RoaValidity::Invalid, Asn::new(65000));
        assert!(cond.matches(&route));
    }

    #[test]
    fn v6_exact_match_is_valid_not_invalid() {
        let rtr = for_testing(
            std::iter::empty(),
            [("2001:db8::".parse().unwrap(), 32, 32, 65001)],
        );
        let route = V6Route {
            nlri: "2001:db8::/32".parse().unwrap(),
            as_path: AsPath::from_sequence(vec![Asn::new(65001)]),
        };
        let cond =
            RoaValidityCondition::<Ipv6Addr>::new(rtr, RoaValidity::Invalid, Asn::new(65000));
        assert!(!cond.matches(&route));
    }

    #[test]
    fn end_to_end_through_policy_invalid_rejected_others_fall_to_default() {
        let rtr = for_testing(
            [(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 65001)],
            std::iter::empty(),
        );
        let policy = PolicyBuilder::<TestRoute>::new(DefaultAction::Accept)
            .term(
                RoaValidityCondition::<Ipv4Addr>::new(rtr, RoaValidity::Invalid, Asn::new(65000)),
                Reject,
            )
            .build();

        let mut invalid = route_with_origin("192.0.2.0/24", 99999);
        assert_eq!(policy.evaluate(&mut invalid), Decision::Reject);

        let mut valid = route_with_origin("192.0.2.0/24", 65001);
        assert_eq!(policy.evaluate(&mut valid), Decision::Accept);

        let mut not_found = route_with_origin("203.0.113.0/24", 65001);
        assert_eq!(policy.evaluate(&mut not_found), Decision::Accept);
    }

    /// Exercises every `BgpRoute` stub method on `V6Route` besides
    /// `nlri()`/`as_path()`/`set_as_path()`, which the tests above already
    /// cover. Asserts the documented fixed contract of each stub (constant
    /// `Origin::Igp`, no `LOCAL_PREF`/`MED`/communities/`NEXT_HOP`/OTC, and that
    /// every non-`as_path` setter is a true no-op) so a typo here — this
    /// crate's ROV correctness surface — would be caught.
    #[test]
    fn v6route_stub_methods_have_the_documented_fixed_contract() {
        let mut route = V6Route {
            nlri: "2001:db8::/32".parse().unwrap(),
            as_path: AsPath::new(),
        };

        assert_eq!(route.origin(), pathvector_types::Origin::Igp);
        assert_eq!(route.local_pref(), None);
        assert_eq!(route.med(), None);
        assert!(route.communities().is_empty());
        assert!(route.large_communities().is_empty());
        assert!(route.extended_communities().is_empty());
        assert_eq!(route.next_hop(), None);
        assert_eq!(route.otc(), None);

        route.set_origin(pathvector_types::Origin::Egp);
        route.set_local_pref(Some(pathvector_types::LocalPref::new(100)));
        route.set_med(Some(pathvector_types::Med::new(50)));
        route.set_communities(vec![pathvector_types::Community::from_parts(65001, 1)]);
        route.set_large_communities(vec![pathvector_types::LargeCommunity::new(65001, 1, 1)]);
        route.set_extended_communities(vec![]);
        route.set_next_hop(Some(pathvector_types::NextHop::V6(
            "2001:db8::1".parse().unwrap(),
        )));
        route.set_otc(Some(Asn::new(65099)));

        // set_as_path is the one real, storage-backed setter on this double
        // (RoaValidityCondition reads the origin AS through it).
        let new_path = AsPath::from_sequence(vec![Asn::new(65001)]);
        route.set_as_path(new_path.clone());
        assert_eq!(route.as_path(), &new_path);

        assert_eq!(
            route.origin(),
            pathvector_types::Origin::Igp,
            "set_origin must be a no-op on this stub"
        );
        assert_eq!(route.local_pref(), None, "set_local_pref must be a no-op");
        assert_eq!(route.med(), None, "set_med must be a no-op");
        assert!(
            route.communities().is_empty(),
            "set_communities must be a no-op"
        );
        assert!(
            route.large_communities().is_empty(),
            "set_large_communities must be a no-op"
        );
        assert_eq!(route.next_hop(), None, "set_next_hop must be a no-op");
        assert_eq!(route.otc(), None, "set_otc must be a no-op on this stub");
    }

    #[test]
    fn matches_via_term_evaluate_not_just_direct_condition_call() {
        // Guards against a term construction mistake (e.g. wrong target
        // hard-coded) that direct `Condition::matches` calls wouldn't catch.
        let rtr = for_testing(
            [(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 65001)],
            std::iter::empty(),
        );
        let term = Term::new(
            RoaValidityCondition::<Ipv4Addr>::new(rtr, RoaValidity::Invalid, Asn::new(65000)),
            Reject,
        );
        let mut route = route_with_origin("192.0.2.0/24", 99999);
        let policy = {
            let mut p = crate::term::Policy::<TestRoute>::new(DefaultAction::Accept);
            p.add_term(term);
            p
        };
        assert_eq!(policy.evaluate(&mut route), Decision::Reject);
    }
}
