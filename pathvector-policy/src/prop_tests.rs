use std::net::Ipv4Addr;

use pathvector_types::{AsPath, Asn, Community, LocalPref, Med, Nlri, Origin};
use proptest::prelude::*;

use crate::{
    action::{
        Accept, Action, ActionSequence, AddCommunity, Next, PrependAsPath, Reject, RemoveCommunity,
        SetLocalPref,
    },
    condition::{AnyCondition, CommunityCondition, Condition},
    outcome::{Decision, DefaultAction},
    route::BgpRoute,
    term::{Policy, PolicyBuilder, Term},
    testutil::TestRoute,
};

// ── Strategies ─────────────────────────────────────────────────────────────

prop_compose! {
    /// Generates an arbitrary AS path of 0–8 hops.
    fn arb_as_path()(
        asns in proptest::collection::vec(1u32..=65535, 0..=8),
    ) -> AsPath {
        if asns.is_empty() {
            AsPath::new()
        } else {
            AsPath::from_sequence(asns.into_iter().map(Asn::new).collect())
        }
    }
}

prop_compose! {
    /// Generates an arbitrary test route with realistic attribute ranges.
    fn arb_route()(
        first_octet in 0u8..=255,
        second_octet in 0u8..=255,
        prefix_len in 0u8..=32,
        origin_byte in 0u8..=2u8,
        local_pref in proptest::option::of(0u32..=500),
        med in proptest::option::of(0u32..=500),
        communities in proptest::collection::vec(0u32..=u32::MAX, 0..=4),
        as_path in arb_as_path(),
    ) -> TestRoute {
        let ip = Ipv4Addr::new(first_octet, second_octet, 0, 0);
        TestRoute {
            nlri: Nlri::new(ip, prefix_len).unwrap().masked(),
            origin: Origin::from_u8(origin_byte).unwrap_or(Origin::Igp),
            local_pref: local_pref.map(LocalPref::new),
            med: med.map(Med::new),
            as_path,
            communities: communities.into_iter().map(Community::new).collect(),
            large_communities: vec![],
            extended_communities: vec![],
            next_hop: None,
        }
    }
}

// ── Policy evaluation invariants ───────────────────────────────────────────

proptest! {
    /// An empty policy always falls through to the default action.
    #[test]
    fn prop_empty_policy_applies_default_reject(mut route in arb_route()) {
        let policy: Policy<TestRoute> = Policy::new(DefaultAction::Reject);
        prop_assert_eq!(policy.evaluate(&mut route), Decision::Reject);
    }

    /// An empty policy with Accept default always accepts.
    #[test]
    fn prop_empty_policy_applies_default_accept(mut route in arb_route()) {
        let policy: Policy<TestRoute> = Policy::new(DefaultAction::Accept);
        prop_assert_eq!(policy.evaluate(&mut route), Decision::Accept);
    }

    /// A policy whose first term is a catch-all Accept always accepts,
    /// regardless of route contents.
    #[test]
    fn prop_catchall_accept_always_accepts(mut route in arb_route()) {
        let policy: Policy<TestRoute> = PolicyBuilder::new(DefaultAction::Reject)
            .term(AnyCondition, Accept)
            .build();
        prop_assert_eq!(policy.evaluate(&mut route), Decision::Accept);
    }

    /// A policy whose first term is a catch-all Reject always rejects.
    #[test]
    fn prop_catchall_reject_always_rejects(mut route in arb_route()) {
        let policy: Policy<TestRoute> = PolicyBuilder::new(DefaultAction::Accept)
            .term(AnyCondition, Reject)
            .build();
        prop_assert_eq!(policy.evaluate(&mut route), Decision::Reject);
    }

    /// A policy made entirely of Next-returning terms reaches the default action.
    #[test]
    fn prop_all_next_terms_reach_default(
        mut route in arb_route(),
        n_terms in 1usize..=5,
    ) {
        let mut policy: Policy<TestRoute> = Policy::new(DefaultAction::Accept);
        for _ in 0..n_terms {
            policy.add_term(Term::new(AnyCondition, Next));
        }
        prop_assert_eq!(policy.evaluate(&mut route), Decision::Accept);
    }
}

// ── First-match-wins and determinism ──────────────────────────────────────

proptest! {
    /// Evaluating the same route state twice against the same policy always
    /// produces the same decision.
    ///
    /// A policy that returns different decisions for identical input would
    /// make operator reasoning about filter behaviour impossible and could
    /// cause oscillating RIB installs across consecutive soft-reconfiguration
    /// cycles.
    #[test]
    fn prop_policy_evaluation_is_deterministic(route in arb_route()) {
        let mut r1 = route.clone();
        let mut r2 = route;

        let policy: Policy<TestRoute> = PolicyBuilder::new(DefaultAction::Reject)
            .term(CommunityCondition::new(Community::NO_EXPORT), Reject)
            .term(AnyCondition, Accept)
            .build();

        prop_assert_eq!(policy.evaluate(&mut r1), policy.evaluate(&mut r2));
    }

    /// When term N matches and returns Accept, term N+1 is never evaluated.
    ///
    /// This is the core first-match-wins guarantee. A policy where a later
    /// Reject term fires after an earlier Accept would silently drop routes
    /// that the operator intended to pass.
    #[test]
    fn prop_first_match_wins_accept_blocks_later_reject(
        mut route in arb_route(),
        c_val in 0u32..=u32::MAX,
    ) {
        let c = Community::new(c_val);

        // Ensure the route carries community c so term 1 will match it.
        if !route.communities().contains(&c) {
            let mut comms: Vec<Community> = route.communities().to_vec();
            comms.push(c);
            route.set_communities(comms);
        }

        // Term 1: if route carries c → Accept (should fire and short-circuit).
        // Term 2: catch-all Reject (must never be reached for this route).
        let policy: Policy<TestRoute> = PolicyBuilder::new(DefaultAction::Reject)
            .term(CommunityCondition::new(c), Accept)
            .term(AnyCondition, Reject)
            .build();

        prop_assert_eq!(policy.evaluate(&mut route), Decision::Accept);
    }
}

// ── Action invariants ──────────────────────────────────────────────────────

proptest! {
    /// PrependAsPath always increases path_length by exactly `times`.
    ///
    /// This holds because each `prepend()` call adds exactly one ASN to a
    /// Sequence segment, contributing exactly 1 to path_length.
    #[test]
    fn prop_prepend_increases_path_length_by_times(
        mut route in arb_route(),
        asn_val in 1u32..=65535,
        times in 1u8..=5,
    ) {
        let before = route.as_path().path_length();
        PrependAsPath::new(Asn::new(asn_val), times).apply(&mut route);
        prop_assert_eq!(
            route.as_path().path_length(),
            before + times as usize,
        );
    }

    /// RemoveCommunity never increases the community count.
    #[test]
    fn prop_remove_community_never_increases_count(
        mut route in arb_route(),
        c_val in 0u32..=u32::MAX,
    ) {
        let before = route.communities().len();
        RemoveCommunity::new(Community::new(c_val)).apply(&mut route);
        prop_assert!(
            route.communities().len() <= before,
            "community count should not grow after removal"
        );
    }

    /// AddCommunity always increases the community count by exactly 1.
    #[test]
    fn prop_add_community_increases_count_by_one(
        mut route in arb_route(),
        c_val in 0u32..=u32::MAX,
    ) {
        let before = route.communities().len();
        AddCommunity::new(Community::new(c_val)).apply(&mut route);
        prop_assert_eq!(
            route.communities().len(),
            before + 1,
            "community count should grow by exactly 1"
        );
    }

    /// SetLocalPref always sets local_pref to exactly the given value.
    #[test]
    fn prop_set_local_pref_sets_exact_value(
        mut route in arb_route(),
        lp_val in 0u32..=u32::MAX,
    ) {
        SetLocalPref::new(LocalPref::new(lp_val)).apply(&mut route);
        prop_assert_eq!(
            route.local_pref(),
            Some(LocalPref::new(lp_val)),
            "local_pref should equal the set value"
        );
    }

    /// A community added to a route is immediately matched by CommunityCondition.
    #[test]
    fn prop_added_community_is_matched(
        mut route in arb_route(),
        c_val in 0u32..=u32::MAX,
    ) {
        let c = Community::new(c_val);
        AddCommunity::new(c).apply(&mut route);
        prop_assert!(
            CommunityCondition::new(c).matches(&route),
            "community just added should be matched"
        );
    }

    /// A community removed from a route is no longer matched, unless
    /// duplicates were present.
    #[test]
    fn prop_removed_community_not_matched_if_unique(
        mut route in arb_route(),
        c_val in 0u32..=u32::MAX,
    ) {
        let c = Community::new(c_val);

        // Remove any pre-existing occurrences so we start clean.
        let clean: Vec<Community> = route.communities().iter()
            .copied()
            .filter(|x| x != &c)
            .collect();
        route.set_communities(clean);

        // Add exactly once, then remove — should no longer match.
        AddCommunity::new(c).apply(&mut route);
        RemoveCommunity::new(c).apply(&mut route);

        prop_assert!(
            !CommunityCondition::new(c).matches(&route),
            "community should not match after add-then-remove"
        );
    }

    /// SetCommunities replaces the entire list with exactly the given values.
    #[test]
    fn prop_set_communities_replaces_all(
        mut route in arb_route(),
        new_vals in proptest::collection::vec(0u32..=u32::MAX, 0..=5),
    ) {
        let new_comms: Vec<Community> = new_vals.into_iter().map(Community::new).collect();
        crate::action::SetCommunities::new(new_comms.clone()).apply(&mut route);
        prop_assert_eq!(
            route.communities(),
            new_comms.as_slice(),
            "communities should be exactly the replacement list"
        );
    }

    /// AnyCondition always matches; Not(AnyCondition) never does.
    #[test]
    fn prop_any_condition_always_matches(route in arb_route()) {
        prop_assert!(AnyCondition.matches(&route));
        prop_assert!(!crate::condition::Not(AnyCondition).matches(&route));
    }

    /// An ActionSequence with a single Accept step always accepts.
    #[test]
    fn prop_sequence_with_accept_always_accepts(mut route in arb_route()) {
        let seq: ActionSequence<TestRoute> = ActionSequence::new().then(Accept);
        prop_assert_eq!(seq.apply(&mut route), Decision::Accept);
    }

    /// An ActionSequence with a single Reject step always rejects.
    #[test]
    fn prop_sequence_with_reject_always_rejects(mut route in arb_route()) {
        let seq: ActionSequence<TestRoute> = ActionSequence::new().then(Reject);
        prop_assert_eq!(seq.apply(&mut route), Decision::Reject);
    }
}
