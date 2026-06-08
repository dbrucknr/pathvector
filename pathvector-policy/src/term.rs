use crate::{
    action::Action,
    condition::Condition,
    outcome::{Decision, DefaultAction},
    route::BgpRoute,
};

/// An internal trait that erases the generic parameters of [`Term<C, A>`]
/// so that heterogeneous terms can be stored in a `Vec`.
///
/// This is the one vtable boundary in the hybrid dispatch design: there is
/// exactly one virtual call per term when iterating a [`Policy`]. The
/// condition and action logic inside each term remains statically dispatched.
///
/// This trait is sealed — it cannot be implemented outside this crate.
/// Users compose policies by creating [`Term<C, A>`] values, not by
/// implementing `EvaluateTerm` directly.
pub(crate) trait EvaluateTerm<R: BgpRoute>: Send + Sync {
    /// Evaluates this term against `route`.
    ///
    /// Returns `Some(decision)` if the condition matched — `decision` is
    /// whatever the action returned. Returns `None` if the condition did not
    /// match; the route is left unmodified.
    fn evaluate(&self, route: &mut R) -> Option<Decision>;
}

/// A condition paired with an action.
///
/// `Term<C, A>` is fully monomorphized — both the condition and action types
/// are resolved at compile time with zero vtable overhead. It is the building
/// block of a [`Policy`].
///
/// Terms are added to a policy via [`Policy::add_term`] or
/// [`PolicyBuilder::term`], at which point they are type-erased into a
/// `Box<dyn EvaluateTerm<R>>` — one vtable call per term, not per attribute
/// check inside the term.
///
/// # Examples
///
/// ```
/// use pathvector_policy::{Accept, AnyCondition, Term};
///
/// // A term that accepts every route
/// let term = Term::new(AnyCondition, Accept);
/// ```
pub struct Term<C, A> {
    condition: C,
    action: A,
}

impl<C, A> Term<C, A> {
    /// Creates a new term from a condition and an action.
    #[must_use]
    pub fn new(condition: C, action: A) -> Self {
        Self { condition, action }
    }
}

impl<R, C, A> EvaluateTerm<R> for Term<C, A>
where
    R: BgpRoute,
    C: Condition<R>,
    A: Action<R>,
{
    fn evaluate(&self, route: &mut R) -> Option<Decision> {
        if self.condition.matches(route) {
            Some(self.action.apply(route))
        } else {
            None
        }
    }
}

/// An ordered list of [`Term`]s with a [`DefaultAction`].
///
/// Evaluation is **first-match-wins**: terms are checked in declaration order.
/// The first term whose condition matches has its action applied, and
/// evaluation stops. If no term matches, `default` is used.
///
/// Build a policy with [`PolicyBuilder`] for a fluent API, or mutate it
/// directly with [`Policy::add_term`].
///
/// # Examples
///
/// ```ignore
/// // Policy<R> requires a concrete BgpRoute type R;
/// // see the unit tests in this module for runnable examples.
/// use pathvector_policy::{
///     Accept, ActionSequence, AnyCondition, CommunityCondition, DefaultAction,
///     Policy, Reject, SetLocalPref, Term,
/// };
/// use pathvector_types::{Community, LocalPref};
///
/// let mut policy: Policy<MyRoute> = Policy::new(DefaultAction::Reject);
///
/// // Term 1: preferred routes get LOCAL_PREF 200
/// policy.add_term(Term::new(
///     CommunityCondition::new(Community::from_parts(65000, 100)),
///     ActionSequence::new()
///         .then(SetLocalPref::new(LocalPref::new(200)))
///         .then(Accept),
/// ));
///
/// // Term 2: catch-all accept
/// policy.add_term(Term::new(AnyCondition, Accept));
/// ```
pub struct Policy<R: BgpRoute> {
    terms: Vec<Box<dyn EvaluateTerm<R>>>,
    default: DefaultAction,
}

impl<R: BgpRoute> Policy<R> {
    /// Creates an empty policy with the given default action.
    #[must_use]
    pub fn new(default: DefaultAction) -> Self {
        Self {
            terms: Vec::new(),
            default,
        }
    }

    /// Appends a term to the end of this policy.
    ///
    /// Terms are evaluated in insertion order. Later terms are only reached
    /// if all earlier terms' conditions failed to match or returned `Next`.
    pub fn add_term<C, A>(&mut self, term: Term<C, A>)
    where
        C: Condition<R> + Send + Sync + 'static,
        A: Action<R> + Send + Sync + 'static,
    {
        self.terms.push(Box::new(term));
    }

    /// Evaluates this policy against `route`.
    ///
    /// Iterates terms in order. Returns the decision of the first matching
    /// term, or the result of the default action if no term matched.
    ///
    /// The route may be modified in place by matching terms even if the final
    /// decision is `Reject` — this is intentional. Rejected routes are
    /// discarded by the caller; their modified state is not observed.
    pub fn evaluate(&self, route: &mut R) -> Decision {
        for term in &self.terms {
            match term.evaluate(route) {
                Some(Decision::Accept) => return Decision::Accept,
                Some(Decision::Reject) => return Decision::Reject,
                // Some(Next) or None: condition didn't match or action said continue
                _ => {}
            }
        }
        self.default.into()
    }

    /// Returns the number of terms in this policy.
    #[must_use]
    pub fn len(&self) -> usize {
        self.terms.len()
    }

    /// Returns `true` if this policy has no terms.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }
}

/// A builder for constructing a [`Policy`] with a fluent API.
///
/// # Examples
///
/// ```ignore
/// // PolicyBuilder<R> requires a concrete BgpRoute type R;
/// // see the unit tests in this module for runnable examples.
/// use pathvector_policy::{
///     Accept, AnyCondition, CommunityCondition, DefaultAction,
///     PolicyBuilder, Reject,
/// };
/// use pathvector_types::Community;
///
/// let policy = PolicyBuilder::<MyRoute>::new(DefaultAction::Reject)
///     .term(
///         CommunityCondition::new(Community::NO_EXPORT),
///         Reject,
///     )
///     .term(AnyCondition, Accept)
///     .build();
/// ```
pub struct PolicyBuilder<R: BgpRoute> {
    terms: Vec<Box<dyn EvaluateTerm<R>>>,
    default: DefaultAction,
}

impl<R: BgpRoute> PolicyBuilder<R> {
    /// Creates a new builder with the given default action.
    #[must_use]
    pub fn new(default: DefaultAction) -> Self {
        Self {
            terms: Vec::new(),
            default,
        }
    }

    /// Appends a term and returns `self` for chaining.
    #[must_use]
    pub fn term<C, A>(mut self, condition: C, action: A) -> Self
    where
        C: Condition<R> + Send + Sync + 'static,
        A: Action<R> + Send + Sync + 'static,
    {
        self.terms.push(Box::new(Term::new(condition, action)));
        self
    }

    /// Consumes the builder and returns the finished [`Policy`].
    #[must_use]
    pub fn build(self) -> Policy<R> {
        Policy {
            terms: self.terms,
            default: self.default,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action::{Accept, ActionSequence, AddCommunity, Next as ActionNext, Reject, SetLocalPref},
        condition::{AnyCondition, CommunityCondition, OriginCondition},
        testutil::TestRoute,
    };
    use pathvector_types::{Community, LocalPref, Origin};

    fn make_route(prefix: &str) -> TestRoute {
        TestRoute::new(prefix)
    }

    // ── Policy::evaluate ───────────────────────────────────────────────────

    #[test]
    fn test_empty_policy_uses_default_reject() {
        let policy: Policy<TestRoute> = Policy::new(DefaultAction::Reject);
        let mut route = make_route("10.0.0.0/8");
        assert_eq!(policy.evaluate(&mut route), Decision::Reject);
    }

    #[test]
    fn test_empty_policy_uses_default_accept() {
        let policy: Policy<TestRoute> = Policy::new(DefaultAction::Accept);
        let mut route = make_route("10.0.0.0/8");
        assert_eq!(policy.evaluate(&mut route), Decision::Accept);
    }

    #[test]
    fn test_first_match_wins() {
        let mut policy: Policy<TestRoute> = Policy::new(DefaultAction::Reject);
        policy.add_term(Term::new(AnyCondition, Accept));
        policy.add_term(Term::new(AnyCondition, Reject)); // never reached

        let mut route = make_route("10.0.0.0/8");
        assert_eq!(policy.evaluate(&mut route), Decision::Accept);
    }

    #[test]
    fn test_non_matching_term_skipped() {
        let no_export = Community::NO_EXPORT;
        let mut policy: Policy<TestRoute> = Policy::new(DefaultAction::Reject);

        // Term 1: reject NO_EXPORT routes
        policy.add_term(Term::new(CommunityCondition::new(no_export), Reject));
        // Term 2: accept everything else
        policy.add_term(Term::new(AnyCondition, Accept));

        let mut clean_route = make_route("10.0.0.0/8");
        assert_eq!(policy.evaluate(&mut clean_route), Decision::Accept);

        let mut tagged_route = make_route("10.0.0.0/8");
        tagged_route.communities = vec![no_export];
        assert_eq!(policy.evaluate(&mut tagged_route), Decision::Reject);
    }

    #[test]
    fn test_next_decision_falls_through() {
        let mut policy: Policy<TestRoute> = Policy::new(DefaultAction::Reject);
        // Term 1: AnyCondition, ActionNext — matches but falls through
        policy.add_term(Term::new(AnyCondition, ActionNext));
        // Term 2: AnyCondition, Accept — reached because term 1 returned Next
        policy.add_term(Term::new(AnyCondition, Accept));

        let mut route = make_route("10.0.0.0/8");
        assert_eq!(policy.evaluate(&mut route), Decision::Accept);
    }

    #[test]
    fn test_route_modified_before_accept() {
        let mut policy: Policy<TestRoute> = Policy::new(DefaultAction::Reject);
        policy.add_term(Term::new(
            AnyCondition,
            ActionSequence::new()
                .then(SetLocalPref::new(LocalPref::new(200)))
                .then(Accept),
        ));

        let mut route = make_route("10.0.0.0/8");
        let decision = policy.evaluate(&mut route);
        assert_eq!(decision, Decision::Accept);
        assert_eq!(route.local_pref, Some(LocalPref::new(200)));
    }

    #[test]
    fn test_community_tagging_before_accept() {
        let mark = Community::from_parts(65000, 999);
        let mut policy: Policy<TestRoute> = Policy::new(DefaultAction::Reject);
        policy.add_term(Term::new(
            AnyCondition,
            ActionSequence::new()
                .then(AddCommunity::new(mark))
                .then(Accept),
        ));

        let mut route = make_route("10.0.0.0/8");
        policy.evaluate(&mut route);
        assert!(route.communities.contains(&mark));
    }

    #[test]
    fn test_origin_condition_term() {
        let mut policy: Policy<TestRoute> = Policy::new(DefaultAction::Accept);
        // Reject any route with INCOMPLETE origin
        policy.add_term(Term::new(OriginCondition::new(Origin::Incomplete), Reject));

        let mut igp_route = make_route("10.0.0.0/8");
        igp_route.origin = Origin::Igp;
        assert_eq!(policy.evaluate(&mut igp_route), Decision::Accept);

        let mut incomplete_route = make_route("10.0.0.0/8");
        incomplete_route.origin = Origin::Incomplete;
        assert_eq!(policy.evaluate(&mut incomplete_route), Decision::Reject);
    }

    #[test]
    fn test_policy_len_and_is_empty() {
        let mut policy: Policy<TestRoute> = Policy::new(DefaultAction::Reject);
        assert!(policy.is_empty());
        assert_eq!(policy.len(), 0);

        policy.add_term(Term::new(AnyCondition, Accept));
        assert!(!policy.is_empty());
        assert_eq!(policy.len(), 1);
    }

    // ── PolicyBuilder ──────────────────────────────────────────────────────

    #[test]
    fn test_policy_builder_basic() {
        let policy: Policy<TestRoute> = PolicyBuilder::new(DefaultAction::Reject)
            .term(AnyCondition, Accept)
            .build();

        let mut route = make_route("10.0.0.0/8");
        assert_eq!(policy.evaluate(&mut route), Decision::Accept);
    }

    #[test]
    fn test_policy_builder_multiple_terms() {
        let no_export = Community::NO_EXPORT;

        let policy: Policy<TestRoute> = PolicyBuilder::new(DefaultAction::Accept)
            .term(CommunityCondition::new(no_export), Reject)
            .term(AnyCondition, Accept)
            .build();

        let mut clean = make_route("10.0.0.0/8");
        assert_eq!(policy.evaluate(&mut clean), Decision::Accept);

        let mut tagged = make_route("10.0.0.0/8");
        tagged.communities = vec![no_export];
        assert_eq!(policy.evaluate(&mut tagged), Decision::Reject);
    }

    #[test]
    fn test_policy_builder_empty_uses_default() {
        let policy: Policy<TestRoute> = PolicyBuilder::new(DefaultAction::Accept).build();
        let mut route = make_route("10.0.0.0/8");
        assert_eq!(policy.evaluate(&mut route), Decision::Accept);
    }

    #[test]
    fn test_combined_modifying_actions_both_applied() {
        // SetLocalPref AND AddCommunity should both take effect before Accept.
        let mark = Community::from_parts(65000, 999);
        let policy: Policy<TestRoute> = PolicyBuilder::new(DefaultAction::Reject)
            .term(
                AnyCondition,
                ActionSequence::new()
                    .then(SetLocalPref::new(LocalPref::new(200)))
                    .then(AddCommunity::new(mark))
                    .then(Accept),
            )
            .build();

        let mut route = make_route("10.0.0.0/8");
        assert_eq!(policy.evaluate(&mut route), Decision::Accept);
        assert_eq!(route.local_pref, Some(LocalPref::new(200)));
        assert!(route.communities.contains(&mark));
    }

    #[test]
    fn test_multiple_next_terms_accumulate_modifications() {
        // Two Next-returning terms each modify an attribute; a final term accepts.
        // All three modifications must be visible in the accepted route.
        let mark_a = Community::from_parts(65000, 1);
        let mark_b = Community::from_parts(65000, 2);

        let policy: Policy<TestRoute> = PolicyBuilder::new(DefaultAction::Reject)
            .term(
                AnyCondition,
                ActionSequence::new()
                    .then(AddCommunity::new(mark_a))
                    .then(crate::action::Next),
            )
            .term(
                AnyCondition,
                ActionSequence::new()
                    .then(AddCommunity::new(mark_b))
                    .then(crate::action::Next),
            )
            .term(AnyCondition, Accept)
            .build();

        let mut route = make_route("10.0.0.0/8");
        assert_eq!(policy.evaluate(&mut route), Decision::Accept);
        assert!(route.communities.contains(&mark_a));
        assert!(route.communities.contains(&mark_b));
        assert_eq!(route.communities.len(), 2);
    }

    #[test]
    fn test_non_matching_term_does_not_modify_route() {
        // A term whose condition fails must not apply its action.
        // Verify the route is unchanged after skipping a non-matching term.
        let irrelevant = Community::from_parts(65001, 1);
        let policy: Policy<TestRoute> = PolicyBuilder::new(DefaultAction::Accept)
            .term(
                CommunityCondition::new(Community::NO_EXPORT), // condition won't match
                ActionSequence::new()
                    .then(SetLocalPref::new(LocalPref::new(999)))
                    .then(Accept),
            )
            .build();

        let mut route = make_route("10.0.0.0/8");
        route.communities = vec![irrelevant];

        // No-export community not present — term condition fails
        assert_eq!(policy.evaluate(&mut route), Decision::Accept); // default
        assert_eq!(route.local_pref, None); // action was NOT applied
    }
}
