use pathvector_types::{Asn, Community, LargeCommunity, LocalPref, Med, NextHop, Origin};

use crate::{outcome::Decision, route::BgpRoute};

/// A modification applied to a [`BgpRoute`] when a [`Term`](crate::Term)'s
/// condition matches.
///
/// Actions receive the route by `&mut` — they modify it in place — and return
/// a [`Decision`] indicating whether to terminate evaluation (`Accept` or
/// `Reject`) or fall through to the next term (`Next`).
///
/// For simple cases use the built-in actions directly. For compound cases —
/// "set local-pref, add a community, then accept" — use [`ActionSequence`],
/// which chains multiple actions with one vtable call per step.
pub trait Action<R: BgpRoute>: Send + Sync {
    /// Applies this action to `route` and returns the resulting [`Decision`].
    fn apply(&self, route: &mut R) -> Decision;
}

// ── Terminal actions ───────────────────────────────────────────────────────

/// Accepts the route. Evaluation stops immediately.
///
/// This is the most common terminal action for an import policy term that
/// matches a desired route.
pub struct Accept;

impl<R: BgpRoute> Action<R> for Accept {
    fn apply(&self, _route: &mut R) -> Decision {
        Decision::Accept
    }
}

/// Rejects the route. Evaluation stops immediately.
///
/// The route will not be propagated to peers or installed in the RIB.
pub struct Reject;

impl<R: BgpRoute> Action<R> for Reject {
    fn apply(&self, _route: &mut R) -> Decision {
        Decision::Reject
    }
}

/// Falls through to the next term without modifying the route.
///
/// Useful when you need an explicit "no-op, continue" action — for example,
/// as the action of a term that only exists to log or count matched routes
/// before letting a later term make the final decision.
pub struct Next;

impl<R: BgpRoute> Action<R> for Next {
    fn apply(&self, _route: &mut R) -> Decision {
        Decision::Next
    }
}

// ── Attribute modification actions ─────────────────────────────────────────

/// Sets the `LOCAL_PREF` attribute and falls through to the next term.
///
/// `LOCAL_PREF` is the primary inbound traffic engineering lever. Setting it
/// above the default (100) makes a route preferred; below makes it a backup.
/// This action does not terminate evaluation — pair it with [`Accept`] via
/// [`ActionSequence`] to modify and accept in one term.
///
/// # Examples
///
/// ```ignore
/// // ActionSequence<R> requires a concrete BgpRoute type R to compile;
/// // see the unit tests in this module for a runnable example.
/// use pathvector_policy::{ActionSequence, Accept, SetLocalPref};
/// use pathvector_types::LocalPref;
///
/// let action: ActionSequence<MyRoute> = ActionSequence::new()
///     .then(SetLocalPref::new(LocalPref::new(200)))
///     .then(Accept);
/// ```
pub struct SetLocalPref(Option<LocalPref>);

impl SetLocalPref {
    /// Sets `LOCAL_PREF` to `value`.
    #[must_use]
    pub fn new(value: LocalPref) -> Self {
        Self(Some(value))
    }

    /// Clears the `LOCAL_PREF` attribute.
    #[must_use]
    pub fn clear() -> Self {
        Self(None)
    }
}

impl<R: BgpRoute> Action<R> for SetLocalPref {
    fn apply(&self, route: &mut R) -> Decision {
        route.set_local_pref(self.0);
        Decision::Next
    }
}

/// Sets the `MED` attribute and falls through.
///
/// MED is a hint sent to neighboring ASes about which entry point they
/// should prefer. Lower MED is preferred. Use this on export policies
/// when advertising to a peer that honours MED.
pub struct SetMed(Option<Med>);

impl SetMed {
    /// Sets `MED` to `value`.
    #[must_use]
    pub fn new(value: Med) -> Self {
        Self(Some(value))
    }

    /// Clears the `MED` attribute.
    #[must_use]
    pub fn clear() -> Self {
        Self(None)
    }
}

impl<R: BgpRoute> Action<R> for SetMed {
    fn apply(&self, route: &mut R) -> Decision {
        route.set_med(self.0);
        Decision::Next
    }
}

/// Sets the `ORIGIN` attribute and falls through.
///
/// Changing ORIGIN is unusual in practice but sometimes used when
/// redistributing static or connected routes to avoid advertising
/// `INCOMPLETE` to peers.
pub struct SetOrigin(Origin);

impl SetOrigin {
    /// Sets `ORIGIN` to `value`.
    #[must_use]
    pub fn new(value: Origin) -> Self {
        Self(value)
    }
}

impl<R: BgpRoute> Action<R> for SetOrigin {
    fn apply(&self, route: &mut R) -> Decision {
        route.set_origin(self.0);
        Decision::Next
    }
}

/// Sets the `NEXT_HOP` attribute and falls through.
///
/// Next-hop rewriting is common on export policies — for example, setting
/// next-hop to self before advertising to eBGP peers, or changing the
/// next-hop for route-server scenarios.
pub struct SetNextHop(Option<NextHop>);

impl SetNextHop {
    /// Sets `NEXT_HOP` to `value`.
    #[must_use]
    pub fn new(value: NextHop) -> Self {
        Self(Some(value))
    }

    /// Clears the `NEXT_HOP` attribute.
    #[must_use]
    pub fn clear() -> Self {
        Self(None)
    }
}

impl<R: BgpRoute> Action<R> for SetNextHop {
    fn apply(&self, route: &mut R) -> Decision {
        route.set_next_hop(self.0);
        Decision::Next
    }
}

// ── AS path actions ────────────────────────────────────────────────────────

/// Prepends an ASN to the `AS_PATH` one or more times, then falls through.
///
/// AS path prepending is used to make a route look less preferred to remote
/// ASes by artificially lengthening the path. Common on export policies
/// toward backup transit providers.
///
/// # Panics
///
/// Panics if `times` is zero.
pub struct PrependAsPath {
    asn: Asn,
    times: u8,
}

impl PrependAsPath {
    /// Prepends `asn` to the AS path `times` times.
    ///
    /// # Panics
    ///
    /// Panics if `times == 0`.
    #[must_use]
    pub fn new(asn: Asn, times: u8) -> Self {
        assert!(times > 0, "PrependAsPath: times must be >= 1");
        Self { asn, times }
    }

    /// Prepends `asn` once — the most common case.
    #[must_use]
    pub fn once(asn: Asn) -> Self {
        Self { asn, times: 1 }
    }
}

impl<R: BgpRoute> Action<R> for PrependAsPath {
    fn apply(&self, route: &mut R) -> Decision {
        let mut path = route.as_path().clone();
        for _ in 0..self.times {
            path.prepend(self.asn);
        }
        route.set_as_path(path);
        Decision::Next
    }
}

// ── Community actions ──────────────────────────────────────────────────────

/// Adds a standard community to the route and falls through.
///
/// If the route already carries this community it is added again — use
/// [`CommunityCondition`](crate::CommunityCondition) in the term's condition
/// to avoid duplicates if needed.
pub struct AddCommunity(Community);

impl AddCommunity {
    /// Creates an action that adds `community` to the route.
    #[must_use]
    pub fn new(community: Community) -> Self {
        Self(community)
    }
}

impl<R: BgpRoute> Action<R> for AddCommunity {
    fn apply(&self, route: &mut R) -> Decision {
        let mut communities = route.communities().to_vec();
        communities.push(self.0);
        route.set_communities(communities);
        Decision::Next
    }
}

/// Removes all occurrences of a specific standard community and falls through.
pub struct RemoveCommunity(Community);

impl RemoveCommunity {
    /// Creates an action that removes `community` from the route.
    #[must_use]
    pub fn new(community: Community) -> Self {
        Self(community)
    }
}

impl<R: BgpRoute> Action<R> for RemoveCommunity {
    fn apply(&self, route: &mut R) -> Decision {
        let communities: Vec<_> = route
            .communities()
            .iter()
            .copied()
            .filter(|c| c != &self.0)
            .collect();
        route.set_communities(communities);
        Decision::Next
    }
}

/// Replaces the entire standard communities list and falls through.
pub struct SetCommunities(Vec<Community>);

impl SetCommunities {
    /// Creates an action that replaces all communities with `communities`.
    #[must_use]
    pub fn new(communities: Vec<Community>) -> Self {
        Self(communities)
    }
}

impl<R: BgpRoute> Action<R> for SetCommunities {
    fn apply(&self, route: &mut R) -> Decision {
        route.set_communities(self.0.clone());
        Decision::Next
    }
}

/// Adds a large community (RFC 8092) to the route and falls through.
pub struct AddLargeCommunity(LargeCommunity);

impl AddLargeCommunity {
    /// Creates an action that adds `community` to the route.
    #[must_use]
    pub fn new(community: LargeCommunity) -> Self {
        Self(community)
    }
}

impl<R: BgpRoute> Action<R> for AddLargeCommunity {
    fn apply(&self, route: &mut R) -> Decision {
        let mut communities = route.large_communities().to_vec();
        communities.push(self.0);
        route.set_large_communities(communities);
        Decision::Next
    }
}

/// Removes all occurrences of a specific large community and falls through.
pub struct RemoveLargeCommunity(LargeCommunity);

impl RemoveLargeCommunity {
    /// Creates an action that removes `community` from the route.
    #[must_use]
    pub fn new(community: LargeCommunity) -> Self {
        Self(community)
    }
}

impl<R: BgpRoute> Action<R> for RemoveLargeCommunity {
    fn apply(&self, route: &mut R) -> Decision {
        let communities: Vec<_> = route
            .large_communities()
            .iter()
            .copied()
            .filter(|c| c != &self.0)
            .collect();
        route.set_large_communities(communities);
        Decision::Next
    }
}

// ── Compound action ────────────────────────────────────────────────────────

/// Runs a sequence of actions in order, stopping at the first terminal decision.
///
/// This is the primary way to combine modifiers with a terminal action in
/// a single term. Each step's `Decision` is checked:
/// - `Accept` or `Reject` — stops the sequence and returns that decision.
/// - `Next` — continues to the next step.
///
/// If all steps return `Next`, the sequence itself returns `Next`.
///
/// Internally uses `Vec<Box<dyn Action<R>>>`, so there is one vtable call
/// per step. This is acceptable — terms typically have 1–3 action steps.
///
/// # Examples
///
/// ```ignore
/// // ActionSequence<R> requires a concrete BgpRoute type R to compile;
/// // see the unit tests in this module for a runnable example.
/// use pathvector_policy::{Accept, ActionSequence, AddCommunity, SetLocalPref};
/// use pathvector_types::{Community, LocalPref};
///
/// let action: ActionSequence<MyRoute> = ActionSequence::new()
///     .then(SetLocalPref::new(LocalPref::new(200)))
///     .then(AddCommunity::new(Community::from_parts(65000, 200)))
///     .then(Accept);
/// ```
pub struct ActionSequence<R: BgpRoute> {
    steps: Vec<Box<dyn Action<R> + Send + Sync>>,
}

impl<R: BgpRoute> ActionSequence<R> {
    /// Creates an empty action sequence.
    #[must_use]
    pub fn new() -> Self {
        Self { steps: Vec::new() }
    }

    /// Appends a step to the sequence and returns `self` for chaining.
    #[must_use]
    pub fn then<A: Action<R> + Send + Sync + 'static>(mut self, action: A) -> Self {
        self.steps.push(Box::new(action));
        self
    }
}

impl<R: BgpRoute> Default for ActionSequence<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: BgpRoute> Action<R> for ActionSequence<R> {
    fn apply(&self, route: &mut R) -> Decision {
        for step in &self.steps {
            match step.apply(route) {
                Decision::Next => {}
                d => return d,
            }
        }
        Decision::Next
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestRoute;

    #[test]
    fn test_accept_action() {
        let mut route = TestRoute::new("10.0.0.0/8");
        assert_eq!(Accept.apply(&mut route), Decision::Accept);
    }

    #[test]
    fn test_reject_action() {
        let mut route = TestRoute::new("10.0.0.0/8");
        assert_eq!(Reject.apply(&mut route), Decision::Reject);
    }

    #[test]
    fn test_next_action() {
        let mut route = TestRoute::new("10.0.0.0/8");
        assert_eq!(Next.apply(&mut route), Decision::Next);
    }

    #[test]
    fn test_set_local_pref() {
        let mut route = TestRoute::new("10.0.0.0/8");
        assert_eq!(
            SetLocalPref::new(LocalPref::new(200)).apply(&mut route),
            Decision::Next
        );
        assert_eq!(route.local_pref, Some(LocalPref::new(200)));
    }

    #[test]
    fn test_set_local_pref_clear() {
        let mut route = TestRoute::new("10.0.0.0/8");
        route.local_pref = Some(LocalPref::new(100));
        SetLocalPref::clear().apply(&mut route);
        assert_eq!(route.local_pref, None);
    }

    #[test]
    fn test_set_med() {
        let mut route = TestRoute::new("10.0.0.0/8");
        SetMed::new(Med::new(50)).apply(&mut route);
        assert_eq!(route.med, Some(Med::new(50)));
    }

    #[test]
    fn test_set_med_clear() {
        let mut route = TestRoute::new("10.0.0.0/8");
        route.med = Some(Med::new(50));
        SetMed::clear().apply(&mut route);
        assert_eq!(route.med, None);
    }

    #[test]
    fn test_set_origin() {
        use pathvector_types::Origin;
        let mut route = TestRoute::new("10.0.0.0/8");
        route.origin = Origin::Incomplete;
        SetOrigin::new(Origin::Igp).apply(&mut route);
        assert_eq!(route.origin, Origin::Igp);
    }

    #[test]
    fn test_prepend_as_path_once() {
        use pathvector_types::{AsPath, Asn};
        let mut route = TestRoute::new("10.0.0.0/8");
        route.as_path = AsPath::from_sequence(vec![Asn::new(65001)]);
        PrependAsPath::once(Asn::new(65002)).apply(&mut route);
        assert_eq!(route.as_path.path_length(), 2);
        assert_eq!(route.as_path.origin_as(), Some(Asn::new(65001)));
    }

    #[test]
    fn test_prepend_as_path_multiple() {
        use pathvector_types::{AsPath, Asn};
        let mut route = TestRoute::new("10.0.0.0/8");
        route.as_path = AsPath::from_sequence(vec![Asn::new(65001)]);
        PrependAsPath::new(Asn::new(65000), 3).apply(&mut route);
        assert_eq!(route.as_path.path_length(), 4); // 3 prepends + original
    }

    #[test]
    #[should_panic(expected = "times must be >= 1")]
    fn test_prepend_as_path_zero_panics() {
        let _ = PrependAsPath::new(Asn::new(65000), 0);
    }

    #[test]
    fn test_add_community() {
        use pathvector_types::Community;
        let c = Community::from_parts(65000, 100);
        let mut route = TestRoute::new("10.0.0.0/8");
        AddCommunity::new(c).apply(&mut route);
        assert_eq!(route.communities, vec![c]);
    }

    #[test]
    fn test_remove_community() {
        use pathvector_types::Community;
        let keep = Community::from_parts(65000, 100);
        let remove = Community::from_parts(65000, 200);
        let mut route = TestRoute::new("10.0.0.0/8");
        route.communities = vec![keep, remove, keep];
        RemoveCommunity::new(remove).apply(&mut route);
        assert_eq!(route.communities, vec![keep, keep]);
    }

    #[test]
    fn test_set_communities() {
        use pathvector_types::Community;
        let a = Community::from_parts(65000, 1);
        let b = Community::from_parts(65000, 2);
        let mut route = TestRoute::new("10.0.0.0/8");
        route.communities = vec![a];
        SetCommunities::new(vec![b]).apply(&mut route);
        assert_eq!(route.communities, vec![b]);
    }

    #[test]
    fn test_add_large_community() {
        use pathvector_types::LargeCommunity;
        let lc = LargeCommunity::new(65000, 1, 100);
        let mut route = TestRoute::new("10.0.0.0/8");
        AddLargeCommunity::new(lc).apply(&mut route);
        assert_eq!(route.large_communities, vec![lc]);
    }

    #[test]
    fn test_remove_large_community() {
        use pathvector_types::LargeCommunity;
        let keep = LargeCommunity::new(65000, 1, 1);
        let remove = LargeCommunity::new(65000, 1, 2);
        let mut route = TestRoute::new("10.0.0.0/8");
        route.large_communities = vec![keep, remove];
        RemoveLargeCommunity::new(remove).apply(&mut route);
        assert_eq!(route.large_communities, vec![keep]);
    }

    #[test]
    fn test_set_next_hop() {
        use pathvector_types::NextHop;
        use std::net::Ipv4Addr;
        let nh = NextHop::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut route = TestRoute::new("10.0.0.0/8");
        SetNextHop::new(nh).apply(&mut route);
        assert_eq!(route.next_hop, Some(nh));
    }

    #[test]
    fn test_set_next_hop_clear() {
        use pathvector_types::NextHop;
        use std::net::Ipv4Addr;
        let nh = NextHop::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut route = TestRoute::new("10.0.0.0/8");
        route.next_hop = Some(nh);
        SetNextHop::clear().apply(&mut route);
        assert_eq!(route.next_hop, None);
    }

    #[test]
    fn test_action_sequence_all_next() {
        let mut route = TestRoute::new("10.0.0.0/8");
        let seq: ActionSequence<_> = ActionSequence::new().then(Next).then(Next);
        assert_eq!(seq.apply(&mut route), Decision::Next);
    }

    #[test]
    fn test_action_sequence_terminates_on_accept() {
        use pathvector_types::LocalPref;
        let mut route = TestRoute::new("10.0.0.0/8");
        let seq: ActionSequence<_> = ActionSequence::new()
            .then(SetLocalPref::new(LocalPref::new(200)))
            .then(Accept)
            .then(Reject); // should never be reached
        assert_eq!(seq.apply(&mut route), Decision::Accept);
        assert_eq!(route.local_pref, Some(LocalPref::new(200)));
    }

    #[test]
    fn test_action_sequence_terminates_on_reject() {
        let mut route = TestRoute::new("10.0.0.0/8");
        let seq: ActionSequence<_> = ActionSequence::new().then(Reject).then(Accept);
        assert_eq!(seq.apply(&mut route), Decision::Reject);
    }

    #[test]
    fn test_action_sequence_empty_returns_next() {
        let mut route = TestRoute::new("10.0.0.0/8");
        let seq: ActionSequence<TestRoute> = ActionSequence::new();
        assert_eq!(seq.apply(&mut route), Decision::Next);
    }

    #[test]
    fn test_action_sequence_default_equivalent_to_new() {
        let mut route = TestRoute::new("10.0.0.0/8");
        let seq: ActionSequence<TestRoute> = ActionSequence::default();
        assert_eq!(seq.apply(&mut route), Decision::Next);
    }
}
