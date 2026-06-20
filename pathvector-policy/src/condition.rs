use ipnetx::{interfaces::IpAddress, ipset::IpSet};
use pathvector_types::{Asn, Community, LargeCommunity, LocalPref, Med, Origin};

use crate::route::BgpRoute;

/// A match predicate applied to a [`BgpRoute`] by a [`Term`](crate::Term).
///
/// Conditions borrow the route immutably — they never modify it. The
/// companion [`Action`](crate::Action) trait handles modification.
///
/// Implement this trait to create custom match logic. The built-in conditions
/// cover the most common BGP policy match criteria.
pub trait Condition<R: BgpRoute>: Send + Sync {
    /// Returns `true` if this condition matches the given route.
    fn matches(&self, route: &R) -> bool;
}

// ── Logical combinators ────────────────────────────────────────────────────

/// A condition that always matches.
///
/// Useful as the condition on a final "catch-all" term — e.g. a term that
/// unconditionally rejects anything that made it this far.
///
/// # Examples
///
/// ```
/// use pathvector_policy::AnyCondition;
/// ```
pub struct AnyCondition;

impl<R: BgpRoute> Condition<R> for AnyCondition {
    fn matches(&self, _route: &R) -> bool {
        true
    }
}

/// A condition that inverts the result of an inner condition.
///
/// # Examples
///
/// ```
/// use pathvector_policy::{Not, OriginCondition};
/// use pathvector_types::Origin;
///
/// // Matches any route whose origin is NOT IGP
/// let c = Not(OriginCondition::new(Origin::Igp));
/// ```
pub struct Not<C>(pub C);

impl<R: BgpRoute, C: Condition<R>> Condition<R> for Not<C> {
    fn matches(&self, route: &R) -> bool {
        !self.0.matches(route)
    }
}

// ── Prefix matching ────────────────────────────────────────────────────────

/// Matches routes whose NLRI falls within a configured [`IpSet`].
///
/// The route's masked network address is checked against the set — if the
/// address falls within any range in the set, the condition matches. This
/// is equivalent to "the route's prefix is covered by any prefix in the
/// prefix-list."
///
/// Build the [`IpSet`] using [`ipnetx::ipset::IpSetBuilder`] and pass it to
/// [`PrefixListCondition::new`].
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use ipnetx::{ipset::IpSetBuilder, prefix::IpPrefix};
/// use pathvector_policy::PrefixListCondition;
///
/// let mut builder = IpSetBuilder::<Ipv4Addr>::new();
/// builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
/// builder.add_prefix(IpPrefix::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap());
///
/// let condition = PrefixListCondition::new(builder.build());
/// ```
pub struct PrefixListCondition<A: IpAddress> {
    set: IpSet<A>,
}

impl<A: IpAddress> PrefixListCondition<A> {
    /// Creates a new prefix-list condition from an [`IpSet`].
    #[must_use]
    pub fn new(set: IpSet<A>) -> Self {
        Self { set }
    }
}

impl<A: IpAddress + Send + Sync, R: BgpRoute<Addr = A>> Condition<R> for PrefixListCondition<A> {
    fn matches(&self, route: &R) -> bool {
        self.set
            .contains_range(route.nlri().prefix().masked().to_range())
    }
}

// ── Community matching ─────────────────────────────────────────────────────

/// Matches routes that carry a specific standard community (RFC 1997).
///
/// # Examples
///
/// ```
/// use pathvector_policy::CommunityCondition;
/// use pathvector_types::Community;
///
/// // Match routes tagged as low-priority by AS 65000
/// let c = CommunityCondition::new(Community::from_parts(65000, 100));
/// ```
pub struct CommunityCondition {
    community: Community,
}

impl CommunityCondition {
    /// Creates a new condition that matches routes carrying `community`.
    #[must_use]
    pub fn new(community: Community) -> Self {
        Self { community }
    }
}

impl<R: BgpRoute> Condition<R> for CommunityCondition {
    fn matches(&self, route: &R) -> bool {
        route.communities().contains(&self.community)
    }
}

/// Matches routes that carry a specific large community (RFC 8092).
///
/// # Examples
///
/// ```
/// use pathvector_policy::LargeCommunityCondition;
/// use pathvector_types::LargeCommunity;
///
/// let c = LargeCommunityCondition::new(LargeCommunity::new(65000, 1, 100));
/// ```
pub struct LargeCommunityCondition {
    community: LargeCommunity,
}

impl LargeCommunityCondition {
    /// Creates a new condition that matches routes carrying `community`.
    #[must_use]
    pub fn new(community: LargeCommunity) -> Self {
        Self { community }
    }
}

impl<R: BgpRoute> Condition<R> for LargeCommunityCondition {
    fn matches(&self, route: &R) -> bool {
        route.large_communities().contains(&self.community)
    }
}

// ── AS path matching ───────────────────────────────────────────────────────

/// Matches routes whose AS path contains a specific ASN in any segment.
///
/// This is one of the most common policy matches — operators use it to
/// detect routes that have passed through a specific network and apply
/// different treatment (e.g. lower local-pref for routes via a competitor).
///
/// # Examples
///
/// ```
/// use pathvector_policy::AsPathContainsCondition;
/// use pathvector_types::Asn;
///
/// // Match any route that transited AS 13335 (Cloudflare)
/// let c = AsPathContainsCondition::new(Asn::new(13335));
/// ```
pub struct AsPathContainsCondition {
    asn: Asn,
}

impl AsPathContainsCondition {
    /// Creates a new condition that matches if the AS path contains `asn`.
    #[must_use]
    pub fn new(asn: Asn) -> Self {
        Self { asn }
    }
}

impl<R: BgpRoute> Condition<R> for AsPathContainsCondition {
    fn matches(&self, route: &R) -> bool {
        route.as_path().contains(self.asn)
    }
}

/// A numeric comparison operator used by attribute-comparison conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    /// `lhs == rhs`
    Equal,
    /// `lhs != rhs`
    NotEqual,
    /// `lhs < rhs`
    LessThan,
    /// `lhs <= rhs`
    LessOrEqual,
    /// `lhs > rhs`
    GreaterThan,
    /// `lhs >= rhs`
    GreaterOrEqual,
}

impl CompareOp {
    /// Applies this operator to two values.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn compare<T: PartialOrd>(self, lhs: T, rhs: T) -> bool {
        match self {
            Self::Equal => lhs == rhs,
            Self::NotEqual => lhs != rhs,
            Self::LessThan => lhs < rhs,
            Self::LessOrEqual => lhs <= rhs,
            Self::GreaterThan => lhs > rhs,
            Self::GreaterOrEqual => lhs >= rhs,
        }
    }
}

/// Matches routes whose AS path length satisfies a numeric comparison.
///
/// AS path length uses the BGP definition: `AS_SEQUENCE` counts per-ASN,
/// `AS_SET` counts as one regardless of size, and confederation segments
/// count as zero.
///
/// # Examples
///
/// ```
/// use pathvector_policy::{AsPathLengthCondition, CompareOp};
///
/// // Prefer short paths — match routes with AS path length <= 3
/// let c = AsPathLengthCondition::new(CompareOp::LessOrEqual, 3);
/// ```
pub struct AsPathLengthCondition {
    op: CompareOp,
    length: usize,
}

impl AsPathLengthCondition {
    /// Creates a new AS path length condition.
    #[must_use]
    pub fn new(op: CompareOp, length: usize) -> Self {
        Self { op, length }
    }
}

impl<R: BgpRoute> Condition<R> for AsPathLengthCondition {
    fn matches(&self, route: &R) -> bool {
        self.op.compare(route.as_path().path_length(), self.length)
    }
}

// ── Attribute comparison conditions ───────────────────────────────────────

/// Matches routes whose `LOCAL_PREF` satisfies a numeric comparison.
///
/// Routes without a `LOCAL_PREF` attribute (typically eBGP-learned routes)
/// never match this condition.
///
/// # Examples
///
/// ```
/// use pathvector_policy::{CompareOp, LocalPrefCondition};
/// use pathvector_types::LocalPref;
///
/// // Match routes that have already been tagged as preferred
/// let c = LocalPrefCondition::new(CompareOp::GreaterOrEqual, LocalPref::new(200));
/// ```
pub struct LocalPrefCondition {
    op: CompareOp,
    value: LocalPref,
}

impl LocalPrefCondition {
    /// Creates a new `LOCAL_PREF` comparison condition.
    #[must_use]
    pub fn new(op: CompareOp, value: LocalPref) -> Self {
        Self { op, value }
    }
}

impl<R: BgpRoute> Condition<R> for LocalPrefCondition {
    fn matches(&self, route: &R) -> bool {
        route
            .local_pref()
            .is_some_and(|lp| self.op.compare(lp, self.value))
    }
}

/// Matches routes whose `MED` satisfies a numeric comparison.
///
/// Routes without a `MED` attribute never match this condition.
///
/// # Examples
///
/// ```
/// use pathvector_policy::{CompareOp, MedCondition};
/// use pathvector_types::Med;
///
/// // Match routes signalling a preferred entry point (low MED)
/// let c = MedCondition::new(CompareOp::LessThan, Med::new(100));
/// ```
pub struct MedCondition {
    op: CompareOp,
    value: Med,
}

impl MedCondition {
    /// Creates a new `MED` comparison condition.
    #[must_use]
    pub fn new(op: CompareOp, value: Med) -> Self {
        Self { op, value }
    }
}

impl<R: BgpRoute> Condition<R> for MedCondition {
    fn matches(&self, route: &R) -> bool {
        route
            .med()
            .is_some_and(|med| self.op.compare(med, self.value))
    }
}

/// Matches routes with a specific `ORIGIN` value.
///
/// # Examples
///
/// ```
/// use pathvector_policy::OriginCondition;
/// use pathvector_types::Origin;
///
/// // Match only routes with a clean IGP origin
/// let c = OriginCondition::new(Origin::Igp);
/// ```
pub struct OriginCondition {
    origin: Origin,
}

impl OriginCondition {
    /// Creates a new origin match condition.
    #[must_use]
    pub fn new(origin: Origin) -> Self {
        Self { origin }
    }
}

impl<R: BgpRoute> Condition<R> for OriginCondition {
    fn matches(&self, route: &R) -> bool {
        route.origin() == self.origin
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestRoute;

    #[test]
    fn test_any_condition_always_matches() {
        let route = TestRoute::new("10.0.0.0/8");
        assert!(AnyCondition.matches(&route));
    }

    #[test]
    fn test_not_inverts_condition() {
        let route = TestRoute::new("10.0.0.0/8");
        assert!(!Not(AnyCondition).matches(&route));
        assert!(Not(Not(AnyCondition)).matches(&route));
    }

    #[test]
    fn test_prefix_list_condition() {
        use ipnetx::{ipset::IpSetBuilder, prefix::IpPrefix};
        use std::net::Ipv4Addr;

        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
        let condition = PrefixListCondition::new(builder.build());

        let inside = TestRoute::new("10.1.2.0/24");
        let outside = TestRoute::new("192.168.0.0/16");

        assert!(condition.matches(&inside));
        assert!(!condition.matches(&outside));
    }

    #[test]
    fn test_prefix_list_condition_host_bits() {
        use ipnetx::{ipset::IpSetBuilder, prefix::IpPrefix};
        use std::net::Ipv4Addr;

        // IpSet covers 10.0.0.0/8. Route prefix has unmasked host bits:
        // 10.1.2.3/24 — masked network is 10.1.2.0, which is inside the /8.
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
        let condition = PrefixListCondition::new(builder.build());

        let route = TestRoute::with_nlri_ip("10.1.2.3/24");
        assert!(condition.matches(&route));
    }

    #[test]
    fn test_community_condition() {
        use pathvector_types::Community;

        let target = Community::from_parts(65000, 100);
        let other = Community::from_parts(65000, 200);
        let condition = CommunityCondition::new(target);

        let mut route = TestRoute::new("10.0.0.0/8");

        assert!(!condition.matches(&route));

        route.communities = vec![other];
        assert!(!condition.matches(&route));

        route.communities = vec![other, target];
        assert!(condition.matches(&route));
    }

    #[test]
    fn test_large_community_condition() {
        use pathvector_types::LargeCommunity;

        let target = LargeCommunity::new(65000, 1, 100);
        let condition = LargeCommunityCondition::new(target);

        let mut route = TestRoute::new("10.0.0.0/8");
        assert!(!condition.matches(&route));

        route.large_communities = vec![target];
        assert!(condition.matches(&route));
    }

    #[test]
    fn test_as_path_contains_condition() {
        use pathvector_types::{AsPath, Asn};

        let condition = AsPathContainsCondition::new(Asn::new(65001));
        let mut route = TestRoute::new("10.0.0.0/8");

        assert!(!condition.matches(&route));

        route.as_path =
            AsPath::from_sequence(vec![Asn::new(65002), Asn::new(65001), Asn::new(65000)]);
        assert!(condition.matches(&route));
    }

    #[test]
    fn test_compare_op() {
        assert!(CompareOp::Equal.compare(5u32, 5));
        assert!(!CompareOp::Equal.compare(5u32, 6));
        assert!(CompareOp::NotEqual.compare(5u32, 6));
        assert!(CompareOp::LessThan.compare(4u32, 5));
        assert!(!CompareOp::LessThan.compare(5u32, 5));
        assert!(CompareOp::LessOrEqual.compare(5u32, 5));
        assert!(CompareOp::GreaterThan.compare(6u32, 5));
        assert!(CompareOp::GreaterOrEqual.compare(5u32, 5));
    }

    #[test]
    fn test_as_path_length_condition() {
        use pathvector_types::{AsPath, Asn};

        let condition = AsPathLengthCondition::new(CompareOp::LessOrEqual, 2);
        let mut route = TestRoute::new("10.0.0.0/8");

        // Empty path — length 0
        assert!(condition.matches(&route));

        // Path of length 2
        route.as_path = AsPath::from_sequence(vec![Asn::new(65002), Asn::new(65001)]);
        assert!(condition.matches(&route));

        // Path of length 3 — no longer matches <= 2
        route.as_path =
            AsPath::from_sequence(vec![Asn::new(65003), Asn::new(65002), Asn::new(65001)]);
        assert!(!condition.matches(&route));
    }

    #[test]
    fn test_local_pref_condition_absent() {
        let condition = LocalPrefCondition::new(CompareOp::GreaterOrEqual, LocalPref::new(100));
        let route = TestRoute::new("10.0.0.0/8"); // no LOCAL_PREF
        assert!(!condition.matches(&route));
    }

    #[test]
    fn test_local_pref_condition_present() {
        use pathvector_types::LocalPref;

        let condition = LocalPrefCondition::new(CompareOp::GreaterOrEqual, LocalPref::new(100));
        let mut route = TestRoute::new("10.0.0.0/8");

        route.local_pref = Some(LocalPref::new(200));
        assert!(condition.matches(&route));

        route.local_pref = Some(LocalPref::new(50));
        assert!(!condition.matches(&route));
    }

    #[test]
    fn test_med_condition_absent() {
        let condition = MedCondition::new(CompareOp::Equal, Med::new(0));
        let route = TestRoute::new("10.0.0.0/8"); // no MED
        assert!(!condition.matches(&route));
    }

    #[test]
    fn test_med_condition_present() {
        use pathvector_types::Med;

        let condition = MedCondition::new(CompareOp::LessThan, Med::new(100));
        let mut route = TestRoute::new("10.0.0.0/8");

        route.med = Some(Med::new(10));
        assert!(condition.matches(&route));

        route.med = Some(Med::new(100));
        assert!(!condition.matches(&route));
    }

    #[test]
    fn test_origin_condition() {
        use pathvector_types::Origin;

        let condition = OriginCondition::new(Origin::Igp);
        let mut route = TestRoute::new("10.0.0.0/8");

        route.origin = Origin::Igp;
        assert!(condition.matches(&route));

        route.origin = Origin::Incomplete;
        assert!(!condition.matches(&route));
    }

    #[test]
    fn test_prefix_list_condition_less_specific_does_not_match_more_specific_entry() {
        // A /8 route should NOT match a prefix-list that only contains a /24.
        // The /8's network address (e.g. 10.0.0.0) is outside the /24 range.
        use ipnetx::{ipset::IpSetBuilder, prefix::IpPrefix};
        use std::net::Ipv4Addr;

        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 1, 0, 0), 24).unwrap());
        let condition = PrefixListCondition::new(builder.build());

        // Less-specific route: 10.0.0.0/8 — network address 10.0.0.0 is NOT in 10.1.0.0/24
        let less_specific = TestRoute::new("10.0.0.0/8");
        assert!(!condition.matches(&less_specific));

        // More-specific route: 10.1.0.0/24 — network address IS in the /24
        let exact = TestRoute::new("10.1.0.0/24");
        assert!(condition.matches(&exact));
    }

    #[test]
    fn test_prefix_list_condition_less_specific_does_not_match_when_network_addr_coincides() {
        // A /8 route should NOT match a prefix-list that only contains a /16,
        // even when both share the same network address (10.0.0.0).
        //
        // The current contains_ip check returns true because 10.0.0.0 falls
        // inside the /16 range (10.0.0.0 – 10.0.255.255), producing a false
        // positive. The correct test is whether the route's entire address range
        // is covered by the set.
        use ipnetx::{ipset::IpSetBuilder, prefix::IpPrefix};
        use std::net::Ipv4Addr;

        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 16).unwrap());
        let condition = PrefixListCondition::new(builder.build());

        // 10.0.0.0/8 is less specific than the /16 entry — must not match.
        let less_specific = TestRoute::new("10.0.0.0/8");
        assert!(!condition.matches(&less_specific));
    }

    #[test]
    fn test_local_pref_condition_equal_op() {
        use pathvector_types::LocalPref;

        let condition = LocalPrefCondition::new(CompareOp::Equal, LocalPref::new(100));
        let mut route = TestRoute::new("10.0.0.0/8");

        route.local_pref = Some(LocalPref::new(100));
        assert!(condition.matches(&route));

        route.local_pref = Some(LocalPref::new(99));
        assert!(!condition.matches(&route));
    }

    #[test]
    fn test_local_pref_condition_not_equal_op() {
        use pathvector_types::LocalPref;

        let condition = LocalPrefCondition::new(CompareOp::NotEqual, LocalPref::new(100));
        let mut route = TestRoute::new("10.0.0.0/8");

        route.local_pref = Some(LocalPref::new(200));
        assert!(condition.matches(&route));

        route.local_pref = Some(LocalPref::new(100));
        assert!(!condition.matches(&route));
    }

    #[test]
    fn test_local_pref_condition_boundary_zero() {
        use pathvector_types::LocalPref;

        let condition = LocalPrefCondition::new(CompareOp::Equal, LocalPref::new(0));
        let mut route = TestRoute::new("10.0.0.0/8");

        route.local_pref = Some(LocalPref::new(0));
        assert!(condition.matches(&route));

        route.local_pref = Some(LocalPref::new(1));
        assert!(!condition.matches(&route));
    }

    #[test]
    fn test_med_condition_equal_op() {
        use pathvector_types::Med;

        let condition = MedCondition::new(CompareOp::Equal, Med::new(50));
        let mut route = TestRoute::new("10.0.0.0/8");

        route.med = Some(Med::new(50));
        assert!(condition.matches(&route));

        route.med = Some(Med::new(51));
        assert!(!condition.matches(&route));
    }

    #[test]
    fn test_med_condition_not_equal_op() {
        use pathvector_types::Med;

        let condition = MedCondition::new(CompareOp::NotEqual, Med::new(100));
        let mut route = TestRoute::new("10.0.0.0/8");

        route.med = Some(Med::new(0));
        assert!(condition.matches(&route));

        route.med = Some(Med::new(100));
        assert!(!condition.matches(&route));
    }

    #[test]
    fn test_med_condition_boundary_max() {
        use pathvector_types::Med;

        let condition = MedCondition::new(CompareOp::Equal, Med::new(u32::MAX));
        let mut route = TestRoute::new("10.0.0.0/8");

        route.med = Some(Med::new(u32::MAX));
        assert!(condition.matches(&route));

        route.med = Some(Med::new(u32::MAX - 1));
        assert!(!condition.matches(&route));
    }

    #[test]
    fn test_as_path_length_condition_equal_op() {
        use pathvector_types::{AsPath, Asn};

        let condition = AsPathLengthCondition::new(CompareOp::Equal, 2);
        let mut route = TestRoute::new("10.0.0.0/8");

        route.as_path = AsPath::from_sequence(vec![Asn::new(65002), Asn::new(65001)]);
        assert!(condition.matches(&route));

        route.as_path = AsPath::from_sequence(vec![Asn::new(65001)]);
        assert!(!condition.matches(&route));
    }
}
