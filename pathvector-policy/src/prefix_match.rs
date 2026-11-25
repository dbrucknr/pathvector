//! Route-prefix matching against a list of [`PrefixMatch`] entries.
//!
//! [`PrefixListCondition`](crate::PrefixListCondition) asks an
//! *address-coverage* question: is every address of the route's prefix inside a
//! set? Its `IpSet` merges adjacent ranges and keeps no entry boundaries or
//! lengths. [`PrefixMatchCondition`] asks a *route-prefix* question instead: is
//! there one configured entry whose prefix contains the route's prefix **and**
//! whose own length window admits the route's length?
//!
//! What a single entry accepts, and which bounds are valid, is defined by
//! [`ipnetx::prefix_match::PrefixMatch`].

use ipnetx::{interfaces::IpAddress, prefix::IpPrefix, prefix_match::PrefixMatch};

use crate::{condition::Condition, route::BgpRoute};

/// Matches routes whose prefix satisfies **at least one** [`PrefixMatch`]
/// entry.
///
/// Each entry is applied on its own: entries are never merged, and one entry's
/// length window never applies to another entry's prefix. Entry order does not
/// affect the result.
///
/// **An empty list matches nothing.** Wrapped in [`Not`](crate::Not) with
/// [`Reject`](crate::Reject), an empty list therefore rejects every route.
///
/// # Using it as a filter
///
/// To drop routes that match no entry while leaving later terms (such as origin
/// validation) able to reject the ones that do, reject the negation rather than
/// accepting the match. An accepting term ends evaluation.
///
/// ```
/// use std::net::Ipv4Addr;
/// use ipnetx::{prefix::IpPrefix, prefix_match::PrefixMatch};
/// use pathvector_policy::{
///     DefaultAction, Not, PolicyBuilder, PrefixMatchCondition, Reject, testutil::TestRoute,
/// };
///
/// let ten = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
/// let allowed = PrefixMatchCondition::new([PrefixMatch::new(ten, 16, 24).unwrap()]);
/// let policy = PolicyBuilder::<TestRoute>::new(DefaultAction::Accept)
///     .term(Not(allowed), Reject)
///     .build();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixMatchCondition<A: IpAddress> {
    entries: Vec<PrefixMatch<A>>,
}

impl<A: IpAddress> PrefixMatchCondition<A> {
    /// Creates a condition from any collection of entries.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::{prefix::IpPrefix, prefix_match::PrefixMatch};
    /// use pathvector_policy::PrefixMatchCondition;
    ///
    /// let ten = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
    /// let condition = PrefixMatchCondition::new([PrefixMatch::or_longer(ten)]);
    /// ```
    #[must_use]
    pub fn new(entries: impl IntoIterator<Item = PrefixMatch<A>>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }

    /// Returns `true` if at least one entry matches `prefix`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::{prefix::IpPrefix, prefix_match::PrefixMatch};
    /// use pathvector_policy::PrefixMatchCondition;
    ///
    /// let ten = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
    /// let condition = PrefixMatchCondition::new([PrefixMatch::exact(ten)]);
    /// assert!(condition.matches_prefix(ten));
    /// ```
    #[must_use]
    pub fn matches_prefix(&self, prefix: IpPrefix<A>) -> bool {
        self.entries.iter().any(|entry| entry.matches(prefix))
    }
}

impl<A: IpAddress + Send + Sync, R: BgpRoute<Addr = A>> Condition<R> for PrefixMatchCondition<A> {
    fn matches(&self, route: &R) -> bool {
        self.matches_prefix(route.nlri().prefix())
    }
}

#[cfg(test)]
mod tests {
    // What one entry accepts is tested in `ipnetx`. These tests cover what the
    // condition adds: reading the route's prefix and combining entries.
    use std::net::{Ipv4Addr, Ipv6Addr};

    use ipnetx::ipset::IpSetBuilder;
    use pathvector_types::{
        AsPath, Asn, Community, ExtendedCommunity, LargeCommunity, LocalPref, Med, NextHop, Nlri,
        Origin,
    };

    use super::*;
    use crate::{
        AnyCondition, Decision, DefaultAction, Not, PolicyBuilder, PrefixListCondition, Reject,
        testutil::TestRoute,
    };

    fn v4(s: &str) -> IpPrefix<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn entry4(s: &str, min: u8, max: u8) -> PrefixMatch<Ipv4Addr> {
        PrefixMatch::new(v4(s), min, max).unwrap()
    }

    #[test]
    fn test_prefix_match_condition_applies_the_window_to_the_route() {
        let condition = PrefixMatchCondition::new([entry4("10.0.0.0/8", 16, 24)]);
        // The last accepted route carries host bits.
        for r in ["10.1.0.0/16", "10.1.2.0/24", "10.1.2.3/24"] {
            assert!(condition.matches(&TestRoute::new(r)), "{r}");
        }
        for r in [
            "10.0.0.0/8",
            "10.0.0.0/15",
            "10.1.2.0/25",
            "10.1.2.3/32",
            "11.1.0.0/16",
            "0.0.0.0/0",
        ] {
            assert!(!condition.matches(&TestRoute::new(r)), "{r}");
        }
    }

    #[test]
    fn test_prefix_match_condition_matches_any_entry_in_any_order() {
        // 10.1.2.0/24 fails the more specific exact entry but satisfies the /8
        // one, so a longest-match-then-check shortcut would get this wrong.
        let wide = PrefixMatch::or_longer(v4("10.0.0.0/8"));
        let narrow = PrefixMatch::exact(v4("10.1.0.0/16"));
        let route = TestRoute::new("10.1.2.0/24");
        assert!(PrefixMatchCondition::new([wide, narrow]).matches(&route));
        assert!(PrefixMatchCondition::new([narrow, wide]).matches(&route));
        assert!(!PrefixMatchCondition::new([narrow]).matches(&route));
    }

    #[test]
    fn test_prefix_match_condition_keeps_each_window_with_its_prefix() {
        let condition = PrefixMatchCondition::new([
            entry4("10.0.0.0/8", 8, 16),
            entry4("192.168.0.0/16", 24, 32),
        ]);
        assert!(condition.matches(&TestRoute::new("10.1.0.0/16")));
        assert!(condition.matches(&TestRoute::new("192.168.1.0/24")));
        // /24 is admitted only under 192.168/16, /16 only under 10/8.
        assert!(!condition.matches(&TestRoute::new("10.1.1.0/24")));
        assert!(!condition.matches(&TestRoute::new("192.168.0.0/16")));
    }

    #[test]
    fn test_prefix_match_condition_does_not_merge_adjacent_entries() {
        let halves = ["10.0.0.0/25", "10.0.0.128/25"];
        let whole = TestRoute::new("10.0.0.0/24");

        let condition = PrefixMatchCondition::new(halves.map(|h| PrefixMatch::or_longer(v4(h))));
        assert!(!condition.matches(&whole));

        // `PrefixListCondition` keeps its address-coverage semantics.
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        for half in halves {
            builder.add_prefix(v4(half));
        }
        assert!(PrefixListCondition::new(builder.build()).matches(&whole));
    }

    #[test]
    fn test_prefix_match_condition_empty_matches_nothing() {
        let empty = PrefixMatchCondition::<Ipv4Addr>::new([]);
        for r in ["0.0.0.0/0", "10.0.0.0/8", "255.255.255.255/32"] {
            assert!(!empty.matches(&TestRoute::new(r)));
        }
    }

    #[test]
    fn test_prefix_match_condition_reject_unless_matched_leaves_later_terms_active() {
        let allowed = PrefixMatchCondition::new([entry4("10.0.0.0/8", 16, 24)]);
        let filter_only = PolicyBuilder::<TestRoute>::new(DefaultAction::Accept)
            .term(Not(allowed.clone()), Reject)
            .build();
        let with_later_term = PolicyBuilder::<TestRoute>::new(DefaultAction::Accept)
            .term(Not(allowed), Reject)
            .term(AnyCondition, Reject)
            .build();

        let mut inside = TestRoute::new("10.1.0.0/16");
        let mut outside = TestRoute::new("11.1.0.0/16");
        assert_eq!(filter_only.evaluate(&mut inside), Decision::Accept);
        assert_eq!(filter_only.evaluate(&mut outside), Decision::Reject);
        assert_eq!(with_later_term.evaluate(&mut inside), Decision::Reject);
    }

    /// Minimal IPv6 `BgpRoute`; the shared `TestRoute` is IPv4-only.
    struct V6Route {
        nlri: Nlri<Ipv6Addr>,
        as_path: AsPath,
    }

    impl BgpRoute for V6Route {
        type Addr = Ipv6Addr;
        fn nlri(&self) -> Nlri<Self::Addr> {
            self.nlri
        }
        fn origin(&self) -> Origin {
            Origin::Igp
        }
        fn local_pref(&self) -> Option<LocalPref> {
            None
        }
        fn med(&self) -> Option<Med> {
            None
        }
        fn as_path(&self) -> &AsPath {
            &self.as_path
        }
        fn communities(&self) -> &[Community] {
            &[]
        }
        fn large_communities(&self) -> &[LargeCommunity] {
            &[]
        }
        fn extended_communities(&self) -> &[ExtendedCommunity] {
            &[]
        }
        fn next_hop(&self) -> Option<NextHop> {
            None
        }
        fn otc(&self) -> Option<Asn> {
            None
        }
        fn set_origin(&mut self, _origin: Origin) {}
        fn set_local_pref(&mut self, _lp: Option<LocalPref>) {}
        fn set_med(&mut self, _med: Option<Med>) {}
        fn set_as_path(&mut self, path: AsPath) {
            self.as_path = path;
        }
        fn set_communities(&mut self, _c: Vec<Community>) {}
        fn set_large_communities(&mut self, _c: Vec<LargeCommunity>) {}
        fn set_extended_communities(&mut self, _c: Vec<ExtendedCommunity>) {}
        fn set_next_hop(&mut self, _nh: Option<NextHop>) {}
        fn set_otc(&mut self, _otc: Option<Asn>) {}
    }

    #[test]
    fn test_prefix_match_condition_v6_route() {
        let entry = PrefixMatch::new("2001:db8::/32".parse().unwrap(), 32, 48).unwrap();
        let condition = PrefixMatchCondition::new([entry]);
        let route = |s: &str| V6Route {
            nlri: s.parse().unwrap(),
            as_path: AsPath::new(),
        };
        assert!(condition.matches(&route("2001:db8:1::/48")));
        assert!(!condition.matches(&route("2001:db8:1::/64")));
        assert!(!condition.matches(&route("2001:db9::/48")));
    }
}
