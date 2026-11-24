// daemon/blackhole.rs — RFC 7999 BLACKHOLE handling as pure values.
//
// This module decides; it never touches a RIB or the FIB. Three pieces:
//
// 1. `BlackholeAgreement<A>` — the per-session answer to RFC 7999 §3.3's two
//    conditions (agreement + authorized prefix scope). It is the only thing
//    that can mint an `AuthorizedBlackhole<A>`.
// 2. `AuthorizedBlackhole<A>` — a witness that a route passed the agreement.
//    `BlackholeBook::claim` accepts nothing else, so "program a null route for
//    a prefix nobody authorized" does not type-check.
// 3. `BlackholeBook<A>` — which peers currently hold an authorized blackhole
//    for which prefix, and the `BlackholeChange`s (null route installed /
//    withdrawn) that follow from a claim or release. A kernel null route is
//    per prefix, not per peer, so it is installed when the first peer claims
//    the prefix and withdrawn only when the last one lets go.
//
// The classification pipeline (`import.rs`) turns a received route into an
// `ImportDecision`; applying a `Blackhole` decision claims here, applying any
// other decision (or a withdrawal, or a session ending) releases here. FIB
// programming stays with the caller, behind `ApplyFibChange`.
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use pathvector_policy::{Condition, OtcLeakCondition};
use pathvector_rib::{PeerId, Route};
use pathvector_types::{Community, IpAddress, Nlri};

use crate::blackhole::{BlackholeScope, ScopeFamily};

/// `true` when `route` carries the RFC 7999 BLACKHOLE community
/// (`65535:666`, `0xFFFF029A`).
pub(crate) fn carries_blackhole_community<A: IpAddress>(route: &Route<A>) -> bool {
    route
        .rare_or_default()
        .communities
        .iter()
        .any(|c| Community::is_blackhole(*c))
}

/// Why a BLACKHOLE-tagged announcement is not honored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlackholeDenied {
    /// The session has no BLACKHOLE agreement (the default). RFC 7999 §3.3
    /// condition 2 / §4.
    NotAgreed,
    /// The prefix is not covered by an authorized prefix. RFC 7999 §3.3
    /// condition 1.
    OutOfScope,
    /// An RFC 9234 §5 route leak: "MUST be considered ineligible". A blackhole
    /// request is exempt from origin validation (RFC 7999 §3.3), not from the
    /// leak check.
    RouteLeak,
}

/// A blackhole request that satisfied RFC 7999 §3.3: the session agreed to
/// honor BLACKHOLE and the prefix is inside the authorized scope.
///
/// Only [`BlackholeAgreement::authorize`] constructs one. It carries the
/// prefix, not the route: the route stays in the Adj-RIB-In (RFC 7999 §3.3
/// encourages keeping every BLACKHOLE announcement) and never enters the
/// Loc-RIB, so it can never be selected, exported or reflected as unicast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthorizedBlackhole<A: IpAddress> {
    nlri: Nlri<A>,
}

impl<A: IpAddress> AuthorizedBlackhole<A> {
    /// The blackholed prefix.
    pub(crate) fn nlri(&self) -> Nlri<A> {
        self.nlri
    }
}

/// One session's BLACKHOLE agreement for one address family (RFC 7999 §3.3).
///
/// [`denied`](Self::denied) — no agreement — is the default; a session gets an
/// agreement only from its configured [`BlackholeScope`].
///
/// # ROV exception
///
/// RFC 7999 §3.3: "An operator MUST ensure that origin validation techniques
/// (such as the one described in RFC 6811) do not inadvertently block
/// legitimate announcements carrying the BLACKHOLE community." A legitimate
/// host blackhole (`/32`, `/128`) is routinely longer than any ROA
/// `maxLength`, so ordinary ROV would mark it Invalid. The exception is
/// structural: an authorized request is classified here, *instead of* by the
/// session's import policy, so neither ROV nor the import default can reject
/// it. Authorization — the explicit scope — takes ROV's place. The only
/// ordinary-import rule that still applies is the RFC 9234 §5 leak check,
/// because a leak is ineligible whatever the route is for.
pub(crate) struct BlackholeAgreement<A: IpAddress> {
    scope: Option<BlackholeScope>,
    leak_guard: Option<OtcLeakCondition>,
    _family: std::marker::PhantomData<A>,
}

impl<A: IpAddress> std::fmt::Debug for BlackholeAgreement<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlackholeAgreement")
            .field("scope", &self.scope)
            .field("leak_guard", &self.leak_guard.is_some())
            .finish()
    }
}

impl<A: IpAddress> BlackholeAgreement<A> {
    /// No agreement: every BLACKHOLE-tagged announcement is denied.
    pub(crate) fn denied() -> Self {
        Self {
            scope: None,
            leak_guard: None,
            _family: std::marker::PhantomData,
        }
    }

    /// The session agreed to honor BLACKHOLE for the prefixes in `scope`.
    pub(crate) fn agreed(scope: BlackholeScope) -> Self {
        Self {
            scope: Some(scope),
            leak_guard: None,
            _family: std::marker::PhantomData,
        }
    }

    /// Keeps RFC 9234 §5 leak detection in force for blackhole requests on a
    /// session that has a BGP Role.
    #[must_use]
    pub(crate) fn with_leak_guard(mut self, guard: OtcLeakCondition) -> Self {
        self.leak_guard = Some(guard);
        self
    }

    /// `true` when the session has no agreement.
    #[cfg(test)]
    pub(crate) fn is_denied(&self) -> bool {
        self.scope.is_none()
    }
}

impl<A: ScopeFamily> BlackholeAgreement<A> {
    /// RFC 7999 §3.3: honor `route` only if the session agreed to BLACKHOLE and
    /// the announced prefix is covered by an authorized one.
    ///
    /// The caller has already established that `route` carries the BLACKHOLE
    /// community ([`carries_blackhole_community`]).
    pub(crate) fn authorize(
        &self,
        route: &Route<A>,
    ) -> Result<AuthorizedBlackhole<A>, BlackholeDenied> {
        let Some(scope) = &self.scope else {
            return Err(BlackholeDenied::NotAgreed);
        };
        if !scope.covers(&route.nlri) {
            return Err(BlackholeDenied::OutOfScope);
        }
        if self
            .leak_guard
            .as_ref()
            .is_some_and(|g| Condition::<Route<A>>::matches(g, route))
        {
            return Err(BlackholeDenied::RouteLeak);
        }
        Ok(AuthorizedBlackhole { nlri: route.nlri })
    }
}

/// A kernel null route to program or remove, as decided by
/// [`BlackholeBook`]. Emitted only on a 0→1 or 1→0 holder transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlackholeChange<A: IpAddress> {
    /// First holder: program `RTN_BLACKHOLE` for the prefix.
    Install(Nlri<A>),
    /// Last holder gone: remove the null route.
    Withdraw(Nlri<A>),
}

/// Which peers hold an authorized blackhole for which prefix.
///
/// This is the single record of "what null routes this daemon asked the kernel
/// for". Reconciliation reads it rather than re-deriving ownership from stored
/// routes, so a route that was *denied* (and never programmed) can never cause
/// another peer's null route to be removed, and two peers requesting the same
/// prefix share one kernel route.
#[derive(Debug)]
pub(crate) struct BlackholeBook<A: IpAddress> {
    holders: HashMap<Nlri<A>, Vec<PeerId>>,
}

impl<A: IpAddress> Default for BlackholeBook<A> {
    fn default() -> Self {
        Self {
            holders: HashMap::new(),
        }
    }
}

impl<A: IpAddress> BlackholeBook<A> {
    /// Records that `peer` holds `blackhole`. Idempotent: claiming what the
    /// peer already holds changes nothing. `Some(Install)` iff no peer held the
    /// prefix before.
    pub(crate) fn claim(
        &mut self,
        peer: PeerId,
        blackhole: AuthorizedBlackhole<A>,
    ) -> Option<BlackholeChange<A>> {
        let nlri = blackhole.nlri();
        let holders = self.holders.entry(nlri).or_default();
        if holders.contains(&peer) {
            return None;
        }
        holders.push(peer);
        (holders.len() == 1).then_some(BlackholeChange::Install(nlri))
    }

    /// Records that `peer` no longer holds a blackhole for `nlri`. `Some(Withdraw)`
    /// iff `peer` was the last holder; `None` if it held nothing or another
    /// peer still holds the prefix.
    pub(crate) fn release(&mut self, peer: PeerId, nlri: &Nlri<A>) -> Option<BlackholeChange<A>> {
        let holders = self.holders.get_mut(nlri)?;
        let before = holders.len();
        holders.retain(|p| *p != peer);
        if holders.len() == before {
            return None;
        }
        if holders.is_empty() {
            self.holders.remove(nlri);
            Some(BlackholeChange::Withdraw(*nlri))
        } else {
            None
        }
    }

    /// Releases everything `peer` holds (session teardown, GR expiry, peer
    /// removal) and returns the resulting null-route withdrawals. Scans the
    /// book — O(blackholes), which are rare — rather than keeping a reverse
    /// index that every claim and release would have to maintain.
    pub(crate) fn release_peer(&mut self, peer: PeerId) -> Vec<BlackholeChange<A>> {
        let held: Vec<Nlri<A>> = self
            .holders
            .iter()
            .filter(|(_, h)| h.contains(&peer))
            .map(|(n, _)| *n)
            .collect();
        held.iter().filter_map(|n| self.release(peer, n)).collect()
    }

    /// `true` when any peer holds `nlri`, i.e. the kernel carries a null route
    /// for it.
    pub(crate) fn is_blackholed(&self, nlri: &Nlri<A>) -> bool {
        self.holders.contains_key(nlri)
    }

    /// `true` when `peer` itself holds `nlri`.
    #[cfg(test)]
    pub(crate) fn holds(&self, peer: PeerId, nlri: &Nlri<A>) -> bool {
        self.holders.get(nlri).is_some_and(|h| h.contains(&peer))
    }

    /// Number of blackholed prefixes.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.holders.len()
    }
}

/// Both families' agreements for one session.
#[derive(Debug)]
pub(crate) struct PeerBlackhole {
    pub(crate) v4: BlackholeAgreement<Ipv4Addr>,
    pub(crate) v6: BlackholeAgreement<Ipv6Addr>,
}

impl PeerBlackhole {
    /// No agreement in either family.
    pub(crate) fn denied() -> Self {
        Self {
            v4: BlackholeAgreement::denied(),
            v6: BlackholeAgreement::denied(),
        }
    }

    /// The agreement a session's configuration describes: denied without a
    /// scope; with one, both families honor the scope's prefixes (a family the
    /// scope lists no prefix for covers nothing). `leak` is the session's RFC
    /// 9234 role and the peer's ASN, when it has a role.
    pub(crate) fn from_config(
        scope: Option<&BlackholeScope>,
        leak: Option<(pathvector_types::Role, pathvector_types::Asn)>,
    ) -> Self {
        let Some(scope) = scope else {
            return Self::denied();
        };
        let guard = || leak.map(|(role, asn)| OtcLeakCondition::new(role, asn));
        let mut v4 = BlackholeAgreement::agreed(scope.clone());
        let mut v6 = BlackholeAgreement::agreed(scope.clone());
        if let Some(g) = guard() {
            v4 = v4.with_leak_guard(g);
        }
        if let Some(g) = guard() {
            v6 = v6.with_leak_guard(g);
        }
        Self { v4, v6 }
    }
}

impl Default for PeerBlackhole {
    fn default() -> Self {
        Self::denied()
    }
}

/// The daemon-wide books, one per address family.
#[derive(Debug, Default)]
pub(crate) struct BlackholeBooks {
    pub(crate) v4: BlackholeBook<Ipv4Addr>,
    pub(crate) v6: BlackholeBook<Ipv6Addr>,
}

#[cfg(test)]
mod tests {
    use pathvector_policy::OtcLeakCondition;
    use pathvector_rib::RouteBuilder;
    use pathvector_types::{AsPath, Asn, Origin, Role};

    use super::*;

    fn peer(n: u8) -> PeerId {
        PeerId::from(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
    }

    fn route(prefix: &str, tagged: bool) -> Route<Ipv4Addr> {
        let mut b = RouteBuilder::new(prefix.parse().unwrap(), Origin::Igp, AsPath::new());
        if tagged {
            b = b.community(Community::BLACKHOLE);
        }
        b.build()
    }

    fn agreed(scope: &[&str]) -> BlackholeAgreement<Ipv4Addr> {
        BlackholeAgreement::agreed(BlackholeScope::new(scope).unwrap())
    }

    /// RFC 7999 §3.3 condition 2 and §4: with no agreement nothing is honored,
    /// however well-scoped the prefix looks.
    #[test]
    fn denied_agreement_authorizes_nothing() {
        let a = BlackholeAgreement::<Ipv4Addr>::denied();
        assert!(a.is_denied());
        assert_eq!(
            a.authorize(&route("192.0.2.1/32", true)),
            Err(BlackholeDenied::NotAgreed)
        );
    }

    /// RFC 7999 §3.3 condition 1.
    #[test]
    fn agreement_authorizes_only_covered_prefixes() {
        let a = agreed(&["192.0.2.0/24"]);
        let ok = a.authorize(&route("192.0.2.1/32", true)).unwrap();
        assert_eq!(ok.nlri(), "192.0.2.1/32".parse().unwrap());
        assert_eq!(
            a.authorize(&route("198.51.100.1/32", true)),
            Err(BlackholeDenied::OutOfScope)
        );
        assert_eq!(
            a.authorize(&route("192.0.0.0/16", true)),
            Err(BlackholeDenied::OutOfScope),
            "a prefix shorter than the authorized one is not covered"
        );
    }

    /// RFC 9234 §5: a leak is ineligible even when the blackhole is otherwise
    /// authorized — the ROV exemption does not extend to it.
    #[test]
    fn leak_guard_still_applies_to_authorized_blackholes() {
        let a = agreed(&["192.0.2.0/24"])
            .with_leak_guard(OtcLeakCondition::new(Role::Provider, Asn::new(64500)));
        let leaked = RouteBuilder::new("192.0.2.1/32".parse().unwrap(), Origin::Igp, AsPath::new())
            .community(Community::BLACKHOLE)
            .otc(Asn::new(64501))
            .build();
        assert_eq!(a.authorize(&leaked), Err(BlackholeDenied::RouteLeak));
        assert!(a.authorize(&route("192.0.2.1/32", true)).is_ok());
    }

    #[test]
    fn carries_blackhole_community_detects_only_the_well_known_value() {
        assert!(carries_blackhole_community(&route("192.0.2.1/32", true)));
        assert!(!carries_blackhole_community(&route("192.0.2.1/32", false)));
        let other: Route<Ipv4Addr> =
            RouteBuilder::new("192.0.2.1/32".parse().unwrap(), Origin::Igp, AsPath::new())
                .community(Community::from_parts(65535, 667))
                .build();
        assert!(!carries_blackhole_community(&other));
    }

    fn auth(a: &BlackholeAgreement<Ipv4Addr>, p: &str) -> AuthorizedBlackhole<Ipv4Addr> {
        a.authorize(&route(p, true)).unwrap()
    }

    /// One kernel null route per prefix: installed by the first holder,
    /// withdrawn by the last; the middle transitions emit nothing.
    #[test]
    fn book_installs_on_first_claim_and_withdraws_on_last_release() {
        let a = agreed(&["192.0.2.0/24"]);
        let b = auth(&a, "192.0.2.1/32");
        let mut book = BlackholeBook::<Ipv4Addr>::default();

        assert_eq!(
            book.claim(peer(1), b),
            Some(BlackholeChange::Install(b.nlri()))
        );
        assert_eq!(book.claim(peer(1), b), None, "re-claim is idempotent");
        assert_eq!(
            book.claim(peer(2), b),
            None,
            "second holder shares the route"
        );
        assert!(book.is_blackholed(&b.nlri()));

        assert_eq!(
            book.release(peer(1), &b.nlri()),
            None,
            "peer 2 still holds it"
        );
        assert!(book.is_blackholed(&b.nlri()));
        assert_eq!(
            book.release(peer(2), &b.nlri()),
            Some(BlackholeChange::Withdraw(b.nlri()))
        );
        assert!(!book.is_blackholed(&b.nlri()));
        assert_eq!(book.len(), 0);
    }

    /// A peer that never held a blackhole (its request was denied) cannot cause
    /// the kernel route another peer holds to be withdrawn.
    #[test]
    fn releasing_a_blackhole_the_peer_never_held_is_a_noop() {
        let a = agreed(&["192.0.2.0/24"]);
        let b = auth(&a, "192.0.2.1/32");
        let mut book = BlackholeBook::<Ipv4Addr>::default();
        let _ = book.claim(peer(1), b);
        assert_eq!(book.release(peer(2), &b.nlri()), None);
        assert!(book.holds(peer(1), &b.nlri()));
    }

    #[test]
    fn release_peer_withdraws_only_prefixes_nobody_else_holds() {
        let a = agreed(&["192.0.2.0/24"]);
        let (x, y) = (auth(&a, "192.0.2.1/32"), auth(&a, "192.0.2.2/32"));
        let mut book = BlackholeBook::<Ipv4Addr>::default();
        let _ = book.claim(peer(1), x);
        let _ = book.claim(peer(1), y);
        let _ = book.claim(peer(2), y);

        let changes = book.release_peer(peer(1));
        assert_eq!(changes, vec![BlackholeChange::Withdraw(x.nlri())]);
        assert!(book.holds(peer(2), &y.nlri()));
        assert!(book.release_peer(peer(1)).is_empty(), "idempotent");
    }

    #[test]
    fn peer_blackhole_from_config() {
        assert!(PeerBlackhole::from_config(None, None).v4.is_denied());
        let scope = BlackholeScope::new(["192.0.2.0/24"]).unwrap();
        let p = PeerBlackhole::from_config(Some(&scope), None);
        assert!(!p.v4.is_denied() && !p.v6.is_denied());
        // IPv6 agreed but the scope lists no IPv6 prefix: covers nothing.
        let r6: Route<Ipv6Addr> = RouteBuilder::new(
            "2001:db8::1/128".parse().unwrap(),
            Origin::Igp,
            AsPath::new(),
        )
        .community(Community::BLACKHOLE)
        .build();
        assert_eq!(p.v6.authorize(&r6), Err(BlackholeDenied::OutOfScope));
    }
}
