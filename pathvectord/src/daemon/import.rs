// daemon/import.rs — RFC 4271 §9 / §9.1.1 import: one received route through
// import policy into the Loc-RIB, identical for both address families.
//
// Three layers, kept apart:
//
// 1. Policy (pure): `ImportDecision::evaluate` runs the peer's import policy
//    over a copy of the received route and says whether the result is
//    eligible. It touches no RIB.
// 2. RIB: `ImportDecision::apply` makes the peer's Loc-RIB candidate for the
//    prefix match that decision and reports the resulting `BestPathChange`.
//    `import_announcement` adds the Adj-RIB-In replacement in front of it.
// 3. Side effects (FIB programming, outbound UPDATEs) stay with the caller,
//    which consumes the returned `BestPathChange`s and affected prefixes.
//
// Both the UPDATE path (`handle_update`) and re-evaluation
// (`reapply_import_policy`) go through layers 1 and 2, so a route is judged
// the same way however it reached the Loc-RIB.
#[allow(clippy::wildcard_imports)]
use super::*;

use pathvector_types::IpAddress;

/// The result of RFC 4271 §9.1.1 Phase 1 for one received route: is it
/// eligible for the Decision Process, and in what (post-policy) form?
///
/// RFC 4271 §9.1 defines Phase 1's output as either a degree of preference or
/// "a value denoting that this route is ineligible to be installed in Loc-RIB
/// and will be excluded from the next phase of route selection." This type is
/// that output.
///
/// Both variants carry work for the Loc-RIB, so the type is `#[must_use]` and
/// [`apply`](Self::apply) is its only consumer: it inserts an `Accepted` route
/// and **withdraws** the peer's candidate on `Rejected`. A rejected
/// *replacement* still implicitly withdraws the peer's older route (RFC 4271
/// §9: the new route "SHALL replace the older route in the Adj-RIB-In, thus
/// implicitly withdrawing the older route from service"); forgetting that half
/// left the superseded route selected and advertised (issue #80).
#[must_use = "an ImportDecision must be applied to the Loc-RIB; a dropped \
              `Rejected` leaves the peer's superseded route selected (issue #80)"]
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ImportDecision<A: IpAddress> {
    /// Import policy accepted the route; this is the post-policy form that
    /// becomes the peer's Phase 2 candidate.
    Accepted(Route<A>),
    /// Import policy found the route ineligible (an explicit `Reject`, an
    /// unresolved `Next`, an RFC 9234 §5 OTC leak or an RFC 6811 Invalid
    /// origin). The peer has no candidate for this prefix.
    Rejected,
}

impl<A: IpAddress> ImportDecision<A> {
    /// Runs `policy` over a copy of `raw`. `raw` itself is left untouched so
    /// the caller can keep it in the Adj-RIB-In for soft reconfiguration.
    ///
    /// A top-level [`Decision::Next`] (no term decided and nothing below to
    /// fall through to) is treated as a rejection, as before this type
    /// existed.
    pub(crate) fn evaluate(policy: &Policy<Route<A>>, raw: &Route<A>) -> Self {
        let mut route = raw.clone();
        match policy.evaluate(&mut route) {
            Decision::Accept => Self::Accepted(route),
            Decision::Reject | Decision::Next => Self::Rejected,
        }
    }

    /// `true` for [`Accepted`](Self::Accepted).
    pub(crate) fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }

    /// Makes `peer`'s Loc-RIB candidate for `nlri` match this decision and
    /// runs the Decision Process for that prefix (RFC 4271 §9: "Once the BGP
    /// speaker updates the Adj-RIB-In, the speaker SHALL run its Decision
    /// Process").
    ///
    /// - `Accepted(route)` installs `route` as the peer's candidate, replacing
    ///   any older one.
    /// - `Rejected` removes the peer's candidate, if it has one. RFC 4271
    ///   §9.1.2: "The Phase 2 process considers all routes that are eligible
    ///   in the Adj-RIBs-In", and the peer's only Adj-RIB-In route for `nlri`
    ///   is now the ineligible one. If the removed candidate was selected,
    ///   the change is `Announced` (another peer's route takes over) or
    ///   `Withdrawn` (none left); if it was not, `Unchanged`.
    ///
    /// For `Accepted`, `nlri` must equal the route's own NLRI.
    pub(crate) fn apply(
        self,
        peer: PeerId,
        nlri: &Nlri<A>,
        loc_rib: &mut LocRib<A>,
        oracle: &dyn NextHopOracle,
    ) -> BestPathChange<A> {
        match self {
            Self::Accepted(route) => {
                debug_assert_eq!(&route.nlri, nlri, "decision applied to the wrong prefix");
                loc_rib.insert(peer, route, oracle)
            }
            Self::Rejected => loc_rib.withdraw(&peer, nlri, oracle),
        }
    }
}

/// Accepted/rejected counts for one batch of import decisions — feeds the
/// `processed UPDATE` / `soft reconfig complete` log lines and
/// `pathvectord_bgp_import_policy_rejected_total`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ImportTally {
    pub(crate) accepted: usize,
    pub(crate) rejected: usize,
}

impl ImportTally {
    fn record<A: IpAddress>(&mut self, decision: &ImportDecision<A>) {
        if decision.is_accepted() {
            self.accepted += 1;
        } else {
            self.rejected += 1;
        }
    }
}

/// Imports one well-formed announcement `raw` received from `peer`.
///
/// 1. RFC 4271 §9: `raw` replaces the peer's older route in the Adj-RIB-In,
///    pre-policy, whatever policy decides — so later re-evaluation (policy
///    change, ROA change) judges the *latest* advertisement.
/// 2. RFC 4271 §9.1.1: import policy decides eligibility.
/// 3. The decision is applied to the Loc-RIB ([`ImportDecision::apply`]):
///    an ineligible replacement withdraws the peer's older candidate.
///
/// Costs one clone of `raw` (the Adj-RIB-In keeps the pre-policy route and the
/// Loc-RIB the post-policy one) and one Loc-RIB update, the same as before for
/// accepted routes; a rejected route now costs one Loc-RIB lookup.
pub(super) fn import_announcement<A: IpAddress>(
    peer: PeerId,
    raw: Route<A>,
    adj_rib_in: &mut AdjRibIn<A>,
    loc_rib: &mut LocRib<A>,
    policy: &Policy<Route<A>>,
    oracle: &dyn NextHopOracle,
    tally: &mut ImportTally,
) -> BestPathChange<A> {
    let nlri = raw.nlri;
    let decision = ImportDecision::evaluate(policy, &raw);
    adj_rib_in.insert(raw);
    tally.record(&decision);
    decision.apply(peer, &nlri, loc_rib, oracle)
}

/// Re-evaluates every route in `peer`'s Adj-RIB-In against `policy` and
/// reconciles `loc_rib` with the result (soft reconfiguration). Used for a
/// changed import default and for an RPKI ROA-cache change, for either
/// address family.
///
/// Applies exactly the decisions [`import_announcement`] would have, so a
/// prefix ends up in the same Loc-RIB state however it got there.
pub(crate) fn reapply_import_policy<A: IpAddress>(
    peer: PeerId,
    adj_rib_in: &AdjRibIn<A>,
    loc_rib: &mut LocRib<A>,
    policy: &Policy<Route<A>>,
    oracle: &dyn NextHopOracle,
) -> Vec<BestPathChange<A>> {
    let mut tally = ImportTally::default();
    let fib_changes: Vec<BestPathChange<A>> = adj_rib_in
        .routes()
        .map(|(nlri, raw)| {
            let decision = ImportDecision::evaluate(policy, raw);
            tally.record(&decision);
            decision.apply(peer, nlri, loc_rib, oracle)
        })
        .collect();

    crate::metrics::on_import_reject(peer.ip(), tally.rejected);
    tracing::info!(
        peer = %peer,
        afi = if A::BITS == 32 { "ipv4" } else { "ipv6" },
        accepted = tally.accepted,
        rejected = tally.rejected,
        rib_size = loc_rib.len(),
        "soft reconfig complete"
    );
    fib_changes
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pathvector_policy::{CommunityCondition, Reject, Term};
    use pathvector_rib::oracle::AlwaysReachable;
    use pathvector_types::Community;

    use super::*;

    const TAG: Community = Community::from_parts(65000, 1);

    fn peer(n: u8) -> PeerId {
        PeerId::from(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
    }

    fn nlri() -> Nlri<Ipv4Addr> {
        "203.0.113.0/24".parse().unwrap()
    }

    fn route(tagged: bool) -> Route<Ipv4Addr> {
        let mut b = RouteBuilder::new(nlri(), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(Ipv4Addr::new(192, 0, 2, 1)));
        if tagged {
            b = b.community(TAG);
        }
        b.build()
    }

    fn reject_tagged() -> Policy<Route<Ipv4Addr>> {
        let mut p = Policy::new(DefaultAction::Accept);
        p.add_term(Term::new(CommunityCondition::new(TAG), Reject));
        p
    }

    /// RFC 4271 §9.1: Phase 1 yields either a preference (here: an accepted
    /// post-policy route) or "a value denoting that this route is
    /// ineligible".
    #[test]
    fn evaluate_maps_policy_decision_to_eligibility() {
        let p = reject_tagged();
        assert_eq!(
            ImportDecision::evaluate(&p, &route(false)),
            ImportDecision::Accepted(route(false))
        );
        assert_eq!(
            ImportDecision::evaluate(&p, &route(true)),
            ImportDecision::Rejected
        );
    }

    /// A route rejected because no term decides and the default is Reject
    /// (RFC 8212 posture) is ineligible too.
    #[test]
    fn evaluate_default_reject_is_rejected() {
        let p: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Reject);
        assert_eq!(
            ImportDecision::evaluate(&p, &route(false)),
            ImportDecision::Rejected
        );
    }

    /// RFC 4271 §9 + §9.1.2: a rejected replacement withdraws the peer's
    /// selected route — `Withdrawn` when it was the only candidate.
    #[test]
    fn apply_rejected_withdraws_peers_selected_candidate() {
        let mut loc_rib = LocRib::new();
        let _ = ImportDecision::Accepted(route(false)).apply(
            peer(1),
            &nlri(),
            &mut loc_rib,
            &AlwaysReachable,
        );
        let change =
            ImportDecision::Rejected.apply(peer(1), &nlri(), &mut loc_rib, &AlwaysReachable);
        assert_eq!(change, BestPathChange::Withdrawn(nlri()));
        assert!(loc_rib.candidates(&nlri()).is_none_or(|c| c.is_empty()));
    }

    /// A rejected route from a peer with no candidate changes nothing — no
    /// spurious withdrawal of another peer's selected route.
    #[test]
    fn apply_rejected_without_candidate_is_unchanged() {
        let mut loc_rib = LocRib::new();
        let _ = ImportDecision::Accepted(route(false)).apply(
            peer(2),
            &nlri(),
            &mut loc_rib,
            &AlwaysReachable,
        );
        let change =
            ImportDecision::Rejected.apply(peer(1), &nlri(), &mut loc_rib, &AlwaysReachable);
        assert_eq!(change, BestPathChange::Unchanged);
        assert_eq!(loc_rib.best_peer(&nlri()), Some(peer(2)));
    }

    /// `import_announcement` stores the *raw* replacement (§9) even when it is
    /// rejected, and withdraws the older accepted candidate.
    #[test]
    fn import_announcement_keeps_rejected_replacement_in_adj_rib_in() {
        let p = reject_tagged();
        let mut adj = AdjRibIn::new(peer(1));
        let mut loc_rib = LocRib::new();
        let mut tally = ImportTally::default();

        let first = import_announcement(
            peer(1),
            route(false),
            &mut adj,
            &mut loc_rib,
            &p,
            &AlwaysReachable,
            &mut tally,
        );
        assert!(matches!(first, BestPathChange::Announced(..)));
        let second = import_announcement(
            peer(1),
            route(true),
            &mut adj,
            &mut loc_rib,
            &p,
            &AlwaysReachable,
            &mut tally,
        );

        assert_eq!(second, BestPathChange::Withdrawn(nlri()));
        assert_eq!(adj.get(&nlri()), Some(&route(true)));
        assert!(loc_rib.best(&nlri()).is_none());
        assert_eq!(
            tally,
            ImportTally {
                accepted: 1,
                rejected: 1
            }
        );
    }
}
