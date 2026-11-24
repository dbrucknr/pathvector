// daemon/import.rs — the import/classification pipeline: one received route
// becomes an `ImportDecision`, and applying that decision reconciles the
// Loc-RIB and the blackhole book. Identical for both address families and for
// every way a route can reach a decision: UPDATE arrival, soft
// reconfiguration (policy change, RPKI ROA change), and Graceful Restart
// stale handling all go through the same two layers below.
//
// Three layers, kept apart:
//
// 1. Classification (pure): `ImportPipeline::classify` decides what a received
//    route *is* — an eligible unicast candidate (post-policy), an authorized
//    BLACKHOLE request (RFC 7999 §3.3), or ineligible — and touches no RIB.
// 2. Reconciliation: `ImportDecision::apply` makes the peer's Loc-RIB
//    candidate and blackhole claim for the prefix match the decision and
//    reports the resulting `ImportEffect`. `import_announcement` adds the
//    Adj-RIB-In replacement in front of it.
// 3. Side effects (FIB programming, outbound UPDATEs) stay with the caller,
//    which consumes the returned `RibEffects` and affected prefixes.
#[allow(clippy::wildcard_imports)]
use super::*;

use pathvector_types::IpAddress;

use super::blackhole::{
    AuthorizedBlackhole, BlackholeAgreement, BlackholeBook, BlackholeChange, BlackholeDenied,
    carries_blackhole_community,
};
use super::ingress::IngressGate;
use crate::blackhole::ScopeFamily;

/// The result of RFC 4271 §9.1.1 Phase 1 for one received route: what is it,
/// and is it eligible for the Decision Process?
///
/// RFC 4271 §9.1 defines Phase 1's output as either a degree of preference or
/// "a value denoting that this route is ineligible to be installed in Loc-RIB
/// and will be excluded from the next phase of route selection." This type is
/// that output, extended with the one other thing a received route can be: an
/// authorized RFC 7999 blackhole, which is honored outside the Loc-RIB.
///
/// Every variant carries work for the RIBs, so the type is `#[must_use]` and
/// [`apply`](Self::apply) is its only consumer: it inserts an `Accepted` route,
/// installs a `Blackhole` claim, and **withdraws** the peer's candidate (and
/// releases its claim) on the rest. A rejected *replacement* still implicitly
/// withdraws the peer's older route (RFC 4271 §9: the new route "SHALL replace
/// the older route in the Adj-RIB-In, thus implicitly withdrawing the older
/// route from service"); forgetting that half left the superseded route
/// selected and advertised (issue #80).
#[must_use = "an ImportDecision must be applied to the Loc-RIB; a dropped \
              `Rejected` leaves the peer's superseded route selected (issue #80)"]
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ImportDecision<A: IpAddress> {
    /// Import policy accepted the route; this is the post-policy form that
    /// becomes the peer's Phase 2 candidate.
    Accepted(Route<A>),
    /// An authorized RFC 7999 blackhole request: program a null route, never
    /// a Loc-RIB candidate, never exported.
    Blackhole(AuthorizedBlackhole<A>),
    /// Import policy found the route ineligible (an explicit `Reject`, an
    /// unresolved `Next`, an RFC 9234 §5 OTC leak or an RFC 6811 Invalid
    /// origin), or the ingress gate did. The peer has no candidate for this
    /// prefix.
    Rejected,
    /// A BLACKHOLE-tagged announcement that RFC 7999 §3.3 does not allow us to
    /// honor (no agreement on the session, prefix outside the authorized
    /// scope, or an RFC 9234 leak). Ineligible like [`Rejected`](Self::Rejected),
    /// and deliberately **not** imported as ordinary unicast: that would put a
    /// route the peer meant as "discard traffic" into Loc-RIB, where it can be
    /// selected, programmed as a forwarding route and exported to other
    /// peers, spreading a blackhole beyond the one session that agreed to it
    /// (RFC 7999 §3.2).
    BlackholeDenied(BlackholeDenied),
}

/// What classification needs from a session: its import policy and its
/// BLACKHOLE agreement. Borrowed per UPDATE / per re-evaluation pass; holds no
/// RIB.
pub(crate) struct ImportPipeline<'a, A: ScopeFamily> {
    pub(crate) policy: &'a Policy<Route<A>>,
    pub(crate) blackhole: &'a BlackholeAgreement<A>,
}

impl<A: ScopeFamily> ImportPipeline<'_, A> {
    /// Classifies `raw`, a well-formed route that already passed the
    /// [`IngressGate`].
    ///
    /// A route carrying the BLACKHOLE community is a blackhole *request* and is
    /// judged only by the session's [`BlackholeAgreement`] (RFC 7999 §3.3);
    /// every other route runs through the import policy over a copy of `raw`.
    /// `raw` itself is left untouched so the caller can keep it in the
    /// Adj-RIB-In for soft reconfiguration.
    ///
    /// Origin validation (RFC 6811) is part of the import policy, so it never
    /// sees a blackhole request: RFC 7999 §3.3's "MUST ensure that origin
    /// validation techniques … do not inadvertently block legitimate
    /// announcements carrying the BLACKHOLE community" holds by construction.
    pub(crate) fn classify(&self, raw: &Route<A>) -> ImportDecision<A> {
        if carries_blackhole_community(raw) {
            return match self.blackhole.authorize(raw) {
                Ok(blackhole) => ImportDecision::Blackhole(blackhole),
                Err(why) => ImportDecision::BlackholeDenied(why),
            };
        }
        ImportDecision::evaluate_policy(self.policy, raw)
    }

    /// Like [`classify`](Self::classify), but a route that fails the
    /// [`IngressGate`] is rejected first: RFC 4271 §9.1.2 excludes an AS-looped
    /// route from Phase 2, and §6.3 says a route whose NEXT_HOP is our own
    /// address "SHOULD be ignored", so neither policy nor a blackhole
    /// agreement can make it eligible.
    ///
    /// This is how a route read back from the Adj-RIB-In (soft
    /// reconfiguration, Graceful Restart) gets the verdict it got on arrival,
    /// so an ineligible replacement stored there can never be installed by a
    /// re-evaluation.
    pub(crate) fn classify_gated(&self, gate: &IngressGate, raw: &Route<A>) -> ImportDecision<A> {
        if gate.check_route(raw).is_some() {
            ImportDecision::Rejected
        } else {
            self.classify(raw)
        }
    }
}

impl<A: IpAddress> ImportDecision<A> {
    /// Runs `policy` over a copy of `raw`: the unicast half of classification.
    ///
    /// A top-level [`Decision::Next`] (no term decided and nothing below to
    /// fall through to) is treated as a rejection.
    pub(crate) fn evaluate_policy(policy: &Policy<Route<A>>, raw: &Route<A>) -> Self {
        let mut route = raw.clone();
        match policy.evaluate(&mut route) {
            Decision::Accept => Self::Accepted(route),
            Decision::Reject | Decision::Next => Self::Rejected,
        }
    }

    /// Makes `peer`'s Loc-RIB candidate and blackhole claim for `nlri` match
    /// this decision and runs the Decision Process for that prefix (RFC 4271
    /// §9: "Once the BGP speaker updates the Adj-RIB-In, the speaker SHALL run
    /// its Decision Process").
    ///
    /// - `Accepted(route)` installs `route` as the peer's candidate, replacing
    ///   any older one, and releases any blackhole the peer held for `nlri`
    ///   (the newer announcement superseded the request).
    /// - `Blackhole(b)` removes the peer's unicast candidate — a forwarding
    ///   route and a null route must not coexist for one prefix — and claims
    ///   the null route.
    /// - `Rejected` / `BlackholeDenied` remove the peer's candidate and release
    ///   its blackhole claim, if it has them. RFC 4271 §9.1.2: "The Phase 2
    ///   process considers all routes that are eligible in the Adj-RIBs-In",
    ///   and the peer's only Adj-RIB-In route for `nlri` is now the ineligible
    ///   one. If the removed candidate was selected, the change is `Announced`
    ///   (another peer's route takes over) or `Withdrawn` (none left); if it
    ///   was not, `Unchanged`.
    ///
    /// For `Accepted` and `Blackhole`, `nlri` must equal the route's own NLRI.
    pub(crate) fn apply(
        self,
        peer: PeerId,
        nlri: &Nlri<A>,
        loc_rib: &mut LocRib<A>,
        book: &mut BlackholeBook<A>,
        oracle: &dyn NextHopOracle,
    ) -> ImportEffect<A> {
        match self {
            Self::Accepted(route) => {
                debug_assert_eq!(&route.nlri, nlri, "decision applied to the wrong prefix");
                ImportEffect {
                    best: loc_rib.insert(peer, route, oracle),
                    blackhole: book.release(peer, nlri),
                }
            }
            Self::Blackhole(blackhole) => {
                debug_assert_eq!(
                    &blackhole.nlri(),
                    nlri,
                    "decision applied to the wrong prefix"
                );
                ImportEffect {
                    best: loc_rib.withdraw(&peer, nlri, oracle),
                    blackhole: book.claim(peer, blackhole),
                }
            }
            Self::Rejected | Self::BlackholeDenied(_) => ImportEffect {
                best: loc_rib.withdraw(&peer, nlri, oracle),
                blackhole: book.release(peer, nlri),
            },
        }
    }
}

/// What applying one [`ImportDecision`] (or a withdrawal) did to the RIBs: the
/// best-path change for the prefix and, independently, any null-route change.
#[derive(Debug, PartialEq)]
pub(crate) struct ImportEffect<A: IpAddress> {
    pub(crate) best: BestPathChange<A>,
    pub(crate) blackhole: Option<BlackholeChange<A>>,
}

/// Everything a batch of imports changed, for the caller to program into the
/// FIB and propagate. The single currency shared by UPDATE handling, soft
/// reconfiguration and Graceful Restart.
#[derive(Debug)]
pub(crate) struct RibEffects<A: IpAddress> {
    pub(crate) best: Vec<BestPathChange<A>>,
    pub(crate) blackhole: Vec<BlackholeChange<A>>,
}

impl<A: IpAddress> Default for RibEffects<A> {
    fn default() -> Self {
        Self {
            best: Vec::new(),
            blackhole: Vec::new(),
        }
    }
}

impl<A: IpAddress> RibEffects<A> {
    /// Appends one effect.
    pub(crate) fn push(&mut self, effect: ImportEffect<A>) {
        self.best.push(effect.best);
        self.blackhole.extend(effect.blackhole);
    }
}

/// Counts for one batch of import decisions — feeds the `processed UPDATE` /
/// `soft reconfig complete` log lines and
/// `pathvectord_bgp_import_policy_rejected_total`.
///
/// `rejected` counts import-policy and ingress rejections only; blackhole
/// requests are tallied apart (`blackholed`, `blackhole_denied`) so a denied
/// RTBH request is never mistaken for an import-policy rejection.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ImportTally {
    pub(crate) accepted: usize,
    pub(crate) rejected: usize,
    pub(crate) blackholed: usize,
    pub(crate) blackhole_denied: usize,
}

impl ImportTally {
    pub(crate) fn record<A: IpAddress>(&mut self, decision: &ImportDecision<A>) {
        match decision {
            ImportDecision::Accepted(_) => self.accepted += 1,
            ImportDecision::Blackhole(_) => self.blackholed += 1,
            ImportDecision::Rejected => self.rejected += 1,
            ImportDecision::BlackholeDenied(_) => self.blackhole_denied += 1,
        }
    }
}

/// Imports one well-formed announcement `raw` received from `peer`.
///
/// 1. RFC 4271 §9: `raw` replaces the peer's older route in the Adj-RIB-In,
///    pre-policy, whatever the decision — so later re-evaluation (policy
///    change, ROA change, agreement change) judges the *latest* advertisement.
/// 2. [`ImportPipeline::classify`] decides what it is (RFC 4271 §9.1.1, RFC
///    7999 §3.3).
/// 3. The decision is applied ([`ImportDecision::apply`]): an ineligible
///    replacement withdraws the peer's older candidate and releases its older
///    blackhole claim.
///
/// Costs one clone of `raw` (the Adj-RIB-In keeps the pre-policy route and the
/// Loc-RIB the post-policy one) and one Loc-RIB update, the same as before for
/// accepted routes; a blackhole request costs no clone at all.
#[allow(clippy::too_many_arguments)]
pub(super) fn import_announcement<A: ScopeFamily>(
    peer: PeerId,
    raw: Route<A>,
    adj_rib_in: &mut AdjRibIn<A>,
    loc_rib: &mut LocRib<A>,
    book: &mut BlackholeBook<A>,
    pipeline: &ImportPipeline<'_, A>,
    oracle: &dyn NextHopOracle,
    tally: &mut ImportTally,
) -> ImportEffect<A> {
    let nlri = raw.nlri;
    let decision = pipeline.classify(&raw);
    adj_rib_in.insert(raw);
    tally.record(&decision);
    decision.apply(peer, &nlri, loc_rib, book, oracle)
}

/// Imports one announcement `raw` that failed the [`IngressGate`] with an
/// [`Ineligible`](super::ingress::Disposition::Ineligible) verdict (an AS loop
/// or our own address as NEXT_HOP; issue #138).
///
/// RFC 4271 §9: `raw` replaces the peer's older route in the Adj-RIB-In, and
/// §9.1.2 excludes it from Phase 2, so the peer is left with no Loc-RIB
/// candidate and no blackhole claim — the same reconciliation as an
/// import-policy rejection ([`ImportDecision::Rejected`]), minus the policy run
/// and the policy counters (the route was never offered to policy).
pub(super) fn import_ineligible<A: IpAddress>(
    peer: PeerId,
    raw: Route<A>,
    adj_rib_in: &mut AdjRibIn<A>,
    loc_rib: &mut LocRib<A>,
    book: &mut BlackholeBook<A>,
    oracle: &dyn NextHopOracle,
) -> ImportEffect<A> {
    let nlri = raw.nlri;
    adj_rib_in.insert(raw);
    ImportDecision::Rejected.apply(peer, &nlri, loc_rib, book, oracle)
}

/// Removes `peer`'s route for `nlri` from the Adj-RIB-In and the Loc-RIB, as an
/// explicit withdrawal does (RFC 4271 §4.3), and releases any blackhole the
/// peer held for it.
///
/// Shared by WITHDRAWN ROUTES, MP_UNREACH_NLRI and every RFC 7606
/// treat-as-withdraw ("handled as though all contained routes had been
/// withdrawn just as if they had been listed in the WITHDRAWN ROUTES field",
/// §2), so the four ways a route can be withdrawn cannot drift apart. What the
/// peer held is read from the [`BlackholeBook`], not inferred from the stored
/// route's communities: a BLACKHOLE request that was denied programmed
/// nothing, so withdrawing it must not remove a null route.
pub(super) fn withdraw_route<A: IpAddress>(
    peer: PeerId,
    nlri: &Nlri<A>,
    adj_rib_in: &mut AdjRibIn<A>,
    loc_rib: &mut LocRib<A>,
    book: &mut BlackholeBook<A>,
    oracle: &dyn NextHopOracle,
) -> ImportEffect<A> {
    adj_rib_in.withdraw(nlri);
    ImportEffect {
        best: loc_rib.withdraw(&peer, nlri, oracle),
        blackhole: book.release(peer, nlri),
    }
}

/// Retires `peer`'s routes for every NLRI in `nlris` — the sweep behind the
/// RFC 4724 §4.2 End-of-RIB rule ("any routes … that are still marked as stale
/// … MUST be deleted") and the Restart Time expiry. Each prefix leaves the
/// Adj-RIB-In (when there is one), the Loc-RIB and the blackhole book exactly
/// as an explicit withdrawal would ([`withdraw_route`]).
pub(super) fn retire_routes<A: IpAddress>(
    peer: PeerId,
    nlris: impl IntoIterator<Item = Nlri<A>>,
    mut adj_rib_in: Option<&mut AdjRibIn<A>>,
    loc_rib: &mut LocRib<A>,
    book: &mut BlackholeBook<A>,
    oracle: &dyn NextHopOracle,
) -> RibEffects<A> {
    let mut effects = RibEffects::default();
    for nlri in nlris {
        if let Some(adj) = adj_rib_in.as_deref_mut() {
            adj.withdraw(&nlri);
        }
        effects.push(ImportEffect {
            best: loc_rib.withdraw(&peer, &nlri, oracle),
            blackhole: book.release(peer, &nlri),
        });
    }
    effects
}

/// Re-evaluates every route in `peer`'s Adj-RIB-In against `gate`, the
/// session's import policy and its BLACKHOLE agreement, and reconciles
/// `loc_rib` and `book` with the result (soft reconfiguration). Used for a
/// changed import default, a changed BLACKHOLE agreement, an RPKI ROA-cache
/// change, and Graceful Restart stale marking, for either address family.
///
/// Applies exactly the decisions arrival would have (the gate for ineligible
/// routes, then [`ImportPipeline::classify`]), so a prefix ends up in the same
/// state however it got there. Idempotent: re-running with nothing changed
/// yields only `Unchanged` best-path changes and no blackhole changes
/// (property-tested).
pub(crate) fn reapply_import_policy<A: ScopeFamily>(
    peer: PeerId,
    adj_rib_in: &AdjRibIn<A>,
    loc_rib: &mut LocRib<A>,
    book: &mut BlackholeBook<A>,
    pipeline: &ImportPipeline<'_, A>,
    gate: &IngressGate,
    oracle: &dyn NextHopOracle,
) -> RibEffects<A> {
    let mut tally = ImportTally::default();
    let mut effects = RibEffects::default();
    effects.best.reserve(adj_rib_in.len());
    for (nlri, raw) in adj_rib_in.routes() {
        let decision = pipeline.classify_gated(gate, raw);
        tally.record(&decision);
        effects.push(decision.apply(peer, nlri, loc_rib, book, oracle));
    }

    crate::metrics::on_import_reject(peer.ip(), tally.rejected);
    tracing::info!(
        peer = %peer,
        afi = if A::BITS == 32 { "ipv4" } else { "ipv6" },
        accepted = tally.accepted,
        rejected = tally.rejected,
        blackholed = tally.blackholed,
        blackhole_denied = tally.blackhole_denied,
        rib_size = loc_rib.len(),
        "soft reconfig complete"
    );
    effects
}

/// [`reapply_import_policy`] for a session with no BLACKHOLE agreement and a
/// throwaway book — what tests about ordinary unicast import want.
#[cfg(test)]
pub(super) fn reapply_without_blackholes<A: ScopeFamily>(
    peer: PeerId,
    adj_rib_in: &AdjRibIn<A>,
    loc_rib: &mut LocRib<A>,
    policy: &Policy<Route<A>>,
    gate: &IngressGate,
    oracle: &dyn NextHopOracle,
) -> RibEffects<A> {
    reapply_import_policy(
        peer,
        adj_rib_in,
        loc_rib,
        &mut BlackholeBook::default(),
        &ImportPipeline {
            policy,
            blackhole: &BlackholeAgreement::denied(),
        },
        gate,
        oracle,
    )
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pathvector_policy::{CommunityCondition, Reject, Term};
    use pathvector_rib::oracle::AlwaysReachable;
    use pathvector_types::Community;

    use super::*;
    use crate::blackhole::BlackholeScope;

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

    fn denied() -> BlackholeAgreement<Ipv4Addr> {
        BlackholeAgreement::denied()
    }

    fn bh_route(prefix: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(prefix.parse().unwrap(), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(Ipv4Addr::new(192, 0, 2, 1)))
            .community(Community::BLACKHOLE)
            .build()
    }

    fn apply_plain(
        d: ImportDecision<Ipv4Addr>,
        p: PeerId,
        loc_rib: &mut LocRib<Ipv4Addr>,
    ) -> ImportEffect<Ipv4Addr> {
        d.apply(
            p,
            &nlri(),
            loc_rib,
            &mut BlackholeBook::default(),
            &AlwaysReachable,
        )
    }

    /// RFC 4271 §9.1: Phase 1 yields either a preference (here: an accepted
    /// post-policy route) or "a value denoting that this route is
    /// ineligible".
    #[test]
    fn evaluate_maps_policy_decision_to_eligibility() {
        let p = reject_tagged();
        assert_eq!(
            ImportDecision::evaluate_policy(&p, &route(false)),
            ImportDecision::Accepted(route(false))
        );
        assert_eq!(
            ImportDecision::evaluate_policy(&p, &route(true)),
            ImportDecision::Rejected
        );
    }

    /// A route rejected because no term decides and the default is Reject
    /// (RFC 8212 posture) is ineligible too.
    #[test]
    fn evaluate_default_reject_is_rejected() {
        let p: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Reject);
        assert_eq!(
            ImportDecision::evaluate_policy(&p, &route(false)),
            ImportDecision::Rejected
        );
    }

    /// RFC 4271 §9 + §9.1.2: a rejected replacement withdraws the peer's
    /// selected route — `Withdrawn` when it was the only candidate.
    #[test]
    fn apply_rejected_withdraws_peers_selected_candidate() {
        let mut loc_rib = LocRib::new();
        let _ = apply_plain(
            ImportDecision::Accepted(route(false)),
            peer(1),
            &mut loc_rib,
        );
        let effect = apply_plain(ImportDecision::Rejected, peer(1), &mut loc_rib);
        assert_eq!(effect.best, BestPathChange::Withdrawn(nlri()));
        assert!(loc_rib.candidates(&nlri()).is_none_or(|c| c.is_empty()));
    }

    /// A rejected route from a peer with no candidate changes nothing — no
    /// spurious withdrawal of another peer's selected route.
    #[test]
    fn apply_rejected_without_candidate_is_unchanged() {
        let mut loc_rib = LocRib::new();
        let _ = apply_plain(
            ImportDecision::Accepted(route(false)),
            peer(2),
            &mut loc_rib,
        );
        let effect = apply_plain(ImportDecision::Rejected, peer(1), &mut loc_rib);
        assert_eq!(effect.best, BestPathChange::Unchanged);
        assert_eq!(loc_rib.best_peer(&nlri()), Some(peer(2)));
    }

    /// `import_announcement` stores the *raw* replacement (§9) even when it is
    /// rejected, and withdraws the older accepted candidate.
    #[test]
    fn import_announcement_keeps_rejected_replacement_in_adj_rib_in() {
        let p = reject_tagged();
        let bh = denied();
        let pipeline = ImportPipeline {
            policy: &p,
            blackhole: &bh,
        };
        let mut adj = AdjRibIn::new(peer(1));
        let mut loc_rib = LocRib::new();
        let mut book = BlackholeBook::default();
        let mut tally = ImportTally::default();

        let first = import_announcement(
            peer(1),
            route(false),
            &mut adj,
            &mut loc_rib,
            &mut book,
            &pipeline,
            &AlwaysReachable,
            &mut tally,
        );
        assert!(matches!(first.best, BestPathChange::Announced(..)));
        let second = import_announcement(
            peer(1),
            route(true),
            &mut adj,
            &mut loc_rib,
            &mut book,
            &pipeline,
            &AlwaysReachable,
            &mut tally,
        );

        assert_eq!(second.best, BestPathChange::Withdrawn(nlri()));
        assert_eq!(adj.get(&nlri()), Some(&route(true)));
        assert!(loc_rib.best(&nlri()).is_none());
        assert_eq!(
            tally,
            ImportTally {
                accepted: 1,
                rejected: 1,
                ..ImportTally::default()
            }
        );
    }

    // ── RFC 7999 §3.3 classification ─────────────────────────────────────────

    /// Origin validation (and any import default) is part of the import
    /// policy. A policy that rejects *everything* — what an ROV term does to a
    /// /32 longer than every ROA `maxLength` — must not stop an authorized
    /// blackhole: RFC 7999 §3.3 "MUST ensure that origin validation
    /// techniques … do not inadvertently block legitimate announcements
    /// carrying the BLACKHOLE community".
    #[test]
    fn authorized_blackhole_is_exempt_from_import_policy() {
        let reject_all: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Reject);
        let agreement = BlackholeAgreement::agreed(BlackholeScope::new(["192.0.2.0/24"]).unwrap());
        let pipeline = ImportPipeline {
            policy: &reject_all,
            blackhole: &agreement,
        };
        let raw = bh_route("192.0.2.77/32");
        assert!(matches!(
            pipeline.classify(&raw),
            ImportDecision::Blackhole(b) if b.nlri() == raw.nlri
        ));
        // The same policy rejects an ordinary route: the exemption is for
        // blackhole requests only.
        assert_eq!(pipeline.classify(&route(false)), ImportDecision::Rejected);
    }

    /// RFC 7999 §3.3 condition 2 / §4: a permissive import policy does not
    /// authorize a blackhole — the default is denied, and a denied request is
    /// not imported as unicast either.
    #[test]
    fn unagreed_blackhole_is_denied_even_under_accept_all() {
        let accept_all: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Accept);
        let bh = denied();
        let pipeline = ImportPipeline {
            policy: &accept_all,
            blackhole: &bh,
        };
        assert_eq!(
            pipeline.classify(&bh_route("192.0.2.77/32")),
            ImportDecision::BlackholeDenied(BlackholeDenied::NotAgreed)
        );
    }

    /// RFC 7999 §3.3 condition 1.
    #[test]
    fn out_of_scope_blackhole_is_denied() {
        let accept_all: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Accept);
        let agreement = BlackholeAgreement::agreed(BlackholeScope::new(["192.0.2.0/24"]).unwrap());
        let pipeline = ImportPipeline {
            policy: &accept_all,
            blackhole: &agreement,
        };
        assert_eq!(
            pipeline.classify(&bh_route("198.51.100.1/32")),
            ImportDecision::BlackholeDenied(BlackholeDenied::OutOfScope)
        );
    }

    /// The gate comes first: an AS-looped blackhole request is ineligible
    /// (RFC 4271 §9.1.2) whatever the agreement says.
    #[test]
    fn classify_gated_rejects_before_blackhole_authorization() {
        let accept_all: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Accept);
        let agreement = BlackholeAgreement::agreed(BlackholeScope::new(["192.0.2.0/24"]).unwrap());
        let pipeline = ImportPipeline {
            policy: &accept_all,
            blackhole: &agreement,
        };
        let gate = IngressGate::new(65001, None, None, None);
        let looped = RouteBuilder::new(
            "192.0.2.77/32".parse().unwrap(),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65001)]),
        )
        .community(Community::BLACKHOLE)
        .build();
        assert_eq!(
            pipeline.classify_gated(&gate, &looped),
            ImportDecision::Rejected
        );
    }

    /// A blackhole decision never leaves a unicast candidate behind and never
    /// enters the Loc-RIB; the book gets the claim.
    #[test]
    fn apply_blackhole_evicts_unicast_candidate_and_claims() {
        let agreement =
            BlackholeAgreement::agreed(BlackholeScope::new(["203.0.113.0/24"]).unwrap());
        let b = agreement.authorize(&bh_route("203.0.113.0/24")).unwrap();
        let mut loc_rib = LocRib::new();
        let mut book = BlackholeBook::default();
        let _ = ImportDecision::Accepted(route(false)).apply(
            peer(1),
            &nlri(),
            &mut loc_rib,
            &mut book,
            &AlwaysReachable,
        );

        let effect = ImportDecision::Blackhole(b).apply(
            peer(1),
            &nlri(),
            &mut loc_rib,
            &mut book,
            &AlwaysReachable,
        );
        assert_eq!(effect.best, BestPathChange::Withdrawn(nlri()));
        assert_eq!(effect.blackhole, Some(BlackholeChange::Install(nlri())));
        assert!(loc_rib.best(&nlri()).is_none());
        assert!(book.holds(peer(1), &nlri()));
    }

    /// A later accepted unicast announcement supersedes the blackhole request
    /// (RFC 4271 §9 implicit withdraw) and removes the null route.
    #[test]
    fn apply_accepted_after_blackhole_releases_the_claim() {
        let agreement =
            BlackholeAgreement::agreed(BlackholeScope::new(["203.0.113.0/24"]).unwrap());
        let b = agreement.authorize(&bh_route("203.0.113.0/24")).unwrap();
        let mut loc_rib = LocRib::new();
        let mut book = BlackholeBook::default();
        let _ = ImportDecision::Blackhole(b).apply(
            peer(1),
            &nlri(),
            &mut loc_rib,
            &mut book,
            &AlwaysReachable,
        );
        let effect = ImportDecision::Accepted(route(false)).apply(
            peer(1),
            &nlri(),
            &mut loc_rib,
            &mut book,
            &AlwaysReachable,
        );
        assert_eq!(effect.blackhole, Some(BlackholeChange::Withdraw(nlri())));
        assert!(matches!(effect.best, BestPathChange::Announced(..)));
        assert!(!book.is_blackholed(&nlri()));
    }

    /// Applying `BlackholeDenied` for a peer that never held the prefix must
    /// not withdraw another peer's null route.
    #[test]
    fn apply_denied_does_not_touch_another_peers_null_route() {
        let agreement =
            BlackholeAgreement::agreed(BlackholeScope::new(["203.0.113.0/24"]).unwrap());
        let b = agreement.authorize(&bh_route("203.0.113.0/24")).unwrap();
        let mut loc_rib = LocRib::new();
        let mut book = BlackholeBook::default();
        let _ = ImportDecision::Blackhole(b).apply(
            peer(1),
            &nlri(),
            &mut loc_rib,
            &mut book,
            &AlwaysReachable,
        );
        let effect = ImportDecision::BlackholeDenied(BlackholeDenied::NotAgreed).apply(
            peer(2),
            &nlri(),
            &mut loc_rib,
            &mut book,
            &AlwaysReachable,
        );
        assert_eq!(effect.blackhole, None);
        assert!(book.holds(peer(1), &nlri()));
    }
}
