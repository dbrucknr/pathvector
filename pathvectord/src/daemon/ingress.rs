// daemon/ingress.rs — checks a received announcement must pass *before* import
// policy, as pure values.
//
// This module decides; it never touches a RIB. Three layers, kept apart
// (issue #138):
//
// 1. Verdict (here, pure): `IngressGate` looks at an announcement's AS_PATH and
//    next hop and returns `Option<IngressDrop>`. `IngressDrop::disposition`
//    maps the reason to what must happen to the peer's route.
// 2. RIB (`import.rs`, `route.rs`): applies the disposition to the Adj-RIB-In
//    and Loc-RIB — the same reconciliation an import-policy rejection uses
//    (issue #80).
// 3. Side effects (FIB, outbound UPDATEs) stay with the caller of
//    `handle_update`.
//
// Both arrival (`handle_update`) and soft reconfiguration
// (`reapply_import_policy`) ask the same gate, so a route is judged the same
// way however it reaches the Loc-RIB.
use std::net::{Ipv4Addr, Ipv6Addr};

use pathvector_rib::Route;
use pathvector_types::{AsPath, Asn, IpAddress, NextHop};

/// Why an announcement is not usable as received, before import policy runs.
///
/// Each reason carries the RFC clause that rejects the route and, through
/// [`disposition`](Self::disposition), what the older route from the same peer
/// for the same NLRI must become. In every case that older route must leave
/// service: RFC 4271 §9, "the new route SHALL replace the older route in the
/// Adj-RIB-In, thus implicitly withdrawing the older route from service".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IngressDrop {
    /// AS 0 in AS_PATH. RFC 7607 §2 prohibits it and delegates the handling
    /// of such an UPDATE to RFC 7606, i.e. treat-as-withdraw.
    AsZero,
    /// The local AS, or the local AS Confederation Identifier, appears in
    /// AS_PATH. RFC 4271 §9.1.2: "the BGP route should be excluded from the
    /// Phase 2 decision function"; RFC 5065 §4: the Confederation Identifier
    /// is treated "in the same fashion as if it had received a path
    /// containing its own AS number".
    AsLoop,
    /// NEXT_HOP is not "a valid IP host address" (RFC 4271 §6.3): unspecified,
    /// loopback, multicast or broadcast. RFC 7606 §3(e) replaces the session
    /// reset with treat-as-withdraw for NEXT_HOP errors.
    NextHopSyntax,
    /// NEXT_HOP is the receiving speaker's own address (RFC 4271 §6.3 (a)).
    /// "The route SHOULD be ignored" and no session reset is specified, so
    /// RFC 7606 §3(e) does not apply.
    NextHopOwnAddress,
}

/// What an [`IngressDrop`] does to the peer's older route for the same NLRI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// RFC 7606 §2: handled "just as if they had been listed in the WITHDRAWN
    /// ROUTES field", "thus causing them to be removed from the Adj-RIB-In".
    /// The route leaves the Adj-RIB-In and the Loc-RIB.
    TreatAsWithdraw,
    /// A well-formed route that may not be used. It replaces the older route
    /// in the Adj-RIB-In (RFC 4271 §9) but is not a Phase 2 input (§9.1.1,
    /// §9.1.2), so the peer has no Loc-RIB candidate. Like a policy
    /// rejection, it stays in the Adj-RIB-In for soft reconfiguration.
    Ineligible,
}

impl IngressDrop {
    /// The treatment this reason requires.
    pub(crate) const fn disposition(self) -> Disposition {
        match self {
            Self::AsZero | Self::NextHopSyntax => Disposition::TreatAsWithdraw,
            Self::AsLoop | Self::NextHopOwnAddress => Disposition::Ineligible,
        }
    }

    /// Short reason for logs, with the clause it comes from.
    pub(crate) const fn describe(self) -> &'static str {
        match self {
            Self::AsZero => "AS_PATH contains reserved AS 0 (RFC 7607)",
            Self::AsLoop => {
                "AS_PATH contains the local AS or confederation ID (RFC 4271 §9.1.2 / RFC 5065 §4)"
            }
            Self::NextHopSyntax => "NEXT_HOP is not a valid host address (RFC 4271 §6.3)",
            Self::NextHopOwnAddress => "NEXT_HOP is the receiver's own address (RFC 4271 §6.3 (a))",
        }
    }

    /// The reason that governs when two apply to one route: treat-as-withdraw
    /// removes the route outright, so it wins over an ineligible verdict.
    pub(crate) fn most_severe(a: Option<Self>, b: Option<Self>) -> Option<Self> {
        match (a, b) {
            (Some(x), Some(y)) => Some(if x.disposition() == Disposition::TreatAsWithdraw {
                x
            } else {
                y
            }),
            (x, None) => x,
            (None, y) => y,
        }
    }
}

/// The local identity an announcement is checked against: our AS, our
/// Confederation Identifier, and our address toward the sending peer.
///
/// Built once per UPDATE (or per re-evaluation pass) from daemon state; holds
/// no RIB reference, so every check is a pure function of its arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IngressGate {
    local_as: Asn,
    confederation_id: Option<Asn>,
    local_v4: Option<Ipv4Addr>,
    local_v6: Option<Ipv6Addr>,
}

impl IngressGate {
    /// `local_v4` is the daemon's address toward the peer under check (RFC
    /// 4271 §6.3 (a) compares NEXT_HOP with "the IP address of the receiving
    /// speaker"); `local_v6` is the daemon's IPv6 address. `None` disables the
    /// own-address check for that family.
    pub(crate) fn new(
        local_as: u32,
        confederation_id: Option<u32>,
        local_v4: Option<Ipv4Addr>,
        local_v6: Option<Ipv6Addr>,
    ) -> Self {
        Self {
            local_as: Asn::new(local_as),
            confederation_id: confederation_id.map(Asn::new),
            local_v4,
            local_v6,
        }
    }

    /// Checks an AS_PATH. Shared by every NLRI of an UPDATE, so
    /// `handle_update` evaluates it once per UPDATE. AS 0 takes precedence
    /// over a loop: it is the stronger (treat-as-withdraw) verdict.
    pub(crate) fn check_as_path(&self, as_path: &AsPath) -> Option<IngressDrop> {
        if as_path.contains(Asn::new(0)) {
            Some(IngressDrop::AsZero)
        } else if as_path.contains(self.local_as)
            || self.confederation_id.is_some_and(|id| as_path.contains(id))
        {
            Some(IngressDrop::AsLoop)
        } else {
            None
        }
    }

    /// Checks a next hop. A syntactically invalid address is reported as
    /// such even when it also equals our own address.
    pub(crate) fn check_next_hop(&self, next_hop: &NextHop) -> Option<IngressDrop> {
        match *next_hop {
            NextHop::V4(addr) => {
                if is_valid_host_v4(addr) {
                    (self.local_v4 == Some(addr)).then_some(IngressDrop::NextHopOwnAddress)
                } else {
                    Some(IngressDrop::NextHopSyntax)
                }
            }
            NextHop::V6(addr) => self.check_global_v6(addr),
            // RFC 2545 §3: the link-local address is interface-scoped, so only
            // its syntax (not multicast) is checked; the global one is
            // checked as for `V6`.
            NextHop::V6WithLinkLocal { global, link_local } => {
                if link_local.is_multicast() {
                    Some(IngressDrop::NextHopSyntax)
                } else {
                    self.check_global_v6(global)
                }
            }
        }
    }

    fn check_global_v6(&self, addr: Ipv6Addr) -> Option<IngressDrop> {
        if is_valid_host_v6(addr) {
            (self.local_v6 == Some(addr)).then_some(IngressDrop::NextHopOwnAddress)
        } else {
            Some(IngressDrop::NextHopSyntax)
        }
    }

    /// Checks a stored route: its AS_PATH and its next hop. Used when a
    /// route comes from the Adj-RIB-In (re-evaluation) rather than from a
    /// fresh UPDATE.
    pub(crate) fn check_route<A: IpAddress>(&self, route: &Route<A>) -> Option<IngressDrop> {
        IngressDrop::most_severe(
            self.check_as_path(&route.as_path),
            route
                .next_hop
                .as_ref()
                .and_then(|nh| self.check_next_hop(nh)),
        )
    }
}

/// RFC 4271 §6.3: "Syntactic correctness means that the NEXT_HOP attribute
/// represents a valid IP host address." RFC 1122 §3.2.1.3 excludes "this
/// host" (0.0.0.0), the loopback network (127/8: "MUST NOT appear outside a
/// host"), the limited broadcast address, and class D (multicast) addresses
/// as host addresses.
fn is_valid_host_v4(addr: Ipv4Addr) -> bool {
    !addr.is_unspecified()
        && !addr.is_loopback()
        && !addr.is_multicast()
        && addr != Ipv4Addr::BROADCAST
}

/// RFC 4291 §2.5.2 (unspecified) and §2.7 (multicast): neither identifies a
/// host. A bare link-local global next hop is accepted because GoBGP and BIRD
/// both use one legitimately in single-hop sessions.
fn is_valid_host_v6(addr: Ipv6Addr) -> bool {
    !addr.is_unspecified() && !addr.is_multicast()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL_AS: u32 = 65001;
    const CONFED_ID: u32 = 65100;
    const OWN_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const OWN_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff);

    fn gate() -> IngressGate {
        IngressGate::new(LOCAL_AS, Some(CONFED_ID), Some(OWN_V4), Some(OWN_V6))
    }

    fn path(asns: &[u32]) -> AsPath {
        AsPath::from_sequence(asns.iter().copied().map(Asn::new).collect())
    }

    /// RFC 4271 §9.1.2 / RFC 5065 §4.
    #[test]
    fn local_as_and_confederation_id_are_loops() {
        assert_eq!(
            gate().check_as_path(&path(&[65002, LOCAL_AS])),
            Some(IngressDrop::AsLoop)
        );
        assert_eq!(
            gate().check_as_path(&path(&[65002, CONFED_ID, 65003])),
            Some(IngressDrop::AsLoop)
        );
        assert_eq!(gate().check_as_path(&path(&[65002, 65003])), None);
    }

    /// Without a confederation the Confederation Identifier is not special.
    #[test]
    fn confederation_id_is_ignored_when_not_configured() {
        let gate = IngressGate::new(LOCAL_AS, None, None, None);
        assert_eq!(gate.check_as_path(&path(&[CONFED_ID])), None);
    }

    /// RFC 7607 §2: AS 0 is a malformed path; it outranks a loop.
    #[test]
    fn as_zero_outranks_a_loop() {
        assert_eq!(
            gate().check_as_path(&path(&[0, LOCAL_AS])),
            Some(IngressDrop::AsZero)
        );
    }

    /// RFC 4271 §6.3 syntactic + RFC 1122 §3.2.1.3.
    #[test]
    fn invalid_v4_host_addresses_are_syntactic_errors() {
        for addr in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(224, 0, 0, 5),
            Ipv4Addr::BROADCAST,
        ] {
            assert_eq!(
                gate().check_next_hop(&NextHop::V4(addr)),
                Some(IngressDrop::NextHopSyntax),
                "{addr}"
            );
        }
        assert_eq!(
            gate().check_next_hop(&NextHop::V4(Ipv4Addr::new(192, 0, 2, 1))),
            None
        );
    }

    /// RFC 4271 §6.3 (a): our own address is semantically, not syntactically,
    /// incorrect — a different clause with a different consequence.
    #[test]
    fn own_address_is_semantic() {
        assert_eq!(
            gate().check_next_hop(&NextHop::V4(OWN_V4)),
            Some(IngressDrop::NextHopOwnAddress)
        );
        assert_eq!(
            gate().check_next_hop(&NextHop::V6(OWN_V6)),
            Some(IngressDrop::NextHopOwnAddress)
        );
        let no_local = IngressGate::new(LOCAL_AS, None, None, None);
        assert_eq!(no_local.check_next_hop(&NextHop::V4(OWN_V4)), None);
    }

    /// RFC 4291 §2.5.2 / §2.7, and RFC 2545 §3's link-local companion.
    #[test]
    fn invalid_v6_host_addresses_are_syntactic_errors() {
        for nh in [
            NextHop::V6(Ipv6Addr::UNSPECIFIED),
            NextHop::V6("ff02::1".parse().unwrap()),
            NextHop::V6WithLinkLocal {
                global: "2001:db8::1".parse().unwrap(),
                link_local: "ff02::1".parse().unwrap(),
            },
            NextHop::V6WithLinkLocal {
                global: Ipv6Addr::UNSPECIFIED,
                link_local: "fe80::1".parse().unwrap(),
            },
        ] {
            assert_eq!(
                gate().check_next_hop(&nh),
                Some(IngressDrop::NextHopSyntax),
                "{nh:?}"
            );
        }
        assert_eq!(
            gate().check_next_hop(&NextHop::V6WithLinkLocal {
                global: "2001:db8::1".parse().unwrap(),
                link_local: "fe80::1".parse().unwrap(),
            }),
            None
        );
    }

    /// RFC 7606 §3(e) vs RFC 4271 §6.3 "SHOULD be ignored": the dispositions
    /// differ, and treat-as-withdraw wins when both apply.
    #[test]
    fn dispositions_and_precedence() {
        assert_eq!(
            IngressDrop::AsZero.disposition(),
            Disposition::TreatAsWithdraw
        );
        assert_eq!(
            IngressDrop::NextHopSyntax.disposition(),
            Disposition::TreatAsWithdraw
        );
        assert_eq!(IngressDrop::AsLoop.disposition(), Disposition::Ineligible);
        assert_eq!(
            IngressDrop::NextHopOwnAddress.disposition(),
            Disposition::Ineligible
        );
        for (a, b, want) in [
            (
                Some(IngressDrop::AsLoop),
                Some(IngressDrop::NextHopSyntax),
                Some(IngressDrop::NextHopSyntax),
            ),
            (
                Some(IngressDrop::NextHopSyntax),
                Some(IngressDrop::AsLoop),
                Some(IngressDrop::NextHopSyntax),
            ),
            (Some(IngressDrop::AsLoop), None, Some(IngressDrop::AsLoop)),
            (None, Some(IngressDrop::AsZero), Some(IngressDrop::AsZero)),
            (None, None, None),
        ] {
            assert_eq!(IngressDrop::most_severe(a, b), want);
        }
    }
}
