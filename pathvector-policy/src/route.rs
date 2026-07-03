use ipnetx::interfaces::IpAddress;
use pathvector_types::{
    AsPath, Asn, Community, ExtendedCommunity, LargeCommunity, LocalPref, Med, NextHop, Nlri,
    Origin,
};

/// A BGP route that can be inspected and modified by a [`Policy`](crate::Policy).
///
/// This trait is the bridge between the policy engine and the route types
/// defined in `pathvector-rib`. The engine never owns a concrete route struct
/// — it operates entirely through this trait, which lets conditions read
/// attributes and actions modify them.
///
/// # Associated type
///
/// `Addr` pins the address family of this route's NLRI. An IPv4 unicast route
/// sets `type Addr = Ipv4Addr`; an IPv6 route sets `type Addr = Ipv6Addr`.
/// This allows [`PrefixListCondition<A>`](crate::PrefixListCondition) to be
/// generic over the address family while remaining fully type-safe.
///
/// # No `Clone` required
///
/// The policy engine takes routes by `&mut R` — it modifies them in place and
/// returns a [`Decision`](crate::Decision) rather than consuming and returning
/// the route. This means `Clone` is never forced on the route type by the
/// engine itself. If the caller needs to preserve the original (e.g. before
/// applying an export policy that strips private communities), they clone at
/// the call site.
pub trait BgpRoute {
    /// The IP address family of this route's NLRI.
    type Addr: IpAddress;

    /// The prefix this route advertises.
    fn nlri(&self) -> Nlri<Self::Addr>;

    /// The `ORIGIN` attribute — how this route was introduced into BGP.
    fn origin(&self) -> Origin;

    /// The `LOCAL_PREF` attribute, if present.
    ///
    /// `None` on routes received from eBGP peers. `LOCAL_PREF` is only
    /// exchanged between iBGP peers and must be stripped before sending to
    /// an external neighbor.
    fn local_pref(&self) -> Option<LocalPref>;

    /// The `MULTI_EXIT_DISC` (MED) attribute, if present.
    fn med(&self) -> Option<Med>;

    /// The `AS_PATH` attribute.
    fn as_path(&self) -> &AsPath;

    /// The standard `COMMUNITIES` attribute (RFC 1997).
    fn communities(&self) -> &[Community];

    /// The `LARGE_COMMUNITIES` attribute (RFC 8092).
    fn large_communities(&self) -> &[LargeCommunity];

    /// The `EXTENDED COMMUNITIES` attribute (RFC 4360).
    fn extended_communities(&self) -> &[ExtendedCommunity];

    /// The `NEXT_HOP` attribute, if present.
    fn next_hop(&self) -> Option<NextHop>;

    /// The `ONLY_TO_CUSTOMER` attribute (RFC 9234 §3), if present.
    fn otc(&self) -> Option<Asn>;

    // ── setters — called by actions ────────────────────────────────────────

    /// Sets the `ORIGIN` attribute.
    fn set_origin(&mut self, origin: Origin);

    /// Sets or clears the `LOCAL_PREF` attribute.
    fn set_local_pref(&mut self, lp: Option<LocalPref>);

    /// Sets or clears the `MED` attribute.
    fn set_med(&mut self, med: Option<Med>);

    /// Replaces the `AS_PATH` attribute.
    fn set_as_path(&mut self, path: AsPath);

    /// Replaces the standard communities list.
    fn set_communities(&mut self, communities: Vec<Community>);

    /// Replaces the large communities list.
    fn set_large_communities(&mut self, communities: Vec<LargeCommunity>);

    /// Replaces the extended communities list.
    fn set_extended_communities(&mut self, communities: Vec<ExtendedCommunity>);

    /// Sets or clears the `NEXT_HOP` attribute.
    fn set_next_hop(&mut self, nh: Option<NextHop>);

    /// Sets or clears the `ONLY_TO_CUSTOMER` attribute (RFC 9234 §3).
    fn set_otc(&mut self, otc: Option<Asn>);
}
