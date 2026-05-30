/// A BGP Address Family Identifier (AFI).
///
/// AFI is a 16-bit value that identifies the network layer protocol a BGP
/// session is exchanging reachability information for. Originally BGP-4 only
/// carried IPv4 routes. [RFC 4760] introduced multiprotocol extensions,
/// allowing BGP to carry routes for any address family — IPv6, L2VPN, and
/// others — by negotiating AFI/SAFI capabilities during session setup.
///
/// This type is a newtype over `u16` rather than an enum. The IANA registry
/// for AFI values is large and evolving; a newtype with named constants can
/// represent any assigned value without needing an `Unknown` catch-all variant
/// that makes pattern matching awkward.
///
/// # Well-known values
///
/// | Constant | Value | Protocol |
/// |---|---|---|
/// | [`Afi::IPV4`] | 1 | Internet Protocol version 4 |
/// | [`Afi::IPV6`] | 2 | Internet Protocol version 6 |
/// | [`Afi::L2VPN`] | 25 | Layer 2 VPN (EVPN, VPLS) |
///
/// [RFC 4760]: https://www.rfc-editor.org/rfc/rfc4760
///
/// # Examples
///
/// ```
/// use pathvector_types::Afi;
///
/// assert_eq!(Afi::IPV4.as_u16(), 1);
/// assert_eq!(Afi::IPV6.as_u16(), 2);
///
/// // Any IANA-assigned value can be represented
/// let private = Afi::new(65535);
/// assert_eq!(private.as_u16(), 65535);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Afi(u16);

impl Afi {
    /// Internet Protocol version 4 (RFC 791).
    pub const IPV4: Self = Self(1);

    /// Internet Protocol version 6 (RFC 8200).
    pub const IPV6: Self = Self(2);

    /// Layer 2 VPN — used for EVPN (RFC 7432) and VPLS (RFC 4761).
    pub const L2VPN: Self = Self(25);

    /// Creates an `Afi` from a raw 16-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Afi;
    ///
    /// assert_eq!(Afi::new(1), Afi::IPV4);
    /// ```
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the raw 16-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Afi;
    ///
    /// assert_eq!(Afi::IPV4.as_u16(), 1);
    /// ```
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl From<u16> for Afi {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<Afi> for u16 {
    fn from(afi: Afi) -> u16 {
        afi.0
    }
}

impl std::fmt::Display for Afi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::IPV4 => write!(f, "IPv4"),
            Self::IPV6 => write!(f, "IPv6"),
            Self::L2VPN => write!(f, "L2VPN"),
            Self(n) => write!(f, "AFI({n})"),
        }
    }
}

/// A BGP Subsequent Address Family Identifier (SAFI).
///
/// SAFI is an 8-bit value that refines an [`Afi`] — it answers "what kind of
/// routing are we doing with these addresses?" For example, IPv4 unicast
/// forwarding and IPv4 MPLS VPN routes are both IPv4, but they live in
/// completely separate routing tables and are exchanged independently.
///
/// Like [`Afi`], this is a newtype over its wire type rather than an enum, so
/// any IANA-assigned value can be represented as the registry evolves.
///
/// # Well-known values
///
/// | Constant | Value | Meaning |
/// |---|---|---|
/// | [`Safi::UNICAST`] | 1 | Standard unicast forwarding |
/// | [`Safi::MULTICAST`] | 2 | Multicast topology (MRIB) |
/// | [`Safi::MPLS_LABELED`] | 4 | MPLS labeled unicast (RFC 3107) |
/// | [`Safi::VPLS`] | 65 | Virtual Private LAN Service (RFC 4761) |
/// | [`Safi::EVPN`] | 70 | Ethernet VPN (RFC 7432) |
/// | [`Safi::MPLS_VPN`] | 128 | MPLS Layer 3 VPN (RFC 4364) |
/// | [`Safi::FLOW_SPEC`] | 133 | Traffic flow specification (RFC 5575) |
/// | [`Safi::FLOW_SPEC_VPN`] | 134 | VPN traffic flow specification |
///
/// # Examples
///
/// ```
/// use pathvector_types::Safi;
///
/// assert_eq!(Safi::UNICAST.as_u8(), 1);
/// assert_eq!(Safi::MPLS_VPN.as_u8(), 128);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Safi(u8);

impl Safi {
    /// Standard unicast forwarding — the route is used to forward individual
    /// packets toward a destination prefix.
    pub const UNICAST: Self = Self(1);

    /// Multicast routing topology. BGP carries multicast routes separately
    /// from unicast so operators can apply different policies to each.
    pub const MULTICAST: Self = Self(2);

    /// MPLS labeled unicast (RFC 3107). Routes carry an MPLS label stack
    /// entry used to forward packets along a label-switched path.
    pub const MPLS_LABELED: Self = Self(4);

    /// Virtual Private LAN Service (VPLS, RFC 4761 / RFC 4762).
    /// A Layer 2 service that connects geographically dispersed sites over
    /// an MPLS backbone as if they were on the same LAN.
    pub const VPLS: Self = Self(65);

    /// Ethernet VPN (EVPN, RFC 7432). A modern Layer 2 / Layer 3 overlay
    /// technology used in data centres and carrier networks. EVPN uses BGP
    /// to distribute MAC and IP reachability information, replacing older
    /// flood-and-learn approaches.
    pub const EVPN: Self = Self(70);

    /// MPLS Layer 3 VPN (RFC 4364). Routes carry an MPLS label that
    /// identifies the customer VRF on the remote PE router. This is the
    /// dominant enterprise WAN VPN technology.
    pub const MPLS_VPN: Self = Self(128);

    /// BGP FlowSpec (RFC 5575). Routes encode traffic-matching rules
    /// (5-tuple, DSCP, packet length, etc.) and actions (rate-limit, drop,
    /// redirect). Used for distributed DDoS mitigation and traffic steering.
    pub const FLOW_SPEC: Self = Self(133);

    /// VPN FlowSpec — FlowSpec rules scoped to a VPN routing instance.
    pub const FLOW_SPEC_VPN: Self = Self(134);

    /// Creates a `Safi` from a raw 8-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Safi;
    ///
    /// assert_eq!(Safi::new(1), Safi::UNICAST);
    /// ```
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Returns the raw 8-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Safi;
    ///
    /// assert_eq!(Safi::UNICAST.as_u8(), 1);
    /// ```
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

impl From<u8> for Safi {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<Safi> for u8 {
    fn from(safi: Safi) -> u8 {
        safi.0
    }
}

impl std::fmt::Display for Safi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::UNICAST => write!(f, "unicast"),
            Self::MULTICAST => write!(f, "multicast"),
            Self::MPLS_LABELED => write!(f, "mpls-labeled"),
            Self::VPLS => write!(f, "vpls"),
            Self::EVPN => write!(f, "evpn"),
            Self::MPLS_VPN => write!(f, "mpls-vpn"),
            Self::FLOW_SPEC => write!(f, "flow-spec"),
            Self::FLOW_SPEC_VPN => write!(f, "flow-spec-vpn"),
            Self(n) => write!(f, "SAFI({n})"),
        }
    }
}

/// A combined AFI/SAFI pair that uniquely identifies a BGP routing table.
///
/// In multiprotocol BGP, every route belongs to exactly one address family,
/// identified by the combination of [`Afi`] and [`Safi`]. BGP speakers
/// negotiate which AFI/SAFI combinations they support during session setup
/// (via the Multiprotocol Extensions capability in the OPEN message), and
/// only exchange routes for mutually supported families.
///
/// Named constants are provided for the most common combinations. Any other
/// pair can be constructed with [`AfiSafi::new`].
///
/// # Common address families
///
/// | Constant | AFI | SAFI | Description |
/// |---|---|---|---|
/// | [`AfiSafi::IPV4_UNICAST`] | 1 | 1 | IPv4 unicast — the classic case |
/// | [`AfiSafi::IPV6_UNICAST`] | 2 | 1 | IPv6 unicast |
/// | [`AfiSafi::IPV4_MULTICAST`] | 1 | 2 | IPv4 multicast topology |
/// | [`AfiSafi::IPV6_MULTICAST`] | 2 | 2 | IPv6 multicast topology |
/// | [`AfiSafi::IPV4_MPLS`] | 1 | 4 | IPv4 MPLS labeled unicast |
/// | [`AfiSafi::IPV6_MPLS`] | 2 | 4 | IPv6 MPLS labeled unicast |
/// | [`AfiSafi::IPV4_MPLS_VPN`] | 1 | 128 | IPv4 MPLS L3VPN |
/// | [`AfiSafi::IPV6_MPLS_VPN`] | 2 | 128 | IPv6 MPLS L3VPN |
/// | [`AfiSafi::EVPN`] | 25 | 70 | Ethernet VPN |
/// | [`AfiSafi::IPV4_FLOW_SPEC`] | 1 | 133 | IPv4 FlowSpec |
/// | [`AfiSafi::IPV6_FLOW_SPEC`] | 2 | 133 | IPv6 FlowSpec |
///
/// # Examples
///
/// ```
/// use pathvector_types::{Afi, AfiSafi, Safi};
///
/// assert_eq!(AfiSafi::IPV4_UNICAST.afi, Afi::IPV4);
/// assert_eq!(AfiSafi::IPV4_UNICAST.safi, Safi::UNICAST);
/// assert_eq!(AfiSafi::IPV4_UNICAST.to_string(), "IPv4 unicast");
///
/// // EVPN: L2VPN AFI + EVPN SAFI
/// assert_eq!(AfiSafi::EVPN.afi, Afi::L2VPN);
/// assert_eq!(AfiSafi::EVPN.safi, Safi::EVPN);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AfiSafi {
    /// The address family identifier.
    pub afi: Afi,
    /// The subsequent address family identifier.
    pub safi: Safi,
}

impl AfiSafi {
    /// IPv4 unicast — standard IPv4 route exchange. The default address family
    /// for BGP-4; supported by every BGP implementation.
    pub const IPV4_UNICAST: Self = Self { afi: Afi::IPV4, safi: Safi::UNICAST };

    /// IPv6 unicast — standard IPv6 route exchange (RFC 4760).
    pub const IPV6_UNICAST: Self = Self { afi: Afi::IPV6, safi: Safi::UNICAST };

    /// IPv4 multicast topology routes.
    pub const IPV4_MULTICAST: Self = Self { afi: Afi::IPV4, safi: Safi::MULTICAST };

    /// IPv6 multicast topology routes.
    pub const IPV6_MULTICAST: Self = Self { afi: Afi::IPV6, safi: Safi::MULTICAST };

    /// IPv4 MPLS labeled unicast (RFC 3107).
    pub const IPV4_MPLS: Self = Self { afi: Afi::IPV4, safi: Safi::MPLS_LABELED };

    /// IPv6 MPLS labeled unicast (RFC 3107).
    pub const IPV6_MPLS: Self = Self { afi: Afi::IPV6, safi: Safi::MPLS_LABELED };

    /// IPv4 MPLS Layer 3 VPN (RFC 4364). The dominant enterprise WAN VPN
    /// technology — routes carry MPLS labels that identify the customer VRF
    /// on the remote PE router.
    pub const IPV4_MPLS_VPN: Self = Self { afi: Afi::IPV4, safi: Safi::MPLS_VPN };

    /// IPv6 MPLS Layer 3 VPN.
    pub const IPV6_MPLS_VPN: Self = Self { afi: Afi::IPV6, safi: Safi::MPLS_VPN };

    /// Ethernet VPN (EVPN, RFC 7432). Uses the L2VPN AFI with the EVPN SAFI.
    /// BGP carries MAC and IP reachability for data centre and carrier overlays.
    pub const EVPN: Self = Self { afi: Afi::L2VPN, safi: Safi::EVPN };

    /// IPv4 FlowSpec — traffic flow rules for DDoS mitigation and steering.
    pub const IPV4_FLOW_SPEC: Self = Self { afi: Afi::IPV4, safi: Safi::FLOW_SPEC };

    /// IPv6 FlowSpec.
    pub const IPV6_FLOW_SPEC: Self = Self { afi: Afi::IPV6, safi: Safi::FLOW_SPEC };

    /// Creates an `AfiSafi` from an [`Afi`] and [`Safi`] pair.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Afi, AfiSafi, Safi};
    ///
    /// let af = AfiSafi::new(Afi::IPV4, Safi::UNICAST);
    /// assert_eq!(af, AfiSafi::IPV4_UNICAST);
    /// ```
    #[must_use]
    pub const fn new(afi: Afi, safi: Safi) -> Self {
        Self { afi, safi }
    }
}

impl std::fmt::Display for AfiSafi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.afi, self.safi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Afi ---

    #[test]
    fn test_afi_constants() {
        assert_eq!(Afi::IPV4.as_u16(), 1);
        assert_eq!(Afi::IPV6.as_u16(), 2);
        assert_eq!(Afi::L2VPN.as_u16(), 25);
    }

    #[test]
    fn test_afi_new_roundtrip() {
        assert_eq!(Afi::new(1), Afi::IPV4);
        assert_eq!(Afi::new(2), Afi::IPV6);
    }

    #[test]
    fn test_afi_from_u16() {
        assert_eq!(Afi::from(1u16), Afi::IPV4);
    }

    #[test]
    fn test_afi_display_known() {
        assert_eq!(Afi::IPV4.to_string(), "IPv4");
        assert_eq!(Afi::IPV6.to_string(), "IPv6");
        assert_eq!(Afi::L2VPN.to_string(), "L2VPN");
    }

    #[test]
    fn test_afi_display_unknown() {
        assert_eq!(Afi::new(9999).to_string(), "AFI(9999)");
    }

    #[test]
    fn test_afi_ordering() {
        assert!(Afi::IPV4 < Afi::IPV6);
        assert!(Afi::IPV6 < Afi::L2VPN);
    }

    // --- Safi ---

    #[test]
    fn test_safi_constants() {
        assert_eq!(Safi::UNICAST.as_u8(), 1);
        assert_eq!(Safi::MULTICAST.as_u8(), 2);
        assert_eq!(Safi::MPLS_LABELED.as_u8(), 4);
        assert_eq!(Safi::VPLS.as_u8(), 65);
        assert_eq!(Safi::EVPN.as_u8(), 70);
        assert_eq!(Safi::MPLS_VPN.as_u8(), 128);
        assert_eq!(Safi::FLOW_SPEC.as_u8(), 133);
        assert_eq!(Safi::FLOW_SPEC_VPN.as_u8(), 134);
    }

    #[test]
    fn test_safi_new_roundtrip() {
        assert_eq!(Safi::new(1), Safi::UNICAST);
        assert_eq!(Safi::new(128), Safi::MPLS_VPN);
    }

    #[test]
    fn test_safi_from_u8() {
        assert_eq!(Safi::from(1u8), Safi::UNICAST);
    }

    #[test]
    fn test_safi_display_known() {
        assert_eq!(Safi::UNICAST.to_string(), "unicast");
        assert_eq!(Safi::MULTICAST.to_string(), "multicast");
        assert_eq!(Safi::MPLS_LABELED.to_string(), "mpls-labeled");
        assert_eq!(Safi::VPLS.to_string(), "vpls");
        assert_eq!(Safi::EVPN.to_string(), "evpn");
        assert_eq!(Safi::MPLS_VPN.to_string(), "mpls-vpn");
        assert_eq!(Safi::FLOW_SPEC.to_string(), "flow-spec");
        assert_eq!(Safi::FLOW_SPEC_VPN.to_string(), "flow-spec-vpn");
    }

    #[test]
    fn test_safi_display_unknown() {
        assert_eq!(Safi::new(99).to_string(), "SAFI(99)");
    }

    // --- AfiSafi ---

    #[test]
    fn test_afisafi_constants() {
        assert_eq!(AfiSafi::IPV4_UNICAST.afi, Afi::IPV4);
        assert_eq!(AfiSafi::IPV4_UNICAST.safi, Safi::UNICAST);
        assert_eq!(AfiSafi::IPV6_UNICAST.afi, Afi::IPV6);
        assert_eq!(AfiSafi::EVPN.afi, Afi::L2VPN);
        assert_eq!(AfiSafi::EVPN.safi, Safi::EVPN);
    }

    #[test]
    fn test_afisafi_new() {
        let af = AfiSafi::new(Afi::IPV4, Safi::UNICAST);
        assert_eq!(af, AfiSafi::IPV4_UNICAST);
    }

    #[test]
    fn test_afisafi_display() {
        assert_eq!(AfiSafi::IPV4_UNICAST.to_string(), "IPv4 unicast");
        assert_eq!(AfiSafi::IPV6_UNICAST.to_string(), "IPv6 unicast");
        assert_eq!(AfiSafi::IPV4_MPLS_VPN.to_string(), "IPv4 mpls-vpn");
        assert_eq!(AfiSafi::EVPN.to_string(), "L2VPN evpn");
    }

    #[test]
    fn test_afisafi_unknown_pair() {
        let af = AfiSafi::new(Afi::new(99), Safi::new(99));
        assert_eq!(af.to_string(), "AFI(99) SAFI(99)");
    }
}
