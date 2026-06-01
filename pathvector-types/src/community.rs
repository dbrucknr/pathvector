/// A standard 32-bit BGP community (RFC 1997).
///
/// Communities are tags attached to routes that carry policy signals between
/// networks. They let operators say things like "do not re-advertise this
/// route" or "this route came from a customer" without baking that logic
/// into the route itself. Routers apply policy based on communities they
/// receive, and strip or rewrite them before forwarding.
///
/// Structurally a community is a `u32` split into two 16-bit halves:
/// - **High 16 bits** — by convention, the operator's AS number
/// - **Low 16 bits** — a locally meaningful value defined by the operator
///
/// Well-known communities use `0xFFFF` in the high half (65535 is not a
/// valid public ASN, guaranteeing no collision with operator communities).
///
/// For 4-byte ASN operators, standard communities cannot hold the full ASN
/// in the high field. Use [`LargeCommunity`] instead.
///
/// # Well-known communities
///
/// | Constant | Value | Meaning |
/// |---|---|---|
/// | [`Community::NO_EXPORT`] | `0xFFFFFF01` | Do not advertise outside this AS |
/// | [`Community::NO_ADVERTISE`] | `0xFFFFFF02` | Do not advertise to any peer |
/// | [`Community::NO_EXPORT_SUBCONFED`] | `0xFFFFFF03` | Do not advertise outside this confederation |
/// | [`Community::BLACKHOLE`] | `0xFFFF029A` | Discard traffic to this prefix (RFC 7999) |
///
/// # Examples
///
/// ```
/// use pathvector_types::Community;
///
/// // Operator-defined: AS 65000 tagging a route as low priority
/// let c = Community::from_parts(65000, 100);
/// assert_eq!(c.high(), 65000);
/// assert_eq!(c.low(), 100);
/// assert_eq!(c.to_string(), "65000:100");
///
/// // Well-known: signal peers not to re-advertise this route
/// assert!(Community::NO_EXPORT.is_no_export());
/// assert!(Community::NO_EXPORT.is_well_known());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Community(u32);

impl Community {
    /// Do not advertise this route to any eBGP peer outside this AS.
    /// The route may still be used internally and advertised to iBGP peers.
    pub const NO_EXPORT: Self = Self(0xFFFF_FF01);

    /// Do not advertise this route to any peer, internal or external.
    /// The route may still be used locally for forwarding.
    pub const NO_ADVERTISE: Self = Self(0xFFFF_FF02);

    /// Do not advertise this route outside the local confederation.
    /// Equivalent to `NO_EXPORT` for non-confederation deployments.
    pub const NO_EXPORT_SUBCONFED: Self = Self(0xFFFF_FF03);

    /// Signal that traffic toward this prefix should be dropped (blackholed).
    /// Used for `DDoS` mitigation — advertise a /32 with this community
    /// to trigger upstream providers to discard matching traffic at their edge.
    /// Defined in RFC 7999.
    pub const BLACKHOLE: Self = Self(0xFFFF_029A);

    /// Creates a community from a raw 32-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Community;
    ///
    /// let c = Community::new(0xFDE8_0064); // AS 65000, value 100
    /// assert_eq!(c.high(), 65000);
    /// assert_eq!(c.low(), 100);
    /// ```
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Creates a community from its two 16-bit halves.
    ///
    /// This is the idiomatic constructor for operator-defined communities,
    /// where the high half is conventionally the operator's AS number.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Community;
    ///
    /// let c = Community::from_parts(65000, 200);
    /// assert_eq!(c.as_u32(), (65000_u32 << 16) | 200);
    /// ```
    #[must_use]
    pub const fn from_parts(high: u16, low: u16) -> Self {
        Self(((high as u32) << 16) | (low as u32))
    }

    /// Returns the raw 32-bit value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the high 16 bits — conventionally the operator's AS number.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Community;
    ///
    /// assert_eq!(Community::from_parts(65000, 100).high(), 65000);
    /// ```
    #[must_use]
    pub const fn high(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// Returns the low 16 bits — the operator-defined local value.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Community;
    ///
    /// assert_eq!(Community::from_parts(65000, 100).low(), 100);
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn low(self) -> u16 {
        // Intentional: extract the low 16 bits of the community u32.
        // A Community value splits as [high: u16][low: u16]; truncation is by design.
        self.0 as u16
    }

    /// Returns `true` if this is a well-known community (high half is `0xFFFF`).
    ///
    /// Well-known communities have globally agreed-upon meanings and must be
    /// honoured by any compliant BGP implementation.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Community;
    ///
    /// assert!(Community::NO_EXPORT.is_well_known());
    /// assert!(!Community::from_parts(65000, 100).is_well_known());
    /// ```
    #[must_use]
    pub const fn is_well_known(self) -> bool {
        self.high() == 0xFFFF
    }

    /// Returns `true` if this is the `NO_EXPORT` community.
    #[must_use]
    pub const fn is_no_export(self) -> bool {
        self.0 == Self::NO_EXPORT.0
    }

    /// Returns `true` if this is the `NO_ADVERTISE` community.
    #[must_use]
    pub const fn is_no_advertise(self) -> bool {
        self.0 == Self::NO_ADVERTISE.0
    }

    /// Returns `true` if this is the `NO_EXPORT_SUBCONFED` community.
    #[must_use]
    pub const fn is_no_export_subconfed(self) -> bool {
        self.0 == Self::NO_EXPORT_SUBCONFED.0
    }

    /// Returns `true` if this is the `BLACKHOLE` community (RFC 7999).
    #[must_use]
    pub const fn is_blackhole(self) -> bool {
        self.0 == Self::BLACKHOLE.0
    }
}

impl From<u32> for Community {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Community> for u32 {
    fn from(c: Community) -> u32 {
        c.0
    }
}

impl std::fmt::Display for Community {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.high(), self.low())
    }
}

/// A large BGP community (RFC 8092).
///
/// Large communities were introduced to give 4-byte ASN operators a clean
/// community namespace. A standard [`Community`] splits its 32 bits as
/// `AS(16):value(16)` — there is no room for a 4-byte ASN in the high field.
/// Large communities solve this by using three independent `u32` fields,
/// written `global-administrator:local-data-1:local-data-2`.
///
/// There are no well-known large communities; operators define all meanings
/// themselves.
///
/// # Fields
///
/// - **`global_administrator`** — the operator's 4-byte AS number (or any
///   globally unique `u32` identifier)
/// - **`local_data_1`** — first operator-defined `u32` value
/// - **`local_data_2`** — second operator-defined `u32` value
///
/// # Examples
///
/// ```
/// use pathvector_types::LargeCommunity;
///
/// // AS 4200000001 tagging a route as belonging to customer 999, policy 1
/// let lc = LargeCommunity::new(4_200_000_001, 999, 1);
/// assert_eq!(lc.to_string(), "4200000001:999:1");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LargeCommunity {
    /// The operator's 4-byte AS number (or another globally unique identifier).
    pub global_administrator: u32,
    /// First operator-defined value.
    pub local_data_1: u32,
    /// Second operator-defined value.
    pub local_data_2: u32,
}

impl LargeCommunity {
    /// Creates a new large community.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::LargeCommunity;
    ///
    /// let lc = LargeCommunity::new(65000, 1, 100);
    /// assert_eq!(lc.global_administrator, 65000);
    /// assert_eq!(lc.local_data_1, 1);
    /// assert_eq!(lc.local_data_2, 100);
    /// ```
    #[must_use]
    pub const fn new(global_administrator: u32, local_data_1: u32, local_data_2: u32) -> Self {
        Self {
            global_administrator,
            local_data_1,
            local_data_2,
        }
    }

    /// Returns the raw 12-byte representation (network byte order).
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::LargeCommunity;
    ///
    /// let lc = LargeCommunity::new(1, 2, 3);
    /// let bytes = lc.to_bytes();
    /// assert_eq!(&bytes[0..4], &1u32.to_be_bytes());
    /// assert_eq!(&bytes[4..8], &2u32.to_be_bytes());
    /// assert_eq!(&bytes[8..12], &3u32.to_be_bytes());
    /// ```
    #[must_use]
    pub fn to_bytes(self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[0..4].copy_from_slice(&self.global_administrator.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.local_data_1.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.local_data_2.to_be_bytes());
        bytes
    }

    /// Parses a large community from its 12-byte wire representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::LargeCommunity;
    ///
    /// let original = LargeCommunity::new(65000, 1, 100);
    /// let restored = LargeCommunity::from_bytes(original.to_bytes());
    /// assert_eq!(original, restored);
    /// ```
    #[must_use]
    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        Self {
            global_administrator: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            local_data_1: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            local_data_2: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        }
    }
}

impl std::fmt::Display for LargeCommunity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.global_administrator, self.local_data_1, self.local_data_2
        )
    }
}

/// An extended BGP community (RFC 4360).
///
/// Extended communities are 8-byte typed values. Unlike standard communities,
/// they carry an explicit type in the first two bytes, which defines how the
/// remaining 6 bytes should be interpreted. This makes them extensible: new
/// community types can be defined without ambiguity.
///
/// Extended communities are used heavily in VPN and EVPN contexts. The most
/// common type is the **Route Target (RT)**, which identifies which VRF
/// (Virtual Routing and Forwarding instance) a route belongs to. When a PE
/// (Provider Edge) router imports a VPN route, it checks the route's RT
/// against its own configured import targets to decide which VRF to place
/// the route in.
///
/// # Type encoding
///
/// The first byte encodes two things:
/// - **Bit 7 (MSB):** IANA authority (0 = IANA assigned, 1 = private use)
/// - **Bit 6:** Transitivity (0 = transitive across ASes, 1 = non-transitive)
/// - **Bits 5–0:** The type value
///
/// The second byte is the sub-type, which refines the interpretation within
/// a type family.
///
/// # Common types
///
/// | Type | Sub-type | Meaning |
/// |---|---|---|
/// | `0x00` | `0x02` | Route Target — 2-byte AS specific |
/// | `0x01` | `0x02` | Route Target — IPv4 address specific |
/// | `0x02` | `0x02` | Route Target — 4-byte AS specific |
/// | `0x00` | `0x03` | Route Origin — 2-byte AS specific |
/// | `0x02` | `0x03` | Route Origin — 4-byte AS specific |
///
/// # Examples
///
/// ```
/// use pathvector_types::ExtendedCommunity;
///
/// // Route Target: AS 65000, value 100 (2-byte AS form)
/// let rt = ExtendedCommunity::route_target_as2(65000, 100);
/// assert!(rt.is_transitive());
/// assert_eq!(rt.type_high(), 0x00);
/// assert_eq!(rt.type_low(), 0x02);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtendedCommunity([u8; 8]);

impl ExtendedCommunity {
    /// Creates an extended community from its raw 8-byte representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::ExtendedCommunity;
    ///
    /// let ec = ExtendedCommunity::from_bytes([0x00, 0x02, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64]);
    /// assert_eq!(ec.type_high(), 0x00);
    /// assert_eq!(ec.type_low(), 0x02);
    /// ```
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 8-byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// Returns the high type byte (encodes IANA authority, transitivity, and type).
    #[must_use]
    pub const fn type_high(&self) -> u8 {
        self.0[0]
    }

    /// Returns the sub-type byte.
    #[must_use]
    pub const fn type_low(&self) -> u8 {
        self.0[1]
    }

    /// Returns `true` if this community is transitive — i.e. it is preserved
    /// when the route crosses AS boundaries.
    ///
    /// Non-transitive communities are stripped at AS boundaries. Bit 6 of the
    /// high type byte controls this: 0 = transitive, 1 = non-transitive.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::ExtendedCommunity;
    ///
    /// let rt = ExtendedCommunity::route_target_as2(65000, 1);
    /// assert!(rt.is_transitive());
    /// ```
    #[must_use]
    pub const fn is_transitive(&self) -> bool {
        self.0[0] & 0x40 == 0
    }

    /// Returns the 6-byte value portion of this extended community.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.0[2..]
    }

    /// Creates a Route Target extended community using a 2-byte AS number
    /// and a 4-byte local value (type `0x00`, sub-type `0x02`).
    ///
    /// Route Targets are the primary mechanism for VPN route import/export
    /// policy. A PE router exports routes with one or more RTs attached;
    /// other PEs import routes whose RTs match their configured import list.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::ExtendedCommunity;
    ///
    /// let rt = ExtendedCommunity::route_target_as2(65000, 100);
    /// assert_eq!(rt.type_high(), 0x00);
    /// assert_eq!(rt.type_low(), 0x02);
    /// assert!(rt.is_transitive());
    /// ```
    #[must_use]
    pub fn route_target_as2(asn: u16, value: u32) -> Self {
        let mut bytes = [0u8; 8];
        bytes[0] = 0x00;
        bytes[1] = 0x02;
        bytes[2..4].copy_from_slice(&asn.to_be_bytes());
        bytes[4..8].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }

    /// Creates a Route Target extended community using a 4-byte AS number
    /// and a 2-byte local value (type `0x02`, sub-type `0x02`).
    ///
    /// Use this form when the operator has a 4-byte ASN.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::ExtendedCommunity;
    ///
    /// let rt = ExtendedCommunity::route_target_as4(4_200_000_001, 100);
    /// assert_eq!(rt.type_high(), 0x02);
    /// assert_eq!(rt.type_low(), 0x02);
    /// ```
    #[must_use]
    pub fn route_target_as4(asn: u32, value: u16) -> Self {
        let mut bytes = [0u8; 8];
        bytes[0] = 0x02;
        bytes[1] = 0x02;
        bytes[2..6].copy_from_slice(&asn.to_be_bytes());
        bytes[6..8].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }

    /// Creates a Route Origin extended community using a 2-byte AS number
    /// and a 4-byte local value (type `0x00`, sub-type `0x03`).
    ///
    /// Route Origin identifies where a VPN route was originally injected.
    /// Unlike Route Target, it is purely informational — it does not drive
    /// import policy.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::ExtendedCommunity;
    ///
    /// let ro = ExtendedCommunity::route_origin_as2(65000, 1);
    /// assert_eq!(ro.type_high(), 0x00);
    /// assert_eq!(ro.type_low(), 0x03);
    /// ```
    #[must_use]
    pub fn route_origin_as2(asn: u16, value: u32) -> Self {
        let mut bytes = [0u8; 8];
        bytes[0] = 0x00;
        bytes[1] = 0x03;
        bytes[2..4].copy_from_slice(&asn.to_be_bytes());
        bytes[4..8].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }
}

impl std::fmt::Display for ExtendedCommunity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}{:02x}:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Community ---

    #[test]
    fn test_community_from_parts_roundtrip() {
        let c = Community::from_parts(65000, 100);
        assert_eq!(c.high(), 65000);
        assert_eq!(c.low(), 100);
    }

    #[test]
    fn test_community_as_u32() {
        let c = Community::from_parts(1, 1);
        assert_eq!(c.as_u32(), (1u32 << 16) | 1);
    }

    #[test]
    fn test_community_well_known_no_export() {
        assert!(Community::NO_EXPORT.is_well_known());
        assert!(Community::NO_EXPORT.is_no_export());
        assert!(!Community::NO_EXPORT.is_no_advertise());
    }

    #[test]
    fn test_community_well_known_no_advertise() {
        assert!(Community::NO_ADVERTISE.is_well_known());
        assert!(Community::NO_ADVERTISE.is_no_advertise());
    }

    #[test]
    fn test_community_well_known_no_export_subconfed() {
        assert!(Community::NO_EXPORT_SUBCONFED.is_well_known());
        assert!(Community::NO_EXPORT_SUBCONFED.is_no_export_subconfed());
    }

    #[test]
    fn test_community_blackhole() {
        assert!(Community::BLACKHOLE.is_well_known());
        assert!(Community::BLACKHOLE.is_blackhole());
    }

    #[test]
    fn test_community_operator_not_well_known() {
        let c = Community::from_parts(65000, 100);
        assert!(!c.is_well_known());
        assert!(!c.is_no_export());
    }

    #[test]
    fn test_community_display() {
        assert_eq!(Community::from_parts(65000, 100).to_string(), "65000:100");
        assert_eq!(Community::from_parts(0, 0).to_string(), "0:0");
    }

    #[test]
    fn test_community_ordering() {
        let a = Community::from_parts(65000, 1);
        let b = Community::from_parts(65000, 2);
        assert!(a < b);
    }

    #[test]
    fn test_community_new() {
        let c = Community::new(0xFDE8_0064);
        assert_eq!(c.high(), 0xFDE8);
        assert_eq!(c.low(), 0x0064);
        assert_eq!(c.as_u32(), 0xFDE8_0064);
    }

    #[test]
    fn test_community_from_u32() {
        let c = Community::from(0xFDE8_0064u32);
        assert_eq!(c.high(), 0xFDE8);
        assert_eq!(c.low(), 0x0064);
    }

    #[test]
    fn test_community_into_u32() {
        let v: u32 = Community::from_parts(65000, 100).into();
        assert_eq!(v, (65000u32 << 16) | 0x64);
    }

    // --- LargeCommunity ---

    #[test]
    fn test_large_community_new() {
        let lc = LargeCommunity::new(4_200_000_001, 999, 1);
        assert_eq!(lc.global_administrator, 4_200_000_001);
        assert_eq!(lc.local_data_1, 999);
        assert_eq!(lc.local_data_2, 1);
    }

    #[test]
    fn test_large_community_bytes_roundtrip() {
        let original = LargeCommunity::new(65000, 1, 100);
        let restored = LargeCommunity::from_bytes(original.to_bytes());
        assert_eq!(original, restored);
    }

    #[test]
    fn test_large_community_display() {
        assert_eq!(
            LargeCommunity::new(65000, 1, 100).to_string(),
            "65000:1:100"
        );
        assert_eq!(
            LargeCommunity::new(4_200_000_001, 999, 1).to_string(),
            "4200000001:999:1"
        );
    }

    // --- ExtendedCommunity ---

    #[test]
    fn test_extended_community_route_target_as2() {
        let rt = ExtendedCommunity::route_target_as2(65000, 100);
        assert_eq!(rt.type_high(), 0x00);
        assert_eq!(rt.type_low(), 0x02);
        assert!(rt.is_transitive());
    }

    #[test]
    fn test_extended_community_route_target_as4() {
        let rt = ExtendedCommunity::route_target_as4(4_200_000_001, 100);
        assert_eq!(rt.type_high(), 0x02);
        assert_eq!(rt.type_low(), 0x02);
        assert!(rt.is_transitive());
    }

    #[test]
    fn test_extended_community_route_origin_as2() {
        let ro = ExtendedCommunity::route_origin_as2(65000, 1);
        assert_eq!(ro.type_high(), 0x00);
        assert_eq!(ro.type_low(), 0x03);
    }

    #[test]
    fn test_extended_community_non_transitive() {
        // Bit 6 set = non-transitive
        let ec = ExtendedCommunity::from_bytes([0x40, 0x02, 0, 0, 0, 0, 0, 0]);
        assert!(!ec.is_transitive());
    }

    #[test]
    fn test_extended_community_bytes_roundtrip() {
        let bytes = [0x00, 0x02, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64];
        let ec = ExtendedCommunity::from_bytes(bytes);
        assert_eq!(ec.as_bytes(), &bytes);
    }

    #[test]
    fn test_extended_community_value() {
        // value() returns the 6 bytes after the type and sub-type bytes.
        let rt = ExtendedCommunity::route_target_as2(65000, 100);
        let v = rt.value();
        assert_eq!(v.len(), 6);
        // bytes[2..4] = 65000 big-endian = [0xFD, 0xE8]
        assert_eq!(v[0], 0xFD);
        assert_eq!(v[1], 0xE8);
        // bytes[4..8] = 100 big-endian = [0x00, 0x00, 0x00, 0x64]
        assert_eq!(&v[2..], &[0x00, 0x00, 0x00, 0x64]);
    }

    #[test]
    fn test_extended_community_display() {
        // Display renders all 8 bytes as hex with a colon after the first two.
        let ec = ExtendedCommunity::from_bytes([0x00, 0x02, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64]);
        assert_eq!(ec.to_string(), "0002:fde800000064");

        let ec2 = ExtendedCommunity::from_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(ec2.to_string(), "0000:000000000000");
    }
}
