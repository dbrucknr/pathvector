/// A 32-bit BGP Autonomous System Number (ASN).
///
/// Every network that participates in BGP is assigned a globally unique ASN by a
/// Regional Internet Registry (ARIN, RIPE, APNIC, etc.). BGP uses these numbers
/// to identify who is advertising a route and to detect routing loops — a router
/// will reject any route whose AS path already contains its own ASN.
///
/// Originally ASNs were 16-bit (1–65535). RFC 6793 extended them to 32-bit in
/// 2007. All modern BGP speakers negotiate 32-bit support during session setup.
/// This type always stores a 32-bit value; 2-byte ASNs are just 32-bit values
/// that happen to fit in 16 bits.
///
/// # Well-known values
///
/// | Constant | Value | Meaning |
/// |---|---|---|
/// | [`Asn::TRANS`] | 23456 | Placeholder for 4-byte ASNs in 2-byte contexts |
/// | [`Asn::PUBLIC_MAX`] | 64511 | Last public 2-byte ASN |
/// | [`Asn::PRIVATE_2B_START`] | 64512 | First private 2-byte ASN |
/// | [`Asn::PRIVATE_2B_END`] | 65534 | Last private 2-byte ASN |
/// | [`Asn::PRIVATE_4B_START`] | 4200000000 | First private 4-byte ASN |
/// | [`Asn::PRIVATE_4B_END`] | 4294967294 | Last private 4-byte ASN |
///
/// # Examples
///
/// ```
/// use pathvector_types::Asn;
///
/// let asn = Asn::new(65000);
/// assert!(asn.is_private());
/// assert!(!asn.is_four_byte());
///
/// let asn4 = Asn::new(4200000001);
/// assert!(asn4.is_four_byte());
/// assert!(asn4.is_private());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Asn(u32);

impl Asn {
    /// Placeholder ASN used when a 4-byte ASN must be carried through a
    /// 2-byte-only BGP segment (RFC 6793 §7). The session layer substitutes
    /// this value on the wire; the actual ASN is preserved in the
    /// `AS4_PATH` attribute.
    pub const TRANS: Self = Self(23456);

    /// Last publicly assignable 2-byte ASN. Values above this in the 2-byte
    /// range are reserved or private.
    pub const PUBLIC_MAX: Self = Self(64511);

    /// First ASN in the 2-byte private range (64512–65534, RFC 1930).
    /// Private ASNs must be stripped before routes are advertised to the
    /// public internet.
    pub const PRIVATE_2B_START: Self = Self(64512);

    /// Last ASN in the 2-byte private range.
    pub const PRIVATE_2B_END: Self = Self(65534);

    /// First ASN in the 4-byte private range (4200000000–4294967294, RFC 6996).
    pub const PRIVATE_4B_START: Self = Self(4_200_000_000);

    /// Last ASN in the 4-byte private range.
    pub const PRIVATE_4B_END: Self = Self(4_294_967_294);

    /// Creates a new `Asn` from a raw 32-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Asn;
    ///
    /// let asn = Asn::new(65000);
    /// assert_eq!(asn.as_u32(), 65000);
    /// ```
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw 32-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Asn;
    ///
    /// assert_eq!(Asn::new(65000).as_u32(), 65000);
    /// ```
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns `true` if this ASN requires 32 bits — i.e. it does not fit in
    /// the original 16-bit ASN space.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Asn;
    ///
    /// assert!(!Asn::new(65000).is_four_byte());
    /// assert!(Asn::new(131072).is_four_byte());
    /// ```
    #[must_use]
    pub const fn is_four_byte(self) -> bool {
        self.0 > u16::MAX as u32
    }

    /// Returns `true` if this ASN falls in a private range.
    ///
    /// Private ASNs (RFC 1930, RFC 6996) are for internal use and must be
    /// stripped before routes are advertised to the public internet.
    ///
    /// Private ranges:
    /// - 2-byte: 64512–65534
    /// - 4-byte: 4200000000–4294967294
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Asn;
    ///
    /// assert!(Asn::new(65000).is_private());
    /// assert!(Asn::new(4_200_000_001).is_private());
    /// assert!(!Asn::new(13335).is_private()); // Cloudflare
    /// ```
    #[must_use]
    pub const fn is_private(self) -> bool {
        (self.0 >= Self::PRIVATE_2B_START.0 && self.0 <= Self::PRIVATE_2B_END.0)
            || (self.0 >= Self::PRIVATE_4B_START.0 && self.0 <= Self::PRIVATE_4B_END.0)
    }

    /// Returns `true` if this is `AS_TRANS` (23456).
    ///
    /// `AS_TRANS` is a reserved placeholder, not a real network. Seeing it in
    /// a route's AS path outside of a 4-byte migration context is unusual.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::Asn;
    ///
    /// assert!(Asn::TRANS.is_trans());
    /// assert!(!Asn::new(65000).is_trans());
    /// ```
    #[must_use]
    pub const fn is_trans(self) -> bool {
        self.0 == Self::TRANS.0
    }
}

impl From<u32> for Asn {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<u16> for Asn {
    fn from(value: u16) -> Self {
        Self(u32::from(value))
    }
}

impl From<Asn> for u32 {
    fn from(asn: Asn) -> u32 {
        asn.0
    }
}

impl std::fmt::Display for Asn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AS{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asn_new_and_value() {
        let asn = Asn::new(65000);
        assert_eq!(asn.as_u32(), 65000);
    }

    #[test]
    fn test_asn_is_four_byte() {
        assert!(!Asn::new(65535).is_four_byte());
        assert!(Asn::new(65536).is_four_byte());
        assert!(Asn::new(4_200_000_001).is_four_byte());
    }

    #[test]
    fn test_asn_is_private() {
        assert!(!Asn::new(64511).is_private());
        assert!(Asn::new(64512).is_private());
        assert!(Asn::new(65000).is_private());
        assert!(Asn::new(65534).is_private());
        assert!(!Asn::new(65535).is_private());
        assert!(Asn::new(4_200_000_000).is_private());
        assert!(Asn::new(4_294_967_294).is_private());
        assert!(!Asn::new(4_294_967_295).is_private());
    }

    #[test]
    fn test_asn_is_trans() {
        assert!(Asn::TRANS.is_trans());
        assert!(!Asn::new(65000).is_trans());
    }

    #[test]
    fn test_asn_display() {
        assert_eq!(Asn::new(65000).to_string(), "AS65000");
        assert_eq!(Asn::new(13335).to_string(), "AS13335");
    }

    #[test]
    fn test_asn_from_u16() {
        let asn = Asn::from(65000u16);
        assert_eq!(asn.as_u32(), 65000);
        assert!(!asn.is_four_byte());
    }

    #[test]
    fn test_asn_from_u32() {
        let asn = Asn::from(131072u32);
        assert_eq!(asn.as_u32(), 131072);
        assert!(asn.is_four_byte());
    }

    #[test]
    fn test_asn_into_u32() {
        let v: u32 = Asn::new(65000).into();
        assert_eq!(v, 65000);
    }

    #[test]
    fn test_asn_ordering() {
        assert!(Asn::new(1) < Asn::new(65000));
        assert!(Asn::new(65000) > Asn::new(64511));
    }

    #[test]
    fn test_asn_constants() {
        assert_eq!(Asn::TRANS.as_u32(), 23456);
        assert_eq!(Asn::PRIVATE_2B_START.as_u32(), 64512);
        assert_eq!(Asn::PRIVATE_2B_END.as_u32(), 65534);
        assert_eq!(Asn::PRIVATE_4B_START.as_u32(), 4_200_000_000);
        assert_eq!(Asn::PRIVATE_4B_END.as_u32(), 4_294_967_294);
    }
}
