use ipnetx::{interfaces::IpAddress, prefix::IpPrefix};

pub use ipnetx::prefix::{InvalidPrefixLen, ParsePrefixError};

/// A BGP Network Layer Reachability Information entry.
///
/// NLRI is the actual payload of a BGP UPDATE message — the IP prefixes being
/// advertised or withdrawn. Every route in BGP reduces to: "I can reach these
/// prefixes, via this path, with these attributes."
///
/// An UPDATE message carries two lists:
/// - **Withdrawn NLRI** — prefixes the sender is pulling back. Routes
///   previously advertised that should be removed from the receiver's RIB.
/// - **Reachable NLRI** — prefixes the sender is advertising, described by
///   the path attributes in the same message (AS path, next-hop, communities,
///   etc.).
///
/// `Nlri<A>` is a thin wrapper around [`IpPrefix<A>`] from
/// [`ipnetx`](https://crates.io/crates/ipnetx) that adds BGP-specific
/// terminology and semantics. The generic parameter `A` is either
/// [`Ipv4Addr`](std::net::Ipv4Addr) or [`Ipv6Addr`](std::net::Ipv6Addr),
/// constrained by the sealed [`IpAddress`] trait.
///
/// # AFI/SAFI context
///
/// `Nlri<A>` does not carry an [`AfiSafi`](crate::AfiSafi). The address family
/// is encoded in the type parameter `A` (IPv4 → AFI 1, IPv6 → AFI 2), and the
/// SAFI is always provided by the surrounding structure — an `MP_REACH_NLRI`
/// attribute, a RIB table keyed by `AfiSafi`, or an UPDATE message. This keeps
/// `Nlri<A>` composable and avoids redundancy.
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use ipnetx::prefix::IpPrefix;
/// use pathvector_types::Nlri;
///
/// // Construct from an IpPrefix
/// let prefix = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
/// let nlri = Nlri::from_prefix(prefix);
/// assert_eq!(nlri.prefix_len(), 24);
/// assert!(nlri.contains(Ipv4Addr::new(192, 168, 1, 100)));
///
/// // Parse from CIDR notation
/// let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
/// assert!(!nlri.is_default_route());
/// assert!(!nlri.is_host_route());
///
/// // Default route and host route detection
/// let default: Nlri<Ipv4Addr> = "0.0.0.0/0".parse().unwrap();
/// assert!(default.is_default_route());
///
/// let host: Nlri<Ipv4Addr> = "192.0.2.1/32".parse().unwrap();
/// assert!(host.is_host_route());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nlri<A: IpAddress> {
    prefix: IpPrefix<A>,
}

impl<A: IpAddress> Nlri<A> {
    /// Creates an `Nlri` from an existing [`IpPrefix`].
    ///
    /// This is the infallible constructor — use it when you already have a
    /// validated prefix. To construct from raw address and length, use
    /// [`Nlri::new`].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::prefix::IpPrefix;
    /// use pathvector_types::Nlri;
    ///
    /// let prefix = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
    /// let nlri = Nlri::from_prefix(prefix);
    /// assert_eq!(nlri.prefix_len(), 8);
    /// ```
    #[must_use]
    pub fn from_prefix(prefix: IpPrefix<A>) -> Self {
        Self { prefix }
    }

    /// Creates an `Nlri` from a raw IP address and prefix length.
    ///
    /// Returns [`Err(InvalidPrefixLen)`](InvalidPrefixLen) if the prefix
    /// length exceeds the address width (`> 32` for IPv4, `> 128` for IPv6).
    ///
    /// Host bits in the address are preserved. Use [`Nlri::masked`] to obtain
    /// canonical form where host bits are zeroed.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use pathvector_types::Nlri;
    ///
    /// let nlri = Nlri::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
    /// assert_eq!(nlri.prefix_len(), 24);
    ///
    /// assert!(Nlri::new(Ipv4Addr::new(0, 0, 0, 0), 33).is_err());
    /// ```
    pub fn new(ip: A, mask: u8) -> Result<Self, InvalidPrefixLen> {
        IpPrefix::new(ip, mask).map(Self::from_prefix)
    }

    /// Returns the underlying [`IpPrefix`].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use pathvector_types::Nlri;
    ///
    /// let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
    /// assert_eq!(nlri.prefix().mask(), 8);
    /// ```
    #[must_use]
    pub fn prefix(self) -> IpPrefix<A> {
        self.prefix
    }

    /// Returns the prefix length (number of network bits).
    ///
    /// Also called the "mask length" in some contexts. Always in the range
    /// `[0, 32]` for IPv4 and `[0, 128]` for IPv6.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use pathvector_types::Nlri;
    ///
    /// let nlri: Nlri<Ipv4Addr> = "192.168.0.0/16".parse().unwrap();
    /// assert_eq!(nlri.prefix_len(), 16);
    /// ```
    #[must_use]
    pub fn prefix_len(self) -> u8 {
        self.prefix.mask()
    }

    /// Returns `true` if `addr` falls within this prefix.
    ///
    /// This is used in forwarding lookups and prefix-list matching in route
    /// policy. Host bits in this NLRI's address are masked out before
    /// comparison, so `192.168.1.100/24` and `192.168.1.0/24` cover the same
    /// set of addresses.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use pathvector_types::Nlri;
    ///
    /// let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
    /// assert!(nlri.contains(Ipv4Addr::new(10, 1, 2, 3)));
    /// assert!(!nlri.contains(Ipv4Addr::new(11, 0, 0, 1)));
    /// ```
    #[must_use]
    pub fn contains(self, addr: A) -> bool {
        self.prefix.contains(addr)
    }

    /// Returns `true` if this is the default route — the catch-all prefix
    /// that matches every address.
    ///
    /// The default route is `0.0.0.0/0` for IPv4 and `::/0` for IPv6. It has
    /// a prefix length of 0, meaning it has no network bits and matches
    /// everything. In BGP, a default route is commonly advertised by an ISP
    /// to a customer to provide internet access without the full routing table.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::{Ipv4Addr, Ipv6Addr};
    /// use pathvector_types::Nlri;
    ///
    /// let v4_default: Nlri<Ipv4Addr> = "0.0.0.0/0".parse().unwrap();
    /// assert!(v4_default.is_default_route());
    ///
    /// let v6_default: Nlri<Ipv6Addr> = "::/0".parse().unwrap();
    /// assert!(v6_default.is_default_route());
    ///
    /// let not_default: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
    /// assert!(!not_default.is_default_route());
    /// ```
    #[must_use]
    pub fn is_default_route(self) -> bool {
        self.prefix.mask() == 0
    }

    /// Returns `true` if this is a host route — a prefix covering exactly one
    /// IP address (`/32` for IPv4 or `/128` for IPv6).
    ///
    /// Host routes appear in several BGP contexts:
    /// - **Loopback advertisement** — routers advertise their loopback address
    ///   as a /32 so other routers can reach them directly.
    /// - **ECMP next-hop resolution** — BGP next-hops are often resolved via
    ///   a /32 in the IGP.
    /// - **Blackhole routing** — a /32 with `BLACKHOLE` community signals
    ///   upstream providers to drop traffic to a specific host (DDoS
    ///   mitigation).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::{Ipv4Addr, Ipv6Addr};
    /// use pathvector_types::Nlri;
    ///
    /// let host: Nlri<Ipv4Addr> = "192.0.2.1/32".parse().unwrap();
    /// assert!(host.is_host_route());
    ///
    /// let v6_host: Nlri<Ipv6Addr> = "2001:db8::1/128".parse().unwrap();
    /// assert!(v6_host.is_host_route());
    ///
    /// let not_host: Nlri<Ipv4Addr> = "192.0.2.0/24".parse().unwrap();
    /// assert!(!not_host.is_host_route());
    /// ```
    #[must_use]
    pub fn is_host_route(self) -> bool {
        self.prefix.is_single_ip()
    }

    /// Returns a new `Nlri` with host bits of the address zeroed — canonical
    /// CIDR form.
    ///
    /// BGP UPDATE messages should carry network addresses, but this method
    /// handles cases where host bits are present (e.g. `192.168.1.100/24`
    /// becomes `192.168.1.0/24`). The prefix length is unchanged.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use pathvector_types::Nlri;
    ///
    /// let nlri = Nlri::new(Ipv4Addr::new(192, 168, 1, 100), 24).unwrap();
    /// let canonical = nlri.masked();
    /// assert_eq!(canonical.to_string(), "192.168.1.0/24");
    /// ```
    #[must_use]
    pub fn masked(self) -> Self {
        Self { prefix: self.prefix.masked() }
    }

    /// Returns `true` if this NLRI shares at least one address with `other`.
    ///
    /// Two CIDR prefixes either nest (one contains the other) or are disjoint —
    /// partial overlap as seen with arbitrary ranges is not possible with CIDR.
    ///
    /// Useful in prefix-list policy: checking whether an advertised route
    /// matches any entry in a configured prefix list.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use pathvector_types::Nlri;
    ///
    /// let broad: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
    /// let narrow: Nlri<Ipv4Addr> = "10.1.0.0/16".parse().unwrap();
    /// let unrelated: Nlri<Ipv4Addr> = "192.168.0.0/16".parse().unwrap();
    ///
    /// assert!(broad.overlaps(&narrow));
    /// assert!(!broad.overlaps(&unrelated));
    /// ```
    #[must_use]
    pub fn overlaps(self, other: &Nlri<A>) -> bool {
        self.prefix.overlaps(&other.prefix)
    }
}

impl<A: IpAddress> PartialOrd for Nlri<A> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<A: IpAddress> Ord for Nlri<A> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.prefix
            .ip()
            .to_u128()
            .cmp(&other.prefix.ip().to_u128())
            .then(self.prefix.mask().cmp(&other.prefix.mask()))
    }
}

impl<A: IpAddress> std::fmt::Display for Nlri<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.prefix.fmt(f)
    }
}

impl<A: IpAddress> std::str::FromStr for Nlri<A> {
    type Err = ParsePrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<IpPrefix<A>>().map(Self::from_prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_nlri_new_v4() {
        let nlri = Nlri::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        assert_eq!(nlri.prefix_len(), 24);
    }

    #[test]
    fn test_nlri_new_invalid_mask() {
        assert!(Nlri::new(Ipv4Addr::new(0, 0, 0, 0), 33).is_err());
        assert!(Nlri::new(Ipv6Addr::UNSPECIFIED, 129).is_err());
    }

    #[test]
    fn test_nlri_from_prefix() {
        let prefix = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
        let nlri = Nlri::from_prefix(prefix);
        assert_eq!(nlri.prefix_len(), 8);
        assert_eq!(nlri.prefix(), prefix);
    }

    #[test]
    fn test_nlri_contains_v4() {
        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        assert!(nlri.contains(Ipv4Addr::new(10, 255, 255, 255)));
        assert!(!nlri.contains(Ipv4Addr::new(11, 0, 0, 0)));
    }

    #[test]
    fn test_nlri_contains_v6() {
        let nlri: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        assert!(nlri.contains(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)));
        assert!(!nlri.contains(Ipv6Addr::new(0x2001, 0x0db9, 0, 0, 0, 0, 0, 0)));
    }

    #[test]
    fn test_nlri_is_default_route_v4() {
        let default: Nlri<Ipv4Addr> = "0.0.0.0/0".parse().unwrap();
        assert!(default.is_default_route());

        let not_default: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        assert!(!not_default.is_default_route());
    }

    #[test]
    fn test_nlri_is_default_route_v6() {
        let default: Nlri<Ipv6Addr> = "::/0".parse().unwrap();
        assert!(default.is_default_route());
    }

    #[test]
    fn test_nlri_is_host_route_v4() {
        let host: Nlri<Ipv4Addr> = "192.0.2.1/32".parse().unwrap();
        assert!(host.is_host_route());

        let not_host: Nlri<Ipv4Addr> = "192.0.2.0/24".parse().unwrap();
        assert!(!not_host.is_host_route());
    }

    #[test]
    fn test_nlri_is_host_route_v6() {
        let host: Nlri<Ipv6Addr> = "2001:db8::1/128".parse().unwrap();
        assert!(host.is_host_route());

        let not_host: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        assert!(!not_host.is_host_route());
    }

    #[test]
    fn test_nlri_masked() {
        let nlri = Nlri::new(Ipv4Addr::new(192, 168, 1, 100), 24).unwrap();
        let canonical = nlri.masked();
        assert_eq!(canonical.to_string(), "192.168.1.0/24");
        assert_eq!(canonical.prefix_len(), 24);
    }

    #[test]
    fn test_nlri_overlaps() {
        let broad: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let narrow: Nlri<Ipv4Addr> = "10.1.0.0/16".parse().unwrap();
        let unrelated: Nlri<Ipv4Addr> = "192.168.0.0/16".parse().unwrap();

        assert!(broad.overlaps(&narrow));
        assert!(narrow.overlaps(&broad));
        assert!(!broad.overlaps(&unrelated));
    }

    #[test]
    fn test_nlri_display() {
        let nlri: Nlri<Ipv4Addr> = "192.168.1.0/24".parse().unwrap();
        assert_eq!(nlri.to_string(), "192.168.1.0/24");

        let nlri6: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        assert_eq!(nlri6.to_string(), "2001:db8::/32");
    }

    #[test]
    fn test_nlri_parse_error() {
        assert!("192.168.1.0".parse::<Nlri<Ipv4Addr>>().is_err());
        assert!("192.168.1.0/33".parse::<Nlri<Ipv4Addr>>().is_err());
    }

    #[test]
    fn test_nlri_ordering() {
        let a: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let b: Nlri<Ipv4Addr> = "10.0.0.0/24".parse().unwrap();
        let c: Nlri<Ipv4Addr> = "192.168.0.0/16".parse().unwrap();

        assert!(a < b); // same address, shorter prefix < longer prefix
        assert!(b < c); // lower address < higher address
        assert!(a < c);
    }

    #[test]
    fn test_nlri_copy() {
        let a: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let b = a; // Copy
        assert_eq!(a, b);
    }
}
