use std::net::IpAddr;

/// The IP address of a BGP peer, used as a key in per-peer RIB tables.
///
/// In BGP, a peer is identified by its IP address. This newtype wraps
/// [`IpAddr`] to make the intent explicit in function signatures and to
/// allow the type to grow (e.g. adding an AS number) without changing call
/// sites.
///
/// `PeerId` is `Copy`, `Hash`, `Eq`, and `Ord` — safe to use as a map key
/// and to compare as a final tie-breaker in best-path selection (lower peer
/// IP address wins, RFC 4271 §9.1 step 10).
///
/// # Examples
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr};
/// use pathvector_rib::PeerId;
///
/// let peer = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
/// assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(IpAddr);

impl PeerId {
    /// Creates a `PeerId` from an IP address.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr};
    /// use pathvector_rib::PeerId;
    ///
    /// let peer = PeerId::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    /// ```
    #[must_use]
    pub fn new(addr: IpAddr) -> Self {
        Self(addr)
    }

    /// Returns the underlying IP address.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::{IpAddr, Ipv6Addr};
    /// use pathvector_rib::PeerId;
    ///
    /// let peer = PeerId::new(IpAddr::V6(Ipv6Addr::LOCALHOST));
    /// assert_eq!(peer.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    /// ```
    #[must_use]
    pub fn ip(self) -> IpAddr {
        self.0
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<IpAddr> for PeerId {
    fn from(addr: IpAddr) -> Self {
        Self(addr)
    }
}

impl From<std::net::Ipv4Addr> for PeerId {
    fn from(addr: std::net::Ipv4Addr) -> Self {
        Self(IpAddr::V4(addr))
    }
}

impl From<std::net::Ipv6Addr> for PeerId {
    fn from(addr: std::net::Ipv6Addr) -> Self {
        Self(IpAddr::V6(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_peer_id_new_and_ip() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer = PeerId::new(addr);
        assert_eq!(peer.ip(), addr);
    }

    #[test]
    fn test_peer_id_ordering() {
        let a = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let b = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(a < b);
    }

    #[test]
    fn test_peer_id_display() {
        let peer = PeerId::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(peer.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_peer_id_from_ipv4() {
        let peer = PeerId::from(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_peer_id_from_ipv6() {
        use std::net::Ipv6Addr;
        let peer = PeerId::from(Ipv6Addr::LOCALHOST);
        assert_eq!(peer.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_peer_id_from_ipaddr() {
        let addr = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        let peer = PeerId::from(addr);
        assert_eq!(peer.ip(), addr);
    }
}
