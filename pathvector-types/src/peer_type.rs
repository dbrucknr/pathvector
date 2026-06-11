/// Source of a BGP route: iBGP peer, eBGP peer, or locally originated.
///
/// The discriminant values encode the RFC 4271 §9.1 best-path preference
/// order. Steps 3 and 7 are combined: locally originated routes (step 3)
/// beat eBGP (step 7) which beats iBGP.
///
/// # Examples
///
/// ```
/// use pathvector_types::PeerType;
///
/// assert!(PeerType::Local > PeerType::External);
/// assert!(PeerType::External > PeerType::Internal);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PeerType {
    /// iBGP — the peer is in the same autonomous system.
    Internal = 0,
    /// eBGP — the peer is in a different autonomous system.
    External = 1,
    /// Locally originated — injected via the origination API, not learned
    /// from any peer. Wins best-path selection at RFC 4271 §9.1 step 3.
    Local = 2,
}

impl std::fmt::Display for PeerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal => write!(f, "ibgp"),
            Self::External => write!(f, "ebgp"),
            Self::Local => write!(f, "local"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_type_ordering() {
        // Step 3: local > eBGP; Step 7: eBGP > iBGP.
        assert!(PeerType::Local > PeerType::External);
        assert!(PeerType::External > PeerType::Internal);
    }

    #[test]
    fn test_peer_type_display() {
        assert_eq!(PeerType::Internal.to_string(), "ibgp");
        assert_eq!(PeerType::External.to_string(), "ebgp");
        assert_eq!(PeerType::Local.to_string(), "local");
    }

    #[test]
    fn test_peer_type_equality() {
        assert_eq!(PeerType::Internal, PeerType::Internal);
        assert_eq!(PeerType::External, PeerType::External);
        assert_eq!(PeerType::Local, PeerType::Local);
        assert_ne!(PeerType::Internal, PeerType::External);
        assert_ne!(PeerType::External, PeerType::Local);
    }
}
