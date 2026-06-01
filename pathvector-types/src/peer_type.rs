/// Whether a BGP session is internal (iBGP) or external (eBGP).
///
/// Determined at session establishment by comparing the local AS number
/// against the peer's AS number resolved from the OPEN message. If they
/// match the session is `Internal`; otherwise it is `External`.
///
/// The ordering (`Internal < External`) reflects best-path preference:
/// RFC 4271 §9.1 step 7 prefers eBGP-learned routes over iBGP-learned
/// routes when all higher-priority criteria tie.
///
/// # Examples
///
/// ```
/// use pathvector_types::PeerType;
///
/// assert!(PeerType::External > PeerType::Internal);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PeerType {
    /// iBGP — the peer is in the same autonomous system.
    Internal = 0,
    /// eBGP — the peer is in a different autonomous system.
    External = 1,
}

impl std::fmt::Display for PeerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal => write!(f, "ibgp"),
            Self::External => write!(f, "ebgp"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_type_ordering() {
        // External is preferred (higher) in best-path step 7.
        assert!(PeerType::External > PeerType::Internal);
    }

    #[test]
    fn test_peer_type_display() {
        assert_eq!(PeerType::Internal.to_string(), "ibgp");
        assert_eq!(PeerType::External.to_string(), "ebgp");
    }

    #[test]
    fn test_peer_type_equality() {
        assert_eq!(PeerType::Internal, PeerType::Internal);
        assert_eq!(PeerType::External, PeerType::External);
        assert_ne!(PeerType::Internal, PeerType::External);
    }
}
