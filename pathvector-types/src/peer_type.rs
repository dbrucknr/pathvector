/// Source of a BGP route: iBGP peer, eBGP peer, confederation-member peer,
/// or locally originated.
///
/// The discriminant values do **not**, by themselves, encode the RFC 4271
/// §9.1 best-path preference order — `Internal` and `ConfedMember` must
/// *tie* in preference (RFC 5065 §5.3: a confederation-member peer's routes
/// "MUST follow the same rules used for information received from members
/// inside the same autonomous system"), which a linear discriminant cannot
/// express. Best-path code must compare via an explicit rank function
/// (see `pathvector-rib`'s `best_path.rs`), not this enum's derived `Ord`.
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
    /// A fellow BGP confederation Member-AS (RFC 5065) — eBGP at the wire
    /// level, but treated like `Internal` for best-path preference,
    /// `LOCAL_PREF`, and split-horizon purposes.
    ConfedMember = 3,
}

impl std::fmt::Display for PeerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal => write!(f, "ibgp"),
            Self::External => write!(f, "ebgp"),
            Self::Local => write!(f, "local"),
            Self::ConfedMember => write!(f, "confed-member"),
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
        assert_eq!(PeerType::ConfedMember.to_string(), "confed-member");
    }

    #[test]
    fn test_peer_type_equality() {
        assert_eq!(PeerType::Internal, PeerType::Internal);
        assert_eq!(PeerType::External, PeerType::External);
        assert_eq!(PeerType::Local, PeerType::Local);
        assert_eq!(PeerType::ConfedMember, PeerType::ConfedMember);
        assert_ne!(PeerType::Internal, PeerType::External);
        assert_ne!(PeerType::External, PeerType::Local);
        assert_ne!(PeerType::Internal, PeerType::ConfedMember);
    }
}
