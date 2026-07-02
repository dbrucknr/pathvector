/// An eBGP session's role in a customer/provider/peer relationship
/// (RFC 9234 §4).
///
/// Roles are declared per-session (not per-AS — the same AS can be a
/// Provider on one session and a Customer on another) and negotiated via the
/// BGP Role capability. RFC 9234's route-leak-prevention mechanism (the
/// `ONLY_TO_CUSTOMER` attribute) is driven entirely by each side's configured
/// role, not by any traffic inspection.
///
/// # Examples
///
/// ```
/// use pathvector_types::Role;
///
/// assert!(Role::Provider.is_compatible_with(Role::Customer));
/// assert!(!Role::Provider.is_compatible_with(Role::Peer));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// We provide transit to the peer.
    Provider = 0,
    /// We operate a route server (typically at an IXP).
    RouteServer = 1,
    /// The peer is a route server client of ours.
    RsClient = 2,
    /// The peer provides transit to us.
    Customer = 3,
    /// Lateral peering — neither side provides transit to the other.
    Peer = 4,
}

impl Role {
    /// The BGP Role capability's single value byte (RFC 9234 §4).
    #[must_use]
    pub fn as_wire_value(self) -> u8 {
        self as u8
    }

    /// Parses a BGP Role capability value byte. Values 5-255 are reserved/
    /// unassigned and return `None` — callers should treat an unrecognized
    /// role the same as a capability that wasn't sent at all (RFC 9234
    /// defines no behavior for future role values, and guessing at one
    /// would be worse than ignoring it).
    #[must_use]
    pub fn from_wire_value(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Provider),
            1 => Some(Self::RouteServer),
            2 => Some(Self::RsClient),
            3 => Some(Self::Customer),
            4 => Some(Self::Peer),
            _ => None,
        }
    }

    /// RFC 9234 §4.2 role-pair correctness: is `self` (our configured role
    /// on this session) compatible with `peer` (the peer's configured
    /// role)? Only complementary pairs are valid — Provider↔Customer,
    /// `RouteServer`↔`RsClient`, Peer↔Peer. Every other combination
    /// (including e.g. two Providers, or a Provider and a `RouteServer`)
    /// indicates at least one side is misconfigured.
    #[must_use]
    pub fn is_compatible_with(self, peer: Self) -> bool {
        matches!(
            (self, peer),
            (Self::Provider, Self::Customer)
                | (Self::Customer, Self::Provider)
                | (Self::RouteServer, Self::RsClient)
                | (Self::RsClient, Self::RouteServer)
                | (Self::Peer, Self::Peer)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_value_round_trips_for_all_defined_roles() {
        for role in [
            Role::Provider,
            Role::RouteServer,
            Role::RsClient,
            Role::Customer,
            Role::Peer,
        ] {
            assert_eq!(Role::from_wire_value(role.as_wire_value()), Some(role));
        }
    }

    #[test]
    fn unassigned_wire_values_are_none() {
        for v in 5..=255u8 {
            assert_eq!(
                Role::from_wire_value(v),
                None,
                "value {v} should be unassigned"
            );
        }
    }

    #[test]
    fn compatible_pairs_are_symmetric_and_correct() {
        assert!(Role::Provider.is_compatible_with(Role::Customer));
        assert!(Role::Customer.is_compatible_with(Role::Provider));
        assert!(Role::RouteServer.is_compatible_with(Role::RsClient));
        assert!(Role::RsClient.is_compatible_with(Role::RouteServer));
        assert!(Role::Peer.is_compatible_with(Role::Peer));
    }

    #[test]
    fn incompatible_pairs_are_rejected() {
        let roles = [
            Role::Provider,
            Role::RouteServer,
            Role::RsClient,
            Role::Customer,
            Role::Peer,
        ];
        let compatible = [
            (Role::Provider, Role::Customer),
            (Role::Customer, Role::Provider),
            (Role::RouteServer, Role::RsClient),
            (Role::RsClient, Role::RouteServer),
            (Role::Peer, Role::Peer),
        ];
        for &a in &roles {
            for &b in &roles {
                let expected = compatible.contains(&(a, b));
                assert_eq!(
                    a.is_compatible_with(b),
                    expected,
                    "{a:?} vs {b:?} compatibility"
                );
            }
        }
    }
}
