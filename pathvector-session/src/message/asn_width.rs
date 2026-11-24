//! The width of AS numbers on the wire for one BGP session (RFC 6793).

use super::open::Capability;

/// How many octets each AS number occupies in `AS_PATH` and `AGGREGATOR`
/// on a given session — the single decision RFC 6793 §4 makes per peer.
///
/// RFC 6793 §4.1: "A BGP speaker that advertises such a capability to a
/// particular peer, and receives from that peer the advertisement of such a
/// capability, MUST encode AS numbers as four-octet entities in both the
/// `AS_PATH` attribute and the `AGGREGATOR` attribute in the updates it sends to
/// the peer and MUST assume that these attributes in the updates received
/// from the peer encode AS numbers as four-octet entities." Without that
/// bilateral negotiation the peer is an "OLD BGP speaker" (§4.2) and both
/// attributes use two-octet AS numbers in both directions.
///
/// The value is derived from the two OPEN messages in exactly one place —
/// [`AsnWidth::negotiate`] — and then handed to the codec, so the codec never
/// has to guess from a bare `bool` and callers cannot confuse the width with
/// another flag.
///
/// `AS4_PATH`, `AS4_AGGREGATOR`, `ONLY_TO_CUSTOMER` and every other
/// four-octet field are unaffected: they are four octets on every session.
///
/// # Examples
///
/// ```
/// use pathvector_session::message::{AsnWidth, Capability};
///
/// let both = [Capability::FourByteAsn(131_072)];
/// assert_eq!(AsnWidth::negotiate(&both, &both), AsnWidth::Four);
///
/// // One side lacks the capability: an OLD speaker, two-octet ASNs.
/// assert_eq!(AsnWidth::negotiate(&both, &[]), AsnWidth::Two);
/// assert_eq!(AsnWidth::Two.octets(), 2);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AsnWidth {
    /// Two-octet AS numbers (RFC 4271): the peer is an OLD BGP speaker.
    /// Non-mappable ASNs travel as `AS_TRANS` plus `AS4_PATH` /
    /// `AS4_AGGREGATOR` (RFC 6793 §4.2.2).
    Two,
    /// Four-octet AS numbers (RFC 6793 §4.1): both sides advertised the
    /// four-octet AS capability. This is also the value assumed before
    /// negotiation completes, matching what this implementation advertises.
    #[default]
    Four,
}

impl AsnWidth {
    /// Derives the session's ASN width from the capabilities this speaker
    /// advertised (`local`) and those the peer advertised (`peer`).
    ///
    /// [`Self::Four`] only if *both* lists contain
    /// [`Capability::FourByteAsn`] — advertised to and received from the
    /// peer (RFC 6793 §4.1; the same condition RFC 7606 §7.7 uses for
    /// `AGGREGATOR`). The AS number inside the capability is irrelevant to
    /// the width; duplicates of the capability are equivalent to one.
    #[must_use]
    pub fn negotiate(local: &[Capability], peer: &[Capability]) -> Self {
        let has =
            |caps: &[Capability]| caps.iter().any(|c| matches!(c, Capability::FourByteAsn(_)));
        if has(local) && has(peer) {
            Self::Four
        } else {
            Self::Two
        }
    }

    /// Octets occupied by one AS number in `AS_PATH` / `AGGREGATOR`.
    #[must_use]
    pub const fn octets(self) -> usize {
        match self {
            Self::Two => 2,
            Self::Four => 4,
        }
    }

    /// `true` for [`Self::Four`].
    #[must_use]
    pub const fn is_four(self) -> bool {
        matches!(self, Self::Four)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_octets_only_when_both_sides_advertise_the_capability() {
        let cap = [Capability::FourByteAsn(65001)];
        let other = [Capability::RouteRefresh];
        assert_eq!(AsnWidth::negotiate(&cap, &cap), AsnWidth::Four);
        // RFC 6793 §4.1: "advertises ... and receives" — both directions.
        assert_eq!(AsnWidth::negotiate(&cap, &other), AsnWidth::Two);
        assert_eq!(AsnWidth::negotiate(&other, &cap), AsnWidth::Two);
        assert_eq!(AsnWidth::negotiate(&[], &[]), AsnWidth::Two);
    }

    #[test]
    fn capability_value_and_duplicates_do_not_affect_width() {
        let local = [Capability::FourByteAsn(1), Capability::FourByteAsn(2)];
        let peer = [
            Capability::RouteRefresh,
            Capability::FourByteAsn(4_200_000_000),
        ];
        assert_eq!(AsnWidth::negotiate(&local, &peer), AsnWidth::Four);
    }

    #[test]
    fn default_is_four_and_octets_match() {
        assert_eq!(AsnWidth::default(), AsnWidth::Four);
        assert_eq!(AsnWidth::Two.octets(), 2);
        assert_eq!(AsnWidth::Four.octets(), 4);
        assert!(AsnWidth::Four.is_four());
        assert!(!AsnWidth::Two.is_four());
    }
}
