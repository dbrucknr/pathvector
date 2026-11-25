//! What may not be advertised, as pure values — the outbound counterpart of
//! `daemon/ingress.rs`.
//!
//! This module decides; it never touches a RIB or a socket. The outbound
//! pipeline applies the decision to the route it is about to advertise, after
//! the peer-specific transforms and export policy, so it judges exactly what
//! would go on the wire.
//!
//! Received routes that break these rules are already rejected on ingress, so
//! what reaches here comes from a non-wire source (policy rewrites, injection).

use pathvector_types::{Aggregator, AsPath, Asn};

/// Why a route must not be advertised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EgressBlock {
    /// RFC 7607 §2: "A BGP speaker MUST NOT originate or propagate a route
    /// with an AS number of zero in the AS_PATH, AS4_PATH, AGGREGATOR, or
    /// AS4_AGGREGATOR attributes." AS4_PATH is derived from AS_PATH, so
    /// checking the latter covers both.
    AsZero,
    /// RFC 9774 §3: "BGP speakers: MUST NOT advertise BGP UPDATE messages
    /// containing AS_SETs or AS_CONFED_SETs". No operator exception is
    /// offered.
    AsSet,
}

impl EgressBlock {
    /// Short reason for logs, with the clause it comes from.
    pub(crate) const fn describe(self) -> &'static str {
        match self {
            Self::AsZero => "AS_PATH contains reserved AS 0 (RFC 7607)",
            Self::AsSet => "AS_PATH contains AS_SET or AS_CONFED_SET (RFC 9774)",
        }
    }
}

/// Checks the AS_PATH about to be advertised.
pub(crate) fn check_as_path(as_path: &AsPath) -> Option<EgressBlock> {
    if as_path.contains(Asn::ZERO) {
        Some(EgressBlock::AsZero)
    } else if as_path.contains_as_set() {
        Some(EgressBlock::AsSet)
    } else {
        None
    }
}

/// The AGGREGATOR to advertise, if any.
///
/// One naming AS 0 is left off (and with it AS4_AGGREGATOR): RFC 7607 §2
/// forbids propagating it, and the attribute is informational — RFC 7606 §7.7
/// handles a malformed one by discarding the attribute, not the route.
pub(crate) fn advertisable_aggregator(aggregator: Option<Aggregator>) -> Option<Aggregator> {
    aggregator.filter(|agg| agg.asn != Asn::ZERO)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pathvector_types::AsPathSegment;

    use super::*;

    #[test]
    fn as_zero_in_any_segment_type_blocks() {
        let asns = vec![Asn::new(65001), Asn::ZERO];
        for segment in [
            AsPathSegment::Sequence(asns.clone()),
            AsPathSegment::Set(asns.clone()),
            AsPathSegment::ConfedSequence(asns.clone()),
            AsPathSegment::ConfedSet(asns.clone()),
        ] {
            let path = AsPath::from_segments(vec![segment]);
            assert_eq!(check_as_path(&path), Some(EgressBlock::AsZero), "{path}");
        }
        assert_eq!(check_as_path(&AsPath::new()), None);
        assert_eq!(
            check_as_path(&AsPath::from_sequence(vec![Asn::new(65001)])),
            None
        );
    }

    #[test]
    fn either_set_type_blocks_and_sequences_do_not() {
        let asns = vec![Asn::new(65001)];
        for (segment, want) in [
            (AsPathSegment::Set(asns.clone()), Some(EgressBlock::AsSet)),
            (
                AsPathSegment::ConfedSet(asns.clone()),
                Some(EgressBlock::AsSet),
            ),
            (AsPathSegment::Sequence(asns.clone()), None),
            (AsPathSegment::ConfedSequence(asns.clone()), None),
        ] {
            let path = AsPath::from_segments(vec![segment]);
            assert_eq!(check_as_path(&path), want, "{path}");
        }
    }

    #[test]
    fn only_an_as_zero_aggregator_is_left_off() {
        let agg = |asn| Aggregator {
            asn,
            ip: Ipv4Addr::new(10, 0, 0, 9),
        };
        assert_eq!(advertisable_aggregator(Some(agg(Asn::ZERO))), None);
        assert_eq!(
            advertisable_aggregator(Some(agg(Asn::new(1)))),
            Some(agg(Asn::new(1)))
        );
        assert_eq!(advertisable_aggregator(None), None);
    }
}
