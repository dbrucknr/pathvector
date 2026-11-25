//! [`CanonicalNlri`]: the only form in which a RIB stores or indexes a prefix.
//!
//! An [`Nlri`] keeps whatever address bits its constructor was given, so
//! `10.1.2.3/8` and `10.0.0.0/8` are unequal and hash differently. On the wire
//! they are the same destination: RFC 4271 §4.3 says of the bits that pad a
//! Withdrawn Routes or NLRI prefix to an octet boundary that "the value of
//! [the] trailing bits is irrelevant", and RFC 4760 §5 repeats it for the
//! multiprotocol attributes. A table keyed on the raw value therefore holds
//! one destination several times, and disagrees with the best-path prefix
//! tree, which has always ignored those bits (issue #71).
//!
//! Every RIB converts the caller's NLRI into this type on entry, and its maps
//! are declared in terms of it, so a non-canonical key cannot be stored. The
//! field is private to this module: [`CanonicalNlri::new`] is the one way in.

use ipnetx::{interfaces::IpAddress, prefix::IpPrefix};
use pathvector_types::Nlri;

/// An [`Nlri`] whose bits beyond the prefix length are all zero.
///
/// Deliberately does **not** implement `Borrow<Nlri<A>>` or `Deref`: either
/// would let a map keyed on this type be probed with a raw `Nlri`, which is the
/// mistake the type exists to rule out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CanonicalNlri<A: IpAddress>(Nlri<A>);

impl<A: IpAddress> CanonicalNlri<A> {
    /// Canonicalizes `nlri` by zeroing the bits beyond its prefix length.
    ///
    /// Infallible and idempotent: every `Nlri` names exactly one destination.
    #[inline]
    pub(crate) fn new(nlri: Nlri<A>) -> Self {
        Self(nlri.masked())
    }

    /// The canonical NLRI, for handing back to callers and storing in routes.
    #[inline]
    pub(crate) fn nlri(self) -> Nlri<A> {
        self.0
    }

    /// Borrowed form of [`nlri`](Self::nlri), for iterators that yield
    /// references into a table.
    #[inline]
    pub(crate) fn as_nlri(&self) -> &Nlri<A> {
        &self.0
    }

    /// The canonical prefix, for the best-path prefix tree.
    #[inline]
    pub(crate) fn prefix(self) -> IpPrefix<A> {
        self.0.prefix()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use proptest::prelude::*;

    use super::*;

    /// `bits` with everything beyond the first `len` of `width` bits cleared,
    /// computed one bit at a time so it shares nothing with `Nlri::masked`.
    fn network(bits: u128, len: u8, width: u32) -> u128 {
        (0..u32::from(len)).fold(0, |acc, i| acc | (bits & (1u128 << (width - 1 - i))))
    }

    /// Every IPv4 length, including the /0 and /32 shift edges.
    #[test]
    fn masks_every_ipv4_length() {
        for len in 0..=32u8 {
            let raw = Nlri::new(Ipv4Addr::from(u32::MAX), len).unwrap();
            let key = CanonicalNlri::new(raw);
            let want = network(u128::from(u32::MAX), len, 32);
            assert_eq!(u128::from(u32::from(key.nlri().prefix().ip())), want);
            assert_eq!(key.nlri().prefix_len(), len);
        }
    }

    /// Every IPv6 length, including /0, where the mask shift is the full
    /// width of a `u128`.
    #[test]
    fn masks_every_ipv6_length() {
        for len in 0..=128u8 {
            let raw = Nlri::new(Ipv6Addr::from(u128::MAX), len).unwrap();
            let key = CanonicalNlri::new(raw);
            let want = network(u128::MAX, len, 128);
            assert_eq!(u128::from(key.nlri().prefix().ip()), want);
            assert_eq!(key.nlri().prefix_len(), len);
        }
    }

    proptest! {
        /// Two NLRIs get the same key exactly when they name the same
        /// destination, and canonicalizing twice changes nothing.
        #[test]
        fn key_equality_is_destination_equality_v4(
            a in any::<u32>(), a_len in 0u8..=32,
            b in any::<u32>(), b_len in 0u8..=32,
        ) {
            let key = |bits: u32, len| {
                CanonicalNlri::new(Nlri::new(Ipv4Addr::from(bits), len).unwrap())
            };
            let same_destination = a_len == b_len
                && network(a.into(), a_len, 32) == network(b.into(), b_len, 32);
            prop_assert_eq!(key(a, a_len) == key(b, b_len), same_destination);
            // Force the interesting half: `b`'s host bits on `a`'s network.
            let host = u32::MAX ^ u32::try_from(network(u32::MAX.into(), a_len, 32)).unwrap();
            prop_assert_eq!(key(a ^ (b & host), a_len), key(a, a_len));
            prop_assert_eq!(CanonicalNlri::new(key(a, a_len).nlri()), key(a, a_len));
        }

        #[test]
        fn key_equality_is_destination_equality_v6(
            a in any::<u128>(), noise in any::<u128>(), len in 0u8..=128,
        ) {
            let key = |bits: u128| {
                CanonicalNlri::new(Nlri::new(Ipv6Addr::from(bits), len).unwrap())
            };
            let host = u128::MAX ^ network(u128::MAX, len, 128);
            prop_assert_eq!(key(a ^ (noise & host)), key(a));
            prop_assert_eq!(key(a).nlri().prefix().ip(), Ipv6Addr::from(network(a, len, 128)));
        }
    }
}
