//! The Validated ROA Payload (RFC 6811 §2), valid by construction.
//!
//! A [`Vrp`] is the only thing a Prefix PDU decodes to and the only thing the
//! ROA table accepts, so a tuple the RPKI-to-Router protocol forbids has no
//! representation anywhere past the decoder's constructor call:
//!
//! * RFC 8210 §5.6 / §5.7: Prefix Length and Max Length are `0..32` for IPv4
//!   and `0..128` for IPv6 (RFC 6810 §5.6 / §5.7 for version 0);
//! * RFC 8210 §5.1 (and RFC 6810 §5.1): Max Length "MUST NOT be less than the
//!   Prefix Length element".
//!
//! # Address bits beyond the Prefix Length
//!
//! Neither RFC 6810 nor RFC 8210 constrains them (the Zero fields they require
//! receivers to ignore are the *marked* ones). RFC 6811 §2 defines a Prefix
//! as `(IP address, prefix length)` "interpreted as is customary" and covering
//! in terms of "all bits specified by the VRP prefix length", so those bits
//! carry no meaning. They are cleared here, which makes two spellings of one
//! prefix the same VRP — for withdrawal matching too.
//!
//! The 8210bis draft (version 2 of the protocol) would make non-zero trailing
//! bits a fatal error. It is not an RFC and this client does not speak version
//! 2, so that rule is deliberately not applied.

use ipnetx::{interfaces::IpAddress, prefix::IpPrefix};

use crate::error::VrpError;

/// One `(prefix, max length, origin AS)` authorisation for address family `A`.
///
/// Invariants: `prefix.mask() <= max_len <= A::BITS`, and the prefix address
/// has no bits set beyond `prefix.mask()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Vrp<A: IpAddress> {
    prefix: IpPrefix<A>,
    max_len: u8,
    asn: u32,
}

impl<A: IpAddress> Vrp<A> {
    /// # Errors
    ///
    /// [`VrpError`] naming the first bound the lengths break.
    pub(crate) fn new(address: A, prefix_len: u8, max_len: u8, asn: u32) -> Result<Self, VrpError> {
        let family_bits = A::BITS;
        let Ok(prefix) = IpPrefix::new(address, prefix_len) else {
            return Err(VrpError::PrefixLengthExceedsFamily {
                prefix_len,
                family_bits,
            });
        };
        if max_len > family_bits {
            return Err(VrpError::MaxLengthExceedsFamily {
                max_len,
                family_bits,
            });
        }
        if max_len < prefix_len {
            return Err(VrpError::MaxLengthBelowPrefixLength {
                prefix_len,
                max_len,
            });
        }
        Ok(Self {
            prefix: prefix.masked(),
            max_len,
            asn,
        })
    }

    pub(crate) fn prefix(&self) -> IpPrefix<A> {
        self.prefix
    }

    pub(crate) fn max_len(&self) -> u8 {
        self.max_len
    }

    pub(crate) fn asn(&self) -> u32 {
        self.asn
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use proptest::prelude::*;

    use super::*;

    /// The issue's list: IPv4 0/32/33 and IPv6 0/128/129, both orders.
    #[test]
    fn family_boundaries() {
        let v4 = Ipv4Addr::new(192, 0, 2, 0);
        let v6: Ipv6Addr = "2001:db8::".parse().unwrap();
        for (prefix_len, max_len) in [(0, 0), (0, 32), (32, 32)] {
            assert!(Vrp::new(v4, prefix_len, max_len, 1).is_ok());
        }
        for (prefix_len, max_len) in [(0, 0), (0, 128), (128, 128), (33, 33)] {
            assert!(Vrp::new(v6, prefix_len, max_len, 1).is_ok());
        }
        assert_eq!(
            Vrp::new(v4, 33, 33, 1),
            Err(VrpError::PrefixLengthExceedsFamily {
                prefix_len: 33,
                family_bits: 32
            })
        );
        assert_eq!(
            Vrp::new(v4, 0, 33, 1),
            Err(VrpError::MaxLengthExceedsFamily {
                max_len: 33,
                family_bits: 32
            })
        );
        assert_eq!(
            Vrp::new(v6, 129, 129, 1),
            Err(VrpError::PrefixLengthExceedsFamily {
                prefix_len: 129,
                family_bits: 128
            })
        );
        assert_eq!(
            Vrp::new(v6, 0, 129, 1),
            Err(VrpError::MaxLengthExceedsFamily {
                max_len: 129,
                family_bits: 128
            })
        );
        assert_eq!(
            Vrp::new(v4, 24, 16, 1),
            Err(VrpError::MaxLengthBelowPrefixLength {
                prefix_len: 24,
                max_len: 16
            })
        );
    }

    /// Every `(prefix_len, max_len)` octet pair, against the RFC's rule.
    fn accepts_exactly_the_rfc_range<A: IpAddress>(address: A, bits: u8) {
        for prefix_len in 0..=u8::MAX {
            for max_len in 0..=u8::MAX {
                let legal = prefix_len <= bits && max_len <= bits && prefix_len <= max_len;
                assert_eq!(
                    Vrp::new(address, prefix_len, max_len, 1).is_ok(),
                    legal,
                    "{prefix_len}/{max_len} in a {bits}-bit family"
                );
            }
        }
    }

    #[test]
    fn exhaustive_over_both_length_octets() {
        accepts_exactly_the_rfc_range(Ipv4Addr::BROADCAST, 32);
        accepts_exactly_the_rfc_range(Ipv6Addr::from(u128::MAX), 128);
    }

    proptest! {
        /// Bits beyond the Prefix Length are not part of the VRP.
        #[test]
        fn trailing_address_bits_do_not_distinguish_vrps(
            bits in any::<u32>(),
            noise in any::<u32>(),
            prefix_len in 0u8..=32,
        ) {
            let host_mask = u32::MAX.checked_shr(u32::from(prefix_len)).unwrap_or(0);
            let clean = Vrp::new(Ipv4Addr::from(bits & !host_mask), prefix_len, 32, 1).unwrap();
            let noisy = Vrp::new(
                Ipv4Addr::from((bits & !host_mask) | (noise & host_mask)),
                prefix_len,
                32,
                1,
            )
            .unwrap();
            prop_assert_eq!(clean, noisy);
            prop_assert_eq!(u32::from(noisy.prefix().ip()) & host_mask, 0);
        }
    }
}
