#![doc = include_str!("../README.md")]

mod afi;
mod asn;
mod aspath;
mod attr;
mod community;
mod nlri;
mod peer_type;
mod role;

pub use afi::{Afi, AfiSafi, Safi};
pub use asn::Asn;
pub use aspath::{AsPath, AsPathSegment};
pub use attr::{Aggregator, AtomicAggregate, LocalPref, Med, NextHop, Origin};
pub use community::{Community, ExtendedCommunity, LargeCommunity};
pub use nlri::{InvalidPrefixLen, Nlri, ParsePrefixError};
pub use peer_type::PeerType;
pub use role::Role;

pub use ipnetx::interfaces::IpAddress;
pub use ipnetx::prefix::IpPrefix;

#[cfg(test)]
mod prop_tests;
