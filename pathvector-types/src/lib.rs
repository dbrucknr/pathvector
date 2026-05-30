#![doc = include_str!("../README.md")]

mod afi;
mod asn;
mod aspath;
mod community;
mod nlri;

pub use afi::{Afi, AfiSafi, Safi};
pub use asn::Asn;
pub use aspath::{AsPath, AsPathSegment};
pub use community::{Community, ExtendedCommunity, LargeCommunity};
pub use nlri::{InvalidPrefixLen, Nlri, ParsePrefixError};

pub use ipnetx::interfaces::IpAddress;
pub use ipnetx::prefix::IpPrefix;
