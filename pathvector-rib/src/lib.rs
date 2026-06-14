#![doc = include_str!("../README.md")]

pub mod adj_rib_in;
pub mod adj_rib_out;
pub mod best_path;
pub mod loc_rib;
pub mod oracle;
pub mod outbound;

mod peer;
mod route;

#[cfg(test)]
mod prop_tests;

pub use adj_rib_in::AdjRibIn;
pub use adj_rib_out::{AdjRibOut, InsertOutcome};
pub use loc_rib::{LocRib, RibView};
pub use peer::PeerId;
pub use route::{Route, RouteBuilder};
