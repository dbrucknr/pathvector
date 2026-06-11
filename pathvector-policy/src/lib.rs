#![doc = include_str!("../README.md")]

mod outcome;
mod route;

pub mod action;
pub mod condition;
pub mod term;

#[cfg(test)]
mod prop_tests;
/// Minimal test double — public so doctests can use it; not part of the stable API.
#[doc(hidden)]
pub mod testutil;

// ── Re-exports ─────────────────────────────────────────────────────────────

pub use outcome::{Decision, DefaultAction};
pub use route::BgpRoute;

// Conditions
pub use condition::{
    AnyCondition, AsPathContainsCondition, AsPathLengthCondition, CommunityCondition, CompareOp,
    Condition, LargeCommunityCondition, LocalPrefCondition, MedCondition, Not, OriginCondition,
    PrefixListCondition,
};

// Actions
pub use action::{
    Accept, Action, ActionSequence, AddCommunity, AddLargeCommunity, Next, PrependAsPath, Reject,
    RemoveCommunity, RemoveLargeCommunity, SetCommunities, SetLocalPref, SetMed, SetNextHop,
    SetOrigin,
};

// Term and Policy
pub use term::{Policy, PolicyBuilder, Term};
