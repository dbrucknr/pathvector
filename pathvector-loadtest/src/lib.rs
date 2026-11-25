//! `pathvector-loadtest` — multi-peer full-table load harness for
//! `pathvectord`, built to produce the evidence `PRODUCTION_READINESS.md`
//! PR-1 asks for: does one peer's heavy work stall everyone else's
//! KEEPALIVEs and the management plane?
//!
//! Pure, unit-tested logic lives here; `main.rs` is the thin orchestrator.

// Mutex `unwrap()`s in this crate can only fail if another thread already
// panicked while holding the lock; in a test harness that is a crash to
// surface, not an error to document on every accessor.
#![allow(clippy::missing_panics_doc)]
// Scenario and helper errors are human-readable strings shown straight to the
// operator; there is no error taxonomy worth a `# Errors` section on each.
#![allow(clippy::missing_errors_doc)]

pub mod config;
pub mod daemon;
pub mod gaps;
pub mod peer;
pub mod promtext;
pub mod report;
pub mod scenarios;
