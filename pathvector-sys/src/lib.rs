//! Safe wrappers over OS-level socket APIs required by pathvector.
//!
//! All unsafe code in the pathvector workspace lives here. Every other crate
//! maintains `unsafe_code = "forbid"` and calls this crate's safe public
//! functions instead.
//!
//! # Current surface
//!
//! - [`apply_tcp_md5sig`] — set `TCP_MD5SIG` socket option (RFC 2385, Linux only)

pub mod tcp;

pub use tcp::apply_tcp_md5sig;
