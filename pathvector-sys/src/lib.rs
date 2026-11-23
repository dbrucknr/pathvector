//! Safe wrappers over OS-level socket APIs required by pathvector.
//!
//! All unsafe code in the pathvector workspace lives here. Every other crate
//! maintains `unsafe_code = "forbid"` and calls this crate's safe public
//! functions instead.
//!
//! # Current surface
//!
//! - [`tcp`] — install and remove TCP MD5 signature keys (RFC 2385) with
//!   [`install_tcp_md5_key`] / [`remove_tcp_md5_key`]. A key that cannot be
//!   enforced is reported as [`TcpMd5Error::Unsupported`], never as success.
//! - [`fib`] — kernel FIB integration via Linux netlink (`RTM_NEWROUTE` / `RTM_DELROUTE`)

pub mod fib;
pub mod tcp;

pub use fib::{FibSnapshot, FibWrite, FibWriter, KernelFib, KernelOracle, RT_TABLE_MAIN};
pub use tcp::{
    KernelTcpMd5, TCP_MD5SIG_MAXKEYLEN, TcpMd5Error, TcpMd5Key, TcpMd5KeyError, TcpMd5Port,
    TcpMd5Unsupported, install_tcp_md5_key, remove_tcp_md5_key,
};
