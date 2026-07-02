//! Connects to a local RTR server and validates one prefix.
//!
//! This is the exact code shown in the crate README's "Quick start" section —
//! see `pathvector-rpki/README.md` for the full walkthrough, including how to
//! run a real RPKI validator (Routinator) locally in Docker so this example
//! has real data to check against.
//!
//! Run with:
//!
//! ```text
//! cargo run -p pathvector-rpki --example validate_prefix
//! ```
//!
//! Requires an RTR server listening on `127.0.0.1:3323` (Routinator's default
//! `--rtr` port). Without one, this will print `NotFound` for every query —
//! the client never blocks on connection failure, it just has no data yet.

use std::net::Ipv4Addr;

use pathvector_rpki::{RoaValidity, RtrClient, RtrConfig};

#[tokio::main]
async fn main() {
    // spawn() returns immediately; the actual TCP session and sync run in a
    // background task, so this never blocks program startup even if the
    // validator is slow to respond or unreachable.
    let (rpki, _join) = RtrClient::spawn(RtrConfig {
        host: "127.0.0.1".to_string(),
        port: 3323,
        ..Default::default()
    });

    // Give the background task a moment to connect and complete its first
    // sync. Real code should poll `rpki.status().connected` instead of
    // sleeping a fixed amount — see pathvectord's daemon wiring
    // (`pathvectord/src/daemon/mod.rs`) for that pattern.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let status = rpki.status();
    println!(
        "RTR status: connected={} roa_count={}",
        status.connected, status.roa_count
    );

    // 1.0.0.0/24, originated by AS13335 (Cloudflare), is a real, stable ROA
    // you can check against at any time — part of the range behind
    // Cloudflare's 1.1.1.1 public DNS resolver.
    let prefix: Ipv4Addr = "1.0.0.0".parse().unwrap();
    match rpki.validate_v4(prefix, 24, 13335) {
        RoaValidity::Valid => println!("1.0.0.0/24 origin AS13335: VALID"),
        RoaValidity::Invalid => println!("1.0.0.0/24 origin AS13335: INVALID"),
        RoaValidity::NotFound => println!("1.0.0.0/24 origin AS13335: NOTFOUND"),
    }

    // Same prefix, wrong origin AS — should be Invalid (a real ROA covers
    // this prefix, but it doesn't authorize AS 99999).
    match rpki.validate_v4(prefix, 24, 99_999) {
        RoaValidity::Valid => println!("1.0.0.0/24 origin AS99999: VALID"),
        RoaValidity::Invalid => println!("1.0.0.0/24 origin AS99999: INVALID"),
        RoaValidity::NotFound => println!("1.0.0.0/24 origin AS99999: NOTFOUND"),
    }

    // RFC 5737 TEST-NET-1 — deliberately unallocated documentation space, no
    // ROA exists — should be NotFound.
    let test_net: Ipv4Addr = "192.0.2.0".parse().unwrap();
    match rpki.validate_v4(test_net, 24, 65001) {
        RoaValidity::Valid => println!("192.0.2.0/24 origin AS65001: VALID"),
        RoaValidity::Invalid => println!("192.0.2.0/24 origin AS65001: INVALID"),
        RoaValidity::NotFound => println!("192.0.2.0/24 origin AS65001: NOTFOUND"),
    }
}
