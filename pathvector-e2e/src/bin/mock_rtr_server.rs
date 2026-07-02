//! A minimal, deterministic RTR (RPKI-to-Router Protocol, RFC 8210 v1) server
//! for the `pathvector-e2e` RPKI test.
//!
//! Serves a fixed, hardcoded pair of ROAs on every connection, then holds the
//! connection open (never sends a `SerialNotify` — the default 3600s refresh
//! interval is never reached during a short-lived e2e test run):
//!
//! - `203.0.113.0/24` (TEST-NET-3), max-len 24, origin AS **65099** —
//!   authorizes a *different* AS than the e2e test's GoBGP peer announces
//!   from, making that announcement `Invalid`.
//! - `198.51.100.0/24` (TEST-NET-2), max-len 24, origin AS **65001** —
//!   matches the e2e harness's GoBGP peer AS, making that announcement
//!   `Valid`.
//!
//! The RTR wire format is hand-encoded here, independent of
//! `pathvector-rpki`'s own (crate-private) encoder — an independently
//! written encoder is a stronger proof that `pathvector-rpki`'s decoder is
//! actually RFC 8210-conformant than one that could share a latent bug with
//! the code under test.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const VERSION_1: u8 = 1;

const PDU_TYPE_CACHE_RESPONSE: u8 = 3;
const PDU_TYPE_IPV4_PREFIX: u8 = 4;
const PDU_TYPE_END_OF_DATA: u8 = 7;

const HEADER_LEN: u32 = 8;
const SESSION_ID: u16 = 1;

/// Builds one PDU: 8-byte header (version, type, field, total length) plus
/// `payload`.
fn build_pdu(pdu_type: u8, field: u16, payload: &[u8]) -> Vec<u8> {
    let payload_len = u32::try_from(payload.len()).expect("mock server payloads are always small");
    let total_len = HEADER_LEN + payload_len;
    let mut buf = Vec::with_capacity(total_len as usize);
    buf.push(VERSION_1);
    buf.push(pdu_type);
    buf.extend_from_slice(&field.to_be_bytes());
    buf.extend_from_slice(&total_len.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Builds an IPv4 Prefix PDU payload (RFC 8210 §5.6): flags, prefix length,
/// max length, one reserved zero byte, 4-byte prefix, 4-byte origin ASN.
fn ipv4_prefix_pdu(prefix: [u8; 4], prefix_len: u8, max_len: u8, asn: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(12);
    payload.push(0x01); // flags: announce
    payload.push(prefix_len);
    payload.push(max_len);
    payload.push(0); // reserved
    payload.extend_from_slice(&prefix);
    payload.extend_from_slice(&asn.to_be_bytes());
    build_pdu(PDU_TYPE_IPV4_PREFIX, 0, &payload)
}

/// Builds an End Of Data PDU payload (RFC 8210 §5.9, v1): serial, refresh,
/// retry, expire intervals.
fn end_of_data_pdu(serial: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(16);
    payload.extend_from_slice(&serial.to_be_bytes());
    payload.extend_from_slice(&3600u32.to_be_bytes()); // refresh
    payload.extend_from_slice(&600u32.to_be_bytes()); // retry
    payload.extend_from_slice(&7200u32.to_be_bytes()); // expire
    build_pdu(PDU_TYPE_END_OF_DATA, SESSION_ID, &payload)
}

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("0.0.0.0:3323")
        .await
        .expect("bind 0.0.0.0:3323");
    eprintln!("mock_rtr_server: listening on 0.0.0.0:3323");

    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("mock_rtr_server: accept failed: {e}");
                continue;
            }
        };
        eprintln!("mock_rtr_server: connection from {peer}");

        tokio::spawn(async move {
            // The client's first message is always a Reset Query (8-byte
            // header, no payload) — this server never persists state across
            // connections, so it never sends a Serial Query. Read and
            // discard the header; the response is fixed regardless.
            let mut header = [0u8; 8];
            if stream.read_exact(&mut header).await.is_err() {
                return;
            }

            let cache_response = build_pdu(PDU_TYPE_CACHE_RESPONSE, SESSION_ID, &[]);
            let roa_invalid_asn = ipv4_prefix_pdu([203, 0, 113, 0], 24, 24, 65099);
            let roa_valid_asn = ipv4_prefix_pdu([198, 51, 100, 0], 24, 24, 65001);
            let end_of_data = end_of_data_pdu(1);

            for pdu in [cache_response, roa_invalid_asn, roa_valid_asn, end_of_data] {
                if stream.write_all(&pdu).await.is_err() {
                    return;
                }
            }

            // Hold the connection open indefinitely — a real RTR client
            // stays connected between syncs. This e2e test never runs long
            // enough to reach the 3600s default refresh interval.
            let mut sink = [0u8; 64];
            loop {
                match stream.read(&mut sink).await {
                    Ok(0) | Err(_) => return, // client disconnected
                    Ok(_) => {}               // ignore anything further sent
                }
            }
        });
    }
}
