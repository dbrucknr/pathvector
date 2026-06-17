//! Minimal MRT `TABLE_DUMP_V2` parser for `RIB_IPV4_UNICAST` entries.
//!
//! Spec: RFC 6396.  Only the record types needed for IPv4 unicast replay
//! are implemented; all others are silently skipped.
//!
//! Returns a `Vec<RibEntry>` — one per unique prefix in the dump.
//! When a prefix has multiple RIB entries (one per originating peer), only the
//! first is kept; the goal is prefix diversity, not per-peer attribute fidelity.

use std::{
    io::{self, Read},
    net::Ipv4Addr,
};

// ── MRT header constants (RFC 6396 §2) ────────────────────────────────────────

const MRT_TYPE_TABLE_DUMP_V2: u16 = 13;
const SUBTYPE_RIB_IPV4_UNICAST: u16 = 2;

// MRT header is always 12 bytes: timestamp(4) + type(2) + subtype(2) + length(4)
const MRT_HEADER_LEN: usize = 12;

// ── Public types ──────────────────────────────────────────────────────────────

/// One IPv4 unicast prefix extracted from a `TABLE_DUMP_V2` MRT file.
///
/// `attrs` contains the raw BGP path attribute bytes from the first peer entry
/// for this prefix.  They are in standard BGP UPDATE attribute wire format and
/// can be embedded directly in a BGP UPDATE message body.
#[derive(Debug, Clone)]
pub struct RibEntry {
    pub prefix: Ipv4Addr,
    pub prefix_len: u8,
    /// Raw BGP path attribute bytes (wire format, ready for UPDATE).
    pub attrs: Vec<u8>,
}

/// Parse an MRT `TABLE_DUMP_V2` dump from `reader`, yielding all IPv4 unicast
/// RIB entries.  The reader may wrap a [`flate2::read::GzDecoder`] for `.gz`
/// files.
pub fn parse<R: Read>(mut reader: R) -> io::Result<Vec<RibEntry>> {
    let mut entries: Vec<RibEntry> = Vec::new();
    let mut header = [0u8; MRT_HEADER_LEN];

    loop {
        // Read the 12-byte MRT record header.
        match reader.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }

        // timestamp (4) | type (2) | subtype (2) | length (4)
        let mrt_type = u16::from_be_bytes([header[4], header[5]]);
        let subtype = u16::from_be_bytes([header[6], header[7]]);
        let body_len = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;

        let mut body = vec![0u8; body_len];
        reader.read_exact(&mut body)?;

        // Skip non-TABLE_DUMP_V2 records and all subtypes other than RIB_IPV4_UNICAST.
        // PEER_INDEX_TABLE, RIB_IPV4_MULTICAST, RIB_IPV6_*, and RIB_GENERIC are not
        // needed for IPv4 unicast replay.
        if mrt_type == MRT_TYPE_TABLE_DUMP_V2
            && subtype == SUBTYPE_RIB_IPV4_UNICAST
            && let Some(entry) = parse_rib_ipv4(&body)
        {
            entries.push(entry);
        }
    }

    Ok(entries)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn parse_rib_ipv4(body: &[u8]) -> Option<RibEntry> {
    let mut pos = 0;

    // sequence_number: u32
    pos += 4;

    // prefix_length: u8
    let prefix_len = *body.get(pos)?;
    pos += 1;

    // prefix bytes: only the significant octets are stored (RFC 6396 §4.3.2)
    let prefix_bytes = (prefix_len as usize).div_ceil(8);
    if pos + prefix_bytes > body.len() {
        return None;
    }
    let mut addr_bytes = [0u8; 4];
    addr_bytes[..prefix_bytes].copy_from_slice(&body[pos..pos + prefix_bytes]);
    let prefix = Ipv4Addr::from(addr_bytes);
    pos += prefix_bytes;

    // entry_count: u16
    if pos + 2 > body.len() {
        return None;
    }
    let entry_count = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;

    if entry_count == 0 {
        return None;
    }

    // Take only the first RIB entry (one per prefix is enough for stress testing).
    // Each entry: peer_index(2) + originated_time(4) + attribute_length(2) + attrs
    if pos + 8 > body.len() {
        return None;
    }
    // peer_index(2) + originated_time(4)
    pos += 6;
    let attr_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;

    if pos + attr_len > body.len() {
        return None;
    }
    let attrs = body[pos..pos + attr_len].to_vec();

    Some(RibEntry {
        prefix,
        prefix_len,
        attrs,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mrt_header(mrt_type: u16, subtype: u16, body_len: u32) -> Vec<u8> {
        let mut h = vec![0u8; 12];
        // timestamp = 0
        h[4..6].copy_from_slice(&mrt_type.to_be_bytes());
        h[6..8].copy_from_slice(&subtype.to_be_bytes());
        h[8..12].copy_from_slice(&body_len.to_be_bytes());
        h
    }

    fn rib_ipv4_record(prefix: Ipv4Addr, prefix_len: u8, attrs: &[u8]) -> Vec<u8> {
        let prefix_bytes = (prefix_len as usize).div_ceil(8);
        let attr_len = u16::try_from(attrs.len()).expect("attrs too large for MRT test");

        // sequence_number(4) + prefix_len(1) + prefix_bytes + entry_count(2) +
        // peer_index(2) + originated_time(4) + attr_len(2) + attrs
        let body_len = 4 + 1 + prefix_bytes + 2 + 2 + 4 + 2 + attrs.len();
        let mut body = Vec::with_capacity(body_len);
        body.extend_from_slice(&0u32.to_be_bytes()); // sequence
        body.push(prefix_len);
        body.extend_from_slice(&prefix.octets()[..prefix_bytes]);
        body.extend_from_slice(&1u16.to_be_bytes()); // entry_count = 1
        body.extend_from_slice(&0u16.to_be_bytes()); // peer_index
        body.extend_from_slice(&0u32.to_be_bytes()); // originated_time
        body.extend_from_slice(&attr_len.to_be_bytes());
        body.extend_from_slice(attrs);
        body
    }

    #[test]
    fn parse_single_prefix() {
        let attrs = [0x40, 0x01, 0x01, 0x00]; // ORIGIN IGP
        let prefix = Ipv4Addr::new(10, 0, 0, 0);
        let body = rib_ipv4_record(prefix, 8, &attrs);

        let body_len = u32::try_from(body.len()).unwrap();
        let mut data = mrt_header(MRT_TYPE_TABLE_DUMP_V2, SUBTYPE_RIB_IPV4_UNICAST, body_len);
        data.extend_from_slice(&body);

        let entries = parse(data.as_slice()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].prefix, prefix);
        assert_eq!(entries[0].prefix_len, 8);
        assert_eq!(entries[0].attrs, attrs);
    }

    #[test]
    fn unknown_mrt_type_skipped() {
        // Non-TABLE_DUMP_V2 record should be skipped
        let body = vec![0u8; 4];
        let mut data = mrt_header(16, 1, 4); // BGP4MP type
        data.extend_from_slice(&body);

        let entries = parse(data.as_slice()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn empty_stream_returns_empty() {
        let entries = parse(&[][..]).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn host_route_slash32() {
        let attrs = [0x40, 0x01, 0x01, 0x00];
        let prefix = Ipv4Addr::new(192, 0, 2, 1);
        let body = rib_ipv4_record(prefix, 32, &attrs);

        let body_len = u32::try_from(body.len()).unwrap();
        let mut data = mrt_header(MRT_TYPE_TABLE_DUMP_V2, SUBTYPE_RIB_IPV4_UNICAST, body_len);
        data.extend_from_slice(&body);

        let entries = parse(data.as_slice()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].prefix, prefix);
        assert_eq!(entries[0].prefix_len, 32);
    }
}
