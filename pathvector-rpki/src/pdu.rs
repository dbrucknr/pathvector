//! RTR (RPKI-to-Router) protocol PDU codec — RFC 8210 §5 (v1), RFC 6810 §5 (v0).
//!
//! Every RTR PDU shares an 8-byte header: protocol version (1 byte), PDU type
//! (1 byte), a 2-byte type-specific field (Session ID for most PDUs, Error
//! Code for Error Report, reserved/zero otherwise), and a 4-byte total length
//! (including the header). `Cursor`/`Writer` mirror the pattern used by
//! `pathvector-session`'s BGP message codec: bounds-checked reads that return
//! [`PduError::Truncated`] rather than panicking on untrusted input.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::PduError;

// ── Codec primitives (private, mirrors pathvector-session's Cursor/Writer) ────

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_u8(&mut self) -> Result<u8, PduError> {
        if self.remaining() < 1 {
            return Err(PduError::Truncated {
                needed: 1,
                available: 0,
            });
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16(&mut self) -> Result<u16, PduError> {
        if self.remaining() < 2 {
            return Err(PduError::Truncated {
                needed: 2,
                available: self.remaining(),
            });
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, PduError> {
        if self.remaining() < 4 {
            return Err(PduError::Truncated {
                needed: 4,
                available: self.remaining(),
            });
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], PduError> {
        if self.remaining() < n {
            return Err(PduError::Truncated {
                needed: n,
                available: self.remaining(),
            });
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_ipv4addr(&mut self) -> Result<Ipv4Addr, PduError> {
        let b = self.read_bytes(4)?;
        Ok(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
    }

    fn read_ipv6addr(&mut self) -> Result<Ipv6Addr, PduError> {
        let b = self.read_bytes(16)?;
        let mut octets = [0u8; 16];
        octets.copy_from_slice(b);
        Ok(Ipv6Addr::from(octets))
    }

    /// Returns all remaining bytes without advancing (used to skip an opaque
    /// payload, e.g. Router Key, whose internal structure we don't parse).
    fn remaining_bytes(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }
}

struct Writer(Vec<u8>);

impl Writer {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn put_u8(&mut self, v: u8) {
        self.0.push(v);
    }

    fn put_u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn put_u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn put_slice(&mut self, s: &[u8]) {
        self.0.extend_from_slice(s);
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

// ── Wire types ─────────────────────────────────────────────────────────────

/// RTR protocol version negotiated for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtrVersion {
    /// RFC 6810.
    V0,
    /// RFC 8210.
    V1,
}

impl RtrVersion {
    fn as_byte(self) -> u8 {
        match self {
            Self::V0 => 0,
            Self::V1 => 1,
        }
    }

    fn from_byte(b: u8) -> Result<Self, PduError> {
        match b {
            0 => Ok(Self::V0),
            1 => Ok(Self::V1),
            other => Err(PduError::UnknownVersion(other)),
        }
    }
}

/// RTR PDU type byte values (RFC 8210 §5 table; the v0 subset per RFC 6810 §5
/// omits Router Key). Type value 5 is unused in the RFC numbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PduType {
    SerialNotify = 0,
    SerialQuery = 1,
    ResetQuery = 2,
    CacheResponse = 3,
    Ipv4Prefix = 4,
    Ipv6Prefix = 6,
    EndOfData = 7,
    CacheReset = 8,
    RouterKey = 9,
    ErrorReport = 10,
}

impl PduType {
    fn as_byte(self) -> u8 {
        self as u8
    }

    fn from_byte(b: u8) -> Result<Self, PduError> {
        match b {
            0 => Ok(Self::SerialNotify),
            1 => Ok(Self::SerialQuery),
            2 => Ok(Self::ResetQuery),
            3 => Ok(Self::CacheResponse),
            4 => Ok(Self::Ipv4Prefix),
            6 => Ok(Self::Ipv6Prefix),
            7 => Ok(Self::EndOfData),
            8 => Ok(Self::CacheReset),
            9 => Ok(Self::RouterKey),
            10 => Ok(Self::ErrorReport),
            other => Err(PduError::UnknownPduType(other)),
        }
    }
}

/// Announce (`true`) or withdraw (`false`) flag on a Prefix PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixFlags {
    pub announce: bool,
}

impl PrefixFlags {
    fn as_byte(self) -> u8 {
        u8::from(self.announce)
    }

    fn from_byte(b: u8) -> Self {
        // RFC 8210 §5.6/5.8: only bit 0 is defined; other bits are reserved
        // and must be ignored on receipt, not rejected.
        Self {
            announce: (b & 0x01) == 1,
        }
    }
}

/// A decoded RTR PDU.
///
/// `RouterKey` carries no fields — Phase 1 doesn't act on `BGPsec` router keys,
/// so its payload is validated for length only and otherwise discarded. This
/// means a well-formed Router Key PDU from a real validator never causes a
/// session error, even though we don't use its contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pdu {
    SerialNotify {
        session_id: u16,
        serial: u32,
    },
    SerialQuery {
        session_id: u16,
        serial: u32,
    },
    ResetQuery,
    CacheResponse {
        session_id: u16,
    },
    Ipv4Prefix {
        flags: PrefixFlags,
        prefix_len: u8,
        max_len: u8,
        prefix: Ipv4Addr,
        asn: u32,
    },
    Ipv6Prefix {
        flags: PrefixFlags,
        prefix_len: u8,
        max_len: u8,
        prefix: Ipv6Addr,
        asn: u32,
    },
    EndOfData {
        session_id: u16,
        serial: u32,
        /// `None` when negotiated at `RtrVersion::V0` (RFC 6810 has no
        /// interval fields on this PDU).
        intervals: Option<EndOfDataIntervals>,
    },
    CacheReset,
    ErrorReport {
        error_code: u16,
        pdu_copy: Vec<u8>,
        text: String,
    },
    RouterKey,
}

/// RFC 8210 §5.9 refresh/retry/expire intervals, present on `EndOfData` only
/// at protocol version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndOfDataIntervals {
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
}

// ── Fixed header/payload sizes (bytes, including the 8-byte header) ─────────

const HEADER_LEN: u32 = 8;
const LEN_SERIAL_NOTIFY: u32 = 12;
const LEN_SERIAL_QUERY: u32 = 12;
const LEN_RESET_QUERY: u32 = 8;
const LEN_CACHE_RESPONSE: u32 = 8;
const LEN_IPV4_PREFIX: u32 = 20;
const LEN_IPV6_PREFIX: u32 = 32;
const LEN_END_OF_DATA_V0: u32 = 12;
const LEN_END_OF_DATA_V1: u32 = 24;
const LEN_CACHE_RESET: u32 = 8;

// ── Encode ────────────────────────────────────────────────────────────────

/// Encodes `pdu` for wire transmission at the given protocol version.
///
/// # Panics
///
/// Panics if `pdu` is `Pdu::EndOfData { intervals: None, .. }` while `version`
/// is `RtrVersion::V1`, or `intervals: Some(_)` while `version` is `V0` — this
/// is a caller-side programming error (the caller must pass an `EndOfData`
/// shaped for the version it's encoding), not a wire-format condition, so a
/// panic here catches a real bug rather than silently emitting a malformed PDU.
pub(crate) fn encode(version: RtrVersion, pdu: &Pdu) -> Vec<u8> {
    let mut w = Writer::new();
    match pdu {
        Pdu::SerialNotify { session_id, serial } => {
            write_header(
                &mut w,
                version,
                PduType::SerialNotify,
                *session_id,
                LEN_SERIAL_NOTIFY,
            );
            w.put_u32(*serial);
        }
        Pdu::SerialQuery { session_id, serial } => {
            write_header(
                &mut w,
                version,
                PduType::SerialQuery,
                *session_id,
                LEN_SERIAL_QUERY,
            );
            w.put_u32(*serial);
        }
        Pdu::ResetQuery => {
            write_header(&mut w, version, PduType::ResetQuery, 0, LEN_RESET_QUERY);
        }
        Pdu::CacheResponse { session_id } => {
            write_header(
                &mut w,
                version,
                PduType::CacheResponse,
                *session_id,
                LEN_CACHE_RESPONSE,
            );
        }
        Pdu::Ipv4Prefix {
            flags,
            prefix_len,
            max_len,
            prefix,
            asn,
        } => {
            write_header(&mut w, version, PduType::Ipv4Prefix, 0, LEN_IPV4_PREFIX);
            encode_prefix_body(
                &mut w,
                *flags,
                *prefix_len,
                *max_len,
                &prefix.octets(),
                *asn,
            );
        }
        Pdu::Ipv6Prefix {
            flags,
            prefix_len,
            max_len,
            prefix,
            asn,
        } => {
            write_header(&mut w, version, PduType::Ipv6Prefix, 0, LEN_IPV6_PREFIX);
            encode_prefix_body(
                &mut w,
                *flags,
                *prefix_len,
                *max_len,
                &prefix.octets(),
                *asn,
            );
        }
        Pdu::EndOfData {
            session_id,
            serial,
            intervals,
        } => encode_end_of_data(&mut w, version, *session_id, *serial, *intervals),
        Pdu::CacheReset => {
            write_header(&mut w, version, PduType::CacheReset, 0, LEN_CACHE_RESET);
        }
        Pdu::ErrorReport {
            error_code,
            pdu_copy,
            text,
        } => {
            let text_bytes = text.as_bytes();
            #[allow(clippy::cast_possible_truncation)]
            let len = HEADER_LEN + 4 + pdu_copy.len() as u32 + 4 + text_bytes.len() as u32;
            write_header(&mut w, version, PduType::ErrorReport, *error_code, len);
            #[allow(clippy::cast_possible_truncation)]
            w.put_u32(pdu_copy.len() as u32);
            w.put_slice(pdu_copy);
            #[allow(clippy::cast_possible_truncation)]
            w.put_u32(text_bytes.len() as u32);
            w.put_slice(text_bytes);
        }
        Pdu::RouterKey => {
            // We never originate Router Key PDUs (client-to-server direction
            // never sends this type); encode is provided for round-trip
            // testing only, using the minimal valid (header-only) form.
            write_header(&mut w, version, PduType::RouterKey, 0, HEADER_LEN);
        }
    }
    w.finish()
}

fn encode_prefix_body(
    w: &mut Writer,
    flags: PrefixFlags,
    prefix_len: u8,
    max_len: u8,
    prefix_octets: &[u8],
    asn: u32,
) {
    w.put_u8(flags.as_byte());
    w.put_u8(prefix_len);
    w.put_u8(max_len);
    w.put_u8(0); // reserved
    w.put_slice(prefix_octets);
    w.put_u32(asn);
}

/// # Panics
///
/// Panics if `intervals` presence doesn't match `version` (`None` at `V1`, or
/// `Some` at `V0`) — a caller-side programming error, not a wire condition.
fn encode_end_of_data(
    w: &mut Writer,
    version: RtrVersion,
    session_id: u16,
    serial: u32,
    intervals: Option<EndOfDataIntervals>,
) {
    match (version, intervals) {
        (RtrVersion::V0, None) => {
            write_header(
                w,
                version,
                PduType::EndOfData,
                session_id,
                LEN_END_OF_DATA_V0,
            );
            w.put_u32(serial);
        }
        (RtrVersion::V1, Some(iv)) => {
            write_header(
                w,
                version,
                PduType::EndOfData,
                session_id,
                LEN_END_OF_DATA_V1,
            );
            w.put_u32(serial);
            w.put_u32(iv.refresh);
            w.put_u32(iv.retry);
            w.put_u32(iv.expire);
        }
        _ => panic!("EndOfData intervals presence must match the encoding RtrVersion"),
    }
}

fn write_header(w: &mut Writer, version: RtrVersion, pdu_type: PduType, field: u16, len: u32) {
    w.put_u8(version.as_byte());
    w.put_u8(pdu_type.as_byte());
    w.put_u16(field);
    w.put_u32(len);
}

// ── Decode ────────────────────────────────────────────────────────────────

/// Decodes the 8-byte PDU header, returning the protocol version, PDU type,
/// the type-specific field (session ID / error code / reserved), and the
/// total declared PDU length (including this header).
pub(crate) fn decode_header(buf: &[u8]) -> Result<(RtrVersion, PduType, u16, u32), PduError> {
    let mut cur = Cursor::new(buf);
    let version = RtrVersion::from_byte(cur.read_u8()?)?;
    let pdu_type = PduType::from_byte(cur.read_u8()?)?;
    let field = cur.read_u16()?;
    let len = cur.read_u32()?;
    Ok((version, pdu_type, field, len))
}

/// Decodes a PDU's payload given the header fields already read from `body`
/// (which must contain exactly `len` bytes total — header included; the
/// caller is responsible for buffering `len` bytes off the wire before
/// calling this, since PDUs are self-describing but not framed by a
/// delimiter).
pub(crate) fn decode_payload(
    version: RtrVersion,
    pdu_type: PduType,
    field: u16,
    len: u32,
    body: &[u8],
) -> Result<Pdu, PduError> {
    // `body` is the full PDU including the 8-byte header; skip it here so
    // each arm only deals with the payload.
    if (body.len() as u64) != u64::from(len) {
        return Err(PduError::InvalidLength {
            pdu_type: pdu_type.as_byte(),
            len,
        });
    }
    let mut cur = Cursor::new(body);
    cur.read_bytes(HEADER_LEN as usize)?; // discard header, already parsed

    match pdu_type {
        PduType::SerialNotify => {
            expect_len(pdu_type, len, LEN_SERIAL_NOTIFY)?;
            let serial = cur.read_u32()?;
            Ok(Pdu::SerialNotify {
                session_id: field,
                serial,
            })
        }
        PduType::SerialQuery => {
            expect_len(pdu_type, len, LEN_SERIAL_QUERY)?;
            let serial = cur.read_u32()?;
            Ok(Pdu::SerialQuery {
                session_id: field,
                serial,
            })
        }
        PduType::ResetQuery => {
            expect_len(pdu_type, len, LEN_RESET_QUERY)?;
            Ok(Pdu::ResetQuery)
        }
        PduType::CacheResponse => {
            expect_len(pdu_type, len, LEN_CACHE_RESPONSE)?;
            Ok(Pdu::CacheResponse { session_id: field })
        }
        PduType::Ipv4Prefix => {
            expect_len(pdu_type, len, LEN_IPV4_PREFIX)?;
            decode_ipv4_prefix_body(&mut cur)
        }
        PduType::Ipv6Prefix => {
            expect_len(pdu_type, len, LEN_IPV6_PREFIX)?;
            decode_ipv6_prefix_body(&mut cur)
        }
        PduType::EndOfData => decode_end_of_data_body(&mut cur, version, pdu_type, field, len),
        PduType::CacheReset => {
            expect_len(pdu_type, len, LEN_CACHE_RESET)?;
            Ok(Pdu::CacheReset)
        }
        PduType::ErrorReport => decode_error_report_body(&mut cur, pdu_type, field, len),
        PduType::RouterKey => decode_router_key_body(&mut cur, pdu_type, len),
    }
}

fn decode_ipv4_prefix_body(cur: &mut Cursor<'_>) -> Result<Pdu, PduError> {
    let flags = PrefixFlags::from_byte(cur.read_u8()?);
    let prefix_len = cur.read_u8()?;
    let max_len = cur.read_u8()?;
    cur.read_u8()?; // reserved
    let prefix = cur.read_ipv4addr()?;
    let asn = cur.read_u32()?;
    Ok(Pdu::Ipv4Prefix {
        flags,
        prefix_len,
        max_len,
        prefix,
        asn,
    })
}

fn decode_ipv6_prefix_body(cur: &mut Cursor<'_>) -> Result<Pdu, PduError> {
    let flags = PrefixFlags::from_byte(cur.read_u8()?);
    let prefix_len = cur.read_u8()?;
    let max_len = cur.read_u8()?;
    cur.read_u8()?; // reserved
    let prefix = cur.read_ipv6addr()?;
    let asn = cur.read_u32()?;
    Ok(Pdu::Ipv6Prefix {
        flags,
        prefix_len,
        max_len,
        prefix,
        asn,
    })
}

fn decode_end_of_data_body(
    cur: &mut Cursor<'_>,
    version: RtrVersion,
    pdu_type: PduType,
    field: u16,
    len: u32,
) -> Result<Pdu, PduError> {
    match version {
        RtrVersion::V0 => {
            expect_len(pdu_type, len, LEN_END_OF_DATA_V0)?;
            let serial = cur.read_u32()?;
            Ok(Pdu::EndOfData {
                session_id: field,
                serial,
                intervals: None,
            })
        }
        RtrVersion::V1 => {
            expect_len(pdu_type, len, LEN_END_OF_DATA_V1)?;
            let serial = cur.read_u32()?;
            let refresh = cur.read_u32()?;
            let retry = cur.read_u32()?;
            let expire = cur.read_u32()?;
            Ok(Pdu::EndOfData {
                session_id: field,
                serial,
                intervals: Some(EndOfDataIntervals {
                    refresh,
                    retry,
                    expire,
                }),
            })
        }
    }
}

fn decode_error_report_body(
    cur: &mut Cursor<'_>,
    pdu_type: PduType,
    field: u16,
    len: u32,
) -> Result<Pdu, PduError> {
    if len < HEADER_LEN + 8 {
        return Err(PduError::InvalidLength {
            pdu_type: pdu_type.as_byte(),
            len,
        });
    }
    let encap_len = cur.read_u32()? as usize;
    let pdu_copy = cur.read_bytes(encap_len)?.to_vec();
    let text_len = cur.read_u32()? as usize;
    let text_bytes = cur.read_bytes(text_len)?;
    let text = std::str::from_utf8(text_bytes)
        .map_err(PduError::Utf8)?
        .to_string();
    Ok(Pdu::ErrorReport {
        error_code: field,
        pdu_copy,
        text,
    })
}

fn decode_router_key_body(
    cur: &mut Cursor<'_>,
    pdu_type: PduType,
    len: u32,
) -> Result<Pdu, PduError> {
    // Opaque: validate the declared length is at least the header, then
    // discard the rest without interpreting SKI/ASN/SPKI fields.
    if len < HEADER_LEN {
        return Err(PduError::InvalidLength {
            pdu_type: pdu_type.as_byte(),
            len,
        });
    }
    let _ = cur.remaining_bytes();
    Ok(Pdu::RouterKey)
}

/// Decodes one PDU from the start of `buf` exactly as `client.rs`'s
/// `read_pdu` does off a live socket — 8-byte header, then `len - 8` more
/// bytes — except operating on an in-memory slice instead of async I/O.
/// Discards the result either way; only used to prove the decoder never
/// panics on adversarial input.
///
/// Exposed only for fuzzing (`pathvector-fuzz`'s `rtr_pdu` target); not part
/// of the crate's normal public API — real callers only ever decode PDUs
/// already framed off a live TCP stream (see `client.rs`).
#[cfg(any(test, feature = "test-util"))]
pub fn decode_for_fuzzing(buf: &[u8]) {
    if buf.len() < HEADER_LEN as usize {
        return;
    }
    let Ok((version, pdu_type, field, len)) = decode_header(buf) else {
        return;
    };
    let len_usize = len as usize;
    if len < HEADER_LEN || buf.len() < len_usize || len > 64 * 1024 {
        return;
    }
    let _ = decode_payload(version, pdu_type, field, len, &buf[..len_usize]);
}

fn expect_len(pdu_type: PduType, actual: u32, expected: u32) -> Result<(), PduError> {
    if actual == expected {
        Ok(())
    } else {
        Err(PduError::InvalidLength {
            pdu_type: pdu_type.as_byte(),
            len: actual,
        })
    }
}

/// Convenience: encode then fully decode `pdu`, for tests and for the client
/// to introspect what it's about to send.
#[cfg(test)]
fn roundtrip(version: RtrVersion, pdu: &Pdu) -> Result<Pdu, PduError> {
    let bytes = encode(version, pdu);
    let (v, t, field, len) = decode_header(&bytes)?;
    decode_payload(v, t, field, len, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn serial_notify_roundtrip() {
        let pdu = Pdu::SerialNotify {
            session_id: 42,
            serial: 100,
        };
        assert_eq!(roundtrip(RtrVersion::V1, &pdu), Ok(pdu));
    }

    #[test]
    fn serial_query_roundtrip() {
        let pdu = Pdu::SerialQuery {
            session_id: 7,
            serial: 999,
        };
        assert_eq!(roundtrip(RtrVersion::V1, &pdu), Ok(pdu));
    }

    #[test]
    fn reset_query_roundtrip() {
        assert_eq!(
            roundtrip(RtrVersion::V1, &Pdu::ResetQuery),
            Ok(Pdu::ResetQuery)
        );
    }

    #[test]
    fn cache_response_roundtrip() {
        let pdu = Pdu::CacheResponse { session_id: 3 };
        assert_eq!(roundtrip(RtrVersion::V1, &pdu), Ok(pdu));
    }

    #[test]
    fn ipv4_prefix_announce_roundtrip() {
        let pdu = Pdu::Ipv4Prefix {
            flags: PrefixFlags { announce: true },
            prefix_len: 24,
            max_len: 24,
            prefix: v4(192, 0, 2, 0),
            asn: 65001,
        };
        assert_eq!(roundtrip(RtrVersion::V1, &pdu), Ok(pdu));
    }

    #[test]
    fn ipv4_prefix_withdraw_roundtrip() {
        let pdu = Pdu::Ipv4Prefix {
            flags: PrefixFlags { announce: false },
            prefix_len: 8,
            max_len: 16,
            prefix: v4(10, 0, 0, 0),
            asn: 65002,
        };
        assert_eq!(roundtrip(RtrVersion::V1, &pdu), Ok(pdu));
    }

    #[test]
    fn ipv6_prefix_roundtrip() {
        let pdu = Pdu::Ipv6Prefix {
            flags: PrefixFlags { announce: true },
            prefix_len: 32,
            max_len: 48,
            prefix: "2001:db8::".parse().unwrap(),
            asn: 65003,
        };
        assert_eq!(roundtrip(RtrVersion::V1, &pdu), Ok(pdu));
    }

    #[test]
    fn end_of_data_v1_roundtrip() {
        let pdu = Pdu::EndOfData {
            session_id: 1,
            serial: 5,
            intervals: Some(EndOfDataIntervals {
                refresh: 3600,
                retry: 600,
                expire: 7200,
            }),
        };
        assert_eq!(roundtrip(RtrVersion::V1, &pdu), Ok(pdu));
    }

    #[test]
    fn end_of_data_v0_roundtrip_omits_intervals() {
        let pdu = Pdu::EndOfData {
            session_id: 1,
            serial: 5,
            intervals: None,
        };
        let bytes = encode(RtrVersion::V0, &pdu);
        assert_eq!(bytes.len(), LEN_END_OF_DATA_V0 as usize);
        assert_eq!(roundtrip(RtrVersion::V0, &pdu), Ok(pdu));
    }

    #[test]
    fn end_of_data_v1_is_longer_than_v0() {
        let v0_pdu = Pdu::EndOfData {
            session_id: 1,
            serial: 5,
            intervals: None,
        };
        let v1_pdu = Pdu::EndOfData {
            session_id: 1,
            serial: 5,
            intervals: Some(EndOfDataIntervals {
                refresh: 1,
                retry: 1,
                expire: 1,
            }),
        };
        assert_eq!(
            encode(RtrVersion::V0, &v0_pdu).len(),
            LEN_END_OF_DATA_V0 as usize
        );
        assert_eq!(
            encode(RtrVersion::V1, &v1_pdu).len(),
            LEN_END_OF_DATA_V1 as usize
        );
    }

    #[test]
    fn cache_reset_roundtrip() {
        assert_eq!(
            roundtrip(RtrVersion::V1, &Pdu::CacheReset),
            Ok(Pdu::CacheReset)
        );
    }

    #[test]
    fn error_report_roundtrip() {
        let pdu = Pdu::ErrorReport {
            error_code: 4,
            pdu_copy: vec![1, 2, 3, 4],
            text: "unsupported protocol version".to_string(),
        };
        assert_eq!(roundtrip(RtrVersion::V1, &pdu), Ok(pdu));
    }

    #[test]
    fn error_report_empty_fields_roundtrip() {
        let pdu = Pdu::ErrorReport {
            error_code: 0,
            pdu_copy: vec![],
            text: String::new(),
        };
        assert_eq!(roundtrip(RtrVersion::V1, &pdu), Ok(pdu));
    }

    #[test]
    fn error_report_invalid_utf8_text_errors() {
        // Hand-craft an Error Report PDU with invalid UTF-8 in the text field.
        let mut w = Writer::new();
        write_header(
            &mut w,
            RtrVersion::V1,
            PduType::ErrorReport,
            0,
            HEADER_LEN + 4 + 4 + 2,
        );
        w.put_u32(0); // encapsulated PDU length
        w.put_u32(2); // text length
        w.put_slice(&[0xFF, 0xFE]); // invalid UTF-8
        let bytes = w.finish();
        let (v, t, field, len) = decode_header(&bytes).unwrap();
        assert!(matches!(
            decode_payload(v, t, field, len, &bytes),
            Err(PduError::Utf8(_))
        ));
    }

    #[test]
    fn router_key_decodes_and_is_discarded() {
        let bytes = encode(RtrVersion::V1, &Pdu::RouterKey);
        let (v, t, field, len) = decode_header(&bytes).unwrap();
        assert_eq!(decode_payload(v, t, field, len, &bytes), Ok(Pdu::RouterKey));
    }

    #[test]
    fn unknown_pdu_type_errors() {
        let mut w = Writer::new();
        write_header(
            &mut w,
            RtrVersion::V1,
            PduType::ResetQuery,
            0,
            LEN_RESET_QUERY,
        );
        let mut bytes = w.finish();
        bytes[1] = 99; // corrupt the type byte
        assert_eq!(decode_header(&bytes), Err(PduError::UnknownPduType(99)));
    }

    #[test]
    fn unknown_version_errors() {
        let mut w = Writer::new();
        write_header(
            &mut w,
            RtrVersion::V1,
            PduType::ResetQuery,
            0,
            LEN_RESET_QUERY,
        );
        let mut bytes = w.finish();
        bytes[0] = 7; // corrupt the version byte
        assert_eq!(decode_header(&bytes), Err(PduError::UnknownVersion(7)));
    }

    #[test]
    fn wrong_length_errors() {
        let pdu = Pdu::ResetQuery;
        let bytes = encode(RtrVersion::V1, &pdu);
        let (v, t, field, len) = decode_header(&bytes).unwrap();
        // Feed a buffer whose actual size doesn't match the declared length.
        let mut short = bytes.clone();
        short.truncate(bytes.len() - 1);
        assert!(matches!(
            decode_payload(v, t, field, len, &short),
            Err(PduError::InvalidLength { .. })
        ));
    }

    #[test]
    fn truncated_header_errors_never_panics() {
        for n in 0..HEADER_LEN as usize {
            let bytes = encode(RtrVersion::V1, &Pdu::ResetQuery);
            let partial = &bytes[..n];
            assert!(matches!(
                decode_header(partial),
                Err(PduError::Truncated { .. })
            ));
        }
    }

    #[test]
    fn truncated_payload_errors_never_panics_for_every_pdu_type() {
        let pdus = vec![
            Pdu::SerialNotify {
                session_id: 1,
                serial: 1,
            },
            Pdu::SerialQuery {
                session_id: 1,
                serial: 1,
            },
            Pdu::ResetQuery,
            Pdu::CacheResponse { session_id: 1 },
            Pdu::Ipv4Prefix {
                flags: PrefixFlags { announce: true },
                prefix_len: 24,
                max_len: 24,
                prefix: v4(192, 0, 2, 0),
                asn: 1,
            },
            Pdu::Ipv6Prefix {
                flags: PrefixFlags { announce: true },
                prefix_len: 32,
                max_len: 32,
                prefix: "2001:db8::".parse().unwrap(),
                asn: 1,
            },
            Pdu::EndOfData {
                session_id: 1,
                serial: 1,
                intervals: Some(EndOfDataIntervals {
                    refresh: 1,
                    retry: 1,
                    expire: 1,
                }),
            },
            Pdu::CacheReset,
            Pdu::ErrorReport {
                error_code: 1,
                pdu_copy: vec![1, 2, 3],
                text: "x".to_string(),
            },
        ];
        for pdu in pdus {
            let full = encode(RtrVersion::V1, &pdu);
            let (v, t, field, len) = decode_header(&full).unwrap();
            for n in HEADER_LEN as usize..full.len() {
                let partial = &full[..n];
                // Either a Truncated or InvalidLength error is acceptable —
                // the only thing that must never happen is a panic.
                let result = decode_payload(v, t, field, len, partial);
                assert!(
                    result.is_err(),
                    "expected error decoding truncated {pdu:?} at {n} bytes"
                );
            }
        }
    }

    #[test]
    fn prefix_flags_ignores_reserved_bits() {
        assert!(PrefixFlags::from_byte(0b1111_1111).announce);
        assert!(!PrefixFlags::from_byte(0b1111_1110).announce);
    }
}

#[cfg(test)]
mod prop_tests {
    use proptest::prelude::*;

    use super::*;

    fn arb_prefix_flags() -> impl Strategy<Value = PrefixFlags> {
        any::<bool>().prop_map(|announce| PrefixFlags { announce })
    }

    fn arb_ipv4_pdu() -> impl Strategy<Value = Pdu> {
        (
            arb_prefix_flags(),
            0u8..=32,
            0u8..=32,
            any::<u32>(),
            any::<u32>(),
        )
            .prop_map(
                |(flags, prefix_len, max_len, prefix_bits, asn)| Pdu::Ipv4Prefix {
                    flags,
                    prefix_len,
                    max_len,
                    prefix: Ipv4Addr::from(prefix_bits),
                    asn,
                },
            )
    }

    fn arb_ipv6_pdu() -> impl Strategy<Value = Pdu> {
        (
            arb_prefix_flags(),
            0u8..=128,
            0u8..=128,
            any::<u128>(),
            any::<u32>(),
        )
            .prop_map(
                |(flags, prefix_len, max_len, prefix_bits, asn)| Pdu::Ipv6Prefix {
                    flags,
                    prefix_len,
                    max_len,
                    prefix: Ipv6Addr::from(prefix_bits),
                    asn,
                },
            )
    }

    fn arb_serial_query() -> impl Strategy<Value = Pdu> {
        (any::<u16>(), any::<u32>())
            .prop_map(|(session_id, serial)| Pdu::SerialQuery { session_id, serial })
    }

    fn arb_end_of_data_v1() -> impl Strategy<Value = Pdu> {
        (
            any::<u16>(),
            any::<u32>(),
            any::<u32>(),
            any::<u32>(),
            any::<u32>(),
        )
            .prop_map(
                |(session_id, serial, refresh, retry, expire)| Pdu::EndOfData {
                    session_id,
                    serial,
                    intervals: Some(EndOfDataIntervals {
                        refresh,
                        retry,
                        expire,
                    }),
                },
            )
    }

    proptest! {
        #[test]
        fn ipv4_prefix_roundtrips(pdu in arb_ipv4_pdu()) {
            prop_assert_eq!(roundtrip(RtrVersion::V1, &pdu), Ok(pdu));
        }

        #[test]
        fn ipv6_prefix_roundtrips(pdu in arb_ipv6_pdu()) {
            prop_assert_eq!(roundtrip(RtrVersion::V1, &pdu), Ok(pdu));
        }

        #[test]
        fn serial_query_roundtrips(pdu in arb_serial_query()) {
            prop_assert_eq!(roundtrip(RtrVersion::V1, &pdu), Ok(pdu));
        }

        #[test]
        fn end_of_data_v1_roundtrips(pdu in arb_end_of_data_v1()) {
            prop_assert_eq!(roundtrip(RtrVersion::V1, &pdu), Ok(pdu));
        }
    }
}
