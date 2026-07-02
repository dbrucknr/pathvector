use std::net::{Ipv4Addr, Ipv6Addr};

use pathvector_types::{
    Afi, AfiSafi, Aggregator, AsPath, AsPathSegment, Asn, Community, ExtendedCommunity,
    LargeCommunity, NextHop, Nlri, Origin, Safi,
};

use super::error::CodecError;
use super::header::{MessageType, encode_header};
use super::{Cursor, Writer};

// ── RFC 7606 error policy types ──────────────────────────────────────────────

/// RFC 7606 §2 error handling policy for a malformed path attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeErrorPolicy {
    /// The session must be reset (NOTIFICATION + teardown).
    /// Reserved for structural errors; attribute-level errors never produce this.
    SessionReset,
    /// The NLRIs in this UPDATE are treated as withdrawn; the session stays up.
    TreatAsWithdraw,
    /// The malformed attribute is silently dropped; the session and UPDATE are
    /// otherwise processed normally.
    AttributeDiscard,
}

/// A per-attribute decode error with its RFC 7606 handling policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeDecodeError {
    /// BGP path attribute type code (1 = `ORIGIN`, 2 = `AS_PATH`, …).
    pub type_code: u8,
    /// RFC 7606 handling policy for this attribute type.
    pub policy: AttributeErrorPolicy,
    /// Human-readable reason the attribute was rejected.
    pub detail: &'static str,
}

/// Outcome of decoding a BGP UPDATE message.
///
/// Structural errors (truncated withdrawn-routes block, truncated attribute
/// header) still return `Err(CodecError)` and require a session reset.
/// Per-attribute decode errors produce a `Partial` outcome instead.
#[derive(Debug, PartialEq)]
pub(super) enum UpdateDecodeOutcome {
    /// All attributes decoded without error.
    Clean(UpdateMessage),
    /// One or more attributes were malformed.
    Partial {
        /// UPDATE with bad attributes removed.
        update: UpdateMessage,
        /// Per-attribute errors with their RFC 7606 policies.
        errors: Vec<AttributeDecodeError>,
        /// `true` if any error has `TreatAsWithdraw` policy — the caller must
        /// treat all announced NLRIs in this UPDATE as withdrawn.
        treat_as_withdraw: bool,
    },
}

/// RFC 7606 §5 per-attribute error policy table.
fn rfc7606_policy(type_code: u8) -> AttributeErrorPolicy {
    match type_code {
        // Well-known: ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF → treat as withdraw
        ATTR_ORIGIN | ATTR_AS_PATH | ATTR_NEXT_HOP | ATTR_LOCAL_PREF => {
            AttributeErrorPolicy::TreatAsWithdraw
        }
        // MP_REACH_NLRI → treat as withdraw for the affected AFI/SAFI
        ATTR_MP_REACH_NLRI => AttributeErrorPolicy::TreatAsWithdraw,
        // Everything else (optional): attribute discard
        _ => AttributeErrorPolicy::AttributeDiscard,
    }
}

fn error_detail(e: &CodecError) -> &'static str {
    match e {
        CodecError::InvalidOrigin(_) => "invalid ORIGIN value",
        CodecError::UnknownAsPathSegmentType(_) => "unknown AS_PATH segment type",
        CodecError::InvalidAttribute { detail, .. } => detail,
        CodecError::Truncated { .. } => "attribute value truncated",
        _ => "malformed attribute",
    }
}

// ── Path attribute flag bits ─────────────────────────────────────────────────

const FLAG_OPTIONAL: u8 = 0x80;
const FLAG_TRANSITIVE: u8 = 0x40;
const FLAG_PARTIAL: u8 = 0x20;
const FLAG_EXT_LEN: u8 = 0x10;

// Well-known mandatory (non-optional, transitive)
const FLAGS_WKM: u8 = FLAG_TRANSITIVE;
// Optional non-transitive
const FLAGS_ONT: u8 = FLAG_OPTIONAL;
// Optional transitive
const FLAGS_OT: u8 = FLAG_OPTIONAL | FLAG_TRANSITIVE;

// ── Path attribute type codes ────────────────────────────────────────────────

const ATTR_ORIGIN: u8 = 1;
const ATTR_AS_PATH: u8 = 2;
const ATTR_NEXT_HOP: u8 = 3;
const ATTR_MED: u8 = 4;
const ATTR_LOCAL_PREF: u8 = 5;
const ATTR_ATOMIC_AGGREGATE: u8 = 6;
const ATTR_AGGREGATOR: u8 = 7;
const ATTR_COMMUNITY: u8 = 8;
const ATTR_ORIGINATOR_ID: u8 = 9;
const ATTR_CLUSTER_LIST: u8 = 10;
const ATTR_MP_REACH_NLRI: u8 = 14;
const ATTR_MP_UNREACH_NLRI: u8 = 15;
const ATTR_EXTENDED_COMMUNITIES: u8 = 16;
const ATTR_AS4_PATH: u8 = 17;
const ATTR_AS4_AGGREGATOR: u8 = 18;
const ATTR_LARGE_COMMUNITY: u8 = 32;
const ATTR_ONLY_TO_CUSTOMER: u8 = 35;

// ── AS path segment type codes (RFC 4271) ────────────────────────────────────

const SEG_SET: u8 = 1;
const SEG_SEQUENCE: u8 = 2;
const SEG_CONFED_SEQUENCE: u8 = 3;
const SEG_CONFED_SET: u8 = 4;

/// A BGP UPDATE message (type 2).
///
/// The primary carrier of routing information. A single UPDATE may carry
/// both withdrawn prefixes (routes being retracted) and newly announced
/// prefixes (routes being advertised). All announced prefixes in one UPDATE
/// share the same set of path attributes.
///
/// IPv4 unicast prefixes are encoded directly in the `withdrawn` and
/// `announced` fields. All other address families (IPv6, VPN, EVPN) are
/// carried inside the [`PathAttribute::MpReachNlri`] and
/// [`PathAttribute::MpUnreachNlri`] attributes.
#[derive(Debug, Clone, PartialEq)]
pub struct UpdateMessage {
    /// IPv4 unicast prefixes being withdrawn.
    pub withdrawn: Vec<Nlri<Ipv4Addr>>,
    /// Path attributes describing the announced routes.
    pub attributes: Vec<PathAttribute>,
    /// IPv4 unicast prefixes being announced.
    pub announced: Vec<Nlri<Ipv4Addr>>,
}

impl UpdateMessage {
    pub(super) fn decode(cur: &mut Cursor<'_>) -> Result<UpdateDecodeOutcome, CodecError> {
        // Withdrawn routes — structural error → session reset.
        let withdrawn_len = cur.read_u16()? as usize;
        let mut wd_cur = cur.fork(withdrawn_len)?;
        let withdrawn = decode_nlri_list_v4(&mut wd_cur)?;

        // Path attributes — structural errors → session reset;
        // per-attribute errors collected for RFC 7606 handling.
        let attrs_len = cur.read_u16()? as usize;
        let mut attrs_cur = cur.fork(attrs_len)?;
        let (attributes, attr_errors) = decode_path_attributes(&mut attrs_cur)?;

        // Announced NLRIs — structural error → session reset.
        let announced = decode_nlri_list_v4(cur)?;

        let update = Self {
            withdrawn,
            attributes,
            announced,
        };

        if attr_errors.is_empty() {
            Ok(UpdateDecodeOutcome::Clean(update))
        } else {
            let treat_as_withdraw = attr_errors
                .iter()
                .any(|e| e.policy == AttributeErrorPolicy::TreatAsWithdraw);
            Ok(UpdateDecodeOutcome::Partial {
                update,
                errors: attr_errors,
                treat_as_withdraw,
            })
        }
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let withdrawn_bytes = encode_nlri_list_v4(&self.withdrawn);
        let attrs_bytes = encode_path_attributes(&self.attributes);
        let announced_bytes = encode_nlri_list_v4(&self.announced);

        let mut body = Writer::new();
        #[allow(clippy::cast_possible_truncation)]
        body.put_u16(withdrawn_bytes.len() as u16);
        body.put_slice(&withdrawn_bytes);
        #[allow(clippy::cast_possible_truncation)]
        body.put_u16(attrs_bytes.len() as u16);
        body.put_slice(&attrs_bytes);
        body.put_slice(&announced_bytes);
        let body = body.finish();

        let mut w = Writer::new();
        encode_header(&mut w, MessageType::Update, body.len());
        w.put_slice(&body);
        w.finish()
    }
}

// ── NLRI wire helpers ────────────────────────────────────────────────────────

/// Decode all variable-length IPv4 NLRI from `cur` until it is exhausted.
fn decode_nlri_list_v4(cur: &mut Cursor<'_>) -> Result<Vec<Nlri<Ipv4Addr>>, CodecError> {
    let mut out = Vec::new();
    while cur.remaining() > 0 {
        out.push(decode_nlri_v4(cur)?);
    }
    Ok(out)
}

/// Decode a single variable-length IPv4 NLRI: `prefix_len` (1 byte) followed
/// by `ceil(prefix_len / 8)` address bytes (only significant bytes are sent).
fn decode_nlri_v4(cur: &mut Cursor<'_>) -> Result<Nlri<Ipv4Addr>, CodecError> {
    let prefix_len = cur.read_u8()?;
    if prefix_len > 32 {
        return Err(CodecError::InvalidNlri { prefix_len });
    }
    let byte_count = (prefix_len as usize).div_ceil(8);
    let addr_bytes = cur.read_bytes(byte_count)?;
    let mut octets = [0u8; 4];
    octets[..byte_count].copy_from_slice(addr_bytes);
    Nlri::new(Ipv4Addr::from(octets), prefix_len)
        .map(Nlri::masked)
        .map_err(|_| CodecError::InvalidNlri { prefix_len })
}

/// Decode a single variable-length IPv6 NLRI.
fn decode_nlri_v6(cur: &mut Cursor<'_>) -> Result<Nlri<Ipv6Addr>, CodecError> {
    let prefix_len = cur.read_u8()?;
    if prefix_len > 128 {
        return Err(CodecError::InvalidNlri { prefix_len });
    }
    let byte_count = (prefix_len as usize).div_ceil(8);
    let addr_bytes = cur.read_bytes(byte_count)?;
    let mut octets = [0u8; 16];
    octets[..byte_count].copy_from_slice(addr_bytes);
    Nlri::new(Ipv6Addr::from(octets), prefix_len)
        .map(Nlri::masked)
        .map_err(|_| CodecError::InvalidNlri { prefix_len })
}

fn decode_nlri_list_v6(cur: &mut Cursor<'_>) -> Result<Vec<Nlri<Ipv6Addr>>, CodecError> {
    let mut out = Vec::new();
    while cur.remaining() > 0 {
        out.push(decode_nlri_v6(cur)?);
    }
    Ok(out)
}

fn encode_nlri_v4(w: &mut Writer, nlri: Nlri<Ipv4Addr>) {
    let prefix_len = nlri.prefix_len();
    let byte_count = (prefix_len as usize).div_ceil(8);
    w.put_u8(prefix_len);
    w.put_slice(&nlri.prefix().ip().octets()[..byte_count]);
}

fn encode_nlri_v6(w: &mut Writer, nlri: &Nlri<Ipv6Addr>) {
    let prefix_len = nlri.prefix_len();
    let byte_count = (prefix_len as usize).div_ceil(8);
    w.put_u8(prefix_len);
    w.put_slice(&nlri.prefix().ip().octets()[..byte_count]);
}

fn encode_nlri_list_v4(nlris: &[Nlri<Ipv4Addr>]) -> Vec<u8> {
    let mut w = Writer::new();
    for nlri in nlris {
        encode_nlri_v4(&mut w, *nlri);
    }
    w.finish()
}

// ── Path attribute decode ────────────────────────────────────────────────────

/// Decode all path attributes from `cur`.
///
/// Structural errors (truncated header, can't advance past attribute bytes)
/// return `Err(CodecError)` and require a session reset. Per-attribute value
/// errors are recorded in the returned `Vec<AttributeDecodeError>` per
/// RFC 7606 §5 — the bad attribute is skipped and parsing continues.
///
/// Duplicate type codes are also detected: RFC 7606 §7.3 requires that a
/// duplicate well-known mandatory attribute be treated as a withdraw.
fn decode_path_attributes(
    cur: &mut Cursor<'_>,
) -> Result<(Vec<PathAttribute>, Vec<AttributeDecodeError>), CodecError> {
    let mut attrs = Vec::new();
    let mut errors: Vec<AttributeDecodeError> = Vec::new();
    let mut seen = [false; 256];

    while cur.remaining() > 0 {
        // Structural reads — any failure here means the attribute block is
        // unsalvageable; propagate as session reset.
        let flags = cur.read_u8()?;
        let type_code = cur.read_u8()?;
        let len = if (flags & FLAG_EXT_LEN) != 0 {
            cur.read_u16()? as usize
        } else {
            cur.read_u8()? as usize
        };
        // fork advances the outer cursor past this attribute's bytes
        // unconditionally, so inner decode errors don't corrupt the stream.
        let mut val = cur.fork(len)?;

        // Duplicate attribute detection (RFC 7606 §7.3).
        if seen[type_code as usize] {
            errors.push(AttributeDecodeError {
                type_code,
                policy: AttributeErrorPolicy::TreatAsWithdraw,
                detail: "duplicate attribute type code",
            });
            continue;
        }
        seen[type_code as usize] = true;

        match decode_attr_value(flags, type_code, &mut val) {
            Ok(attr) => attrs.push(attr),
            Err(e) => errors.push(AttributeDecodeError {
                type_code,
                policy: rfc7606_policy(type_code),
                detail: error_detail(&e),
            }),
        }
    }

    Ok((attrs, errors))
}

#[allow(clippy::too_many_lines)]
fn decode_attr_value(
    flags: u8,
    type_code: u8,
    cur: &mut Cursor<'_>,
) -> Result<PathAttribute, CodecError> {
    match type_code {
        ATTR_ORIGIN => {
            if cur.remaining() < 1 {
                return Err(CodecError::InvalidAttribute {
                    type_code,
                    detail: "ORIGIN must be 1 byte",
                });
            }
            let v = cur.read_u8()?;
            let origin = Origin::from_u8(v).ok_or(CodecError::InvalidOrigin(v))?;
            Ok(PathAttribute::Origin(origin))
        }

        ATTR_AS_PATH => {
            let segments = decode_as_path_segments(cur)?;
            Ok(PathAttribute::AsPath(AsPath::from_segments(segments)))
        }

        ATTR_NEXT_HOP => {
            if cur.remaining() < 4 {
                return Err(CodecError::InvalidAttribute {
                    type_code,
                    detail: "NEXT_HOP must be 4 bytes",
                });
            }
            Ok(PathAttribute::NextHop(cur.read_ipv4addr()?))
        }

        ATTR_MED => {
            if cur.remaining() < 4 {
                return Err(CodecError::InvalidAttribute {
                    type_code,
                    detail: "MED must be 4 bytes",
                });
            }
            Ok(PathAttribute::Med(cur.read_u32()?))
        }

        ATTR_LOCAL_PREF => {
            if cur.remaining() < 4 {
                return Err(CodecError::InvalidAttribute {
                    type_code,
                    detail: "LOCAL_PREF must be 4 bytes",
                });
            }
            Ok(PathAttribute::LocalPref(cur.read_u32()?))
        }

        ATTR_ONLY_TO_CUSTOMER => {
            if cur.remaining() < 4 {
                return Err(CodecError::InvalidAttribute {
                    type_code,
                    detail: "ONLY_TO_CUSTOMER must be 4 bytes",
                });
            }
            Ok(PathAttribute::OnlyToCustomer(Asn::new(cur.read_u32()?)))
        }

        ATTR_ATOMIC_AGGREGATE => Ok(PathAttribute::AtomicAggregate),

        ATTR_AGGREGATOR => {
            if cur.remaining() < 8 {
                return Err(CodecError::InvalidAttribute {
                    type_code,
                    detail: "AGGREGATOR must be 8 bytes (4-byte ASN mode)",
                });
            }
            let asn = Asn::new(cur.read_u32()?);
            let ip = cur.read_ipv4addr()?;
            Ok(PathAttribute::Aggregator(Aggregator::new(asn, ip)))
        }

        ATTR_COMMUNITY => {
            if !cur.remaining().is_multiple_of(4) {
                return Err(CodecError::InvalidAttribute {
                    type_code,
                    detail: "COMMUNITY length must be a multiple of 4",
                });
            }
            let mut communities = Vec::new();
            while cur.remaining() > 0 {
                communities.push(Community::new(cur.read_u32()?));
            }
            Ok(PathAttribute::Communities(communities))
        }

        ATTR_ORIGINATOR_ID => {
            if cur.remaining() != 4 {
                return Err(CodecError::InvalidAttribute {
                    type_code,
                    detail: "ORIGINATOR_ID must be exactly 4 bytes",
                });
            }
            Ok(PathAttribute::OriginatorId(cur.read_ipv4addr()?))
        }

        ATTR_CLUSTER_LIST => {
            if !cur.remaining().is_multiple_of(4) {
                return Err(CodecError::InvalidAttribute {
                    type_code,
                    detail: "CLUSTER_LIST length must be a multiple of 4",
                });
            }
            let mut ids = Vec::with_capacity(cur.remaining() / 4);
            while cur.remaining() > 0 {
                ids.push(cur.read_u32()?);
            }
            Ok(PathAttribute::ClusterList(ids))
        }

        ATTR_MP_REACH_NLRI => {
            if cur.remaining() < 4 {
                return Err(CodecError::InvalidAttribute {
                    type_code,
                    detail: "MP_REACH_NLRI too short",
                });
            }
            let afi = Afi::new(cur.read_u16()?);
            let safi = Safi::new(cur.read_u8()?);
            let nh_len = cur.read_u8()? as usize;
            let nh_bytes = cur.read_bytes(nh_len)?;
            let next_hop = decode_next_hop(afi, nh_bytes)?;
            let _snpa = cur.read_u8()?; // reserved
            let prefixes = decode_mp_nlri(afi, cur)?;
            Ok(PathAttribute::MpReachNlri(MpReachNlri {
                afi_safi: AfiSafi::new(afi, safi),
                next_hop,
                prefixes,
            }))
        }

        ATTR_MP_UNREACH_NLRI => {
            if cur.remaining() < 3 {
                return Err(CodecError::InvalidAttribute {
                    type_code,
                    detail: "MP_UNREACH_NLRI too short",
                });
            }
            let afi = Afi::new(cur.read_u16()?);
            let safi = Safi::new(cur.read_u8()?);
            let prefixes = decode_mp_nlri(afi, cur)?;
            Ok(PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi_safi: AfiSafi::new(afi, safi),
                prefixes,
            }))
        }

        ATTR_EXTENDED_COMMUNITIES => {
            if !cur.remaining().is_multiple_of(8) {
                return Err(CodecError::InvalidAttribute {
                    type_code,
                    detail: "EXTENDED_COMMUNITIES length must be a multiple of 8",
                });
            }
            let mut ecs = Vec::new();
            while cur.remaining() > 0 {
                let bytes = cur.read_bytes(8)?;
                let arr: [u8; 8] = bytes.try_into().expect("read exactly 8 bytes");
                ecs.push(ExtendedCommunity::from_bytes(arr));
            }
            Ok(PathAttribute::ExtendedCommunities(ecs))
        }

        ATTR_AS4_PATH => {
            let segments = decode_as_path_segments(cur)?;
            Ok(PathAttribute::As4Path(AsPath::from_segments(segments)))
        }

        ATTR_AS4_AGGREGATOR => {
            if cur.remaining() < 8 {
                return Err(CodecError::InvalidAttribute {
                    type_code,
                    detail: "AS4_AGGREGATOR must be 8 bytes",
                });
            }
            let asn = cur.read_u32()?;
            let bgp_id = cur.read_ipv4addr()?;
            Ok(PathAttribute::As4Aggregator { asn, bgp_id })
        }

        ATTR_LARGE_COMMUNITY => {
            if !cur.remaining().is_multiple_of(12) {
                return Err(CodecError::InvalidAttribute {
                    type_code,
                    detail: "LARGE_COMMUNITY length must be a multiple of 12",
                });
            }
            let mut lcs = Vec::new();
            while cur.remaining() > 0 {
                let ga = cur.read_u32()?;
                let ld1 = cur.read_u32()?;
                let ld2 = cur.read_u32()?;
                lcs.push(LargeCommunity::new(ga, ld1, ld2));
            }
            Ok(PathAttribute::LargeCommunities(lcs))
        }

        _ => {
            let value = cur.read_remaining().to_vec();
            Ok(PathAttribute::Unknown {
                flags,
                type_code,
                value,
            })
        }
    }
}

/// Decode `AS_PATH` or `AS4_PATH` segments (always 4-byte ASNs).
fn decode_as_path_segments(cur: &mut Cursor<'_>) -> Result<Vec<AsPathSegment>, CodecError> {
    let mut segments = Vec::new();
    while cur.remaining() > 0 {
        let seg_type = cur.read_u8()?;
        let count = cur.read_u8()? as usize;
        let mut asns = Vec::with_capacity(count);
        for _ in 0..count {
            if cur.remaining() < 4 {
                return Err(CodecError::InvalidAttribute {
                    type_code: ATTR_AS_PATH,
                    detail: "truncated ASN in AS_PATH segment",
                });
            }
            asns.push(Asn::new(cur.read_u32()?));
        }
        let seg = match seg_type {
            SEG_SET => AsPathSegment::Set(asns),
            SEG_SEQUENCE => AsPathSegment::Sequence(asns),
            SEG_CONFED_SEQUENCE => AsPathSegment::ConfedSequence(asns),
            SEG_CONFED_SET => AsPathSegment::ConfedSet(asns),
            _ => return Err(CodecError::UnknownAsPathSegmentType(seg_type)),
        };
        segments.push(seg);
    }
    Ok(segments)
}

/// Decode the `NEXT_HOP` value from `MP_REACH_NLRI` based on the `AFI` and byte
/// length of the next-hop field.
fn decode_next_hop(afi: Afi, bytes: &[u8]) -> Result<NextHop, CodecError> {
    match (afi, bytes.len()) {
        (Afi::IPV4, 4) => Ok(NextHop::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        (Afi::IPV6, 16) => {
            let arr: [u8; 16] = bytes.try_into().expect("read exactly 16 bytes");
            Ok(NextHop::V6(Ipv6Addr::from(arr)))
        }
        (Afi::IPV6, 32) => {
            let global_arr: [u8; 16] = bytes[..16].try_into().expect("16 bytes");
            let ll_arr: [u8; 16] = bytes[16..].try_into().expect("16 bytes");
            Ok(NextHop::V6WithLinkLocal {
                global: Ipv6Addr::from(global_arr),
                link_local: Ipv6Addr::from(ll_arr),
            })
        }
        _ => Err(CodecError::InvalidAttribute {
            type_code: ATTR_MP_REACH_NLRI,
            detail: "unexpected next-hop length for AFI",
        }),
    }
}

/// Decode the NLRI list in `MP_REACH` or `MP_UNREACH` based on the AFI.
fn decode_mp_nlri(afi: Afi, cur: &mut Cursor<'_>) -> Result<Vec<Prefix>, CodecError> {
    if afi == Afi::IPV4 {
        Ok(decode_nlri_list_v4(cur)?
            .into_iter()
            .map(Prefix::V4)
            .collect())
    } else if afi == Afi::IPV6 {
        Ok(decode_nlri_list_v6(cur)?
            .into_iter()
            .map(Prefix::V6)
            .collect())
    } else {
        // For unknown AFIs, consume the remaining bytes without parsing.
        let _raw = cur.read_remaining();
        Ok(vec![])
    }
}

// ── Public encoding helpers ──────────────────────────────────────────────────

/// Returns the number of bytes an IPv4 NLRI occupies on the wire.
///
/// Wire format: 1-byte prefix length + `ceil(prefix_len / 8)` address bytes.
#[must_use]
pub fn nlri_encoded_len(nlri: &Nlri<Ipv4Addr>) -> usize {
    1 + (nlri.prefix_len() as usize).div_ceil(8)
}

/// Returns the number of bytes an IPv6 NLRI occupies on the wire.
///
/// Wire format: 1-byte prefix length + `ceil(prefix_len / 8)` address bytes
/// (same encoding as IPv4, just wider — up to 16 address bytes).
#[must_use]
pub fn nlri_v6_encoded_len(nlri: &Nlri<Ipv6Addr>) -> usize {
    1 + (nlri.prefix_len() as usize).div_ceil(8)
}

/// Encodes a slice of path attributes to their wire representation.
///
/// The returned bytes are the raw attribute TLVs with no length prefix —
/// suitable for use as a grouping key or for computing the attribute portion
/// of a BGP UPDATE's wire size.
#[must_use]
pub fn encode_attributes(attrs: &[PathAttribute]) -> Vec<u8> {
    encode_path_attributes(attrs)
}

// ── Path attribute encode ────────────────────────────────────────────────────

fn encode_path_attributes(attrs: &[PathAttribute]) -> Vec<u8> {
    let mut out = Writer::new();
    for attr in attrs {
        encode_one_path_attr(&mut out, attr);
    }
    out.finish()
}

/// Write one complete path attribute (flags + type + length + value) into `w`.
fn encode_one_path_attr(w: &mut Writer, attr: &PathAttribute) {
    let (flags, type_code, value) = encode_attr_value(attr);
    let ext_len = value.len() > 255;
    let flags = if ext_len { flags | FLAG_EXT_LEN } else { flags };
    w.put_u8(flags);
    w.put_u8(type_code);
    if ext_len {
        #[allow(clippy::cast_possible_truncation)]
        w.put_u16(value.len() as u16);
    } else {
        #[allow(clippy::cast_possible_truncation)]
        w.put_u8(value.len() as u8);
    }
    w.put_slice(&value);
}

#[allow(clippy::too_many_lines)]
fn encode_attr_value(attr: &PathAttribute) -> (u8, u8, Vec<u8>) {
    match attr {
        PathAttribute::Origin(origin) => (FLAGS_WKM, ATTR_ORIGIN, vec![origin.as_u8()]),

        PathAttribute::AsPath(path) => {
            let mut v = Writer::new();
            encode_as_path_segments(&mut v, path);
            (FLAGS_WKM, ATTR_AS_PATH, v.finish())
        }

        PathAttribute::NextHop(ip) => (FLAGS_WKM, ATTR_NEXT_HOP, ip.octets().to_vec()),

        PathAttribute::Med(med) => (FLAGS_ONT, ATTR_MED, med.to_be_bytes().to_vec()),

        PathAttribute::LocalPref(lp) => (FLAGS_WKM, ATTR_LOCAL_PREF, lp.to_be_bytes().to_vec()),

        PathAttribute::OnlyToCustomer(asn) => (
            FLAGS_OT,
            ATTR_ONLY_TO_CUSTOMER,
            u32::from(*asn).to_be_bytes().to_vec(),
        ),

        PathAttribute::AtomicAggregate => (FLAGS_WKM, ATTR_ATOMIC_AGGREGATE, vec![]),

        PathAttribute::Aggregator(agg) => {
            let mut v = Writer::new();
            v.put_u32(u32::from(agg.asn));
            v.put_slice(&agg.ip.octets());
            (FLAGS_OT, ATTR_AGGREGATOR, v.finish())
        }

        PathAttribute::Communities(communities) => {
            let mut v = Writer::new();
            for c in communities {
                v.put_u32(u32::from(*c));
            }
            (FLAGS_OT, ATTR_COMMUNITY, v.finish())
        }

        PathAttribute::OriginatorId(id) => (FLAGS_ONT, ATTR_ORIGINATOR_ID, id.octets().to_vec()),

        PathAttribute::ClusterList(ids) => {
            let mut v = Writer::new();
            for id in ids {
                v.put_u32(*id);
            }
            (FLAGS_ONT, ATTR_CLUSTER_LIST, v.finish())
        }

        PathAttribute::MpReachNlri(mp) => {
            let mut v = Writer::new();
            v.put_u16(mp.afi_safi.afi.as_u16());
            v.put_u8(mp.afi_safi.safi.as_u8());
            let nh_bytes = encode_next_hop(&mp.next_hop);
            #[allow(clippy::cast_possible_truncation)]
            v.put_u8(nh_bytes.len() as u8);
            v.put_slice(&nh_bytes);
            v.put_u8(0); // SNPA (reserved, must be 0)
            for prefix in &mp.prefixes {
                match prefix {
                    Prefix::V4(n) => encode_nlri_v4(&mut v, *n),
                    Prefix::V6(n) => encode_nlri_v6(&mut v, n),
                }
            }
            (FLAGS_ONT, ATTR_MP_REACH_NLRI, v.finish())
        }

        PathAttribute::MpUnreachNlri(mp) => {
            let mut v = Writer::new();
            v.put_u16(mp.afi_safi.afi.as_u16());
            v.put_u8(mp.afi_safi.safi.as_u8());
            for prefix in &mp.prefixes {
                match prefix {
                    Prefix::V4(n) => encode_nlri_v4(&mut v, *n),
                    Prefix::V6(n) => encode_nlri_v6(&mut v, n),
                }
            }
            (FLAGS_ONT, ATTR_MP_UNREACH_NLRI, v.finish())
        }

        PathAttribute::ExtendedCommunities(ecs) => {
            let mut v = Writer::new();
            for ec in ecs {
                v.put_slice(ec.as_bytes());
            }
            (FLAGS_OT, ATTR_EXTENDED_COMMUNITIES, v.finish())
        }

        PathAttribute::As4Path(path) => {
            let mut v = Writer::new();
            encode_as_path_segments(&mut v, path);
            (FLAGS_OT, ATTR_AS4_PATH, v.finish())
        }

        PathAttribute::As4Aggregator { asn, bgp_id } => {
            let mut v = Writer::new();
            v.put_u32(*asn);
            v.put_slice(&bgp_id.octets());
            (FLAGS_OT, ATTR_AS4_AGGREGATOR, v.finish())
        }

        PathAttribute::LargeCommunities(lcs) => {
            let mut v = Writer::new();
            for lc in lcs {
                v.put_u32(lc.global_administrator);
                v.put_u32(lc.local_data_1);
                v.put_u32(lc.local_data_2);
            }
            (FLAGS_OT, ATTR_LARGE_COMMUNITY, v.finish())
        }

        PathAttribute::Unknown {
            flags,
            type_code,
            value,
        } => {
            // RFC 4271 §5: the Partial bit MUST be set when forwarding an
            // unrecognised optional transitive attribute.
            let flags = if flags & FLAG_OPTIONAL != 0 && flags & FLAG_TRANSITIVE != 0 {
                flags | FLAG_PARTIAL
            } else {
                *flags
            };
            (flags, *type_code, value.clone())
        }
    }
}

fn encode_as_path_segments(w: &mut Writer, path: &AsPath) {
    for seg in path.segments() {
        let (seg_type, asns) = match seg {
            AsPathSegment::Set(a) => (SEG_SET, a),
            AsPathSegment::Sequence(a) => (SEG_SEQUENCE, a),
            AsPathSegment::ConfedSequence(a) => (SEG_CONFED_SEQUENCE, a),
            AsPathSegment::ConfedSet(a) => (SEG_CONFED_SET, a),
        };
        w.put_u8(seg_type);
        #[allow(clippy::cast_possible_truncation)]
        w.put_u8(asns.len() as u8);
        for asn in asns {
            w.put_u32(u32::from(*asn));
        }
    }
}

fn encode_next_hop(nh: &NextHop) -> Vec<u8> {
    match nh {
        NextHop::V4(ip) => ip.octets().to_vec(),
        NextHop::V6(ip) => ip.octets().to_vec(),
        NextHop::V6WithLinkLocal { global, link_local } => {
            let mut v = global.octets().to_vec();
            v.extend_from_slice(&link_local.octets());
            v
        }
    }
}

// ── Public types ─────────────────────────────────────────────────────────────

/// A BGP path attribute.
///
/// Typed variants are provided for all attributes defined in the core RFCs.
/// Any attribute whose type code is not recognised is preserved in the
/// `Unknown` variant so that optional-transitive attributes can be forwarded
/// without corruption.
#[derive(Debug, Clone, PartialEq)]
pub enum PathAttribute {
    /// `ORIGIN` (type 1) — IGP, EGP, or Incomplete.
    Origin(Origin),
    /// `AS_PATH` (type 2) — the sequence of ASes the route has traversed.
    /// Decoded assuming 4-byte ASNs (modern default).
    AsPath(AsPath),
    /// `NEXT_HOP` (type 3) — IPv4 forwarding address for IPv4 unicast routes.
    NextHop(Ipv4Addr),
    /// `MULTI_EXIT_DISC` (type 4) — MED hint to neighbouring AS.
    Med(u32),
    /// `LOCAL_PREF` (type 5) — inbound preference lever; higher wins.
    LocalPref(u32),
    /// `ATOMIC_AGGREGATE` (type 6) — signals that path info was suppressed
    /// during aggregation.
    AtomicAggregate,
    /// `AGGREGATOR` (type 7) — ASN and router-id of the aggregating router.
    Aggregator(Aggregator),
    /// `COMMUNITY` (type 8, RFC 1997) — standard 32-bit community tags.
    Communities(Vec<Community>),
    /// `ORIGINATOR_ID` (type 9, RFC 4456) — BGP Identifier of the router
    /// that first injected this route into the iBGP mesh via a route
    /// reflector. Set by the first reflector to receive the route from a
    /// client; not modified by subsequent reflectors.
    OriginatorId(Ipv4Addr),
    /// `CLUSTER_LIST` (type 10, RFC 4456) — ordered list of `CLUSTER_ID`
    /// values (4-byte each) identifying the route-reflector clusters this
    /// route has passed through. Used for loop detection: a reflector that
    /// sees its own `cluster_id` in this list discards the route.
    ClusterList(Vec<u32>),
    /// `MP_REACH_NLRI` (type 14, RFC 4760) — reachable prefixes for
    /// non-IPv4-unicast address families.
    MpReachNlri(MpReachNlri),
    /// `MP_UNREACH_NLRI` (type 15, RFC 4760) — withdrawn prefixes for
    /// non-IPv4-unicast address families.
    MpUnreachNlri(MpUnreachNlri),
    /// `EXTENDED_COMMUNITIES` (type 16, RFC 4360) — 8-byte typed community
    /// tags; used heavily in MPLS VPN and EVPN.
    ExtendedCommunities(Vec<ExtendedCommunity>),
    /// `AS4_PATH` (type 17, RFC 6793) — 4-byte AS path used during the
    /// 2-byte → 4-byte ASN transition.
    As4Path(AsPath),
    /// `AS4_AGGREGATOR` (type 18, RFC 6793) — 4-byte AGGREGATOR used during
    /// the transition.
    As4Aggregator { asn: u32, bgp_id: Ipv4Addr },
    /// `LARGE_COMMUNITY` (type 32, RFC 8092) — three-field community designed
    /// for 4-byte ASN operators.
    LargeCommunities(Vec<LargeCommunity>),
    /// `ONLY_TO_CUSTOMER` (type 35, RFC 9234) — route-leak prevention marker.
    /// Carries the ASN of the peer the route was received from (ingress) or
    /// the local ASN (egress). Once set, must be preserved unchanged and must
    /// not be forwarded to a Provider, Peer, or Route Server — only to
    /// Customers/RS-Clients.
    OnlyToCustomer(Asn),
    /// Any unrecognised attribute. Flags and value are preserved intact so
    /// optional-transitive attributes can be forwarded to the next hop.
    Unknown {
        flags: u8,
        type_code: u8,
        value: Vec<u8>,
    },
}

impl PathAttribute {
    /// Returns the BGP type code for this attribute (used for duplicate detection).
    #[must_use]
    pub fn type_code(&self) -> u8 {
        match self {
            Self::Origin(_) => ATTR_ORIGIN,
            Self::AsPath(_) => ATTR_AS_PATH,
            Self::NextHop(_) => ATTR_NEXT_HOP,
            Self::Med(_) => ATTR_MED,
            Self::LocalPref(_) => ATTR_LOCAL_PREF,
            Self::AtomicAggregate => ATTR_ATOMIC_AGGREGATE,
            Self::Aggregator(_) => ATTR_AGGREGATOR,
            Self::Communities(_) => ATTR_COMMUNITY,
            Self::OriginatorId(_) => ATTR_ORIGINATOR_ID,
            Self::ClusterList(_) => ATTR_CLUSTER_LIST,
            Self::MpReachNlri(_) => ATTR_MP_REACH_NLRI,
            Self::MpUnreachNlri(_) => ATTR_MP_UNREACH_NLRI,
            Self::ExtendedCommunities(_) => ATTR_EXTENDED_COMMUNITIES,
            Self::As4Path(_) => ATTR_AS4_PATH,
            Self::As4Aggregator { .. } => ATTR_AS4_AGGREGATOR,
            Self::LargeCommunities(_) => ATTR_LARGE_COMMUNITY,
            Self::OnlyToCustomer(_) => ATTR_ONLY_TO_CUSTOMER,
            Self::Unknown { type_code, .. } => *type_code,
        }
    }
}

/// Reachable prefixes for a specific AFI/SAFI, carried in `MP_REACH_NLRI`.
#[derive(Debug, Clone, PartialEq)]
pub struct MpReachNlri {
    pub afi_safi: AfiSafi,
    pub next_hop: NextHop,
    pub prefixes: Vec<Prefix>,
}

/// Withdrawn prefixes for a specific AFI/SAFI, carried in `MP_UNREACH_NLRI`.
#[derive(Debug, Clone, PartialEq)]
pub struct MpUnreachNlri {
    pub afi_safi: AfiSafi,
    pub prefixes: Vec<Prefix>,
}

/// An NLRI prefix from any address family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prefix {
    V4(Nlri<Ipv4Addr>),
    V6(Nlri<Ipv6Addr>),
}

#[cfg(test)]
mod tests {
    use pathvector_types::Asn;

    use super::*;

    fn roundtrip(msg: UpdateMessage) {
        let encoded = msg.encode();
        let mut cur = Cursor::new(&encoded[19..]);
        assert_eq!(
            UpdateMessage::decode(&mut cur).unwrap(),
            UpdateDecodeOutcome::Clean(msg)
        );
    }

    fn nlri4(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn nlri6(s: &str) -> Nlri<Ipv6Addr> {
        s.parse().unwrap()
    }

    #[test]
    fn test_empty_update_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_withdrawal_only_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![nlri4("10.0.0.0/8"), nlri4("192.168.0.0/16")],
            attributes: vec![],
            announced: vec![],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_announcement_with_core_attributes() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![
                    Asn::new(65001),
                    Asn::new(65002),
                ])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
                PathAttribute::Med(100),
                PathAttribute::LocalPref(200),
            ],
            announced: vec![nlri4("10.0.0.0/8")],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_communities_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::Communities(vec![
                    Community::new(0xFDE8_0064), // 65000:100
                    Community::new(0xFDE8_00C8), // 65000:200
                ]),
            ],
            announced: vec![nlri4("172.16.0.0/12")],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_large_communities_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Egp),
                PathAttribute::LargeCommunities(vec![
                    LargeCommunity::new(65000, 1, 100),
                    LargeCommunity::new(65001, 2, 200),
                ]),
            ],
            announced: vec![nlri4("192.0.2.0/24")],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_atomic_aggregate_and_aggregator_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Incomplete),
                PathAttribute::AtomicAggregate,
                PathAttribute::Aggregator(Aggregator::new(
                    Asn::new(65000),
                    Ipv4Addr::new(10, 0, 0, 1),
                )),
            ],
            announced: vec![nlri4("10.0.0.0/8")],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_only_to_customer_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::OnlyToCustomer(Asn::new(65000)),
            ],
            announced: vec![nlri4("192.0.2.0/24")],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_only_to_customer_encodes_as_optional_transitive() {
        // RFC 9234 §3: OTC must be optional (0x80) + transitive (0x40) = 0xC0.
        let attr = PathAttribute::OnlyToCustomer(Asn::new(65000));
        let (flags, type_code, _) = encode_attr_value(&attr);
        assert_eq!(flags, FLAGS_OT);
        assert_eq!(type_code, 35);
    }

    #[test]
    fn test_mp_reach_ipv6_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::MpReachNlri(MpReachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                prefixes: vec![Prefix::V6(nlri6("2001:db8::/32"))],
            })],
            announced: vec![],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_mp_unreach_ipv6_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                prefixes: vec![Prefix::V6(nlri6("2001:db8::/32"))],
            })],
            announced: vec![],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_unknown_attribute_preserved() {
        // Input already has the Partial bit set (as it would after the first
        // forwarding hop). The encoder must preserve it and the value unchanged.
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::Unknown {
                flags: FLAGS_OT | FLAG_PARTIAL,
                type_code: 200,
                value: vec![0xDE, 0xAD, 0xBE, 0xEF],
            }],
            announced: vec![],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_unknown_optional_transitive_partial_bit_set_on_reencode() {
        // RFC 4271 §5: when forwarding an unrecognised optional transitive
        // attribute, the Partial bit MUST be set even if the originating
        // router did not set it.
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::Unknown {
                flags: FLAGS_OT, // no Partial bit — as received from the originator
                type_code: 200,
                value: vec![1, 2, 3],
            }],
            announced: vec![],
        };
        let encoded = msg.encode();
        let mut cur = Cursor::new(&encoded[19..]);
        assert_eq!(
            UpdateMessage::decode(&mut cur).unwrap(),
            UpdateDecodeOutcome::Clean(UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::Unknown {
                    flags: FLAGS_OT | FLAG_PARTIAL,
                    type_code: 200,
                    value: vec![1, 2, 3],
                }],
                announced: vec![],
            }),
            "Partial bit must be set on re-encode of unrecognised optional transitive attribute (RFC 4271 §5)"
        );
    }

    #[test]
    fn test_unknown_non_transitive_partial_bit_not_set() {
        // RFC 4271 §5: the Partial bit must NOT be set for optional
        // non-transitive attributes, since they are not forwarded.
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::Unknown {
                flags: FLAGS_ONT, // optional, non-transitive
                type_code: 201,
                value: vec![0xAB],
            }],
            announced: vec![],
        };
        // roundtrip asserts full equality — unchanged flags proves Partial bit was not added
        roundtrip(msg);
    }

    #[test]
    fn test_as_path_with_set_roundtrip() {
        let path = AsPath::from_segments(vec![
            AsPathSegment::Sequence(vec![Asn::new(65003)]),
            AsPathSegment::Set(vec![Asn::new(65001), Asn::new(65002)]),
        ]);
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(path),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
            ],
            announced: vec![nlri4("10.0.0.0/8")],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_nlri_variable_length_encoding() {
        // /8 prefix: only 1 address byte on the wire.
        // /0 prefix: no address bytes on the wire.
        let msg = UpdateMessage {
            withdrawn: vec![
                nlri4("0.0.0.0/0"),
                nlri4("10.0.0.0/8"),
                nlri4("192.168.1.0/24"),
                nlri4("10.1.2.3/32"),
            ],
            attributes: vec![],
            announced: vec![],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_invalid_origin_is_treat_as_withdraw() {
        // RFC 7606 §5: malformed ORIGIN → treat as withdraw, not session reset.
        let body: &[u8] = &[0x00, 0x00, 0x00, 0x04, FLAGS_WKM, ATTR_ORIGIN, 0x01, 99];
        assert_eq!(
            decode_raw(body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_ORIGIN,
                    policy: AttributeErrorPolicy::TreatAsWithdraw,
                    detail: "invalid ORIGIN value",
                }],
                treat_as_withdraw: true,
            }
        );
    }

    // ── Missing roundtrip coverage ────────────────────────────────────────────

    #[test]
    fn test_extended_communities_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::ExtendedCommunities(vec![
                ExtendedCommunity::from_bytes([0x00, 0x02, 0xFF, 0xE9, 0x00, 0x00, 0x00, 0x64]),
            ])],
            announced: vec![],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_as4_path_roundtrip() {
        let path = AsPath::from_sequence(vec![Asn::new(131_072), Asn::new(131_073)]);
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::As4Path(path)],
            announced: vec![],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_as4_aggregator_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::As4Aggregator {
                asn: 131_072,
                bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            }],
            announced: vec![],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_mp_reach_ipv4_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::MpReachNlri(MpReachNlri {
                afi_safi: AfiSafi::IPV4_UNICAST,
                next_hop: NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)),
                prefixes: vec![Prefix::V4(nlri4("10.0.0.0/8"))],
            })],
            announced: vec![],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_mp_reach_ipv6_link_local_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::MpReachNlri(MpReachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                next_hop: NextHop::V6WithLinkLocal {
                    global: "2001:db8::1".parse().unwrap(),
                    link_local: "fe80::1".parse().unwrap(),
                },
                prefixes: vec![Prefix::V6(nlri6("2001:db8::/32"))],
            })],
            announced: vec![],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_mp_unreach_ipv4_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi_safi: AfiSafi::IPV4_UNICAST,
                prefixes: vec![Prefix::V4(nlri4("10.0.0.0/8"))],
            })],
            announced: vec![],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_as_path_confed_segments_roundtrip() {
        let path = AsPath::from_segments(vec![
            AsPathSegment::ConfedSequence(vec![Asn::new(65001), Asn::new(65002)]),
            AsPathSegment::ConfedSet(vec![Asn::new(65003)]),
        ]);
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::AsPath(path)],
            announced: vec![],
        };
        roundtrip(msg);
    }

    #[test]
    fn test_extended_length_encode_path() {
        // 65 communities × 4 bytes = 260 bytes → encode_one_path_attr uses ext-len.
        let communities: Vec<Community> = (0u32..65).map(Community::new).collect();
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::Communities(communities)],
            announced: vec![],
        };
        roundtrip(msg);
    }

    // ── Raw-byte decode helpers ───────────────────────────────────────────────

    fn decode_raw(body: &[u8]) -> Result<UpdateDecodeOutcome, CodecError> {
        let mut cur = Cursor::new(body);
        UpdateMessage::decode(&mut cur)
    }

    /// Build an UPDATE body: no withdrawn routes, one path attribute (short len).
    fn update_with_attr(flags: u8, type_code: u8, value: &[u8]) -> Vec<u8> {
        let attr_total = 3 + value.len(); // flags + type + 1-byte len + value
        let mut body = vec![0u8, 0]; // withdrawn_len = 0
        body.extend_from_slice(&u16::try_from(attr_total).unwrap().to_be_bytes());
        body.push(flags);
        body.push(type_code);
        body.push(u8::try_from(value.len()).unwrap());
        body.extend_from_slice(value);
        body
    }

    /// Build an UPDATE body using the extended-length (2-byte) flag.
    fn update_with_ext_attr(flags: u8, type_code: u8, value: &[u8]) -> Vec<u8> {
        let attr_total = 4 + value.len(); // flags + type + 2-byte len + value
        let mut body = vec![0u8, 0];
        body.extend_from_slice(&u16::try_from(attr_total).unwrap().to_be_bytes());
        body.push(flags | FLAG_EXT_LEN);
        body.push(type_code);
        body.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        body.extend_from_slice(value);
        body
    }

    // ── NLRI error paths ──────────────────────────────────────────────────────

    #[test]
    fn test_invalid_ipv4_nlri_prefix_too_long() {
        // withdrawn prefix_len = 33 (> 32 for IPv4) — structural error in the
        // withdrawn-routes block → session reset (not an attribute error).
        let body: &[u8] = &[0x00, 0x02, 33, 0x00, 0x00, 0x00];
        assert!(matches!(
            decode_raw(body),
            Err(CodecError::InvalidNlri { prefix_len: 33 })
        ));
    }

    #[test]
    fn test_invalid_ipv6_nlri_prefix_too_long_is_attribute_discard() {
        // MP_UNREACH NLRI with IPv6 prefix_len = 129 (> 128).
        // This is inside an MP_UNREACH_NLRI attribute value (type 15), so
        // RFC 7606 applies: attribute discard, not session reset.
        let mp_body: &[u8] = &[0x00, 0x02, 0x01, 129, 0x00]; // AFI=2 IPv6, SAFI=1, pfx_len=129
        let body = update_with_attr(FLAGS_ONT, ATTR_MP_UNREACH_NLRI, mp_body);
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_MP_UNREACH_NLRI,
                    policy: AttributeErrorPolicy::AttributeDiscard,
                    detail: "malformed attribute",
                }],
                treat_as_withdraw: false,
            }
        );
    }

    // ── Extended-length attribute ─────────────────────────────────────────────

    #[test]
    fn test_extended_length_origin_attribute() {
        let body = update_with_ext_attr(FLAGS_WKM, ATTR_ORIGIN, &[0u8]); // ORIGIN=IGP
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Clean(UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::Origin(Origin::Igp)],
                announced: vec![],
            })
        );
    }

    // ── RFC 7606 per-attribute error policy tests ─────────────────────────────
    //
    // Each test verifies the RFC 7606 §5 policy for a malformed attribute:
    //   TreatAsWithdraw — well-known mandatory attributes
    //   AttributeDiscard — optional attributes

    #[test]
    fn test_origin_too_short_is_treat_as_withdraw() {
        let body = update_with_attr(FLAGS_WKM, ATTR_ORIGIN, &[]);
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_ORIGIN,
                    policy: AttributeErrorPolicy::TreatAsWithdraw,
                    detail: "ORIGIN must be 1 byte",
                }],
                treat_as_withdraw: true,
            }
        );
    }

    #[test]
    fn test_next_hop_too_short_is_treat_as_withdraw() {
        let body = update_with_attr(FLAGS_WKM, ATTR_NEXT_HOP, &[10, 0, 0]); // 3 bytes, needs 4
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_NEXT_HOP,
                    policy: AttributeErrorPolicy::TreatAsWithdraw,
                    detail: "NEXT_HOP must be 4 bytes",
                }],
                treat_as_withdraw: true,
            }
        );
    }

    #[test]
    fn test_local_pref_too_short_is_treat_as_withdraw() {
        let body = update_with_attr(FLAGS_WKM, ATTR_LOCAL_PREF, &[0u8; 3]);
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_LOCAL_PREF,
                    policy: AttributeErrorPolicy::TreatAsWithdraw,
                    detail: "LOCAL_PREF must be 4 bytes",
                }],
                treat_as_withdraw: true,
            }
        );
    }

    #[test]
    fn test_mp_reach_nlri_too_short_is_treat_as_withdraw() {
        let body = update_with_attr(FLAGS_ONT, ATTR_MP_REACH_NLRI, &[0x00, 0x01]); // only 2 bytes
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_MP_REACH_NLRI,
                    policy: AttributeErrorPolicy::TreatAsWithdraw,
                    detail: "MP_REACH_NLRI too short",
                }],
                treat_as_withdraw: true,
            }
        );
    }

    #[test]
    fn test_as_path_unknown_segment_is_treat_as_withdraw() {
        let body = update_with_attr(FLAGS_WKM, ATTR_AS_PATH, &[9, 0]); // unknown seg type
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_AS_PATH,
                    policy: AttributeErrorPolicy::TreatAsWithdraw,
                    detail: "unknown AS_PATH segment type",
                }],
                treat_as_withdraw: true,
            }
        );
    }

    #[test]
    fn test_med_too_short_is_attribute_discard() {
        let body = update_with_attr(FLAGS_ONT, ATTR_MED, &[0u8; 3]);
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_MED,
                    policy: AttributeErrorPolicy::AttributeDiscard,
                    detail: "MED must be 4 bytes",
                }],
                treat_as_withdraw: false,
            }
        );
    }

    #[test]
    fn test_aggregator_too_short_is_attribute_discard() {
        let body = update_with_attr(FLAGS_OT, ATTR_AGGREGATOR, &[0u8; 7]); // needs 8
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_AGGREGATOR,
                    policy: AttributeErrorPolicy::AttributeDiscard,
                    detail: "AGGREGATOR must be 8 bytes (4-byte ASN mode)",
                }],
                treat_as_withdraw: false,
            }
        );
    }

    #[test]
    fn test_community_bad_length_is_attribute_discard() {
        let body = update_with_attr(FLAGS_OT, ATTR_COMMUNITY, &[0u8; 3]); // not multiple of 4
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_COMMUNITY,
                    policy: AttributeErrorPolicy::AttributeDiscard,
                    detail: "COMMUNITY length must be a multiple of 4",
                }],
                treat_as_withdraw: false,
            }
        );
    }

    #[test]
    fn test_mp_unreach_nlri_too_short_is_attribute_discard() {
        let body = update_with_attr(FLAGS_ONT, ATTR_MP_UNREACH_NLRI, &[0x00]); // only 1 byte
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_MP_UNREACH_NLRI,
                    policy: AttributeErrorPolicy::AttributeDiscard,
                    detail: "MP_UNREACH_NLRI too short",
                }],
                treat_as_withdraw: false,
            }
        );
    }

    #[test]
    fn test_extended_communities_bad_length_is_attribute_discard() {
        let body = update_with_attr(FLAGS_OT, ATTR_EXTENDED_COMMUNITIES, &[0u8; 7]); // not multiple of 8
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_EXTENDED_COMMUNITIES,
                    policy: AttributeErrorPolicy::AttributeDiscard,
                    detail: "EXTENDED_COMMUNITIES length must be a multiple of 8",
                }],
                treat_as_withdraw: false,
            }
        );
    }

    #[test]
    fn test_as4_aggregator_too_short_is_attribute_discard() {
        let body = update_with_attr(FLAGS_OT, ATTR_AS4_AGGREGATOR, &[0u8; 7]); // needs 8
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_AS4_AGGREGATOR,
                    policy: AttributeErrorPolicy::AttributeDiscard,
                    detail: "AS4_AGGREGATOR must be 8 bytes",
                }],
                treat_as_withdraw: false,
            }
        );
    }

    #[test]
    fn test_large_community_bad_length_is_attribute_discard() {
        let body = update_with_attr(FLAGS_OT, ATTR_LARGE_COMMUNITY, &[0u8; 11]); // not multiple of 12
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_LARGE_COMMUNITY,
                    policy: AttributeErrorPolicy::AttributeDiscard,
                    detail: "LARGE_COMMUNITY length must be a multiple of 12",
                }],
                treat_as_withdraw: false,
            }
        );
    }

    // ── RFC 7606 §7.3 — duplicate attribute → treat as withdraw ──────────────

    #[test]
    fn test_duplicate_attribute_is_treat_as_withdraw() {
        // Two ORIGIN attributes in the same UPDATE.
        let mut body = vec![0x00, 0x00]; // no withdrawn
        let attr = |v: u8| [FLAGS_WKM, ATTR_ORIGIN, 0x01, v];
        let attrs: Vec<u8> = attr(0).iter().chain(attr(1).iter()).copied().collect();
        body.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&attrs);
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![PathAttribute::Origin(Origin::Igp)],
                    announced: vec![],
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_ORIGIN,
                    policy: AttributeErrorPolicy::TreatAsWithdraw,
                    detail: "duplicate attribute type code",
                }],
                treat_as_withdraw: true,
            }
        );
    }

    // ── RFC 7606: good attributes survive alongside bad ones ──────────────────

    #[test]
    fn test_attribute_discard_preserves_other_attrs() {
        // MED is malformed (3 bytes) but ORIGIN is fine.
        // The result should be Partial with only ORIGIN in the decoded attrs.
        let mut body = vec![0x00, 0x00]; // no withdrawn
        let origin_attr = [FLAGS_WKM, ATTR_ORIGIN, 0x01, 0x00u8]; // ORIGIN=IGP
        let bad_med = [FLAGS_ONT, ATTR_MED, 0x03, 0x00, 0x00, 0x00u8]; // MED, 3 bytes (needs 4)
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&origin_attr);
        attrs.extend_from_slice(&bad_med);
        body.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&attrs);

        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![PathAttribute::Origin(Origin::Igp)],
                    announced: vec![],
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_MED,
                    policy: AttributeErrorPolicy::AttributeDiscard,
                    detail: "MED must be 4 bytes",
                }],
                treat_as_withdraw: false,
            }
        );
    }

    // ── AS_PATH error and edge cases ──────────────────────────────────────────

    #[test]
    fn test_unknown_as_path_segment_type_is_treat_as_withdraw() {
        // seg_type=9 (unknown), count=0
        let body = update_with_attr(FLAGS_WKM, ATTR_AS_PATH, &[9, 0]);
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_AS_PATH,
                    policy: AttributeErrorPolicy::TreatAsWithdraw,
                    detail: "unknown AS_PATH segment type",
                }],
                treat_as_withdraw: true,
            }
        );
    }

    #[test]
    fn test_truncated_asn_in_as_path_is_treat_as_withdraw() {
        // SEG_SEQUENCE, count=2, but only 4 bytes (enough for 1 ASN, not 2).
        let body = update_with_attr(FLAGS_WKM, ATTR_AS_PATH, &[2, 2, 0, 0, 0x00, 0x01]);
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_AS_PATH,
                    policy: AttributeErrorPolicy::TreatAsWithdraw,
                    detail: "truncated ASN in AS_PATH segment",
                }],
                treat_as_withdraw: true,
            }
        );
    }

    // ── MP_REACH next-hop error paths ─────────────────────────────────────────

    #[test]
    fn test_mp_reach_invalid_next_hop_length_is_treat_as_withdraw() {
        // AFI=IPv4, SAFI=1, nh_len=3 (not 4 → decode_next_hop fails).
        let mp_body: &[u8] = &[
            0x00, 0x01, // AFI = IPv4
            0x01, // SAFI = unicast
            0x03, // nh_len = 3
            10, 0, 0,    // 3 next-hop bytes (should be 4)
            0x00, // SNPA
        ];
        let body = update_with_attr(FLAGS_ONT, ATTR_MP_REACH_NLRI, mp_body);
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_MP_REACH_NLRI,
                    policy: AttributeErrorPolicy::TreatAsWithdraw,
                    detail: "unexpected next-hop length for AFI",
                }],
                treat_as_withdraw: true,
            }
        );
    }

    // ── Unknown AFI in MP_UNREACH → decode_mp_nlri else branch ───────────────

    #[test]
    fn test_mp_unreach_unknown_afi_produces_empty_prefixes() {
        // AFI=9 (unknown), no further NLRI bytes.
        let mp_body: &[u8] = &[0x00, 0x09, 0x01]; // AFI=9, SAFI=1
        let body = update_with_attr(FLAGS_ONT, ATTR_MP_UNREACH_NLRI, mp_body);
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Clean(UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi_safi: AfiSafi::new(Afi::new(9), Safi::new(1)),
                    prefixes: vec![],
                })],
                announced: vec![],
            })
        );
    }

    // ── error_detail Truncated path ───────────────────────────────────────────

    #[test]
    fn test_as_path_truncated_mid_segment_is_treat_as_withdraw() {
        // AS_PATH with one byte (segment-type only, count byte missing) triggers
        // CodecError::Truncated from read_u8(), exercising the Truncated arm of
        // error_detail().
        let body = update_with_attr(FLAGS_WKM, ATTR_AS_PATH, &[0x02]);
        assert_eq!(
            decode_raw(&body).unwrap(),
            UpdateDecodeOutcome::Partial {
                update: UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![]
                },
                errors: vec![AttributeDecodeError {
                    type_code: ATTR_AS_PATH,
                    policy: AttributeErrorPolicy::TreatAsWithdraw,
                    detail: "attribute value truncated",
                }],
                treat_as_withdraw: true,
            }
        );
    }

    // ── Public encoding helpers ───────────────────────────────────────────────

    #[test]
    fn test_nlri_encoded_len_values() {
        assert_eq!(nlri_encoded_len(&nlri4("0.0.0.0/0")), 1); // 1 + 0
        assert_eq!(nlri_encoded_len(&nlri4("10.0.0.0/8")), 2); // 1 + 1
        assert_eq!(nlri_encoded_len(&nlri4("10.0.0.0/24")), 4); // 1 + 3
        assert_eq!(nlri_encoded_len(&nlri4("10.0.0.1/32")), 5); // 1 + 4
    }

    #[test]
    fn test_encode_attributes_non_empty() {
        let attrs = vec![PathAttribute::Origin(Origin::Igp)];
        let bytes = encode_attributes(&attrs);
        // ORIGIN attr: flags(1) + type(1) + len(1) + value(1) = 4 bytes
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[1], ATTR_ORIGIN);
    }

    // ── PathAttribute::type_code for remaining variants ───────────────────────

    #[test]
    fn test_type_code_for_uncovered_path_attribute_variants() {
        assert_eq!(
            PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi_safi: pathvector_types::AfiSafi::IPV4_UNICAST,
                prefixes: vec![],
            })
            .type_code(),
            ATTR_MP_UNREACH_NLRI
        );
        assert_eq!(
            PathAttribute::ExtendedCommunities(vec![]).type_code(),
            ATTR_EXTENDED_COMMUNITIES
        );
        assert_eq!(
            PathAttribute::As4Path(AsPath::from_segments(vec![])).type_code(),
            ATTR_AS4_PATH
        );
        assert_eq!(
            PathAttribute::As4Aggregator {
                asn: 65001,
                bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            }
            .type_code(),
            ATTR_AS4_AGGREGATOR
        );
        assert_eq!(
            PathAttribute::Unknown {
                type_code: 200,
                flags: 0,
                value: vec![],
            }
            .type_code(),
            200
        );
        assert_eq!(
            PathAttribute::OriginatorId(Ipv4Addr::UNSPECIFIED).type_code(),
            ATTR_ORIGINATOR_ID
        );
        assert_eq!(
            PathAttribute::ClusterList(vec![]).type_code(),
            ATTR_CLUSTER_LIST
        );
    }

    /// `ORIGINATOR_ID` (type 9) encodes as 4-byte IPv4 address and round-trips.
    #[test]
    fn test_originator_id_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
                PathAttribute::OriginatorId(Ipv4Addr::new(192, 168, 1, 1)),
            ],
            announced: vec![nlri4("10.0.0.0/8")],
        };
        roundtrip(msg);
    }

    /// `CLUSTER_LIST` (type 10) encodes as packed u32 list and round-trips.
    #[test]
    fn test_cluster_list_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
                PathAttribute::ClusterList(vec![0x0101_0101, 0x0202_0202, 0x0303_0303]),
            ],
            announced: vec![nlri4("10.0.0.0/8")],
        };
        roundtrip(msg);
    }

    /// Empty `CLUSTER_LIST` round-trips without error.
    #[test]
    fn test_empty_cluster_list_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
                PathAttribute::ClusterList(vec![]),
            ],
            announced: vec![nlri4("10.0.0.0/8")],
        };
        roundtrip(msg);
    }

    /// `ORIGINATOR_ID` with wrong length (3 bytes instead of 4) is rejected.
    ///
    /// Hand-crafted UPDATE: 19-byte header + 2-byte withdrawn-len (0) +
    /// 2-byte attr-len (6) + attr [flags=0x80, type=9, len=3, val=1,2,3] +
    /// 0-byte NLRI.
    #[test]
    fn test_originator_id_wrong_length_is_error() {
        // flags: optional non-transitive (0x80), type=9, length=3, value=[1,2,3]
        let attr: &[u8] = &[0x80, 9, 3, 1, 2, 3];
        let attr_len = u16::try_from(attr.len()).unwrap();
        let total_len = u16::try_from(19 + 2 + 2 + attr.len()).unwrap();

        let mut msg = Vec::new();
        msg.extend_from_slice(&[0xff_u8; 16]); // marker
        msg.extend_from_slice(&total_len.to_be_bytes()); // length
        msg.push(2); // type = UPDATE
        msg.extend_from_slice(&0u16.to_be_bytes()); // withdrawn-len
        msg.extend_from_slice(&attr_len.to_be_bytes()); // attr-len
        msg.extend_from_slice(attr);

        let mut cur = Cursor::new(&msg[19..]);
        let result = UpdateMessage::decode(&mut cur);
        assert!(
            result.is_err() || matches!(result, Ok(UpdateDecodeOutcome::Partial { .. })),
            "ORIGINATOR_ID with 3-byte value must be an error or partial decode"
        );
    }
}

// ── RFC 7606 property tests ───────────────────────────────────────────────────

#[cfg(test)]
mod prop_tests {
    use std::net::Ipv4Addr;

    use proptest::prelude::*;

    use super::*;

    // ── Encode/decode roundtrip properties ───────────────────────────────────

    /// Generate an arbitrary `Nlri<Ipv4Addr>` within the 10.x.0.0/8..24 block.
    fn arb_nlri_v4() -> impl Strategy<Value = Nlri<Ipv4Addr>> {
        (0u8..=255u8, 0u8..=24u8).prop_map(|(b, prefix_len)| {
            // Mask the host bits so the network address is canonical.
            let shift = 32u32.saturating_sub(u32::from(prefix_len));
            let raw = u32::from_be_bytes([10, b, 0, 0]);
            let masked = if shift >= 32 {
                0
            } else {
                (raw >> shift) << shift
            };
            let addr = Ipv4Addr::from(masked);
            format!("{addr}/{prefix_len}").parse().unwrap()
        })
    }

    /// Generate a small set of withdrawn-only NLRIs — no attributes needed.
    fn arb_withdraw_only_update() -> impl Strategy<Value = UpdateMessage> {
        proptest::collection::vec(arb_nlri_v4(), 0..=8).prop_map(|withdrawn| UpdateMessage {
            withdrawn,
            attributes: vec![],
            announced: vec![],
        })
    }

    /// Generate an update with announced NLRIs + the three mandatory attributes.
    fn arb_announce_update() -> impl Strategy<Value = UpdateMessage> {
        (
            proptest::collection::vec(arb_nlri_v4(), 1..=8),
            proptest::collection::vec(arb_nlri_v4(), 0..=4),
            0u32..=200,
            (0u8..=2_u8), // Origin: 0=IGP, 1=EGP, 2=Incomplete
        )
            .prop_map(|(announced, withdrawn, med, origin_byte)| {
                let origin = match origin_byte {
                    0 => Origin::Igp,
                    1 => Origin::Egp,
                    _ => Origin::Incomplete,
                };
                UpdateMessage {
                    withdrawn,
                    attributes: vec![
                        PathAttribute::Origin(origin),
                        PathAttribute::AsPath(AsPath::new()),
                        PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
                        PathAttribute::Med(med),
                    ],
                    announced,
                }
            })
    }

    proptest! {
        /// Withdraw-only updates survive a full encode→decode roundtrip.
        #[test]
        fn prop_withdraw_only_update_roundtrip(msg in arb_withdraw_only_update()) {
            let encoded = msg.encode();
            let mut cur = Cursor::new(&encoded[19..]);
            let decoded = UpdateMessage::decode(&mut cur)
                .expect("structural decode error on well-formed message");
            prop_assert_eq!(decoded, UpdateDecodeOutcome::Clean(msg));
        }

        /// Announce updates with mandatory attributes survive a full encode→decode roundtrip.
        #[test]
        fn prop_announce_update_roundtrip(msg in arb_announce_update()) {
            let encoded = msg.encode();
            let mut cur = Cursor::new(&encoded[19..]);
            let decoded = UpdateMessage::decode(&mut cur)
                .expect("structural decode error on well-formed message");
            prop_assert_eq!(decoded, UpdateDecodeOutcome::Clean(msg));
        }

        /// encode→decode is idempotent: encoding the decoded message produces identical bytes.
        #[test]
        fn prop_encode_is_idempotent(msg in arb_announce_update()) {
            let first = msg.encode();
            let mut cur = Cursor::new(&first[19..]);
            let roundtripped = match UpdateMessage::decode(&mut cur).unwrap() {
                UpdateDecodeOutcome::Clean(m) => m,
                UpdateDecodeOutcome::Partial { .. } => panic!("expected Clean, got Partial"),
            };
            let second = roundtripped.encode();
            prop_assert_eq!(first, second, "double-encode must be byte-identical");
        }
    }

    // (type_code, canonical malformed value) for TreatAsWithdraw attributes.
    //
    // Each value is chosen to be definitely malformed for that type:
    //   ORIGIN    — value 99 is not a valid origin code
    //   AS_PATH   — segment type 9 is unknown; empty value is valid (zero segs)
    //   NEXT_HOP  — 3 bytes, needs 4
    //   LOCAL_PREF — 3 bytes, needs 4
    //   MP_REACH_NLRI — 2 bytes, needs ≥ 4
    const TREAT_AS_WITHDRAW_CASES: &[(u8, &[u8])] = &[
        (ATTR_ORIGIN, &[99]),
        (ATTR_AS_PATH, &[9, 0]),
        (ATTR_NEXT_HOP, &[10, 0, 0]),
        (ATTR_LOCAL_PREF, &[0; 3]),
        (ATTR_MP_REACH_NLRI, &[0; 2]),
    ];

    // (type_code, canonical malformed value) for AttributeDiscard attributes.
    //
    // Note: zero-length values are valid for COMMUNITY/EXTCOMMUNITY/LARGE_COMMUNITY
    // (they represent empty lists), so we use wrong-length non-zero values instead.
    const ATTRIBUTE_DISCARD_CASES: &[(u8, &[u8])] = &[
        (ATTR_MED, &[0; 3]),                  // 3 bytes, needs 4
        (ATTR_AGGREGATOR, &[0; 7]),           // 7 bytes, needs 8
        (ATTR_COMMUNITY, &[0; 3]),            // 3 bytes, not multiple of 4
        (ATTR_MP_UNREACH_NLRI, &[0; 1]),      // 1 byte, needs ≥ 3
        (ATTR_EXTENDED_COMMUNITIES, &[0; 7]), // 7 bytes, not multiple of 8
        (ATTR_AS4_PATH, &[9, 0]),             // unknown segment type
        (ATTR_AS4_AGGREGATOR, &[0; 7]),       // 7 bytes, needs 8
        (ATTR_LARGE_COMMUNITY, &[0; 11]),     // 11 bytes, not multiple of 12
        (ATTR_ONLY_TO_CUSTOMER, &[0; 3]),     // 3 bytes, needs 4
    ];

    /// Build a minimal UPDATE body with one attribute whose value is `value`.
    fn one_attr_update(flags: u8, type_code: u8, value: &[u8]) -> Vec<u8> {
        let attr_total = 3 + value.len(); // flags + type + 1-byte len + value
        let mut body = vec![0u8, 0]; // withdrawn_len = 0
        body.extend_from_slice(&u16::try_from(attr_total).unwrap().to_be_bytes());
        body.push(flags);
        body.push(type_code);
        body.push(u8::try_from(value.len()).unwrap());
        body.extend_from_slice(value);
        body
    }

    fn decode_outcome(body: &[u8]) -> UpdateDecodeOutcome {
        let mut cur = Cursor::new(body);
        UpdateMessage::decode(&mut cur).expect("structural decode error")
    }

    proptest! {
        /// For each TreatAsWithdraw type code, a canonical malformed value must
        /// produce a `Partial` outcome with `treat_as_withdraw = true`.
        #[test]
        fn prop_treat_as_withdraw_cases_produce_correct_policy(
            case in proptest::sample::select(TREAT_AS_WITHDRAW_CASES),
        ) {
            let (type_code, value) = case;
            let body = one_attr_update(FLAG_TRANSITIVE, type_code, value);
            match decode_outcome(&body) {
                UpdateDecodeOutcome::Partial { errors, treat_as_withdraw, .. } => {
                    prop_assert!(treat_as_withdraw,
                        "type_code={type_code}: treat_as_withdraw must be true");
                    prop_assert!(
                        errors.iter().any(|e| e.type_code == type_code
                            && e.policy == AttributeErrorPolicy::TreatAsWithdraw),
                        "type_code={type_code}: error must have TreatAsWithdraw policy"
                    );
                }
                UpdateDecodeOutcome::Clean(_) => {
                    prop_assert!(false, "type_code={type_code}: expected Partial, got Clean");
                }
            }
        }

        /// For each AttributeDiscard type code, a canonical malformed value must
        /// produce a `Partial` outcome with `treat_as_withdraw = false`.
        #[test]
        fn prop_attribute_discard_cases_produce_correct_policy(
            case in proptest::sample::select(ATTRIBUTE_DISCARD_CASES),
        ) {
            let (type_code, value) = case;
            let body = one_attr_update(FLAG_OPTIONAL, type_code, value);
            match decode_outcome(&body) {
                UpdateDecodeOutcome::Partial { errors, treat_as_withdraw, .. } => {
                    prop_assert!(!treat_as_withdraw,
                        "type_code={type_code}: treat_as_withdraw must be false for discard");
                    prop_assert!(
                        errors.iter().any(|e| e.type_code == type_code
                            && e.policy == AttributeErrorPolicy::AttributeDiscard),
                        "type_code={type_code}: error must have AttributeDiscard policy"
                    );
                }
                UpdateDecodeOutcome::Clean(_) => {
                    prop_assert!(false, "type_code={type_code}: expected Partial, got Clean");
                }
            }
        }

        /// The treat_as_withdraw flag is the logical OR of each error's policy:
        /// true iff any error has TreatAsWithdraw, false iff all have AttributeDiscard.
        ///
        /// Uses the canonical discard cases (all produce definite errors) to build
        /// a multi-attribute UPDATE and verify the flag.
        #[test]
        fn prop_treat_as_withdraw_flag_is_disjunction(
            cases in proptest::collection::vec(
                proptest::sample::select(ATTRIBUTE_DISCARD_CASES),
                1..5usize,
            ),
        ) {
            // Deduplicate by type code to avoid the duplicate-attr path.
            let mut seen = std::collections::HashSet::new();
            let cases: Vec<_> = cases
                .into_iter()
                .filter(|(tc, _)| seen.insert(*tc))
                .collect();

            // Build an UPDATE with one canonical malformed attribute per case.
            let mut attrs = Vec::new();
            for &(tc, value) in &cases {
                attrs.push(FLAG_OPTIONAL);
                attrs.push(tc);
                attrs.push(u8::try_from(value.len()).unwrap());
                attrs.extend_from_slice(value);
            }
            let mut body = vec![0u8, 0];
            body.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
            body.extend_from_slice(&attrs);

            match decode_outcome(&body) {
                UpdateDecodeOutcome::Partial { errors, treat_as_withdraw, .. } => {
                    let any_taw = errors
                        .iter()
                        .any(|e| e.policy == AttributeErrorPolicy::TreatAsWithdraw);
                    prop_assert_eq!(
                        treat_as_withdraw, any_taw,
                        "treat_as_withdraw flag must equal (any error is TreatAsWithdraw)"
                    );
                }
                UpdateDecodeOutcome::Clean(_) => {
                    prop_assert!(false, "all cases use canonical malformed values; expected Partial");
                }
            }
        }

        /// A malformed attribute in position N does not corrupt attributes N+1…end.
        /// The surviving valid attributes must all appear in the decoded output.
        #[test]
        fn prop_bad_attribute_does_not_corrupt_subsequent_valid_attrs(
            // Use MED (discard) as the injected bad attribute so other attrs survive.
            good_med_val in any::<u32>(),
            inject_bad_before in proptest::bool::ANY,
        ) {
            // Encode a valid ORIGIN(IGP) and an invalid MED (3 bytes instead of 4).
            let origin_attr = [FLAG_TRANSITIVE, ATTR_ORIGIN, 1u8, 0u8]; // ORIGIN=IGP
            let bad_med = [FLAG_OPTIONAL, ATTR_MED, 3u8, 0u8, 0u8, 0u8]; // 3 bytes, needs 4
            let valid_med: Vec<u8> = {
                let mut v = vec![FLAG_OPTIONAL, ATTR_MED, 4u8];
                v.extend_from_slice(&good_med_val.to_be_bytes());
                v
            };

            let mut attrs = Vec::new();
            if inject_bad_before {
                attrs.extend_from_slice(&bad_med);
                attrs.extend_from_slice(&origin_attr);
            } else {
                attrs.extend_from_slice(&origin_attr);
                attrs.extend_from_slice(&bad_med);
            }
            // Add the valid MED after the bad one to verify subsequent attrs decode.
            // (Can't have two MEDs — would trigger duplicate detection — so use valid_med
            // only when inject_bad_before is true and we're checking post-bad position.)
            let _ = valid_med; // used below

            let mut body = vec![0u8, 0];
            body.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
            body.extend_from_slice(&attrs);

            match decode_outcome(&body) {
                UpdateDecodeOutcome::Partial { update, errors, .. } => {
                    // ORIGIN must have decoded successfully.
                    prop_assert!(
                        update.attributes.iter().any(|a| matches!(a, PathAttribute::Origin(_))),
                        "ORIGIN must survive the malformed MED attribute"
                    );
                    // Only MED should be in errors.
                    prop_assert_eq!(errors.len(), 1);
                    prop_assert_eq!(errors[0].type_code, ATTR_MED);
                }
                UpdateDecodeOutcome::Clean(_) => {
                    prop_assert!(false, "expected Partial with bad MED");
                }
            }
        }

        /// `make_treat_as_withdraw` produces a withdrawal that contains every
        /// announced IPv4 NLRI from the original UPDATE.
        #[test]
        fn prop_treat_as_withdraw_contains_all_announced_nlri(
            announced in proptest::collection::vec(
                (any::<[u8; 4]>(), 0u8..=32u8)
                    .prop_map(|(addr, len)| {
                        pathvector_types::Nlri::new(
                            std::net::Ipv4Addr::from(addr), len
                        ).unwrap().masked()
                    }),
                0..8usize,
            ),
            existing_withdrawn in proptest::collection::vec(
                (any::<[u8; 4]>(), 0u8..=32u8)
                    .prop_map(|(addr, len)| {
                        pathvector_types::Nlri::new(
                            std::net::Ipv4Addr::from(addr), len
                        ).unwrap().masked()
                    }),
                0..4usize,
            ),
        ) {
            let update = UpdateMessage {
                withdrawn: existing_withdrawn.clone(),
                attributes: vec![],
                announced: announced.clone(),
            };
            let result = super::super::super::transport::make_treat_as_withdraw(update);

            // Every announced NLRI must appear in the result's withdrawn list.
            for nlri in &announced {
                prop_assert!(
                    result.withdrawn.contains(nlri),
                    "announced NLRI {nlri:?} must appear in treat-as-withdraw result"
                );
            }
            // Every originally-withdrawn NLRI must also be preserved.
            for nlri in &existing_withdrawn {
                prop_assert!(
                    result.withdrawn.contains(nlri),
                    "existing withdrawn NLRI {nlri:?} must be preserved"
                );
            }
            // No NLRIs should be announced in the result.
            prop_assert!(result.announced.is_empty(), "result must have no announced NLRIs");
        }
    }
}
