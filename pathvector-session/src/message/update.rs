use std::net::{Ipv4Addr, Ipv6Addr};

use pathvector_types::{
    Afi, AfiSafi, Aggregator, AsPath, AsPathSegment, Asn, Community, ExtendedCommunity,
    LargeCommunity, NextHop, Nlri, Origin, Safi,
};

use super::error::CodecError;
use super::header::{MessageType, encode_header};
use super::{Cursor, Writer};

// ── Path attribute flag bits ─────────────────────────────────────────────────

const FLAG_OPTIONAL: u8 = 0x80;
const FLAG_TRANSITIVE: u8 = 0x40;
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
const ATTR_MP_REACH_NLRI: u8 = 14;
const ATTR_MP_UNREACH_NLRI: u8 = 15;
const ATTR_EXTENDED_COMMUNITIES: u8 = 16;
const ATTR_AS4_PATH: u8 = 17;
const ATTR_AS4_AGGREGATOR: u8 = 18;
const ATTR_LARGE_COMMUNITY: u8 = 32;

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
    pub(super) fn decode(cur: &mut Cursor<'_>) -> Result<Self, CodecError> {
        // Withdrawn routes.
        let withdrawn_len = cur.read_u16()? as usize;
        let mut wd_cur = cur.fork(withdrawn_len)?;
        let withdrawn = decode_nlri_list_v4(&mut wd_cur)?;

        // Path attributes.
        let attrs_len = cur.read_u16()? as usize;
        let mut attrs_cur = cur.fork(attrs_len)?;
        let attributes = decode_path_attributes(&mut attrs_cur)?;

        // Announced NLRIs (remainder of the message).
        let announced = decode_nlri_list_v4(cur)?;

        Ok(Self {
            withdrawn,
            attributes,
            announced,
        })
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

fn decode_path_attributes(cur: &mut Cursor<'_>) -> Result<Vec<PathAttribute>, CodecError> {
    let mut out = Vec::new();
    while cur.remaining() > 0 {
        out.push(decode_one_path_attr(cur)?);
    }
    Ok(out)
}

fn decode_one_path_attr(cur: &mut Cursor<'_>) -> Result<PathAttribute, CodecError> {
    let flags = cur.read_u8()?;
    let type_code = cur.read_u8()?;
    let len = if (flags & FLAG_EXT_LEN) != 0 {
        cur.read_u16()? as usize
    } else {
        cur.read_u8()? as usize
    };
    let mut val = cur.fork(len)?;
    decode_attr_value(flags, type_code, &mut val)
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
            if cur.remaining() % 4 != 0 {
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
            if cur.remaining() % 8 != 0 {
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
            if cur.remaining() % 12 != 0 {
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
        } => (*flags, *type_code, value.clone()),
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
    /// Any unrecognised attribute. Flags and value are preserved intact so
    /// optional-transitive attributes can be forwarded to the next hop.
    Unknown {
        flags: u8,
        type_code: u8,
        value: Vec<u8>,
    },
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

    fn roundtrip(msg: &UpdateMessage) -> UpdateMessage {
        let encoded = msg.encode();
        let mut cur = Cursor::new(&encoded[19..]);
        UpdateMessage::decode(&mut cur).unwrap()
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
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_withdrawal_only_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![nlri4("10.0.0.0/8"), nlri4("192.168.0.0/16")],
            attributes: vec![],
            announced: vec![],
        };
        assert_eq!(roundtrip(&msg), msg);
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
        assert_eq!(roundtrip(&msg), msg);
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
        assert_eq!(roundtrip(&msg), msg);
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
        assert_eq!(roundtrip(&msg), msg);
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
        assert_eq!(roundtrip(&msg), msg);
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
        assert_eq!(roundtrip(&msg), msg);
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
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_unknown_attribute_preserved() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::Unknown {
                flags: FLAGS_OT,
                type_code: 200,
                value: vec![0xDE, 0xAD, 0xBE, 0xEF],
            }],
            announced: vec![],
        };
        assert_eq!(roundtrip(&msg), msg);
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
        assert_eq!(roundtrip(&msg), msg);
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
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_invalid_origin_rejected() {
        let body: &[u8] = &[0x00, 0x00, 0x00, 0x04, FLAGS_WKM, ATTR_ORIGIN, 0x01, 99];
        let mut cur = Cursor::new(body);
        assert!(matches!(
            UpdateMessage::decode(&mut cur),
            Err(CodecError::InvalidOrigin(99))
        ));
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
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_as4_path_roundtrip() {
        let path = AsPath::from_sequence(vec![Asn::new(131072), Asn::new(131073)]);
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::As4Path(path)],
            announced: vec![],
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_as4_aggregator_roundtrip() {
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::As4Aggregator {
                asn: 131072,
                bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            }],
            announced: vec![],
        };
        assert_eq!(roundtrip(&msg), msg);
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
        assert_eq!(roundtrip(&msg), msg);
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
        assert_eq!(roundtrip(&msg), msg);
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
        assert_eq!(roundtrip(&msg), msg);
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
        assert_eq!(roundtrip(&msg), msg);
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
        assert_eq!(roundtrip(&msg), msg);
    }

    // ── Raw-byte decode helpers ───────────────────────────────────────────────

    fn decode_update(body: &[u8]) -> Result<UpdateMessage, CodecError> {
        let mut cur = Cursor::new(body);
        UpdateMessage::decode(&mut cur)
    }

    /// Build an UPDATE body: no withdrawn routes, one path attribute (short len).
    fn update_with_attr(flags: u8, type_code: u8, value: &[u8]) -> Vec<u8> {
        let attr_total = 3 + value.len(); // flags + type + 1-byte len + value
        let mut body = vec![0u8, 0]; // withdrawn_len = 0
        body.extend_from_slice(&(attr_total as u16).to_be_bytes());
        body.push(flags);
        body.push(type_code);
        body.push(value.len() as u8);
        body.extend_from_slice(value);
        body
    }

    /// Build an UPDATE body using the extended-length (2-byte) flag.
    fn update_with_ext_attr(flags: u8, type_code: u8, value: &[u8]) -> Vec<u8> {
        let attr_total = 4 + value.len(); // flags + type + 2-byte len + value
        let mut body = vec![0u8, 0];
        body.extend_from_slice(&(attr_total as u16).to_be_bytes());
        body.push(flags | FLAG_EXT_LEN);
        body.push(type_code);
        body.extend_from_slice(&(value.len() as u16).to_be_bytes());
        body.extend_from_slice(value);
        body
    }

    // ── NLRI error paths ──────────────────────────────────────────────────────

    #[test]
    fn test_invalid_ipv4_nlri_prefix_too_long() {
        // withdrawn prefix_len = 33 (> 32 for IPv4).
        let body: &[u8] = &[0x00, 0x02, 33, 0x00, 0x00, 0x00];
        assert!(matches!(
            decode_update(body),
            Err(CodecError::InvalidNlri { prefix_len: 33 })
        ));
    }

    #[test]
    fn test_invalid_ipv6_nlri_prefix_too_long() {
        // MP_UNREACH NLRI with IPv6 prefix_len = 129 (> 128).
        let mp_body: &[u8] = &[0x00, 0x02, 0x01, 129, 0x00]; // AFI=2 IPv6, SAFI=1, pfx_len=129
        let body = update_with_attr(FLAGS_ONT, ATTR_MP_UNREACH_NLRI, mp_body);
        assert!(matches!(
            decode_update(&body),
            Err(CodecError::InvalidNlri { prefix_len: 129 })
        ));
    }

    // ── Extended-length attribute ─────────────────────────────────────────────

    #[test]
    fn test_extended_length_origin_attribute() {
        let body = update_with_ext_attr(FLAGS_WKM, ATTR_ORIGIN, &[0u8]); // ORIGIN=IGP
        let update = decode_update(&body).unwrap();
        assert!(matches!(update.attributes[0], PathAttribute::Origin(_)));
    }

    // ── Path attribute error paths ────────────────────────────────────────────

    #[test]
    fn test_origin_too_short_is_error() {
        let body = update_with_attr(FLAGS_WKM, ATTR_ORIGIN, &[]);
        assert!(matches!(
            decode_update(&body),
            Err(CodecError::InvalidAttribute { type_code: 1, .. })
        ));
    }

    #[test]
    fn test_next_hop_too_short_is_error() {
        let body = update_with_attr(FLAGS_WKM, ATTR_NEXT_HOP, &[10, 0, 0]); // 3 bytes, needs 4
        assert!(matches!(
            decode_update(&body),
            Err(CodecError::InvalidAttribute { type_code: 3, .. })
        ));
    }

    #[test]
    fn test_med_too_short_is_error() {
        let body = update_with_attr(FLAGS_ONT, ATTR_MED, &[0u8; 3]);
        assert!(matches!(
            decode_update(&body),
            Err(CodecError::InvalidAttribute { type_code: 4, .. })
        ));
    }

    #[test]
    fn test_local_pref_too_short_is_error() {
        let body = update_with_attr(FLAGS_WKM, ATTR_LOCAL_PREF, &[0u8; 3]);
        assert!(matches!(
            decode_update(&body),
            Err(CodecError::InvalidAttribute { type_code: 5, .. })
        ));
    }

    #[test]
    fn test_aggregator_too_short_is_error() {
        let body = update_with_attr(FLAGS_OT, ATTR_AGGREGATOR, &[0u8; 7]); // needs 8
        assert!(matches!(
            decode_update(&body),
            Err(CodecError::InvalidAttribute { type_code: 7, .. })
        ));
    }

    #[test]
    fn test_community_bad_length_is_error() {
        let body = update_with_attr(FLAGS_OT, ATTR_COMMUNITY, &[0u8; 3]); // not multiple of 4
        assert!(matches!(
            decode_update(&body),
            Err(CodecError::InvalidAttribute { type_code: 8, .. })
        ));
    }

    #[test]
    fn test_mp_reach_nlri_too_short_is_error() {
        let body = update_with_attr(FLAGS_ONT, ATTR_MP_REACH_NLRI, &[0x00, 0x01]); // only 2 bytes
        assert!(matches!(
            decode_update(&body),
            Err(CodecError::InvalidAttribute { type_code: 14, .. })
        ));
    }

    #[test]
    fn test_mp_unreach_nlri_too_short_is_error() {
        let body = update_with_attr(FLAGS_ONT, ATTR_MP_UNREACH_NLRI, &[0x00]); // only 1 byte
        assert!(matches!(
            decode_update(&body),
            Err(CodecError::InvalidAttribute { type_code: 15, .. })
        ));
    }

    #[test]
    fn test_extended_communities_bad_length_is_error() {
        let body = update_with_attr(FLAGS_OT, ATTR_EXTENDED_COMMUNITIES, &[0u8; 7]); // not multiple of 8
        assert!(matches!(
            decode_update(&body),
            Err(CodecError::InvalidAttribute { type_code: 16, .. })
        ));
    }

    #[test]
    fn test_as4_aggregator_too_short_is_error() {
        let body = update_with_attr(FLAGS_OT, ATTR_AS4_AGGREGATOR, &[0u8; 7]); // needs 8
        assert!(matches!(
            decode_update(&body),
            Err(CodecError::InvalidAttribute { type_code: 18, .. })
        ));
    }

    #[test]
    fn test_large_community_bad_length_is_error() {
        let body = update_with_attr(FLAGS_OT, ATTR_LARGE_COMMUNITY, &[0u8; 11]); // not multiple of 12
        assert!(matches!(
            decode_update(&body),
            Err(CodecError::InvalidAttribute { type_code: 32, .. })
        ));
    }

    // ── AS_PATH error and edge cases ──────────────────────────────────────────

    #[test]
    fn test_unknown_as_path_segment_type_is_error() {
        // seg_type=9 (unknown), count=0
        let body = update_with_attr(FLAGS_WKM, ATTR_AS_PATH, &[9, 0]);
        assert!(matches!(
            decode_update(&body),
            Err(CodecError::UnknownAsPathSegmentType(9))
        ));
    }

    #[test]
    fn test_truncated_asn_in_as_path_is_error() {
        // SEG_SEQUENCE, count=2, but only 4 bytes (enough for 1 ASN, not 2).
        let body = update_with_attr(FLAGS_WKM, ATTR_AS_PATH, &[2, 2, 0, 0, 0x00, 0x01]);
        assert!(matches!(
            decode_update(&body),
            Err(CodecError::InvalidAttribute { type_code: 2, .. })
        ));
    }

    // ── MP_REACH next-hop error paths ─────────────────────────────────────────

    #[test]
    fn test_mp_reach_invalid_next_hop_length_is_error() {
        // AFI=IPv4, SAFI=1, nh_len=3 (not 4 → decode_next_hop fails).
        let mp_body: &[u8] = &[
            0x00, 0x01, // AFI = IPv4
            0x01, // SAFI = unicast
            0x03, // nh_len = 3
            10, 0, 0,    // 3 next-hop bytes (should be 4)
            0x00, // SNPA
        ];
        let body = update_with_attr(FLAGS_ONT, ATTR_MP_REACH_NLRI, mp_body);
        assert!(matches!(
            decode_update(&body),
            Err(CodecError::InvalidAttribute { type_code: 14, .. })
        ));
    }

    // ── Unknown AFI in MP_UNREACH → decode_mp_nlri else branch ───────────────

    #[test]
    fn test_mp_unreach_unknown_afi_produces_empty_prefixes() {
        // AFI=9 (unknown), no further NLRI bytes.
        let mp_body: &[u8] = &[0x00, 0x09, 0x01]; // AFI=9, SAFI=1
        let body = update_with_attr(FLAGS_ONT, ATTR_MP_UNREACH_NLRI, mp_body);
        let update = decode_update(&body).unwrap();
        assert!(matches!(
            &update.attributes[0],
            PathAttribute::MpUnreachNlri(mp) if mp.prefixes.is_empty()
        ));
    }
}
