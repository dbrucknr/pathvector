use std::net::Ipv4Addr;

use pathvector_types::{Afi, AfiSafi, Safi};

use super::error::CodecError;
use super::header::{MessageType, encode_header};
use super::{Cursor, Writer};

/// The BGP version advertised in OPEN messages. Must be 4.
const BGP_VERSION: u8 = 4;
/// Optional parameter type code for capabilities (RFC 3392).
const OPT_PARAM_CAPABILITIES: u8 = 2;

/// A BGP OPEN message (type 1).
///
/// Both peers send an OPEN immediately after TCP is established. The
/// connection is not confirmed until both OPENs have been received and
/// validated. Capabilities are negotiated here — a feature is only used
/// if both sides advertise the matching capability code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenMessage {
    /// BGP version — always 4 on receive; always written as 4 on send.
    pub version: u8,
    /// The sender's 2-byte AS field.
    ///
    /// For 4-byte ASNs this field carries `AS_TRANS` (23456) and the real
    /// ASN is in the [`Capability::FourByteAsn`] value.
    pub my_as: u16,
    /// Proposed hold time in seconds. The negotiated value will be
    /// `min(our_hold_time, peer_hold_time)`. Zero disables the hold timer.
    pub hold_time: u16,
    /// The sender's BGP identifier (router-id).
    pub bgp_id: Ipv4Addr,
    /// All capabilities the sender wishes to advertise.
    pub capabilities: Vec<Capability>,
}

impl OpenMessage {
    pub(super) fn decode(cur: &mut Cursor<'_>) -> Result<Self, CodecError> {
        let version = cur.read_u8()?;
        if version != BGP_VERSION {
            return Err(CodecError::UnsupportedVersion(version));
        }
        let my_as = cur.read_u16()?;
        let hold_time = cur.read_u16()?;
        let bgp_id = cur.read_ipv4addr()?;
        let opt_len = cur.read_u8()? as usize;
        let mut opt_cur = cur.fork(opt_len)?;
        let capabilities = decode_capabilities(&mut opt_cur)?;
        Ok(Self {
            version,
            my_as,
            hold_time,
            bgp_id,
            capabilities,
        })
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let caps_bytes = encode_capabilities(&self.capabilities);

        // Optional parameters: only type-2 (capabilities) if non-empty.
        let mut opt_params = Writer::new();
        if !caps_bytes.is_empty() {
            opt_params.put_u8(OPT_PARAM_CAPABILITIES);
            #[allow(clippy::cast_possible_truncation)]
            opt_params.put_u8(caps_bytes.len() as u8);
            opt_params.put_slice(&caps_bytes);
        }
        let opt_params = opt_params.finish();

        let mut body = Writer::new();
        body.put_u8(BGP_VERSION);
        body.put_u16(self.my_as);
        body.put_u16(self.hold_time);
        body.put_slice(&self.bgp_id.octets());
        #[allow(clippy::cast_possible_truncation)]
        body.put_u8(opt_params.len() as u8);
        body.put_slice(&opt_params);
        let body = body.finish();

        let mut w = Writer::new();
        encode_header(&mut w, MessageType::Open, body.len());
        w.put_slice(&body);
        w.finish()
    }
}

/// Parse optional parameters from the OPEN body, collecting all capability
/// TLVs from parameter type 2 into a flat `Vec<Capability>`.
fn decode_capabilities(opt_cur: &mut Cursor<'_>) -> Result<Vec<Capability>, CodecError> {
    let mut caps = Vec::new();
    while opt_cur.remaining() > 0 {
        let param_type = opt_cur.read_u8()?;
        let param_len = opt_cur.read_u8()? as usize;
        let mut param_cur = opt_cur.fork(param_len)?;
        if param_type == OPT_PARAM_CAPABILITIES {
            while param_cur.remaining() > 0 {
                let cap_code = param_cur.read_u8()?;
                let cap_len = param_cur.read_u8()? as usize;
                let mut cap_cur = param_cur.fork(cap_len)?;
                caps.push(decode_capability(cap_code, &mut cap_cur)?);
            }
        }
        // Unknown parameter types are silently skipped.
    }
    Ok(caps)
}

fn decode_capability(code: u8, cur: &mut Cursor<'_>) -> Result<Capability, CodecError> {
    match code {
        // Multi-Protocol (RFC 4760): AFI(2) + reserved(1) + SAFI(1)
        1 => {
            if cur.remaining() < 4 {
                return Err(CodecError::InvalidCapability { code });
            }
            let afi = Afi::new(cur.read_u16()?);
            let _reserved = cur.read_u8()?;
            let safi = Safi::new(cur.read_u8()?);
            Ok(Capability::MultiProtocol(AfiSafi::new(afi, safi)))
        }
        // Route Refresh (RFC 2918): no value
        2 => Ok(Capability::RouteRefresh),
        // Extended Message (RFC 8654): no value
        6 => Ok(Capability::ExtendedMessage),
        // 4-byte ASN (RFC 6793): 4-byte AS number
        65 => {
            if cur.remaining() < 4 {
                return Err(CodecError::InvalidCapability { code });
            }
            Ok(Capability::FourByteAsn(cur.read_u32()?))
        }
        // Graceful Restart (RFC 4724):
        // 2 bytes: restart flags (bit 15=R, bits 11-0=restart time)
        // then per-family: AFI(2) + SAFI(1) + flags(1)
        64 => {
            if cur.remaining() < 2 {
                return Err(CodecError::InvalidCapability { code });
            }
            let flags_time = cur.read_u16()?;
            let restart_flags = (flags_time >> 12) as u8;
            let restart_time = flags_time & 0x0FFF;
            let mut families = Vec::new();
            while cur.remaining() >= 4 {
                let afi = Afi::new(cur.read_u16()?);
                let safi = Safi::new(cur.read_u8()?);
                let fwd_flags = cur.read_u8()?;
                families.push(GracefulRestartFamily {
                    afi_safi: AfiSafi::new(afi, safi),
                    forwarding_preserved: (fwd_flags & 0x80) != 0,
                });
            }
            Ok(Capability::GracefulRestart {
                restart_flags,
                restart_time,
                families,
            })
        }
        _ => {
            let value = cur.read_remaining().to_vec();
            Ok(Capability::Unknown { code, value })
        }
    }
}

/// Encode all capabilities into a flat byte string suitable for wrapping in
/// an optional parameter of type 2.
fn encode_capabilities(caps: &[Capability]) -> Vec<u8> {
    let mut out = Writer::new();
    for cap in caps {
        let value = encode_capability_value(cap);
        out.put_u8(cap.code());
        #[allow(clippy::cast_possible_truncation)]
        out.put_u8(value.len() as u8);
        out.put_slice(&value);
    }
    out.finish()
}

fn encode_capability_value(cap: &Capability) -> Vec<u8> {
    let mut v = Writer::new();
    match cap {
        Capability::MultiProtocol(afi_safi) => {
            v.put_u16(afi_safi.afi.as_u16());
            v.put_u8(0); // reserved
            v.put_u8(afi_safi.safi.as_u8());
        }
        Capability::RouteRefresh | Capability::ExtendedMessage => {}
        Capability::FourByteAsn(asn) => {
            v.put_u32(*asn);
        }
        Capability::GracefulRestart {
            restart_flags,
            restart_time,
            families,
        } => {
            let flags_time = (u16::from(*restart_flags) << 12) | (restart_time & 0x0FFF);
            v.put_u16(flags_time);
            for fam in families {
                v.put_u16(fam.afi_safi.afi.as_u16());
                v.put_u8(fam.afi_safi.safi.as_u8());
                v.put_u8(if fam.forwarding_preserved { 0x80 } else { 0x00 });
            }
        }
        Capability::Unknown { value, .. } => {
            v.put_slice(value);
        }
    }
    v.finish()
}

/// A BGP capability advertised in the OPEN message optional parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// Multi-Protocol Extensions (RFC 4760, code 1).
    ///
    /// Signals support for routes beyond IPv4 unicast. One instance per
    /// AFI/SAFI pair.
    MultiProtocol(AfiSafi),

    /// Route Refresh (RFC 2918, code 2).
    ///
    /// Both sides must advertise this for ROUTE-REFRESH messages to be
    /// sent and honoured.
    RouteRefresh,

    /// 4-byte ASN support (RFC 6793, code 65).
    ///
    /// Carries the sender's full 32-bit ASN. When both peers advertise this,
    /// `AS_PATH` uses 4-byte ASNs and `AS_TRANS` substitution is not needed.
    FourByteAsn(u32),

    /// Graceful Restart (RFC 4724, code 64).
    ///
    /// Allows forwarding to continue while the BGP control plane restarts.
    /// `restart_time` is in seconds (max 4095). Each `GracefulRestartFamily`
    /// entry indicates whether forwarding state was preserved for that
    /// AFI/SAFI across the restart.
    GracefulRestart {
        restart_flags: u8,
        restart_time: u16,
        families: Vec<GracefulRestartFamily>,
    },

    /// Extended Message support (RFC 8654, code 6).
    ///
    /// When both peers advertise this, UPDATE (and other) messages may be up
    /// to 65535 bytes instead of the default 4096-byte limit.
    ExtendedMessage,

    /// Any capability code not recognised above. The raw value bytes are
    /// preserved so unknown capabilities can be forwarded without corruption.
    Unknown { code: u8, value: Vec<u8> },
}

impl Capability {
    pub(crate) fn code(&self) -> u8 {
        match self {
            Self::MultiProtocol(_) => 1,
            Self::RouteRefresh => 2,
            Self::ExtendedMessage => 6,
            Self::FourByteAsn(_) => 65,
            Self::GracefulRestart { .. } => 64,
            Self::Unknown { code, .. } => *code,
        }
    }
}

/// Per-address-family entry in a Graceful Restart capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GracefulRestartFamily {
    pub afi_safi: AfiSafi,
    /// `true` if the sender preserved forwarding state for this family across
    /// the most recent restart.
    pub forwarding_preserved: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: &OpenMessage) -> OpenMessage {
        let encoded = msg.encode();
        let mut cur = Cursor::new(&encoded[19..]);
        OpenMessage::decode(&mut cur).unwrap()
    }

    fn base_open() -> OpenMessage {
        OpenMessage {
            version: 4,
            my_as: 65001,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            capabilities: vec![],
        }
    }

    #[test]
    fn test_minimal_open_roundtrip() {
        assert_eq!(roundtrip(&base_open()), base_open());
    }

    #[test]
    fn test_open_with_capabilities_roundtrip() {
        let mut msg = base_open();
        msg.capabilities = vec![
            Capability::FourByteAsn(65001),
            Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
            Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
            Capability::RouteRefresh,
        ];
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_graceful_restart_roundtrip() {
        let mut msg = base_open();
        msg.capabilities = vec![Capability::GracefulRestart {
            restart_flags: 0,
            restart_time: 120,
            families: vec![
                GracefulRestartFamily {
                    afi_safi: AfiSafi::IPV4_UNICAST,
                    forwarding_preserved: true,
                },
                GracefulRestartFamily {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    forwarding_preserved: false,
                },
            ],
        }];
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_unknown_capability_preserved() {
        let mut msg = base_open();
        msg.capabilities = vec![Capability::Unknown {
            code: 200,
            value: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }];
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_unsupported_version_rejected() {
        let msg = OpenMessage {
            version: 3,
            ..base_open()
        };
        // Manually build a version-3 OPEN body.
        let encoded = msg.encode();
        // The version byte is at offset 19 (after the header).
        let mut bad = encoded.clone();
        bad[19] = 3;
        let mut cur = Cursor::new(&bad[19..]);
        assert_eq!(
            OpenMessage::decode(&mut cur),
            Err(CodecError::UnsupportedVersion(3))
        );
    }

    #[test]
    fn test_minimal_open_encoded_length() {
        // header(19) + version(1) + my_as(2) + hold_time(2) + bgp_id(4) + opt_len(1) = 29.
        assert_eq!(base_open().encode().len(), 29);
    }

    /// Build an OPEN body with a custom optional-parameter byte string.
    fn open_with_raw_opt_params(opt_params: &[u8]) -> Vec<u8> {
        let mut body: Vec<u8> = vec![
            4, // version
            0xFF, 0xE9, // my_as = 65001
            0x00, 0x5A, // hold_time = 90
            10, 0, 0, 1, // bgp_id
        ];
        body.push(u8::try_from(opt_params.len()).unwrap());
        body.extend_from_slice(opt_params);
        body
    }

    fn decode_open_body(body: &[u8]) -> Result<OpenMessage, CodecError> {
        let mut cur = Cursor::new(body);
        OpenMessage::decode(&mut cur)
    }

    #[test]
    fn test_unknown_opt_param_type_is_skipped() {
        // param_type=99 (unknown) should be silently skipped, yielding no capabilities.
        let params = [99_u8, 0]; // type=99, len=0
        let body = open_with_raw_opt_params(&params);
        let open = decode_open_body(&body).unwrap();
        assert!(open.capabilities.is_empty());
    }

    #[test]
    fn test_truncated_multiprotocol_capability_is_error() {
        // cap_code=1 (MultiProtocol), cap_len=2, but MultiProtocol needs 4 bytes.
        let params = [
            OPT_PARAM_CAPABILITIES,
            4, // type=2, param_len=4
            1,
            2, // cap_code=1, cap_len=2 (should be 4)
            0x00,
            0x01, // only 2 bytes of value
        ];
        let body = open_with_raw_opt_params(&params);
        assert!(matches!(
            decode_open_body(&body),
            Err(CodecError::InvalidCapability { code: 1 })
        ));
    }

    #[test]
    fn test_truncated_four_byte_asn_capability_is_error() {
        // cap_code=65 (FourByteAsn), cap_len=2, but FourByteAsn needs 4 bytes.
        let params = [
            OPT_PARAM_CAPABILITIES,
            4,
            65,
            2, // cap_code=65, cap_len=2
            0x00,
            0x01,
        ];
        let body = open_with_raw_opt_params(&params);
        assert!(matches!(
            decode_open_body(&body),
            Err(CodecError::InvalidCapability { code: 65 })
        ));
    }

    #[test]
    fn test_truncated_graceful_restart_capability_is_error() {
        // cap_code=64 (GracefulRestart), cap_len=1, but needs at least 2 bytes.
        let params = [
            OPT_PARAM_CAPABILITIES,
            3,
            64,
            1,    // cap_code=64, cap_len=1
            0x00, // only 1 byte
        ];
        let body = open_with_raw_opt_params(&params);
        assert!(matches!(
            decode_open_body(&body),
            Err(CodecError::InvalidCapability { code: 64 })
        ));
    }

    #[test]
    fn test_graceful_restart_zero_families_roundtrip() {
        let mut msg = base_open();
        msg.capabilities = vec![Capability::GracefulRestart {
            restart_flags: 0,
            restart_time: 300,
            families: vec![],
        }];
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_graceful_restart_nonzero_restart_flags_roundtrip() {
        // restart_flags=8 sets the Restart State (R) bit in the high nibble.
        let mut msg = base_open();
        msg.capabilities = vec![Capability::GracefulRestart {
            restart_flags: 8,
            restart_time: 60,
            families: vec![GracefulRestartFamily {
                afi_safi: AfiSafi::IPV4_UNICAST,
                forwarding_preserved: false,
            }],
        }];
        let rt = roundtrip(&msg);
        assert_eq!(rt, msg);
        if let Capability::GracefulRestart { restart_flags, .. } = &rt.capabilities[0] {
            assert_eq!(*restart_flags, 8);
        } else {
            panic!("expected GracefulRestart");
        }
    }

    #[test]
    fn test_graceful_restart_max_restart_time_roundtrip() {
        // restart_time is a 12-bit field (max 4095).
        let mut msg = base_open();
        msg.capabilities = vec![Capability::GracefulRestart {
            restart_flags: 0,
            restart_time: 4095,
            families: vec![],
        }];
        let rt = roundtrip(&msg);
        if let Capability::GracefulRestart { restart_time, .. } = &rt.capabilities[0] {
            assert_eq!(*restart_time, 4095);
        } else {
            panic!("expected GracefulRestart");
        }
    }

    #[test]
    fn test_unknown_capability_empty_value_roundtrip() {
        let mut msg = base_open();
        msg.capabilities = vec![Capability::Unknown {
            code: 201,
            value: vec![],
        }];
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_multiple_opt_param_blocks_merged() {
        // Two separate optional parameter TLVs of type 2, each containing one capability.
        // RFC 3392 allows multiple opt-param blocks; capabilities from all must be collected.
        let params: Vec<u8> = vec![
            OPT_PARAM_CAPABILITIES,
            2,
            6,
            0, // ExtendedMessage
            OPT_PARAM_CAPABILITIES,
            2,
            2,
            0, // RouteRefresh
        ];
        let body = open_with_raw_opt_params(&params);
        let open = decode_open_body(&body).unwrap();
        assert_eq!(open.capabilities.len(), 2);
        assert!(open.capabilities.contains(&Capability::ExtendedMessage));
        assert!(open.capabilities.contains(&Capability::RouteRefresh));
    }

    #[test]
    fn test_extended_message_capability_roundtrip() {
        // cap_code=6 (ExtendedMessage), cap_len=0
        let params = [OPT_PARAM_CAPABILITIES, 2, 6, 0];
        let body = open_with_raw_opt_params(&params);
        let open = decode_open_body(&body).unwrap();
        assert_eq!(open.capabilities, vec![Capability::ExtendedMessage]);
        // Verify that encoding back produces the correct capability code.
        let roundtripped = roundtrip(&open);
        assert_eq!(roundtripped.capabilities, vec![Capability::ExtendedMessage]);
    }

    /// RFC 4724 §3: the F-bit (`forwarding_preserved`) must survive an encode/decode
    /// roundtrip.  If it were dropped, the peer would not hold our routes on restart
    /// even though `restart_time > 0` — a silent protocol failure.
    #[test]
    fn test_gr_family_forwarding_preserved_roundtrip() {
        use pathvector_types::AfiSafi;

        let cap = Capability::GracefulRestart {
            restart_flags: 0,
            restart_time: 120,
            families: vec![
                GracefulRestartFamily {
                    afi_safi: AfiSafi::IPV4_UNICAST,
                    forwarding_preserved: true,
                },
                GracefulRestartFamily {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    forwarding_preserved: false,
                },
            ],
        };

        let open = OpenMessage {
            version: 4,
            my_as: 65001,
            hold_time: 90,
            bgp_id: "1.2.3.4".parse().unwrap(),
            capabilities: vec![cap],
        };

        let roundtripped = roundtrip(&open);
        let Capability::GracefulRestart { restart_time, families, .. } =
            &roundtripped.capabilities[0]
        else {
            panic!("expected GracefulRestart capability");
        };

        assert_eq!(*restart_time, 120);
        assert_eq!(families.len(), 2);
        assert!(
            families[0].forwarding_preserved,
            "IPv4 F-bit must survive encode/decode roundtrip"
        );
        assert!(
            !families[1].forwarding_preserved,
            "IPv6 F-bit (false) must survive encode/decode roundtrip"
        );
    }
}
