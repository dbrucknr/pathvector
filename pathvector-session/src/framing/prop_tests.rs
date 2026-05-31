use std::net::Ipv4Addr;

use bytes::BytesMut;
use proptest::prelude::*;
use tokio_util::codec::{Decoder, Encoder};

use super::BgpCodec;
use crate::message::{
    BgpMessage, NotificationError, NotificationMessage, OpenMessage, UpdateMessage,
};

fn arb_bgp_message() -> impl Strategy<Value = BgpMessage> {
    prop_oneof![
        Just(BgpMessage::Keepalive),
        (any::<u16>(), any::<u16>(), any::<[u8; 4]>()).prop_map(|(my_as, hold_time, id)| {
            BgpMessage::Open(OpenMessage {
                version: 4,
                my_as,
                hold_time,
                bgp_id: Ipv4Addr::from(id),
                capabilities: vec![],
            })
        }),
        Just(BgpMessage::Notification(NotificationMessage {
            error: NotificationError::HoldTimerExpired,
            data: vec![],
        })),
        Just(BgpMessage::Update(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })),
    ]
}

proptest! {
    /// Encode then decode via the codec produces the original message and
    /// leaves the buffer empty.
    #[test]
    fn prop_encode_decode_roundtrip(msg in arb_bgp_message()) {
        let mut codec = BgpCodec;
        let mut buf = BytesMut::new();
        codec.encode(msg.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        prop_assert_eq!(decoded, msg);
        prop_assert_eq!(buf.len(), 0);
    }

    /// The decoder must never panic on arbitrary byte input.
    #[test]
    fn prop_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let mut codec = BgpCodec;
        let mut buf = BytesMut::from(bytes.as_slice());
        let _ = codec.decode(&mut buf);
    }

    /// Two messages concatenated in one buffer are decoded in order with exact
    /// byte consumption after each call.
    #[test]
    fn prop_back_to_back_messages_decode_in_order(
        first  in arb_bgp_message(),
        second in arb_bgp_message(),
    ) {
        let mut codec = BgpCodec;
        let mut buf = BytesMut::new();
        codec.encode(first.clone(), &mut buf).unwrap();
        codec.encode(second.clone(), &mut buf).unwrap();

        let got_first = codec.decode(&mut buf).unwrap().unwrap();
        prop_assert_eq!(got_first, first);

        let got_second = codec.decode(&mut buf).unwrap().unwrap();
        prop_assert_eq!(got_second, second);

        prop_assert_eq!(buf.len(), 0);
    }

    /// Every prefix strictly shorter than the full encoded message returns
    /// Ok(None) — the codec waits for more bytes rather than erroring.
    #[test]
    fn prop_partial_message_returns_none(msg in arb_bgp_message()) {
        let mut codec = BgpCodec;
        let full = msg.encode();
        for trunc_len in 0..full.len() {
            let mut buf = BytesMut::from(&full[..trunc_len]);
            prop_assert!(
                matches!(codec.decode(&mut buf), Ok(None)),
                "truncation at {trunc_len} of {} should return Ok(None)",
                full.len()
            );
        }
    }

    /// A length field outside [19, 4096] is rejected before the body arrives.
    #[test]
    fn prop_out_of_range_length_is_error(
        bad_len in prop_oneof![
            0u16..19u16,
            4097u16..=u16::MAX,
        ],
    ) {
        let mut codec = BgpCodec;
        let mut buf = BytesMut::from([0xFF_u8; 16].as_slice()); // all-FF marker
        buf.extend_from_slice(&bad_len.to_be_bytes());
        buf.extend_from_slice(&[4u8]); // type byte (Keepalive)
        prop_assert!(matches!(codec.decode(&mut buf), Err(_)));
    }
}
