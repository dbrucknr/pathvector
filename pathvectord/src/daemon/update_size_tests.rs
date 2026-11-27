//! Re-advertised UPDATEs stay within the peer's maximum message size, however
//! many received UPDATEs one flush coalesces (issue #178).

use std::net::{IpAddr, Ipv6Addr};

use pathvector_session::message::{
    AsnWidth, BgpMessage, MAX_LEN, MpReachNlri, PathAttribute, Prefix, UpdateMessage,
};
use pathvector_types::{AfiSafi, AsPath, Asn, NextHop, Nlri, Origin};

use super::last_feasible_tests::{
    AS_A, LOCAL_AS, PEER_A, PEER_B, RESOLVABLE_V6, established, sent_to,
};

fn prefixes(from: u16) -> Vec<Prefix> {
    (from..from + 250)
        .map(|i| {
            let n: Nlri<Ipv6Addr> = format!("2001:db8:{i:x}::/48").parse().unwrap();
            Prefix::V6(n)
        })
        .collect()
}

fn size(msg: &UpdateMessage, width: AsnWidth) -> usize {
    BgpMessage::Update(msg.clone()).encode_with(width).len()
}

fn up6(from: u16) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(AS_A)])),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                next_hop: NextHop::V6(RESOLVABLE_V6),
                prefixes: prefixes(from),
            }),
        ],
        announced: vec![],
    }
}

/// RFC 4271 §4.1: no message longer than 4096 octets. Four in-limit UPDATEs
/// with equal attributes, handled before one flush, must not be re-advertised
/// as one message. Each observer is measured at the AS number width its
/// session negotiated (RFC 6793 §4).
#[test]
fn coalesced_ipv6_announcements_stay_within_max_len() {
    for width in [AsnWidth::Two, AsnWidth::Four] {
        // The fixture's peers advertise no four-octet AS capability.
        let (mut state, mut rx) = established();
        if width.is_four() {
            state.four_byte_peers.insert(IpAddr::V4(PEER_B));
        }
        for from in [0, 250, 500, 750] {
            let update = up6(from);
            assert!(
                size(&update, AsnWidth::Four) <= MAX_LEN,
                "precondition: input is in limit"
            );
            assert!(state.on_route_update(IpAddr::V4(PEER_A), update).is_none());
        }
        let msgs = sent_to(&mut state, &mut rx, PEER_B);
        let sizes: Vec<usize> = msgs.iter().map(|m| size(m, width)).collect();
        assert!(sizes.iter().all(|&s| s <= MAX_LEN), "{width:?}: {sizes:?}");

        let mut sent = Vec::new();
        for msg in &msgs {
            // eBGP re-advertisement: our AS prepended, next hop rewritten.
            assert!(msg.attributes.iter().any(|a| matches!(
                a,
                PathAttribute::AsPath(p)
                    if *p == AsPath::from_sequence(vec![Asn::new(LOCAL_AS), Asn::new(AS_A)])
            )));
            for attr in &msg.attributes {
                if let PathAttribute::MpReachNlri(mp) = attr {
                    assert_eq!(mp.next_hop, NextHop::V6("2001:db8::ff".parse().unwrap()));
                    sent.extend(mp.prefixes.clone());
                }
            }
        }
        let mut expected: Vec<Prefix> = [0, 250, 500, 750].into_iter().flat_map(prefixes).collect();
        sent.sort_by_key(|p| format!("{p:?}"));
        expected.sort_by_key(|p| format!("{p:?}"));
        assert_eq!(sent, expected, "{width:?}: every prefix exactly once");
    }
}
