//! Minimal BGP TCP speaker for MRT replay.
//!
//! Connects to a running `pathvectord` instance, completes the BGP FSM
//! handshake (OPEN → KEEPALIVE), then streams all MRT entries as BGP UPDATE
//! messages.  Only IPv4 unicast is supported.
//!
//! UPDATE messages carry raw MRT attribute bytes (already in BGP wire format)
//! so no attribute parse→re-encode round-trip is needed.  Prefixes with
//! identical attribute bytes are batched into the same UPDATE message up to
//! the RFC 4271 §4.3 4096-byte limit.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use pathvector_session::message::{BgpMessage, Capability, OpenMessage};
use pathvector_types::AfiSafi;

use crate::mrt::RibEntry;

// ── BGP constants ─────────────────────────────────────────────────────────────

const BGP_MARKER: [u8; 16] = [0xFF; 16];
const HEADER_LEN: usize = 19;
const MAX_MSG_LEN: usize = 4096;
const MSG_TYPE_UPDATE: u8 = 2;
// RFC 6793 §7: use AS_TRANS in the 2-byte my_as field when AS > 65535.
const AS_TRANS: u16 = 23456;
// Send KEEPALIVE every this many UPDATE messages so the hold timer never expires.
const KEEPALIVE_EVERY_N_UPDATES: u64 = 50;

// ── Public types ──────────────────────────────────────────────────────────────

/// Result of a [`BgpSpeaker::announce`] call.
pub struct AnnounceResult {
    pub prefixes_sent: u64,
    pub updates_sent: u64,
    pub unique_attr_sets: usize,
}

// ── BgpSpeaker ────────────────────────────────────────────────────────────────

/// Minimal BGP speaker: connects, handshakes, and announces prefixes.
pub struct BgpSpeaker {
    stream: TcpStream,
}

impl BgpSpeaker {
    /// Connect to `peer_addr` and complete the BGP Open-Confirm handshake.
    pub async fn connect(
        peer_addr: SocketAddr,
        my_as: u32,
        router_id: Ipv4Addr,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let stream = TcpStream::connect(peer_addr).await?;
        stream.set_nodelay(true)?;
        let mut s = Self { stream };
        s.handshake(my_as, router_id).await?;
        Ok(s)
    }

    /// Announce all `entries` to the peer and return statistics.
    ///
    /// Prefixes with identical attribute bytes are batched into the same UPDATE
    /// message.  A KEEPALIVE is sent every [`KEEPALIVE_EVERY_N_UPDATES`]
    /// messages to keep the session alive during long announcement runs.
    pub async fn announce(
        &mut self,
        entries: &[RibEntry],
    ) -> Result<AnnounceResult, Box<dyn std::error::Error>> {
        // Group prefixes by attribute bytes for efficient batching.
        let mut by_attrs: HashMap<&[u8], Vec<(Ipv4Addr, u8)>> = HashMap::new();
        for e in entries {
            by_attrs
                .entry(e.attrs.as_slice())
                .or_default()
                .push((e.prefix, e.prefix_len));
        }

        let unique_attr_sets = by_attrs.len();
        let mut prefixes_sent: u64 = 0;
        let mut updates_sent: u64 = 0;

        for (attrs, prefixes) in &by_attrs {
            let mut batch: Vec<(Ipv4Addr, u8)> = Vec::new();
            let mut batch_nlri_bytes: usize = 0;

            // Bytes available for NLRIs given this attr set.
            let available_for_nlri = MAX_MSG_LEN
                .saturating_sub(HEADER_LEN)
                .saturating_sub(4) // withdrawn_len(2) + attr_len(2)
                .saturating_sub(attrs.len());

            for &(prefix, plen) in prefixes {
                let nlri_size = 1 + (plen as usize).div_ceil(8);

                if !batch.is_empty() && batch_nlri_bytes + nlri_size > available_for_nlri {
                    self.send_update(attrs, &batch).await?;
                    updates_sent += 1;
                    prefixes_sent += batch.len() as u64;

                    if updates_sent.is_multiple_of(KEEPALIVE_EVERY_N_UPDATES) {
                        self.send_keepalive().await?;
                    }

                    batch.clear();
                    batch_nlri_bytes = 0;
                }

                batch.push((prefix, plen));
                batch_nlri_bytes += nlri_size;
            }

            if !batch.is_empty() {
                self.send_update(attrs, &batch).await?;
                updates_sent += 1;
                prefixes_sent += batch.len() as u64;
            }
        }

        Ok(AnnounceResult {
            prefixes_sent,
            updates_sent,
            unique_attr_sets,
        })
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    async fn handshake(
        &mut self,
        my_as: u32,
        router_id: Ipv4Addr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let my_as_wire = if my_as > u32::from(u16::MAX) {
            AS_TRANS
        } else {
            u16::try_from(my_as).unwrap_or(AS_TRANS)
        };
        let open = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: my_as_wire,
            hold_time: 90,
            bgp_id: router_id,
            capabilities: vec![
                Capability::FourByteAsn(my_as),
                Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
            ],
        });
        self.write_bytes(&open.encode()).await?;

        // Read OPEN from peer.
        let peer_msg = self.read_msg().await?;
        if !matches!(peer_msg, BgpMessage::Open(_)) {
            return Err(format!("expected OPEN from peer, got {peer_msg:?}").into());
        }

        // Send KEEPALIVE to confirm.
        self.send_keepalive().await?;

        // Wait for peer's KEEPALIVE — session now Established.
        loop {
            match self.read_msg().await? {
                BgpMessage::Keepalive => break,
                BgpMessage::Notification(n) => {
                    return Err(format!("peer sent NOTIFICATION during handshake: {n:?}").into());
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn send_keepalive(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.write_bytes(&BgpMessage::Keepalive.encode()).await
    }

    /// Assemble a raw BGP UPDATE message and send it.
    ///
    /// The attribute bytes are taken verbatim from the MRT entry — they are
    /// already in BGP wire format (RFC 4271 §4.3).
    async fn send_update(
        &mut self,
        attrs: &[u8],
        prefixes: &[(Ipv4Addr, u8)],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let nlri_bytes = encode_nlris(prefixes);
        // body = withdrawn_len(2=0) + attr_len(2) + attrs + NLRIs
        let body_len = 2 + 2 + attrs.len() + nlri_bytes.len();
        let total_len = HEADER_LEN + body_len;

        let mut msg = Vec::with_capacity(total_len);
        msg.extend_from_slice(&BGP_MARKER);
        // total_len ≤ MAX_MSG_LEN = 4096, so fits in u16.
        #[allow(clippy::cast_possible_truncation)]
        msg.extend_from_slice(&(total_len as u16).to_be_bytes());
        msg.push(MSG_TYPE_UPDATE);
        msg.extend_from_slice(&0u16.to_be_bytes()); // withdrawn_routes_length = 0
        // attrs.len() ≤ available_for_nlri ≤ MAX_MSG_LEN, so fits in u16.
        #[allow(clippy::cast_possible_truncation)]
        msg.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        msg.extend_from_slice(attrs);
        msg.extend_from_slice(&nlri_bytes);

        self.write_bytes(&msg).await
    }

    async fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.stream.write_all(bytes).await?;
        Ok(())
    }

    /// Read one complete BGP message from the TCP stream.
    async fn read_msg(&mut self) -> Result<BgpMessage, Box<dyn std::error::Error>> {
        let mut header = [0u8; HEADER_LEN];
        self.stream.read_exact(&mut header).await?;

        let total_len = u16::from_be_bytes([header[16], header[17]]) as usize;
        if total_len < HEADER_LEN {
            return Err(format!("BGP message length {total_len} < 19").into());
        }

        // Re-assemble full wire bytes so BgpMessage::decode can process them.
        let mut full = vec![0u8; total_len];
        full[..HEADER_LEN].copy_from_slice(&header);
        if total_len > HEADER_LEN {
            self.stream.read_exact(&mut full[HEADER_LEN..]).await?;
        }

        BgpMessage::decode(&full).map_err(|e| format!("BGP decode error: {e:?}").into())
    }
}

// ── NLRI encoding ─────────────────────────────────────────────────────────────

/// Encode a list of IPv4 prefixes as BGP NLRI bytes (RFC 4271 §4.3).
fn encode_nlris(prefixes: &[(Ipv4Addr, u8)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(addr, plen) in prefixes {
        let byte_count = (plen as usize).div_ceil(8);
        out.push(plen);
        out.extend_from_slice(&addr.octets()[..byte_count]);
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_nlris_slash24() {
        // 10.0.0.0/24 → prefix_len(1) + 3 octets
        let nlri = encode_nlris(&[(Ipv4Addr::new(10, 0, 0, 0), 24)]);
        assert_eq!(nlri, &[24, 10, 0, 0]);
    }

    #[test]
    fn encode_nlris_slash8() {
        // 10.0.0.0/8 → prefix_len(1) + 1 octet
        let nlri = encode_nlris(&[(Ipv4Addr::new(10, 0, 0, 0), 8)]);
        assert_eq!(nlri, &[8, 10]);
    }

    #[test]
    fn encode_nlris_default_route() {
        // 0.0.0.0/0 → prefix_len(1) only, zero prefix bytes
        let nlri = encode_nlris(&[(Ipv4Addr::UNSPECIFIED, 0)]);
        assert_eq!(nlri, &[0]);
    }
}
