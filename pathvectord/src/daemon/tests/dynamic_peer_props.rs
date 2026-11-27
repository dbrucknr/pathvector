//! Property tests for the dynamic peer management API.
//!
//! These tests exercise arbitrary sequences of `add_peer` / `remove_peer` calls
//! against a `DaemonState` and assert that the state maps remain self-consistent
//! after every operation — no panics, no dangling keys, no phantom entries.

use std::{collections::HashMap, net::Ipv4Addr};

use proptest::prelude::*;
use tokio::sync::mpsc;

use crate::config;
use crate::daemon::*;

fn peer_cfg(address: IpAddr, remote_as: u32) -> config::PeerConfig {
    config::PeerConfig {
        address,
        port: 179,
        remote_as,
        import_default: Some(config::ImportDefault::Accept),
        export_default: Some(config::ExportDefault::Accept),
        import_default_v6: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: false,
        hold_time: None,
        shutdown_message: None,
        connect_retry_time: None,
        max_prefixes_v4: None,
        max_prefixes_v6: None,
        max_prefixes_restart: None,
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    }
}

fn fresh_state(peers: &[(Ipv4Addr, u32)]) -> DaemonState {
    let mut senders = HashMap::new();
    for &(ip, _) in peers {
        let (tx, _rx) = mpsc::channel(8);
        senders.insert(IpAddr::V4(ip), tx);
    }
    let cfgs: Vec<config::PeerConfig> = peers
        .iter()
        .map(|&(a, r)| peer_cfg(IpAddr::V4(a), r))
        .collect();
    DaemonState::new(
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &cfgs,
        senders,
        vec![],
    )
}

/// A `DaemonState` is self-consistent when every key present in
/// `adj_ribs_in` also appears in `peer_remote_as`, `adj_ribs_out`,
/// `import_policies`, `export_policies`, and `export_policies_v6` — and
/// vice-versa.
fn assert_consistent(s: &DaemonState, label: &str) {
    let ribs_in: std::collections::HashSet<_> = s.adj_ribs_in.keys().collect();
    let remote_as: std::collections::HashSet<_> = s.rib.peer_remote_as.keys().collect();
    let ribs_out: std::collections::HashSet<_> = s.adj_ribs_out.keys().collect();
    let import: std::collections::HashSet<_> = s.import_policies.keys().collect();
    let export: std::collections::HashSet<_> = s.export_policies.keys().collect();
    let export_v6: std::collections::HashSet<_> = s.export_policies_v6.keys().collect();

    assert_eq!(
        ribs_in, remote_as,
        "{label}: adj_ribs_in keys must equal peer_remote_as keys"
    );
    assert_eq!(
        ribs_in, ribs_out,
        "{label}: adj_ribs_in keys must equal adj_ribs_out keys"
    );
    assert_eq!(
        ribs_in, import,
        "{label}: adj_ribs_in keys must equal import_policies keys"
    );
    assert_eq!(
        ribs_in, export,
        "{label}: adj_ribs_in keys must equal export_policies keys"
    );
    assert_eq!(
        ribs_in, export_v6,
        "{label}: adj_ribs_in keys must equal export_policies_v6 keys"
    );
}

/// Arbitrary sequences of add/remove for up to 4 peers must never corrupt
/// state.  Uses the last octet of 10.0.0.x as the peer discriminant.
#[derive(Clone, Debug)]
enum Op {
    Add(u8), // peer last octet, always remote_as 65000 + octet
    Remove(u8),
}

fn op_strategy() -> impl Strategy<Value = Op> {
    (1u8..=4u8).prop_flat_map(|octet| prop_oneof![Just(Op::Add(octet)), Just(Op::Remove(octet)),])
}

proptest! {
    /// Any sequence of up to 20 add/remove operations must leave
    /// `DaemonState` self-consistent and must not panic.
    #[test]
    fn prop_add_remove_sequence_leaves_state_consistent(
        ops in prop::collection::vec(op_strategy(), 1..=20)
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut state = fresh_state(&[]);
            assert_consistent(&state, "initial");

            for (i, op) in ops.iter().enumerate() {
                match op {
                    Op::Add(octet) => {
                        let ip = Ipv4Addr::new(10, 0, 0, *octet);
                        let remote_as = 65000 + u32::from(*octet);
                        let (tx, _rx) = mpsc::channel(8);
                        state.add_peer(&peer_cfg(IpAddr::V4(ip), remote_as), tx);
                    }
                    Op::Remove(octet) => {
                        let ip = Ipv4Addr::new(10, 0, 0, *octet);
                        state.remove_peer(IpAddr::V4(ip)); // may return false — that's fine
                    }
                }
                assert_consistent(&state, &format!("after op {i}: {op:?}"));
            }

            // pending_removal must be empty (we never used it in this test).
            prop_assert!(
                state.pending_removal.is_empty(),
                "pending_removal must be empty after direct add/remove ops"
            );
            Ok(())
        }).unwrap();
    }

    /// `add_peer` followed by `remove_peer` for the same address must leave
    /// the state as if neither call was made — no phantom entries, no
    /// dangling keys.
    #[test]
    fn prop_add_then_remove_is_identity(octet in 1u8..=4u8) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let ip = Ipv4Addr::new(10, 0, 0, octet);
            let remote_as = 65000 + u32::from(octet);

            let state_before = fresh_state(&[]);
            let mut state_after = fresh_state(&[]);

            let (tx, _rx) = mpsc::channel(8);
            state_after.add_peer(&peer_cfg(IpAddr::V4(ip), remote_as), tx);
            state_after.remove_peer(IpAddr::V4(ip));

            // Key sets must match: after add+remove, no peer should remain.
            prop_assert_eq!(
                state_after.adj_ribs_in.len(),
                state_before.adj_ribs_in.len(),
                "adj_ribs_in must be empty after add+remove"
            );
            prop_assert_eq!(
                state_after.rib.peer_remote_as.len(),
                state_before.rib.peer_remote_as.len(),
                "peer_remote_as must be empty after add+remove"
            );
            assert_consistent(&state_after, "after add+remove");
            Ok(())
        }).unwrap();
    }
}
