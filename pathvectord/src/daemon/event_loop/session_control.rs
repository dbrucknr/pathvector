//! The outbound side of the event loop: the commands it sends to sessions,
//! and the teardown handling that decides what is owed to them.

use std::net::IpAddr;

use pathvector_session::{
    message::{Capability, CeaseError, NotificationError, NotificationMessage},
    transport::{SessionCommand, TerminationReason},
};
use pathvector_types::PeerType;
use tokio::sync::mpsc;

use super::StopSenders;
use crate::daemon::{
    DaemonState, capabilities::build_local_capabilities, peering::effective_session_as,
};
use crate::proto;

/// Handles one [`SessionEvent::Retired`](pathvector_session::transport::SessionEvent::Retired):
/// purges a peer that `RemovePeer` marked — its routes, then every piece of
/// per-peer state, including the command sender.
///
/// Only this event completes a removal, and it is the last one a session
/// emits. Until it is handled the address stays taken (`AddPeer` is ignored),
/// so no event of the removed session can be mistaken for one of a later
/// session at the same address.
pub(super) fn handle_session_retired(
    s: &mut DaemonState,
    peer_ip: IpAddr,
    stop_senders: &StopSenders,
) {
    if !s.pending_removal.contains(&peer_ip) {
        // The session task died by itself, and this was the last event from it.
        // Without a sender, `RemovePeer` knows to complete the removal itself.
        stop_senders.lock().unwrap().remove(&peer_ip);
        return;
    }
    // Capture identity fields while they are still in the RIB.  on_terminated
    // clears session-level state (peer_types, hold_times, etc.); remove_peer
    // clears everything including peer_remote_as.  Both run below.
    let removal_identity = s
        .rib
        .peer_remote_as
        .get(&peer_ip)
        .copied()
        .map(|remote_as| (remote_as, s.rib.local_as));
    // Each teardown walks the whole Loc-RIB, so skip it if `Terminated` has
    // done it and no later session has been Established since.
    let torn_down =
        s.removal_torn_down.remove(&peer_ip) && !s.rib.peer_types.contains_key(&peer_ip);
    if !torn_down {
        // For a session that had no `Terminated` to report, such as one that
        // was between sessions with routes retained.  Suppress the
        // intermediate Changed(None) broadcast — the explicit Removed event
        // below is the authoritative notification.
        s.on_terminated(peer_ip, TerminationReason::OperatorStop, false);
    }
    s.pending_removal.remove(&peer_ip);
    // Permanent removal: erase all per-peer state so the peer no longer
    // appears in gRPC responses and remove the stop sender so no further
    // commands can be sent to this session.
    s.remove_peer(peer_ip);
    stop_senders.lock().unwrap().remove(&peer_ip);
    // Broadcast a Removed event carrying the last-known remote_as and
    // local_as so watch_peers subscribers can identify the removed peer
    // without re-reading a snapshot that no longer contains it.
    if let Some((remote_as, local_as)) = removal_identity {
        let _ = s.peer_tx.send(proto::PeerEvent {
            r#type: proto::PeerEventType::Removed as i32,
            peer: Some(proto::PeerState {
                address: peer_ip.to_string(),
                remote_as,
                local_as,
                ..Default::default()
            }),
        });
    }
}

/// A [`SessionCommand::SetCapabilities`] owed to a session whose teardown has
/// just been processed.
///
/// Built under the state write lock and sent after it is released, so the lock
/// is never held across the channel send.
#[must_use = "send the capability refresh once the state lock is released"]
pub(in crate::daemon) struct CapabilityRefresh {
    session: mpsc::Sender<SessionCommand>,
    capabilities: Vec<Capability>,
}

impl CapabilityRefresh {
    pub(super) async fn send(self) {
        let _ = self
            .session
            .send(SessionCommand::SetCapabilities(self.capabilities))
            .await;
    }
}

/// Handles one [`SessionEvent::Terminated`](pathvector_session::transport::SessionEvent::Terminated).
///
/// This is the only handler for that event: `run_event_loop` calls it both for
/// the event that starts a batch and for events coalesced behind it, which used
/// to be two copies that drifted apart (GH #105, GH #148).
///
/// Returns the capability refresh the session needs before its next OPEN, or
/// `None` if the peer was being removed (or has no command channel).
pub(in crate::daemon) fn handle_session_terminated(
    s: &mut DaemonState,
    peer_ip: IpAddr,
    termination_reason: TerminationReason,
    stop_senders: &StopSenders,
) -> Option<CapabilityRefresh> {
    // Recorded before `on_terminated` consumes the reason.
    crate::metrics::on_session_terminated(peer_ip, &termination_reason);
    // A peer being removed stays marked until its session's `Retired`: no
    // restart window opens, and the Removed event that follows is the only
    // notification.
    let removing = s.pending_removal.contains(&peer_ip);
    s.on_terminated(peer_ip, termination_reason, !removing);
    if removing {
        s.removal_torn_down.insert(peer_ip);
        return None;
    }

    // RFC 4724 §4.2: when re-establishing a session, the Restart State (R) bit
    // "MUST NOT be set unless the Receiving Speaker has restarted". The session
    // may still hold the R=1/F=0 set it was spawned with after our restart, so
    // replace it: this teardown was not a restart of ours, and F=0 would make
    // the peer delete the routes it retained for us.
    let gr_time = s
        .config_capabilities
        .iter()
        .find_map(|c| {
            if let Capability::GracefulRestart { restart_time, .. } = c {
                Some(*restart_time)
            } else {
                None
            }
        })
        .unwrap_or(0);
    // RFC 5065 §4: the FourByteAsn capability must carry the same AS number as
    // `my_as` — the Confederation Identifier for `External` peers, the
    // Member-AS Number otherwise.  `peer_config_types` survives disconnects
    // (only cleared on permanent removal), so it reflects this peer's static
    // classification here.
    let peer_type = s
        .peer_config_types
        .get(&peer_ip)
        .copied()
        .unwrap_or(PeerType::External);
    let public_as = effective_session_as(s.rib.local_as, s.rib.confederation_id, peer_type);
    let capabilities = build_local_capabilities(
        public_as,
        gr_time,
        false,
        s.rib.peer_roles.get(&peer_ip).copied(),
    );
    let session = stop_senders.lock().unwrap().get(&peer_ip).cloned()?;
    Some(CapabilityRefresh {
        session,
        capabilities,
    })
}

/// Stops a session that must not come back by itself
/// ([`SessionCommand::Notification`]), with a Cease of the given subcode.
pub(super) fn hold_down(subcode: CeaseError) -> SessionCommand {
    SessionCommand::Notification(NotificationMessage {
        error: NotificationError::Cease(subcode),
        data: vec![],
    })
}

/// The command for a NOTIFICATION that `on_route_update` asks for.
///
/// After a maximum-prefix CEASE the session stays stopped: the daemon starts it
/// again itself if `max_prefixes_restart` is set, and otherwise only an
/// operator does. Any other (an UPDATE error) reconnects by itself.
pub(super) fn route_reset(notification: NotificationMessage) -> SessionCommand {
    if notification.error == NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached) {
        SessionCommand::Notification(notification)
    } else {
        SessionCommand::AutomaticStop(notification)
    }
}

/// A reset of a session that should come back by itself
/// ([`SessionCommand::AutomaticStop`]), with a Cease of the given subcode.
pub(super) fn automatic_stop(subcode: CeaseError) -> SessionCommand {
    SessionCommand::AutomaticStop(NotificationMessage {
        error: NotificationError::Cease(subcode),
        data: vec![],
    })
}

/// Sends `command` to `peer`'s session, if it still has one.
///
/// The stop-sender lock is released before the send is awaited.
pub(super) async fn send_to_session(
    stop_senders: &StopSenders,
    peer: IpAddr,
    command: SessionCommand,
) {
    let session = stop_senders.lock().unwrap().get(&peer).cloned();
    if let Some(session) = session {
        let _ = session.send(command).await;
    }
}
