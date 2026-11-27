//! Handlers for the event loop's non-session wake-ups: FIB changes and the
//! Graceful Restart, selection-deferral, max-prefix and MRAI timers.

use std::{net::IpAddr, sync::Arc, time::Instant};

use pathvector_session::{message::CeaseError, transport::SessionCommand};
use tokio::sync::{RwLock, mpsc::error::TrySendError};

use super::{
    StopSenders,
    session_control::{automatic_stop, send_to_session},
};
use crate::daemon::DaemonState;

/// The kernel routing table changed: next-hop reachability may have too.
pub(super) async fn on_fib_change(state: &Arc<RwLock<DaemonState>>, stop_senders: &StopSenders) {
    let mut s = crate::lock_timing::write_timed(state, "fib_change").await;
    s.on_fib_change();
    s.flush_pending();
    let stalled = s.take_stalled_peers();
    drop(s);

    for peer in stalled {
        tracing::error!(
            peer = %peer,
            "closing session: outbound UPDATE channel overflowed after FIB change; \
             session will re-establish and perform a fresh full-table dump"
        );
        send_to_session(
            stop_senders,
            peer,
            automatic_stop(CeaseError::OutOfResources),
        )
        .await;
    }
}

/// RFC 4724 §4.2: one or more Graceful Restart windows reached their deadline.
pub(super) async fn on_gr_deadline(state: &Arc<RwLock<DaemonState>>, stop_senders: &StopSenders) {
    let now = Instant::now();
    let expired: Vec<IpAddr> = {
        let mut s = crate::lock_timing::write_timed(state, "gr_deadline").await;
        let expired = s.gr.drain_expired(now);
        for peer_ip in &expired {
            s.on_gr_deadline_expired(*peer_ip);
        }
        expired
    };
    if !expired.is_empty() {
        let stalled = crate::lock_timing::write_timed(state, "gr_deadline")
            .await
            .take_stalled_peers();
        for peer in stalled {
            tracing::error!(
                peer = %peer,
                "closing session: outbound UPDATE channel overflowed during GR deadline flush"
            );
            send_to_session(
                stop_senders,
                peer,
                automatic_stop(CeaseError::OutOfResources),
            )
            .await;
        }
    }
}

/// RFC 4724 §4.1: the Selection_Deferral_Timer expired.
pub(super) async fn on_selection_deferral_expired(
    state: &Arc<RwLock<DaemonState>>,
    stop_senders: &StopSenders,
) {
    let mut s = crate::lock_timing::write_timed(state, "selection_deferral").await;
    tracing::warn!(
        "RFC 4724 §4.1: selection-deferral timer expired — \
         releasing any still-deferred address family unconditionally"
    );
    s.force_release_selection_deferral();
    s.flush_pending();
    let stalled = s.take_stalled_peers();
    drop(s);

    for peer in stalled {
        tracing::error!(
            peer = %peer,
            "closing session: outbound UPDATE channel overflowed during \
             selection-deferral timer flush"
        );
        send_to_session(
            stop_senders,
            peer,
            automatic_stop(CeaseError::OutOfResources),
        )
        .await;
    }
}

/// A max-prefix idle-hold expired (RFC 4271 §8.1.3 `IdleHoldTimer_Expires`).
pub(super) async fn on_max_prefix_idle_expired(
    state: &Arc<RwLock<DaemonState>>,
    stop_senders: &StopSenders,
) {
    let now = Instant::now();
    let mut s = crate::lock_timing::write_timed(state, "max_prefix_idle").await;
    let expired: Vec<IpAddr> = s
        .max_prefix_idle
        .iter()
        .filter(|(_, deadline)| *deadline <= &now)
        .map(|(ip, _)| *ip)
        .collect();
    for peer_ip in expired {
        s.max_prefix_idle.remove(&peer_ip);
        // A peer being removed has been sent its stop already.
        if s.pending_removal.contains(&peer_ip) {
            continue;
        }
        let session = stop_senders.lock().unwrap().get(&peer_ip).cloned();
        let Some(session) = session else { continue };
        // Sent without releasing the state lock, so a concurrent
        // `RemovePeer` cannot queue its stop ahead of this start.
        // That rules out waiting for room in the channel.
        if let Err(TrySendError::Full(_)) = session.try_send(SessionCommand::Start) {
            s.max_prefix_idle
                .insert(peer_ip, now + std::time::Duration::from_millis(100));
            continue;
        }
        tracing::info!(
            peer = %peer_ip,
            "max-prefix idle-hold expired — restarting session"
        );
    }
}

/// RFC 4271 §9.2.1.1: periodic flush of MRAI-suppressed advertisements.
pub(super) async fn on_mrai_tick(state: &Arc<RwLock<DaemonState>>, stop_senders: &StopSenders) {
    let mut s = crate::lock_timing::write_timed(state, "mrai").await;
    // Flush any coalesced decisions before MRAI processing so the
    // MRAI check sees the fully-accumulated outbound state.
    s.flush_pending();
    if s.has_mrai_pending() {
        s.flush_mrai_pending();
        // flush_mrai_pending calls propagate_to_all_peers which
        // buffers; drain those decisions now.
        s.flush_pending();
        crate::metrics::update_rib_sizes(
            s.rib.loc_rib.len(),
            s.rib.loc_rib_v6.len(),
            &s.rib.prefixes_advertised,
        );
        let stalled = s.take_stalled_peers();
        drop(s);
        for peer in stalled {
            tracing::error!(
                peer = %peer,
                "closing session: outbound UPDATE channel overflowed during MRAI flush; \
                 session will re-establish and perform a fresh full-table dump"
            );
            send_to_session(
                stop_senders,
                peer,
                automatic_stop(CeaseError::OutOfResources),
            )
            .await;
        }
    }
}
