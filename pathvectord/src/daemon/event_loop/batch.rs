//! Handles one batch of session events: the event that woke the loop plus
//! everything already queued behind it, followed by a single flush.

use std::{net::IpAddr, sync::Arc};

use pathvector_session::{
    message::{CeaseError, NotificationMessage},
    transport::SessionEvent,
};
use tokio::sync::{RwLock, mpsc};

use super::{
    StopSenders,
    session_control::{
        CapabilityRefresh, automatic_stop, handle_session_retired, handle_session_terminated,
        hold_down, route_reset, send_to_session,
    },
};
use crate::daemon::DaemonState;
use crate::lock_timing::TimedWriteGuard;

/// Applies `event`, coalesces the events queued behind it, flushes once and
/// sends the session commands the batch owes.
pub(super) async fn on_session_events(
    peer_ip: IpAddr,
    event: SessionEvent,
    event_rx: &mut mpsc::Receiver<(IpAddr, SessionEvent)>,
    state: &Arc<RwLock<DaemonState>>,
    stop_senders: &StopSenders,
) {
    // `event_batch` covers the whole lock hold: the triggering
    // event plus every event coalesced by the drain loop below.
    let mut s = crate::lock_timing::write_timed(state, "event_batch").await;
    match event {
        SessionEvent::Established(info) => {
            // A peer held down after a max-prefix CEASE is not
            // registered, even if its session got as far as
            // Established before the stop reached it. Skipping
            // `on_established` leaves the session unregistered, so
            // `on_route_update` ignores any UPDATE already queued.
            if s.is_max_prefix_held(peer_ip) {
                tracing::info!(
                    peer = %peer_ip,
                    "held down after max-prefix — rejecting session"
                );
                drop(s);
                send_to_session(
                    stop_senders,
                    peer_ip,
                    hold_down(CeaseError::ConnectionRejected),
                )
                .await;
                return;
            }
            s.on_established(
                peer_ip,
                info.peer_bgp_id,
                info.peer_type,
                info.peer_as,
                info.hold_time,
                &info.peer_capabilities,
                info.local_addr,
            );
            crate::metrics::on_session_established(peer_ip);
            // Snapshot RIB sizes after the full-table dump so
            // adj_rib_out reflects the session bring-up immediately.
            crate::metrics::update_rib_sizes(
                s.rib.loc_rib.len(),
                s.rib.loc_rib_v6.len(),
                &s.rib.prefixes_advertised,
            );
        }
        SessionEvent::Terminated(termination_reason) => {
            let refresh =
                handle_session_terminated(&mut s, peer_ip, termination_reason, stop_senders);
            // This arm skips the end-of-batch gauge refresh below, so
            // refresh the RIB-size gauges here: the peer's routes have
            // just been flushed (GH #105).
            crate::metrics::update_rib_sizes(
                s.rib.loc_rib.len(),
                s.rib.loc_rib_v6.len(),
                &s.rib.prefixes_advertised,
            );
            // Drop the write guard before awaiting so we don't hold the
            // lock while the channel send blocks, then skip the coalescing
            // loop (no pending_decisions were touched in Terminated path).
            drop(s);
            if let Some(refresh) = refresh {
                refresh.send().await;
            }
            return;
        }
        SessionEvent::Retired => {
            handle_session_retired(&mut s, peer_ip, stop_senders);
            crate::metrics::update_rib_sizes(
                s.rib.loc_rib.len(),
                s.rib.loc_rib_v6.len(),
                &s.rib.prefixes_advertised,
            );
            return;
        }
        SessionEvent::RouteUpdate(msg) => {
            let notify_err = s.on_route_update(peer_ip, msg);
            let adj_in = s.rib.prefixes_received.get(&peer_ip).copied().unwrap_or(0);
            crate::metrics::on_route_update(peer_ip, adj_in);
            // handle_update returns Some(NotificationMessage) only for
            // conditions RFC 7606 still classifies as session-reset-worthy
            // (e.g. duplicate MP_REACH/MP_UNREACH_NLRI — Malformed Attribute
            // List). A missing well-known mandatory attribute is normally
            // NOT one of them: RFC 7606 §3(d) requires treat-as-withdraw
            // instead, and handle_update returns None for that case. The
            // exception is RFC 7606 §5.2 "Missing NLRI": an UPDATE with path
            // attributes other than MP_UNREACH_NLRI but no reachable NLRI at
            // all can't be confidently treated-as-withdraw (there's nothing
            // reliable to withdraw), so a missing-mandatory-attribute error
            // in that specific shape still resets the session here.
            if let Some(err) = notify_err {
                // Flush pending decisions for other peers before
                // tearing this one down so they don't starve.
                s.flush_pending();
                let stalled = s.take_stalled_peers();
                drop(s);
                send_to_session(stop_senders, peer_ip, route_reset(err)).await;
                // Process any stalled peers before next iteration.
                for peer in stalled {
                    send_to_session(
                        stop_senders,
                        peer,
                        automatic_stop(CeaseError::OutOfResources),
                    )
                    .await;
                }
                return;
            }
        }
    }
    drain_and_flush(s, event_rx, stop_senders).await;
}

/// The rest of a batch, entered holding the write lock taken for its first
/// event. Releases it before sending anything.
async fn drain_and_flush(
    mut s: TimedWriteGuard<'_, DaemonState>,
    event_rx: &mut mpsc::Receiver<(IpAddr, SessionEvent)>,
    stop_senders: &StopSenders,
) {
    // Drain any immediately-available events to coalesce bursts
    // before flushing. This is the key mechanism for cross-UPDATE
    // NLRI batching: when many BGP UPDATEs arrive back-to-back
    // (e.g. during MRT replay or full-table session establishment),
    // we process them all into the pending_decisions buffers first,
    // then flush_pending emits fewer, larger UPDATE messages.
    //
    // The drain loop has two ways out: the channel is empty, or a
    // coalesced UPDATE needs a NOTIFICATION. Both fall through to
    // the code after the loop, so what the batch owes is sent from
    // one place. Leave the loop only with `break`: skipping that
    // code drops commands the batch has already promised.
    //
    // Peers that reconnected while held down after a max-prefix
    // CEASE; their stop is sent after the drain loop alongside the
    // stalled peers' resets
    // to avoid dropping and re-acquiring the write lock mid-iteration.
    let mut idle_hold_rejected: Vec<IpAddr> = Vec::new();
    // Owed by coalesced `Terminated` events.
    let mut capability_refreshes: Vec<CapabilityRefresh> = Vec::new();
    // Set when a coalesced UPDATE ends the batch early.
    let mut notification: Option<(IpAddr, NotificationMessage)> = None;

    // PR-1: the drain loop has no cap, so batch size is the main
    // driver of `event_batch` lock-hold time. Counted here
    // (primary event + each coalesced one) and recorded once the
    // channel is empty; the NOTIFICATION paths skip it.
    let mut batch_events: u32 = 1;

    while let Ok((extra_ip, extra_event)) = event_rx.try_recv() {
        batch_events += 1;
        match extra_event {
            SessionEvent::Established(info) => {
                // Same max-prefix guard as the primary Established arm.
                if s.is_max_prefix_held(extra_ip) {
                    tracing::info!(
                        peer = %extra_ip,
                        "held down after max-prefix — rejecting session (coalesced)"
                    );
                    idle_hold_rejected.push(extra_ip);
                    continue;
                }
                s.on_established(
                    extra_ip,
                    info.peer_bgp_id,
                    info.peer_type,
                    info.peer_as,
                    info.hold_time,
                    &info.peer_capabilities,
                    info.local_addr,
                );
                // Same hook as the first-event arm: coalescing must
                // not change what gets recorded (GH #105).
                crate::metrics::on_session_established(extra_ip);
            }
            SessionEvent::Terminated(termination_reason) => {
                capability_refreshes.extend(handle_session_terminated(
                    &mut s,
                    extra_ip,
                    termination_reason,
                    stop_senders,
                ));
            }
            SessionEvent::Retired => {
                handle_session_retired(&mut s, extra_ip, stop_senders);
            }
            SessionEvent::RouteUpdate(msg) => {
                // See the primary RouteUpdate arm above: this only
                // fires for the session-reset-worthy conditions RFC
                // 7606 still calls for (not a missing mandatory
                // attribute, which is now treat-as-withdraw and
                // returns None here).
                let notify_err = s.on_route_update(extra_ip, msg);
                // Counted per UPDATE and the Adj-RIB-In gauge set from
                // live state, exactly as in the first-event arm; both
                // used to be skipped for coalesced events (GH #105).
                let adj_in = s.rib.prefixes_received.get(&extra_ip).copied().unwrap_or(0);
                crate::metrics::on_route_update(extra_ip, adj_in);
                if let Some(err) = notify_err {
                    notification = Some((extra_ip, err));
                    break;
                }
            }
        }
    }
    // After an early exit the channel may not be empty, so the
    // batch size is not recorded.
    if notification.is_none() {
        metrics::histogram!("pathvectord_event_loop_batch_events").record(f64::from(batch_events));
    }
    // Flush all accumulated outbound decisions. On the early exit
    // this keeps other peers from starving behind the teardown.
    s.flush_pending();
    crate::metrics::update_rib_sizes(
        s.rib.loc_rib.len(),
        s.rib.loc_rib_v6.len(),
        &s.rib.prefixes_advertised,
    );
    // Collect any peers whose outbound channel overflowed.  Drain
    // outside the write-lock so we don't hold it across async sends.
    let stalled = s.take_stalled_peers();
    drop(s);

    // Before any reset below: a session being reset still needs
    // the new set for its next OPEN.
    for refresh in capability_refreshes {
        refresh.send().await;
    }

    // Before the other resets, so a session that is also stalled
    // still reports why it is being reset.
    if let Some((peer, err)) = notification {
        send_to_session(stop_senders, peer, route_reset(err)).await;
    }

    for peer in stalled {
        tracing::error!(
            peer = %peer,
            "closing session: outbound UPDATE channel overflowed; \
             session will re-establish and perform a fresh full-table dump"
        );
        send_to_session(
            stop_senders,
            peer,
            automatic_stop(CeaseError::OutOfResources),
        )
        .await;
    }

    for peer in idle_hold_rejected {
        send_to_session(
            stop_senders,
            peer,
            hold_down(CeaseError::ConnectionRejected),
        )
        .await;
    }
}
