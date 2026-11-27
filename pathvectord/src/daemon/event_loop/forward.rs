//! The per-session task that feeds the event loop.

use std::net::IpAddr;

use pathvector_session::transport::{SessionEvent, SessionHandle};
use tokio::sync::mpsc;

/// Owns a session's handle and forwards its events to the event loop, ending
/// with exactly one [`SessionEvent::Retired`].
///
/// A session task that dies emits none, so it is added here, behind everything
/// the task did emit. Sent from anywhere else it could overtake those events.
pub(in crate::daemon) async fn forward_events<H: SessionHandle>(
    mut handle: H,
    peer_ip: IpAddr,
    event_tx: mpsc::Sender<(IpAddr, SessionEvent)>,
) {
    let mut retired = false;
    while let Some(event) = handle.next_event().await {
        retired |= matches!(event, SessionEvent::Retired);
        if event_tx.send((peer_ip, event)).await.is_err() {
            return;
        }
    }
    if !retired {
        let _ = event_tx.send((peer_ip, SessionEvent::Retired)).await;
    }
}
