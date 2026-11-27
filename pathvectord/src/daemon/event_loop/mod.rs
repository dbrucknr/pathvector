//! The driving adapter for BGP: one `select!` over session events and timers.
//!
//! This loop decides *when* to call into [`DaemonState`] and delivers the
//! session commands that result. The routing decisions themselves are
//! `DaemonState` methods.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use pathvector_session::transport::{SessionCommand, SessionEvent};
use tokio::sync::{RwLock, mpsc, watch};

use super::{DaemonState, MRAI};

mod batch;
mod session_control;
mod timers;

#[cfg(test)]
pub(super) use session_control::handle_session_terminated;

/// Each peer's session command channel, shared with the command processor.
pub(super) type StopSenders = Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>;

pub(crate) async fn run_event_loop(
    mut event_rx: mpsc::Receiver<(IpAddr, SessionEvent)>,
    state: Arc<RwLock<DaemonState>>,
    stop_senders: Arc<StopSenders>,
    mut fib_change_rx: Option<watch::Receiver<()>>,
) {
    // MRAI flush timer — fires every MRAI/2 so suppressed eBGP routes are
    // re-advertised within one interval of their window expiring (RFC 4271 §9.2.1.1).
    // The first tick fires immediately but is a no-op (no sessions yet); subsequent
    // ticks are spaced MRAI/2 apart. MissedTickBehavior::Delay prevents burst
    // catch-up when the event loop is held under a write lock for an extended period.
    let mut mrai_timer = tokio::time::interval(MRAI / 2);
    mrai_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // `std::future::pending()` for the None branch ensures the select arm
        // is compiled in but never resolves, keeping the loop alive on the
        // BGP event path alone.
        let fib_changed = async {
            match fib_change_rx.as_mut() {
                Some(rx) => rx.changed().await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            event = event_rx.recv() => {
                let Some((peer_ip, event)) = event else { break; };
                batch::on_session_events(peer_ip, event, &mut event_rx, &state, &stop_senders).await;
            }

            Ok(()) = fib_changed => timers::on_fib_change(&state, &stop_senders).await,

            // RFC 4724 §4.2 — GR deadline timer.  Fire whenever the earliest
            // active deadline is reached.  If there are no active GR windows the
            // future is `pending()` so this branch never wakes the select.
            () = async {
                let earliest = state.read().await.gr.earliest_deadline();
                match earliest {
                    Some(d) => tokio::time::sleep_until(d.into()).await,
                    None    => std::future::pending::<()>().await,
                }
            } => timers::on_gr_deadline(&state, &stop_senders).await,

            // RFC 4724 §4.1 — Selection_Deferral_Timer.  Fires once, at
            // whichever family still hasn't released by the deadline (path
            // (b) — the wait-set-satisfied path (a) is driven reactively by
            // `recompute_selection_deferral` on EOR receipt / establishment /
            // permanent removal, not by this timer). `pending_deadline()`
            // returns `None` once both families are released, or when the
            // feature is disabled, so this branch is dormant in the common
            // case.
            () = async {
                let deadline = state.read().await.selection_deferral.pending_deadline();
                match deadline {
                    Some(d) => tokio::time::sleep_until(d.into()).await,
                    None    => std::future::pending::<()>().await,
                }
            } => timers::on_selection_deferral_expired(&state, &stop_senders).await,

            // Max-prefix idle-hold expiry timer.  When no
            // idle-hold is active, `pending()` keeps this branch dormant.
            //
            // The deadline is read with a temporary read guard (no local
            // binding) so the lock is released before the sleep begins.
            // Holding a read guard across the await would deadlock the
            // event arm which needs a write lock.
            () = async {
                let earliest = state.read().await.max_prefix_idle.values().copied().min();
                match earliest {
                    Some(d) => tokio::time::sleep_until(d.into()).await,
                    None    => std::future::pending::<()>().await,
                }
            } => timers::on_max_prefix_idle_expired(&state, &stop_senders).await,

            _ = mrai_timer.tick() => timers::on_mrai_tick(&state, &stop_senders).await,
        }
    }
}
