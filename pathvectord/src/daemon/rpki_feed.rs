//! Inbound adapter for the RPKI RTR client: feeds ROA cache changes into
//! import policy.

use std::sync::Arc;

use tokio::sync::RwLock;

use super::DaemonState;

/// Installs the ROV import-policy term (if `reject_invalid`) and stores
/// `handle` on `state`. If `reject_invalid`, also spawns the background task
/// that re-evaluates every peer's import policy whenever `handle`'s ROA
/// cache changes (see `pathvector_rpki::RtrHandle::subscribe`).
///
/// Split out from `run_with` so this exact sequence is directly testable
/// against any `RtrHandle` — a real one from `RtrClient::spawn`, or a
/// `for_testing()`/`insert_roa_v4`-driven one in tests — without needing a
/// live TCP RTR server either way.
pub(super) async fn install_rpki(
    handle: pathvector_rpki::RtrHandle,
    reject_invalid: bool,
    state: &Arc<RwLock<DaemonState>>,
) {
    // Subscribe before doing anything else. `handle` was already returned
    // by `RtrClient::spawn`, whose background sync task starts running
    // concurrently the instant it's spawned — on a multi-thread runtime
    // that's a real second OS thread, not just cooperative scheduling. A
    // `watch` receiver only observes changes sent *after* it subscribes, so
    // subscribing late risks missing the very first sync's notification
    // outright (not just seeing it delayed). Subscribing here, before the
    // `state.write().await` below, minimizes that window; the eager
    // `status().connected` check further down closes it completely by
    // catching the case where the first sync still won the race.
    let changed = reject_invalid.then(|| handle.subscribe());

    {
        let mut guard = crate::lock_timing::write_timed(state, "rpki_install").await;
        if reject_invalid {
            guard.install_rpki_import_terms(&handle);
        }
        guard.rpki = Some(handle.clone());
    }
    if let Some(mut changed) = changed {
        // If the first sync already completed before we subscribed above,
        // its notification was sent to no receiver and this one will never
        // see it — the watch channel only fires for changes after
        // subscription. Catch that case explicitly rather than relying on
        // subscribe() having won the race against the background task.
        if handle.status().connected {
            crate::lock_timing::write_timed(state, "rpki_reeval")
                .await
                .reevaluate_all_import_policies();
        }
        // Re-evaluates every peer's import policy whenever the ROA cache
        // changes (any later update) — closes the window between "route
        // accepted while the cache was empty/stale" and the cache actually
        // reflecting reality, without waiting for a session reset. Ends
        // only if the RtrClient's own task ever drops its side of the
        // channel, which never happens in practice (that task runs
        // forever) — a clean, non-panicking exit either way.
        let reeval_state = Arc::clone(state);
        tokio::spawn(async move {
            while changed.changed().await.is_ok() {
                crate::lock_timing::write_timed(&reeval_state, "rpki_reeval")
                    .await
                    .reevaluate_all_import_policies();
            }
        });
    }
}
