//! The error RFC 9687 requires to be logged when the `SendHoldTimer` expires.
//!
//! A test binary of its own, holding this one test. `tracing` caches, for the
//! whole process, whether anything wants a given event, so a test running
//! alongside without a subscriber can switch the event off before this one's
//! subscriber sees it. nextest hides that by running each test in a process of
//! its own; `cargo test` runs a binary's tests as threads of one.

mod supervision_support;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pathvector_session::message::BgpMessage;
use pathvector_session::transport::{SessionEvent, SessionHandle, TerminationReason};
use supervision_support::*;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// §5: "an error MUST be logged in the local system, indicating the "Send Hold
/// Timer Expired" Error Code."
#[tokio::test(start_paused = true)]
async fn send_hold_expiry_logs_an_error_naming_the_error_code() {
    let log = Captured::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (mut handle, peer) = established(config(90)).await;
    peer.set_reading(false);
    handle.update_sender().send(update(1)).await.unwrap();
    // The peer stays alive, so that only the `SendHoldTimer` can end this.
    let expired = async {
        loop {
            peer.push(BgpMessage::Keepalive);
            if let Ok(event) =
                tokio::time::timeout(Duration::from_secs(10), handle.next_event()).await
            {
                return event;
            }
        }
    };
    let event = tokio::time::timeout(Duration::from_secs(600), expired)
        .await
        .expect("no SendHoldTimer expiry");
    assert!(
        matches!(
            event,
            Some(SessionEvent::Terminated(
                TerminationReason::SendHoldTimerExpired
            ))
        ),
        "{event:?}"
    );

    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let line = text
        .lines()
        .find(|l| l.contains("Send Hold Timer Expired"))
        .expect("nothing logged");
    assert!(line.contains("ERROR"), "{line}");
    assert!(line.contains("error_code=8"), "{line}");
}
