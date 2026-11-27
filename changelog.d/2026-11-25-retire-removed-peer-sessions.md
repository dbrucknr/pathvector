## 2026-11-25 (`RemovePeer` ends the session and always completes)

Found by reading the code during issue #102, then reproduced over loopback before the fix:

- removing an Established peer left its session task and forwarding task running: the forwarding
  task owns the handle, which holds a command sender, so the session never saw its command channel
  close;
- removing a peer that was not Established (never connected, in OpenSent, or between sessions)
  never completed. Such a session reports no `Terminated`, so the peer stayed configured and every
  later `AddPeer` for it was refused.

A third problem, found while making the change and shown by a test: if a Graceful Restart peer's
connection failed just before `RemovePeer`, that termination opened a restart window for the peer
being removed. Its routes stayed in the Loc-RIB with nothing left to withdraw them.

**The fix**

- `SessionCommand::Retire` stops a session and ends its task, whoever still holds a sender. The task
  first delivers the NOTIFICATION and every pending event, then `SessionEvent::Retired`.
- `RemovePeer` sends it after the stop. `Retired`, being the session's last event, is the only one
  that completes a removal, from any state, including a peer held down after a max-prefix CEASE.
- Until then the address stays taken and `AddPeer` for it is ignored, so no event of the removed
  session can be mistaken for one of a later session. A repeated `RemovePeer` does nothing more.
- `Terminated` for a peer being removed still withdraws its routes at once, and opens no restart
  window.
- If the session task has died, `RemovePeer` completes the removal itself.

**API change:** `SessionCommand` has a new `Retire` variant and `SessionEvent` a new `Retired`
variant.
