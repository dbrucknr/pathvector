# RFC Requirements — pathvector-bmp

This crate will own the **BGP Monitoring Protocol (BMP)** implementation: connecting to
one or more BMP monitoring stations, sending the required message types, and maintaining
per-peer per-message-type state.

This crate is **not yet started**. This file serves as a requirements stub so the
protocol obligations are captured and the boundary with other crates is defined before
implementation begins.

**Status key:** ✅ Implemented and tested | ⚠️ Partial — see notes | ❌ Not started  
**Verified by key:** `test_name` — unit test | `interop:x` — interop test | `—` — no automated verification

---

## RFC 7854 — BGP Monitoring Protocol (BMP)

**Owns:** All BMP message types; session lifecycle to monitoring stations; per-peer RIB
data export.  
**Boundary:** Route data comes from `pathvector-rib` (Adj-RIB-In or Loc-RIB snapshots).
BGP UPDATE payload encoding uses `pathvector-session` codec. Peer metadata comes from
`pathvectord` session state.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc7854

| Requirement | File | Status | Verified by |
|---|---|---|---|
| BMP common header (version 3, message length, message type) | — | ❌ | — |
| Message type 0: Route Monitoring — wrap BGP UPDATE in per-peer header | — | ❌ | — |
| Message type 1: Statistics Report — counters (prefixes rejected, updates, withdrawals) | — | ❌ | — |
| Message type 2: Peer Down Notification — reason code + optional NOTIFICATION data | — | ❌ | — |
| Message type 3: Peer Up Notification — local/remote addresses, OPEN messages | — | ❌ | — |
| Message type 4: Initiation Message — sysDescr and sysName TLVs | — | ❌ | — |
| Message type 5: Termination Message — reason TLV before TCP close | — | ❌ | — |
| Message type 6: Route Mirroring — relay received BGP messages verbatim | — | ❌ | — |
| Per-Peer Header: peer type, peer flags (L=Loc-RIB, F=filtered), peer distinguisher, peer address, peer AS, peer BGP ID, timestamp | — | ❌ | — |
| Initial table dump: send all Adj-RIB-In routes via Route Monitoring on Peer Up | — | ❌ | — |
| Reconnect to monitoring station on TCP disconnect with backoff | — | ❌ | — |
| Support multiple simultaneous monitoring stations | — | ❌ | — |

**Deferred:** Everything. Implementation plan:

1. TCP client to monitoring station with reconnect backoff.
2. Initiation and Termination messages.
3. Peer Up / Peer Down from `pathvectord` session events.
4. Route Monitoring from `pathvector-rib` `RibSnapshot` on Peer Up + live Loc-RIB deltas.
5. Statistics Report on a configurable interval.
6. Route Mirroring (optional, requires raw message access from `pathvector-session`).
