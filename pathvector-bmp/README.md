# pathvector-bmp

BGP Monitoring Protocol (BMP) receiver for the pathvector ecosystem.

**Status: planned — not yet started.** The crate exists as a placeholder. No BMP
functionality is implemented. This README describes the intended scope.

---

## What is BMP?

BGP Monitoring Protocol ([RFC 7854](https://www.rfc-editor.org/rfc/rfc7854)) is a
read-only protocol that lets a router stream its BGP state to an external collector
without participating in any BGP sessions itself. The collector is called a BMP
*monitoring station*; the router is the BMP *client*.

The key property of BMP: it is purely passive. The monitoring station receives route
updates and peer events from the router, but never sends routes or influences routing
decisions. This makes it safe to run in production alongside a live BGP speaker without
any risk of disrupting the routing table.

BMP is widely used for:
- **Route visibility** — see every route a router receives, including ones rejected by
  import policy (BMP reports pre-policy routes)
- **Monitoring** — detect route flaps, peer drops, and unexpected prefix changes
- **Archiving** — record a full history of routing table changes for compliance or
  post-incident analysis

---

## Protocol overview

A BMP session is a persistent TCP connection from the router to the monitoring station.
The router sends BMP messages; the station only reads. There are 7 message types:

| Type | Description |
|---|---|
| Route Monitoring | BGP UPDATE messages from the router's Adj-RIB-In, pre-policy |
| Statistics Report | Counters: prefixes received, duplicates, withdrawals, etc. |
| Peer Down Notification | A BGP session on the router has dropped |
| Peer Up Notification | A BGP session on the router has been established |
| Initiation | Identifies the router at session start (sysName, sysDescr) |
| Termination | Graceful shutdown of the BMP session |
| Route Mirroring | Copy of raw BGP messages for lossless message capture |

---

## Planned scope

`pathvector-bmp` is intended to be a **BMP monitoring station** (receiver), not a client.
It will:

1. Accept TCP connections from BMP clients (routers)
2. Decode all 7 BMP message types per RFC 7854
3. Provide a typed Rust API for consuming the decoded messages
4. Integrate with `pathvector-rib` to populate an external view of a router's RIB

It will **not** implement the BMP client side (sending BMP messages). pathvectord does
not currently send BMP; if that is needed, it is a separate scope item.

---

## Why a separate crate?

BMP is architecturally independent from BGP session management. A BMP monitoring station
does not need to understand BGP path selection, policy evaluation, or the RIB structures.
It only needs to decode BGP UPDATE messages embedded in BMP Route Monitoring messages.

Keeping BMP in a separate crate means:
- Operators who only need BGP peer management do not pull in BMP code
- BMP can evolve independently (RFC 7854 has extensions: RFC 8671, RFC 9069, etc.)
- The BMP receiver can be embedded in non-BGP applications (log aggregators, monitoring
  systems) without pulling in the full pathvector stack

---

## RFC target

| RFC | Title | Status |
|---|---|---|
| [RFC 7854](https://www.rfc-editor.org/rfc/rfc7854) | BGP Monitoring Protocol (BMP) | ❌ Not started |

---

## License

MIT
