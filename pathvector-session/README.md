# pathvector-session

BGP session management for the [pathvector](https://github.com/dbrucknr/pathvector) ecosystem.

This crate implements the session layer of a BGP router: the TCP transport, the BGP Finite State Machine, and the codec that encodes and decodes every BGP message type. It sits between the network and `pathvector-rib`, transforming raw TCP bytes into decoded route objects on the way in, and encoded UPDATE messages on the way out.

---

## What is a BGP session?

A BGP session is a persistent TCP connection between two BGP speakers, established on port 179. It is the channel through which two routers exchange their entire view of the routing table — and keep it in sync as prefixes are advertised, withdrawn, and updated over the lifetime of the peering relationship.

Unlike most client-server protocols, BGP is symmetric: both peers attempt to connect to each other simultaneously. The FSM handles this **connection collision** deterministically — the router with the higher BGP identifier (router-id) wins and its outbound TCP connection is kept.

Sessions are either **iBGP** (internal — both routers are in the same AS) or **eBGP** (external — the routers are in different ASes). The distinction changes several rules about which attributes are preserved, which are stripped, and which routes may be re-advertised. See [iBGP vs eBGP](#ibgp-vs-ebgp) below.

---

## The BGP Finite State Machine

[RFC 4271 §8](https://www.rfc-editor.org/rfc/rfc4271#section-8) defines the BGP FSM. Every BGP session — from initial TCP dial to graceful teardown — is driven by this machine. There are six states:

| State | Meaning |
|---|---|
| **Idle** | No connection is being attempted. The session enters this state on startup and after any error. A `ConnectRetryTimer` controls re-entry into Connect. |
| **Connect** | A TCP connection is being dialled. If it succeeds, an OPEN is sent and the state advances to OpenSent. If it fails, the state moves to Active. |
| **Active** | The TCP dial failed; the router is actively retrying. When the `ConnectRetryTimer` expires the state returns to Connect for another attempt. |
| **OpenSent** | TCP is established and an OPEN message has been sent. The router is waiting for the peer's OPEN. |
| **OpenConfirm** | Both OPENs have been received and validated. Waiting for the first KEEPALIVE to confirm the peer also accepted our OPEN. |
| **Established** | The session is fully operational. UPDATE, KEEPALIVE, and ROUTE-REFRESH messages may be exchanged. |

```text
                              Start
                                │
                                ▼
                  ┌─────────── Idle ◄──────────────────────────────┐
                  │                                                 │
              ConnectRetry                                       any error /
                  │                                             NOTIFICATION
                  ▼
               Connect ──── TCP ok ──────► OpenSent ── OPEN rx ──► OpenConfirm
                  │                            │                        │
               TCP fail                  error/timer               KEEPALIVE rx
                  │                            │                        │
                  ▼                            └──────────────────►     ▼
               Active ─── TCP ok ─────────────────────────────► Established
                  │
            ConnectRetry
                  │
                  └──► Connect
```

Every transition out of **OpenSent**, **OpenConfirm**, and **Established** caused by an error sends a NOTIFICATION message before closing the TCP connection, giving the peer a machine-readable reason for the teardown.

---

## BGP messages

All BGP messages share a **19-byte header**:

```text
┌──────────────────────────────────── 16 bytes ───────────────────────────────────────┐
│  Marker (all 0xFF — legacy authentication field, always 0xFF in modern deployments) │
└─────────────────────────────────────────────────────────────────────────────────────┘
┌─── 2 bytes ────┐ ┌─ 1 byte ─┐
│  Total length  │ │   Type   │
└────────────────┘ └──────────┘
```

Total length covers the header and body combined. The minimum valid message is 19 bytes (a KEEPALIVE). The maximum is 4096 bytes, except for UPDATE messages with the Extended Message capability ([RFC 8654](https://www.rfc-editor.org/rfc/rfc8654)) where up to 65535 bytes are allowed.

### OPEN (type 1)

Sent immediately after TCP is established. Both peers send their OPEN before waiting for the other's — the connection is only confirmed once both OPENs have been validated.

```text
┌─ 1 byte ─┐ ┌── 2 bytes ──┐ ┌── 2 bytes ──┐ ┌─── 4 bytes ───┐ ┌─ 1 byte ─┐ ┌── variable ──┐
│ Version  │ │   My AS     │ │  Hold Time  │ │   BGP ID      │ │ Opt. Len │ │  Opt. Params │
│   (= 4)  │ │ (2-byte AS) │ │  (seconds)  │ │ (router-id)   │ │          │ │ (capabilities│
└──────────┘ └─────────────┘ └─────────────┘ └───────────────┘ └──────────┘ └──────────────┘
```

**My AS** is only 2 bytes. If the sender's ASN exceeds 65535, this field is set to `AS_TRANS` (23456) and the real ASN is carried in the 4-byte ASN capability. Both peers must support the 4-byte ASN capability for this to work.

**BGP ID** is a 4-byte value that uniquely identifies the router. By convention it is one of the router's IPv4 addresses, often the loopback. It is used for connection collision detection: when both peers dial each other simultaneously, the session initiated by the router with the *higher* BGP ID is kept.

**Hold time** is the maximum number of seconds that may pass between messages before the session is considered dead. The negotiated value is `min(our_hold_time, peer_hold_time)`. A value of 0 disables the hold timer entirely. See [Hold time and keepalives](#hold-time-and-keepalives).

### UPDATE (type 2)

The workhorse of BGP — carries route advertisements and withdrawals. A single UPDATE may advertise multiple prefixes that share the same path attributes, and simultaneously withdraw multiple prefixes.

```text
┌── 2 bytes ──┐ ┌── variable ──┐ ┌── 2 bytes ──┐ ┌── variable ─────┐ ┌── variable ──┐
│  Withdrawn  │ │   Withdrawn  │ │  Path Attr  │ │  Path Attributes │ │  Announced   │
│  Routes Len │ │    NLRIs     │ │  Length     │ │  (TLV list)      │ │  NLRIs       │
└─────────────┘ └──────────────┘ └─────────────┘ └──────────────────┘ └──────────────┘
```

The **Announced NLRIs** and **Withdrawn NLRIs** fields carry IPv4 unicast prefixes only. All other address families (IPv6, VPN, EVPN) use the `MP_REACH_NLRI` and `MP_UNREACH_NLRI` path attributes instead ([RFC 4760](https://www.rfc-editor.org/rfc/rfc4760)). NLRI on the wire are variable-length encoded: only the bytes needed to represent the prefix are transmitted, not a full 4-byte address.

**Path attributes** are TLV-encoded and carry metadata about the announced routes:

| Attribute | Type Code | Description |
|---|---|---|
| `ORIGIN` | 1 | How the route was introduced into BGP: IGP, EGP, or Incomplete |
| `AS_PATH` | 2 | The sequence of ASes the route has traversed |
| `NEXT_HOP` | 3 | IPv4 next-hop for forwarding (IPv4 unicast only; MP extensions carry IPv6 next-hops) |
| `MULTI_EXIT_DISC` | 4 | MED — hint to neighbouring AS about preferred entry point |
| `LOCAL_PREF` | 5 | iBGP only — inbound traffic engineering lever; higher wins |
| `ATOMIC_AGGREGATE` | 6 | Flag indicating aggregated path information was suppressed |
| `AGGREGATOR` | 7 | The ASN and router-id of the router that performed aggregation |
| `COMMUNITY` | 8 | Standard BGP communities (RFC 1997) |
| `MP_REACH_NLRI` | 14 | Reachable NLRI for non-IPv4-unicast address families (RFC 4760) |
| `MP_UNREACH_NLRI` | 15 | Withdrawn NLRI for non-IPv4-unicast address families (RFC 4760) |
| `EXTENDED_COMMUNITIES` | 16 | Extended communities (RFC 4360) |
| `AS4_PATH` | 17 | 4-byte AS path used during 2-byte/4-byte ASN transition (RFC 6793) |
| `AS4_AGGREGATOR` | 18 | 4-byte AGGREGATOR used during transition (RFC 6793) |
| `LARGE_COMMUNITY` | 32 | Large communities (RFC 8092) |

Each path attribute carries four flag bits in its first byte: **Optional** (well-known vs. optional), **Transitive** (whether an unrecognised attribute is forwarded), **Partial** (set by a router that did not recognise a transitive attribute), and **Extended-length** (whether the length field is 1 or 2 bytes).

### KEEPALIVE (type 4)

A 19-byte header with no body. Sent periodically to prevent the hold timer from expiring when no UPDATEs are pending. Also sent in response to an OPEN as confirmation that the peer's OPEN was accepted, triggering the transition from OpenConfirm to Established.

### NOTIFICATION (type 3)

Signals an error and immediately terminates the session. The TCP connection is closed after the NOTIFICATION is sent.

```text
┌─ 1 byte ─┐ ┌─ 1 byte ─┐ ┌─ variable ─┐
│   Error  │ │  Error   │ │    Data    │
│   Code   │ │ Sub-code │ │ (optional) │
└──────────┘ └──────────┘ └────────────┘
```

| Error Code | Meaning |
|---|---|
| 1 | Message Header Error — invalid marker, bad length, or unknown type |
| 2 | OPEN Message Error — unsupported version, bad AS, unacceptable hold time |
| 3 | UPDATE Message Error — malformed attribute, invalid NLRI, etc. |
| 4 | Hold Timer Expired — no message received within the negotiated hold time |
| 5 | Finite State Machine Error — message received in an unexpected state |
| 6 | Cease — operator-initiated teardown ([RFC 4486](https://www.rfc-editor.org/rfc/rfc4486) defines subcodes) |

### ROUTE-REFRESH (type 5)

Requests the peer to re-advertise all routes for a given AFI/SAFI without tearing down the session. Requires both peers to have negotiated the Route Refresh capability during OPEN ([RFC 2918](https://www.rfc-editor.org/rfc/rfc2918)). Essential for applying updated import policy without resetting the session.

```text
┌── 2 bytes ──┐ ┌─ 1 byte ─┐ ┌─ 1 byte ─┐
│     AFI     │ │ Reserved │ │   SAFI   │
└─────────────┘ └──────────┘ └──────────┘
```

---

## Capabilities

Capabilities are advertised in the OPEN message as optional parameters. They allow BGP speakers to negotiate support for protocol extensions before exchanging any routes. A feature is only used if both peers include the corresponding capability in their OPEN.

| Capability | Code | RFC | Purpose |
|---|---|---|---|
| Multi-Protocol | 1 | [RFC 4760](https://www.rfc-editor.org/rfc/rfc4760) | Support address families beyond IPv4 unicast |
| Route Refresh | 2 | [RFC 2918](https://www.rfc-editor.org/rfc/rfc2918) | On-demand route resynchronisation without session reset |
| 4-byte ASN | 65 | [RFC 6793](https://www.rfc-editor.org/rfc/rfc6793) | Exchange ASNs greater than 65535 |
| Graceful Restart | 64 | [RFC 4724](https://www.rfc-editor.org/rfc/rfc4724) | Maintain forwarding state while the control plane restarts |
| Extended Message | 6 | [RFC 8654](https://www.rfc-editor.org/rfc/rfc8654) | Allow UPDATE messages up to 65535 bytes |

### 4-byte ASN negotiation

The OPEN message's "My AS" field is only 2 bytes, a limitation from the original protocol design. [RFC 6793](https://www.rfc-editor.org/rfc/rfc6793) introduced the 4-byte ASN capability to carry the full ASN in a capability TLV instead.

When both peers support this capability, the real ASN is taken from the capability value and "My AS" is ignored. When a router with a 4-byte ASN peers with a 2-byte-only router (which cannot understand the capability), it substitutes `AS_TRANS` (23456) in the "My AS" field and uses a separate `AS4_PATH` attribute to carry the true AS path through the 2-byte-only segment of the network.

---

## Hold time and keepalives

The hold timer is BGP's session liveness mechanism. During OPEN, each peer proposes a hold time in seconds; the negotiated value is `min(our_hold_time, peer_hold_time)`. A value of zero disables the hold timer entirely.

Once established, the session must receive a KEEPALIVE or UPDATE from the peer within every hold-time window. If none arrives, a NOTIFICATION (Hold Timer Expired, error code 4) is sent and the session drops.

To keep the timer from expiring when there are no routes to advertise, each peer sends a KEEPALIVE every `hold_time / 3` seconds. With the common 90-second hold time this means a keepalive every 30 seconds and a 3-missed-keepalive tolerance before the session drops.

---

## iBGP vs eBGP

The same BGP protocol runs on both internal and external sessions, but two rules apply only to iBGP:

**1. iBGP split horizon.** A route learned from an iBGP peer is not re-advertised to other iBGP peers. This prevents routing loops inside an AS without needing to track the full AS path for internal hops. The consequence is that every BGP-speaking router in an AS must either be in a full mesh or use **Route Reflectors** ([RFC 4456](https://www.rfc-editor.org/rfc/rfc4456)) or **Confederations** ([RFC 5065](https://www.rfc-editor.org/rfc/rfc5065)) to work around the full-mesh scaling problem.

**2. Next-hop preservation.** When a router re-advertises an eBGP-learned route to its iBGP peers, it does not change `NEXT_HOP` to its own address. The original eBGP peer's address is preserved. Every iBGP peer in the AS must have an IGP route to that next-hop address — this is the fundamental reason BGP and an IGP (OSPF, IS-IS) must run together inside a network.

Additional differences by session type:

| Attribute / Rule | iBGP | eBGP |
|---|---|---|
| `LOCAL_PREF` | Carried and honoured | Stripped before sending |
| `MED` | Accepted from peer | Compared only within same neighbouring AS |
| AS path | Not prepended on re-advertisement | Sender's ASN prepended |
| `NEXT_HOP` | Preserved from eBGP source | Set to sender's address |
| Route re-advertisement | Blocked to other iBGP peers | Freely re-advertised |

---

## This crate's role in the stack

`pathvector-session` sits between the TCP socket and the RIB layer. It owns everything that requires understanding the BGP wire protocol.

```text
                    TCP (port 179)
                         │
         ┌───────────────▼───────────────┐
         │       pathvector-session       │
         │                               │
         │  ┌─────────────────────────┐  │
         │  │  Message codec          │  │
         │  │  OPEN / UPDATE /        │  │
         │  │  KEEPALIVE / NOTIF /    │  │
         │  │  ROUTE-REFRESH          │  │
         │  └───────────┬─────────────┘  │
         │              │                │
         │  ┌───────────▼─────────────┐  │
         │  │  BGP FSM                │  │
         │  │  Idle → ... → Established│  │
         │  │  Hold timer             │  │
         │  │  Capability negotiation │  │
         │  └───────────┬─────────────┘  │
         └──────────────┼────────────────┘
                        │ decoded Route<A> objects
                        │ + withdrawals
                        ▼
         ┌──────────────────────────────┐
         │       pathvector-rib          │
         │  AdjRibIn → LocRib →          │
         │  best-path → AdjRibOut        │
         └──────────────┬───────────────┘
                        │ Route<A> from AdjRibOut
                        ▼
         ┌──────────────────────────────┐
         │       pathvector-session      │
         │  encode UPDATE messages       │
         └──────────────┬───────────────┘
                        │
                    TCP (port 179)
```

The RIB and policy layers never see raw TCP bytes — they only see decoded `Route<A>` objects. The session layer never makes routing decisions — it only parses, validates, and hands off. This separation means import and export policy can be changed and re-applied without resetting sessions.

---

## Types

*Implementation in progress. Types will be documented here as they are built.*

---

## License

MIT
