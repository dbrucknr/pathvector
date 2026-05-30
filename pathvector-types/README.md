# pathvector-types

Core BGP types for the [pathvector](https://github.com/dbrucknr/pathvector) ecosystem.

This crate defines the fundamental data structures that all other pathvector crates build on. It has no dependencies outside the Rust standard library and is intended to be a stable foundation — if a concept exists in BGP, its canonical Rust representation lives here.

---

## A brief introduction to BGP

The internet is not one network — it is tens of thousands of independent networks stitched together. Each of these networks is called an **Autonomous System (AS)**: a collection of IP prefixes under common administrative control. Your ISP is an AS. Google is an AS. Your company's corporate network might be an AS.

**BGP (Border Gateway Protocol)** is the protocol that these autonomous systems use to tell each other what IP prefixes they can reach and how to get there. It is the routing protocol of the public internet, and it is formally classified as a *path vector* protocol — meaning that every route advertisement carries the full sequence of autonomous systems it has passed through to reach you. That sequence is called the **AS path**.

BGP has been the backbone of the internet since the early 1990s. The current version, BGP-4, is defined in [RFC 4271](https://www.rfc-editor.org/rfc/rfc4271).

---

## Types

### `Asn` — Autonomous System Number

**Concept:** Every autonomous system on the internet has a globally unique number called an ASN, assigned by a Regional Internet Registry (ARIN in North America, RIPE in Europe, APNIC in Asia-Pacific, etc.). When a BGP router receives a route, it checks the AS path for its own ASN — if it finds it, the route is rejected. This is BGP's primary loop-prevention mechanism.

Originally ASNs were 16-bit integers, giving a range of 1–65535. The internet exhausted this space, and [RFC 6793](https://www.rfc-editor.org/rfc/rfc6793) extended ASNs to 32 bits in 2007. All modern BGP speakers negotiate 32-bit ASN support during session setup. This crate always stores ASNs as `u32`.

**Private ranges** work like private IP addresses — they are reserved for internal use and must be stripped before routes are advertised to the public internet:
- 2-byte private: `64512–65534` ([RFC 1930](https://www.rfc-editor.org/rfc/rfc1930))
- 4-byte private: `4200000000–4294967294` ([RFC 6996](https://www.rfc-editor.org/rfc/rfc6996))

**`AS_TRANS` (23456)** is a special reserved value used during the transition from 2-byte to 4-byte ASNs. When a 4-byte ASN must travel through a router that only understands 2-byte ASNs, `AS_TRANS` is substituted on the wire and the real ASN is preserved in a separate `AS4_PATH` attribute. You will rarely need to work with this directly — the session layer handles it.

```rust
use pathvector_types::Asn;

// A well-known public ASN (Cloudflare)
let cloudflare = Asn::new(13335);
assert!(!cloudflare.is_private());
assert!(!cloudflare.is_four_byte());

// A private ASN for internal use
let internal = Asn::new(65000);
assert!(internal.is_private());

// A 4-byte ASN
let large = Asn::new(4_200_000_001);
assert!(large.is_four_byte());
assert!(large.is_private());
```

---

### `AsPath` / `AsPathSegment` — AS Path

**Concept:** Every BGP route carries an AS path — the sequence of autonomous systems the route has traversed to reach the current router. As a route propagates across the internet, each router prepends its own ASN before re-advertising. The result is an ordered record of every AS the route passed through, with the most recent hop first and the originating AS last.

The AS path serves two critical roles:

1. **Loop prevention** — a BGP speaker rejects any route whose AS path already contains its own ASN. If you see yourself in the path, the route has looped back to you.
2. **Path selection** — all else being equal, shorter paths are preferred. BGP uses the *path length* (not a raw ASN count) in its decision process.

An AS path is not a flat list — it is composed of typed **segments**:

| Segment | Meaning |
|---|---|
| `AS_SEQUENCE` | Ordered list of ASNs; the normal case |
| `AS_SET` | Unordered group; produced when routes from multiple ASes are aggregated into one prefix |
| `AS_CONFED_SEQUENCE` | Ordered list within a BGP confederation ([RFC 5065](https://www.rfc-editor.org/rfc/rfc5065)) |
| `AS_CONFED_SET` | Unordered group within a confederation |

**Path length** is computed per segment type, not per raw ASN:
- `AS_SEQUENCE` — each ASN counts as 1
- `AS_SET` — the entire set counts as exactly 1, regardless of size
- Confederation segments — count as 0 (they are internal hops, not public internet distance)

**Prepending** is what a router does before re-advertising a route to an eBGP peer: it inserts its own ASN at the front of the path. Per RFC 4271, if the first segment is a full `AS_SEQUENCE` (255 entries) or is an `AS_SET`, a new `AS_SEQUENCE` segment is created in front rather than modifying the existing one.

```rust
use pathvector_types::{Asn, AsPath, AsPathSegment};

// A route from AS 65001, re-advertised by AS 65002
let mut path = AsPath::from_sequence(vec![Asn::new(65002), Asn::new(65001)]);
assert_eq!(path.path_length(), 2);
assert_eq!(path.origin_as(), Some(Asn::new(65001)));

// AS 65003 receives this and would reject it if it's already in the path
assert!(!path.contains(Asn::new(65003)));

// AS 65003 prepends itself before re-advertising
path.prepend(Asn::new(65003));
assert_eq!(path.path_length(), 3);

// A mixed path: sequence + set (produced by aggregation)
let aggregated = AsPath::from_segments(vec![
    AsPathSegment::Sequence(vec![Asn::new(65003)]),
    AsPathSegment::Set(vec![Asn::new(65001), Asn::new(65002)]),
]);
assert_eq!(aggregated.path_length(), 2); // 1 (sequence) + 1 (set)
```

---

### `Community` / `LargeCommunity` / `ExtendedCommunity` — BGP Communities

**Concept:** Communities are tags attached to routes that carry policy signals between networks. They let operators say things like "do not re-advertise this route" or "this is a customer route" without encoding that logic into the route itself. Routers apply policy based on the communities they receive, and strip or rewrite them before forwarding.

There are three generations of BGP community, each introduced to solve a problem the previous one could not handle:

**Standard community ([RFC 1997](https://www.rfc-editor.org/rfc/rfc1997))** — a 32-bit value split into two 16-bit halves: `high:low`, conventionally written as `ASN:value`. Well-known communities use `0xFFFF` in the high half (65535 is not a valid public ASN, preventing collision with operator communities). The limitation: no room for a 4-byte ASN in the 16-bit high field.

| Well-known | Value | Meaning |
|---|---|---|
| `NO_EXPORT` | `0xFFFFFF01` | Do not advertise outside this AS |
| `NO_ADVERTISE` | `0xFFFFFF02` | Do not advertise to any peer |
| `NO_EXPORT_SUBCONFED` | `0xFFFFFF03` | Do not advertise outside this confederation |
| `BLACKHOLE` | `0xFFFF029A` | Drop traffic to this prefix (RFC 7999) |

**Large community ([RFC 8092](https://www.rfc-editor.org/rfc/rfc8092))** — three `u32` fields: `global-administrator:local-data-1:local-data-2`. Designed specifically for 4-byte ASN operators who cannot fit their ASN into a standard community's 16-bit field.

**Extended community ([RFC 4360](https://www.rfc-editor.org/rfc/rfc4360))** — 8 bytes with an explicit type in the first two bytes. The type determines how the remaining 6 bytes are interpreted. Used heavily in VPN and EVPN. The most important extended community is the **Route Target (RT)**: it identifies which VRF (Virtual Routing and Forwarding instance) a VPN route belongs to. PE routers import routes whose RTs match their configured import policy.

```rust
use pathvector_types::{Community, LargeCommunity, ExtendedCommunity};

// Standard: AS 65000 marks a route as low-priority
let c = Community::from_parts(65000, 100);
assert_eq!(c.to_string(), "65000:100");
assert!(!c.is_well_known());

// Well-known: signal peers not to re-advertise
assert!(Community::NO_EXPORT.is_no_export());

// Large: 4-byte ASN operator, two local data fields
let lc = LargeCommunity::new(4_200_000_001, 999, 1);
assert_eq!(lc.to_string(), "4200000001:999:1");

// Extended: Route Target for MPLS VPN (2-byte AS form)
let rt = ExtendedCommunity::route_target_as2(65000, 100);
assert!(rt.is_transitive());
assert_eq!(rt.type_high(), 0x00); // 2-byte AS specific
assert_eq!(rt.type_low(), 0x02);  // Route Target sub-type
```

---

## Coming soon

The following types are planned and will be documented here as they are implemented.

### `Afi` / `Safi` — Address Family Identifiers

**Concept:** BGP was originally IPv4-only. Multiprotocol extensions ([RFC 4760](https://www.rfc-editor.org/rfc/rfc4760)) generalized it to carry reachability information for any address family. AFI (Address Family Identifier) and SAFI (Subsequent AFI) together identify what kind of prefixes a capability or route advertisement refers to.

Common combinations:
- AFI 1, SAFI 1 — IPv4 unicast (the classic case)
- AFI 2, SAFI 1 — IPv6 unicast
- AFI 1, SAFI 128 — IPv4 VPN (MPLS L3VPN)
- AFI 25, SAFI 70 — EVPN (Ethernet VPN)

### `Nlri` — Network Layer Reachability Information

**Concept:** NLRI is the actual payload of a BGP UPDATE message — the IP prefixes being advertised or withdrawn. Each NLRI entry is an IP prefix (e.g. `192.0.2.0/24`) paired with an AFI/SAFI that says what kind of prefix it is.

`Nlri<A>` in this crate wraps `IpPrefix<A>` from [`ipnetx`](https://crates.io/crates/ipnetx), reusing its set algebra and prefix math.

### Route Attributes — `Origin`, `Med`, `LocalPref`, `NextHop`, `Aggregator`

**Concept:** BGP routes carry a set of **path attributes** that describe the route's properties and influence the best-path selection algorithm ([RFC 4271 §9.1](https://www.rfc-editor.org/rfc/rfc4271#section-9.1)):

- **`ORIGIN`** — how the route was learned: `IGP` (from an interior routing protocol), `EGP` (from the older EGP protocol), or `INCOMPLETE` (redistributed from some other source). IGP is preferred.
- **`NEXT_HOP`** — the IP address of the next router to send packets toward this prefix.
- **`LOCAL_PREF`** — a 32-bit value used *inside* an AS to express route preference. Higher is better. Not sent to eBGP peers.
- **`MULTI_EXIT_DISC` (MED)** — a hint sent to neighboring ASes to influence which entry point they use into your network. Lower is preferred. Unlike `LOCAL_PREF`, this crosses AS boundaries.
- **`ATOMIC_AGGREGATE`** — a flag indicating that the route is an aggregate and some path information has been suppressed.
- **`AGGREGATOR`** — the ASN and IP address of the router that performed route aggregation.

---

## License

MIT
