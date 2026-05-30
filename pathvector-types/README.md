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

## Coming soon

The following types are planned and will be documented here as they are implemented.

### `AsPath` — AS Path

**Concept:** Every BGP route carries an AS path — the ordered list of autonomous systems the route has traversed to reach the current router. When AS 65001 advertises a prefix to AS 65002, and AS 65002 re-advertises it to AS 65003, the path `[65001, 65002]` is attached. AS 65003 prepends its own ASN before passing it along.

The AS path serves two purposes: loop prevention (reject any route containing your own ASN) and path selection (shorter paths are generally preferred, all else being equal).

Paths are made up of **segments**, not flat lists, because BGP supports sets of ASNs in addition to sequences:
- `AS_SEQUENCE` — an ordered list; the normal case
- `AS_SET` — an unordered set used when routes from multiple ASNs are aggregated into one
- `AS_CONFED_SEQUENCE` / `AS_CONFED_SET` — variants used inside BGP confederations ([RFC 5065](https://www.rfc-editor.org/rfc/rfc5065))

### `Community` — BGP Community

**Concept:** Communities are 32-bit tags attached to routes that carry policy signals. They let networks say things like "do not advertise this route beyond your region" or "this route came from a customer, treat it accordingly" without encoding that logic into the route itself.

Standard communities ([RFC 1997](https://www.rfc-editor.org/rfc/rfc1997)) are 32-bit values conventionally written as `ASN:value` — e.g. `65000:100` might mean "low priority" within AS 65000's policy.

Well-known communities have globally agreed-upon meanings:
- `NO_EXPORT` (`0xFFFFFF01`) — do not advertise outside this AS
- `NO_ADVERTISE` (`0xFFFFFF02`) — do not advertise to any peer
- `NO_EXPORT_SUBCONFED` (`0xFFFFFF03`) — do not advertise outside this confederation

**Large communities** ([RFC 8092](https://www.rfc-editor.org/rfc/rfc8092)) extend this to 96 bits (`global-admin:local-data-1:local-data-2`), solving the problem that standard communities have no unambiguous namespace for 4-byte ASNs.

**Extended communities** ([RFC 4360](https://www.rfc-editor.org/rfc/rfc4360)) are 64-bit values with a typed structure, used primarily in VPN and EVPN contexts.

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
