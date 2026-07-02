# pathvector-rpki

RPKI Route Origin Validation (ROV) support for the pathvector ecosystem: an RTR
(RPKI-to-Router Protocol) client that connects to an external RPKI validator and
maintains a live ROA validity cache.

---

## The problem this solves, in plain English

BGP — the protocol that decides how traffic finds its way across the internet — runs
almost entirely on trust. When a network announces "I originate 192.0.2.0/24," every
other network on the internet mostly just believes it. There's no built-in mechanism in
BGP itself to check whether that announcement is legitimate.

This is exploitable. If someone else — by mistake or on purpose — announces a prefix
they don't actually own, some fraction of the internet's traffic for that prefix can
get misdirected to them instead of the real owner. This is called a **BGP hijack**, and
it happens regularly: sometimes as a simple typo in a router config, sometimes as a
deliberate attack (traffic interception, denial of service, spam origination). A famous
example: in 2008, a Pakistani ISP trying to block YouTube domestically accidentally
leaked that block globally, taking YouTube offline worldwide for about two hours.

**RPKI (Resource Public Key Infrastructure)** is the internet's answer to this. The
legitimate owner of a prefix (e.g., an ISP or company) can publish a cryptographically
signed statement called a **ROA (Route Origin Authorization)**:

> "AS 65001 is authorized to originate 192.0.2.0/24, for prefixes up to /24."

**Route Origin Validation (ROV)** is the process of checking every route a router
receives against the full set of published ROAs, and classifying it:

| Verdict | Meaning |
|---|---|
| **Valid** | A ROA authorizes this exact origin AS for this prefix (or the ROA covers a broader range up to its stated max length). This is the route working as intended. |
| **Invalid** | A ROA exists covering this prefix, but it names a *different* origin AS, or the announced prefix is more specific than the ROA allows. This is almost certainly a hijack or a misconfiguration — most operators are configured to reject these outright. |
| **NotFound** | No ROA exists for this prefix at all. RPKI adoption isn't universal yet, so this is still the majority case for the internet-wide routing table — it means "unverifiable," not "bad." Most operators accept these by default. |

Once a router knows a route is `Invalid`, it can simply refuse to use it or propagate
it — closing off a large class of real-world routing incidents.

## Why this crate doesn't do RPKI cryptography itself

Actually validating ROAs requires fetching certificate chains from RPKI repositories
(over rsync or RRDP) and verifying X.509 signatures — a large, security-sensitive scope
with its own complexities (revocation, chain-of-trust validation, handling
misconfigured or slow-to-respond repositories). Every serious BGP implementation
delegates this to a separate, purpose-built program called an **RPKI validator** —
examples include [Routinator](https://github.com/NLnetLabs/routinator) (NLnet Labs),
`rpki-client` (OpenBSD), OctoRPKI (Cloudflare), and Cloudflare's `gortr`. The validator
does the heavy lifting continuously in the background and exposes its results over a
lightweight protocol.

That protocol is **RTR (RPKI-to-Router Protocol)** — the subject of this crate.
`pathvector-rpki` implements the RTR client side: it connects to a validator over TCP
(RFC 8210, with automatic fallback to the older RFC 6810), stays connected, and keeps
an in-memory cache of every published ROA up to date in real time. Any part of
pathvector (or your own code, if you use this crate standalone) can then ask "is this
`(prefix, origin AS)` combination `Valid`, `Invalid`, or `NotFound`?" without touching
the network — the answer comes straight out of the local cache. This mirrors exactly
how BIRD, FRR, and GoBGP handle RPKI: the validator does the cryptography, the router
just needs a fast, current cache.

---

## Quick start — using the crate directly

```toml
[dependencies]
pathvector-rpki = "0.1"
tokio = { version = "1", features = ["full"] }
```

```rust
use std::net::Ipv4Addr;
use pathvector_rpki::{RtrClient, RtrConfig, RoaValidity};

#[tokio::main]
async fn main() {
    // Connects to a validator listening on 127.0.0.1:3323 (Routinator's
    // default RTR port — see "Try it against a real validator" below).
    // spawn() returns immediately; the actual TCP session and sync run in
    // a background task, so this never blocks your program's startup.
    let (rpki, _join) = RtrClient::spawn(RtrConfig {
        host: "127.0.0.1".to_string(),
        port: 3323,
        ..Default::default()
    });

    // Give the background task a moment to connect and complete its first
    // sync. In real code you'd check `rpki.status().connected` instead of
    // sleeping — see pathvectord's daemon wiring for the pattern.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let prefix: Ipv4Addr = "1.0.0.0".parse().unwrap();
    match rpki.validate_v4(prefix, 24, 13335) {
        RoaValidity::Valid => println!("origin AS13335 is authorized for 1.0.0.0/24"),
        RoaValidity::Invalid => println!("this route is invalid — likely a hijack"),
        RoaValidity::NotFound => println!("no ROA published for this prefix"),
    }
}
```

This exact code (plus a couple more example queries) lives in the crate as a runnable
example:

```bash
cargo run -p pathvector-rpki --example validate_prefix
```

## Try it against a real validator

Everything above works against a real, live RPKI dataset — not synthetic test data.
Here's how to see it for yourself using [Routinator](https://github.com/NLnetLabs/routinator),
NLnet Labs' open-source RPKI validator, via Docker.

**1. Start Routinator.** It ships as a ready-to-run container that fetches and
validates the full RPKI dataset from all five Regional Internet Registries (ARIN,
RIPE, APNIC, LACNIC, AFRINIC):

```bash
docker run -d --name routinator -p 3323:3323 -p 8323:8323 nlnetlabs/routinator:latest
```

`3323` is the RTR port (what this crate connects to). `8323` is a separate HTTP port
Routinator uses for its own status page and metrics — useful for watching progress in
the next step, but not something `pathvector-rpki` talks to.

**2. Wait for the first sync to complete.** On a fresh container this typically takes
a few minutes — Routinator has to download and cryptographically verify certificate
chains from all five registries. Poll its status page until it reports real numbers
instead of "ongoing":

```bash
curl -s http://localhost:8323/status
```

```text
version: routinator/0.15.2
serial: 0
...
valid-roas: 377985
valid-roas-per-tal: afrinic=11791 apnic=48108 arin=223467 lacnic=34017 ripe=60602
vrps: 978014
```

**3. Run the quick-start example above** (or `pathvectord` — see its README for the
full daemon walkthrough). Once connected, `pathvector-rpki` will report a `roa_count`
close to Routinator's `vrps` figure (a small difference is expected and harmless — see
"Why `roa_count` doesn't exactly match Routinator's `vrps`" below).

**4. Verify against a real, well-known ROA.** `1.0.0.0/24`, originated by `AS13335`
(Cloudflare — this is part of the range behind their `1.1.1.1` public DNS resolver), is
a stable, real-world example you can check against at any time:

```rust
// Real ROA — should print "Valid":
rpki.validate_v4("1.0.0.0".parse().unwrap(), 24, 13335);

// Same prefix, wrong origin AS — should print "Invalid":
rpki.validate_v4("1.0.0.0".parse().unwrap(), 24, 99999);

// RFC 5737 TEST-NET-1 — deliberately unallocated, no ROA exists —
// should print "NotFound":
rpki.validate_v4("192.0.2.0".parse().unwrap(), 24, 65001);
```

**5. Clean up:**

```bash
docker stop routinator && docker rm routinator
```

### Why `roa_count` doesn't exactly match Routinator's `vrps`

Don't expect an exact match, and don't treat a small gap as a bug. `roa_count` counts
individual `(prefix, max-length, origin-AS)` entries currently held in the cache;
Routinator's `vrps` figure is its own internal count of Validated ROA Payloads, which
can differ slightly for reasons that don't affect correctness — e.g.
`pathvector-rpki`'s `RoaTable` deduplicates identical entries received at the same
exact prefix (see `insert` in `src/table.rs`), and the two numbers are also snapshots
taken at slightly different points in time. In one real run this repo's authors
observed `roa_count` a few tenths of a percent below Routinator's `vrps` — small,
expected, and not investigated further since it has no bearing on whether any given
`validate()` call returns the right answer (which is what the differential proptest in
`table.rs` actually proves).

---

## Status

**RTR client, ROA cache, and policy-layer filtering: implemented and hardened.**
`pathvectord` rejects `Invalid` routes by default (`Valid`/`NotFound` are accepted) via
a `RoaValidityCondition` in [`pathvector-policy`](../pathvector-policy) wired into every
peer's import policy — see [RFC.md](RFC.md) for the detailed requirement-by-requirement
status.

**Phase 1** shipped RTR session management, the ROA validity cache, and a read-only way
to inspect it (`pathvector rpki status`/`validate`), deliberately without touching route
acceptance. **Phase 2** added the policy integration: `pathvectord`'s
`[daemon.rpki].reject_invalid` (default `true`) controls whether `Invalid` routes are
actually rejected, or whether RPKI runs in monitoring-only mode. See
`pathvectord/README.md`'s "Local RPKI interop with Routinator" section for a full
walkthrough, including how to verify a hijacked/misoriginated route actually gets
rejected.

---

## How the cache works

Internally, `pathvector-rpki` uses [`routemap`](https://crates.io/crates/routemap) (a
treebitmap-based longest-prefix-match table) as the storage engine, composed to answer
RFC 6811 §2's "any covering ROA" semantics — not just the single longest match a routing
table would care about. See `src/table.rs` for the algorithm.

---

## RFC target

| RFC | Title | Status |
|---|---|---|
| [RFC 8210](https://www.rfc-editor.org/rfc/rfc8210) | The RPKI-to-Router Protocol, Version 1 | See [RFC.md](RFC.md) |
| [RFC 6810](https://www.rfc-editor.org/rfc/rfc6810) | The RPKI-to-Router Protocol (Version 0) | See [RFC.md](RFC.md) |
| [RFC 6811](https://www.rfc-editor.org/rfc/rfc6811) | BGP Prefix Origin Validation | See [RFC.md](RFC.md) |

---

## License

MIT
