# pathvector-rpki

RPKI Route Origin Validation (ROV) support for the pathvector ecosystem: an RTR
(RPKI-to-Router Protocol) client that connects to an external RPKI validator and
maintains a live ROA validity cache.

---

## What is RPKI ROV, and why an RTR client?

RPKI (Resource Public Key Infrastructure) lets a prefix's legitimate owner publish a
Route Origin Authorization (ROA): a cryptographically signed statement of the form
"AS 65001 is authorized to originate 192.0.2.0/24, up to /24." Route Origin Validation
checks every received BGP route against the set of published ROAs and classifies it:

- **Valid** — a ROA exists that authorizes this exact origin AS for this prefix (or a
  less specific one, up to the ROA's max length)
- **Invalid** — a ROA exists covering this prefix, but it doesn't authorize this origin
  AS or this prefix length — almost certainly a hijack or misconfiguration
- **NotFound** — no ROA exists for this prefix at all (RPKI adoption isn't universal —
  this is the majority case for internet-wide tables today)

Validating ROAs requires fetching and cryptographically verifying certificate chains
from RPKI repositories (rsync/RRDP) — a large, security-sensitive scope of its own.
Rather than duplicating that work, `pathvector-rpki` implements the **RTR protocol**
(RFC 8210, with RFC 6810 fallback): a lightweight TCP protocol for consuming
already-validated ROA data from an external **RPKI validator** (Routinator, rpki-client,
OctoRPKI, Cloudflare's gortr, etc.). This mirrors how BIRD, FRR, and GoBGP all handle
RPKI — the validator does the cryptography; the router just needs a fast, current cache.

---

## Status

**RTR client + ROA cache: implemented.** `pathvectord` integration and policy
enforcement are being layered on top — see [RFC.md](RFC.md) for the detailed
requirement-by-requirement status.

**Phase 1 scope (current):** RTR session management, ROA validity cache, and a
read-only way to inspect it. This phase deliberately does **not** filter or reject any
BGP routes — it proves out the RTR client and cache correctness first. Automatic route
filtering based on ROA validity is a follow-up phase, wired through `pathvector-policy`.

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
