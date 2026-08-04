# Production readiness

This document defines what "production ready" means for `pathvectord`. It is a
deployment gate, not a second protocol backlog:

- [`RFC_REQUIREMENTS.md`](RFC_REQUIREMENTS.md) tracks protocol coverage.
- [`RFC_AUDIT.md`](RFC_AUDIT.md) records clause-by-clause correctness evidence.
- [`TODO.md`](TODO.md) tracks implementation work and optional features.
- This document asks whether the daemon can be operated safely, recovered
  predictably, and trusted under the intended production load.

The distinction matters. A daemon can implement an RFC correctly and still be
unsafe to expose because its management API is unauthenticated, a background
task can die silently, or a full-table operation can delay KEEPALIVEs for every
peer.

> **⚠️ Known security exposure — read before deploying.** By default,
> `pathvectord`'s gRPC management API binds to `0.0.0.0`, speaks plaintext
> HTTP/2, has gRPC reflection enabled, and requires no authentication or
> authorization. Any host that can reach the configured `grpc_port` can add or
> remove peers, change import/export policy, and originate or withdraw routes
> — full control of the daemon's routing behavior. There is currently no
> daemon-level mitigation; a network-level firewall restricting access to
> trusted operator hosts is **required**, not optional, for any deployment
> reachable from an untrusted network. See [PR-2](#pr-2-secure-the-management-plane)
> below for the tracked fix and exit criteria.

---

## Current assessment

`pathvectord` is a strong production candidate for controlled deployments and
redundant pilots. It is not yet ready to be the sole BGP speaker on a
high-consequence, full-table internet edge.

The project already has unusually strong foundations:

- systematic RFC audits derived from primary text;
- unit, property, fuzz, real-TCP, adversarial, and Docker end-to-end tests;
- interoperability coverage with GoBGP, BIRD, and FRR;
- IPv4/IPv6, RPKI/ROV, RFC 8212 reject-by-default, BGP Roles/OTC, Graceful
  Restart, route reflection, max-prefix protection, TCP MD5 for IPv4 peers,
  Linux FIB integration, and Prometheus metrics;
- full-table replay and memory benchmarks.

Those establish protocol credibility. The remaining gates are primarily
operational isolation, lifecycle management, security, and evidence from
sustained production-shaped load.

### Deployment profiles

| Profile | Current position | Minimum expectation |
|---|---|---|
| Lab, development, or internal experimentation | Suitable | Normal CI and configuration review |
| Controlled route origination / DDoS blackhole speaker with a redundant fallback | Pilot-ready | Management-plane isolation, max-prefix limits, monitoring, tested rollback |
| Internal BGP with bounded route counts | Candidate | Deployment-specific soak test and failure drill |
| Full-table edge with another proven implementation available for fallback | Not yet pilot-ready by default | All blocking gates below, plus deployment-scale validation |
| Sole critical internet-edge speaker | Not ready | All blocking and required gates, operational history, independent interoperability evidence |

"Suitable" here is not a warranty. Operators must still validate their exact
peer mix, policy, kernel, route scale, and failure model.

---

## Blocking gates

These should be closed, or explicitly mitigated and accepted by an operator,
before a high-consequence deployment.

### PR-1: Bound control-plane stalls under production load

**Status:** Open; underlying architecture and several hot paths are already
tracked in [`TODO.md`](TODO.md).

All peer events currently converge on one daemon event loop and a broad
`DaemonState` write lock. Full-table advertisement, Graceful Restart stale-route
marking, peer teardown propagation, and RPKI-triggered policy re-evaluation can
hold that lock while processing many routes. A slow operation for one peer can
therefore delay state transitions and management reads for every peer.

**Exit criteria:**

- Run at least two simultaneous full-table peers plus one control peer while
  continuously measuring event-loop latency and KEEPALIVE scheduling.
- Exercise initial convergence, peer teardown, GR recovery, route refresh,
  RPKI cache replacement, and full export-policy re-evaluation.
- Demonstrate that the control peer does not miss a negotiated hold timer at
  the documented maximum supported scale.
- Establish and publish a supported capacity envelope: peer count, IPv4/IPv6
  route count, update rate, policy complexity, memory, and convergence target.
- If measurements exceed the budget, batch work outside the global write-lock
  interval or introduce finer-grained processing before declaring the envelope
  supported.

### PR-2: Secure the management plane

**Status:** Open; not previously represented as a production gate in
[`TODO.md`](TODO.md).

The gRPC server binds to `0.0.0.0`, uses plaintext HTTP/2, enables reflection,
and has no authentication or authorization. Its services can add/remove peers,
change policy, and originate/withdraw routes. A firewall is a necessary current
mitigation, but it should not be the only boundary offered by the daemon.

**Exit criteria:**

- Add a configurable management bind address; default to loopback or require an
  explicit opt-in for an all-interface bind.
- Support TLS, preferably mutual TLS for operator/API clients.
- Authorize mutating RPCs separately from read-only inspection.
- Allow reflection to be disabled.
- Add negative e2e tests proving an unauthenticated or unauthorized caller
  cannot mutate routing state.
- Document firewall and certificate-rotation procedures.
- **When any of the above changes the default exposure** (bind address,
  auth requirement, or reflection default), update the security warning in
  [`README.md`](README.md)'s Quick Start and the "Known security exposure"
  callout at the top of this document in the same change — don't let the
  warnings outlive the risk they describe.

### PR-3: Implement coordinated startup and graceful shutdown

**Status:** Open; not currently tracked as a complete daemon-lifecycle item.

`main` awaits `daemon::run()` without handling SIGINT/SIGTERM. A normal service
stop therefore relies on process termination rather than an orderly sequence.
Several subsystems are spawned independently, and bind failure in a listener or
management endpoint can leave a partially useful daemon running.

**Exit criteria:**

- Handle SIGINT and SIGTERM explicitly.
- Stop accepting management mutations, send the configured administrative
  shutdown notification to established peers, drain or discard outbound work by
  documented policy, and close sessions within a bounded deadline.
- Withdraw or deliberately retain kernel state according to a documented
  shutdown mode.
- Treat failure of required listeners/services during startup as a startup
  failure rather than silently running partially initialized.
- Add real-process tests for SIGTERM during idle operation, convergence, and an
  active GR window.

### PR-4: Add one authoritative startup configuration validation boundary

**Status:** Open; not currently tracked as a production gate.

Dynamic peer RPCs validate selected inputs, but static TOML loading does not
appear to run an equivalent, comprehensive preflight before sessions and
background tasks start. Map-based construction also makes duplicate peer
addresses particularly dangerous: one entry can overwrite another subsystem's
state while more than one session is spawned.

**Exit criteria:**

- Implement `Config::validate()` and call it before any socket bind, task spawn,
  sidecar mutation, or FIB change.
- Reject duplicate peer addresses across static and persisted dynamic config.
- Reject reserved or unusable local/remote ASNs, invalid BGP identifiers,
  impossible timer combinations, invalid MD5 configurations, and conflicting
  role/peer-type settings.
- Validate ports, table IDs, path permissions, and address-family prerequisites.
- Return all actionable validation errors together where practical.
- Use the same validators for TOML startup and gRPC mutations so the two paths
  cannot drift.
- Add a `pathvectord check <config>` or equivalent dry-run command suitable for
  CI and pre-deployment checks.

### PR-5: Supervise required background tasks and expose meaningful readiness

**Status:** Partially tracked for the metrics exporter; broader daemon-level
supervision and readiness are not.

The daemon spawns the gRPC server, BGP listeners, FIB tracker/writer, RPKI
client, command processor, metrics exporter, and per-peer work in separate
tasks. Some failures are logged, but there is no single supervisor defining
which task deaths are fatal, restartable, or degraded. The container health
check only proves that the gRPC TCP port accepts connections.

**Exit criteria:**

- Keep handles for required long-lived tasks and surface unexpected completion.
- Define fatal versus degraded subsystem failure policy. For example, loss of
  the only BGP listener should not look healthy merely because gRPC still works.
- Expose liveness and readiness separately. Readiness should include event-loop
  health and configured required subsystems, not merely an open TCP port.
- Export task restart/failure metrics and a machine-readable degraded reason.
- Test task panic, listener failure, RPKI loss, FIB writer failure, and metrics
  failure independently.

### PR-6: Produce sustained-churn and soak evidence

**Status:** Open; backpressure testing is already mentioned in
[`TODO.md`](TODO.md), but a release gate and duration are not defined.

Short correctness and replay benchmarks do not expose leaks, timer starvation,
counter drift, reconnect storms, allocator fragmentation, or rare races that
appear after hours or days.

**Exit criteria:**

- Run a reproducible multi-peer churn test with announcements, withdrawals,
  session resets, malformed-peer isolation, RPKI changes, and a deliberately
  slow outbound peer.
- Include at least one 24-hour CI/nightly soak and a longer pre-release soak for
  production candidates.
- Assert bounded RSS after convergence/churn cycles, no task loss, no stalled
  healthy peer, no unexpected session reset, and no RIB/FIB divergence.
- Preserve workload, version, hardware, peak resource use, and failure logs as
  release evidence rather than recording only a headline throughput number.

---

## Required before a broad production recommendation

These may be mitigated in a narrow deployment, but should be resolved before
advertising the daemon as a general replacement for mature routing suites.

### PR-7: Define persistence and restart semantics for operator mutations

Peer additions are persisted in a sidecar, while other runtime state—policy
changes, originated routes, timers, and transient control-plane decisions—has
different or implicit restart behavior. Operators need to know exactly what
survives a process restart and how static config interacts with persisted state.

**Exit criteria:** document a persistence matrix for every mutating RPC; make
durable mutations atomic and versioned; detect corrupt/incompatible state; and
provide an explicit export/backup/restore path. Ephemeral mutations should be
named and reported as such.

### PR-8: Define compatibility, upgrade, and rollback contracts

The project is pre-1.0 and publishes binaries/images, but there is no explicit
compatibility contract for TOML, the dynamic-peer sidecar, protobuf APIs, or
on-host kernel state across upgrades.

**Exit criteria:** define supported upgrade/rollback paths; add compatibility
tests using the previous released config and sidecar formats; state protobuf
field-evolution rules; and publish an operator runbook for rolling upgrade,
failed upgrade, and rollback while peers are active.

### PR-9: Harden release artifacts and runtime packaging

The release workflow builds binaries and an OCI image, but production consumers
also need artifact integrity and a least-privilege runtime story.

**Exit criteria:** publish checksums and signed provenance, generate an SBOM,
scan release images/dependencies, document required Linux capabilities, and run
the container as a non-root user where feasible. Pin base images by digest for
reproducible releases and document the minimum writable filesystem paths.

### PR-10: Reconcile observed and actual kernel forwarding state

The existing FIB metric is derived from operations the daemon believes
succeeded. It is not a periodic proof that the kernel still contains the
intended routes. External changes or silent drift can therefore make telemetry
and forwarding reality diverge.

**Exit criteria:** periodically compare intended Loc-RIB/FIB state with the
configured kernel table; expose drift; repair or alert according to explicit
policy; and test external deletion/replacement of installed routes.

### PR-11: Close remaining error-path ambiguity

The protocol audit records some body-decoding errors that are still dropped
without the most precise RFC NOTIFICATION mapping. Capability fallback for
older peers is also incomplete. These are narrower than the operational gates
above but matter for diagnosing and recovering from unusual interoperability
failures.

**Exit criteria:** map every externally reachable decode failure to a tested
session outcome; verify NOTIFICATION code/subcode/data on the wire; and document
which capability negotiation failures are retried versus terminal.

---

## Important but deployment-dependent

The following should remain visible without becoming universal release blockers:

- IPv6 TCP MD5 support;
- ECMP/multipath;
- dynamic neighbors and peer groups;
- AS-path regular-expression policy;
- BMP export/monitoring;
- full confederation-member operation;
- legacy two-byte-only peer AS4 reconstruction;
- route flap dampening;
- commercial router interoperability beyond the current open-source peers.

A deployment needing one of these features must treat it as a local blocking
gate. A deployment that does not use it should not be held hostage to it.

---

## Production-candidate evidence checklist

A release proposed for production should attach or link evidence for all of the
following:

- exact commit, Rust version, build profile, target, and artifact digest;
- clean unit, property, fuzz-smoke, doctest, lint, MSRV, and e2e CI;
- interoperability results for every peer implementation/version in the target
  deployment;
- configuration dry-run output;
- supported capacity envelope and the benchmark/soak workload proving it;
- management-plane exposure and authentication configuration;
- max-prefix, import/export policy, RPKI, and FIB settings;
- startup, shutdown, peer-loss, RPKI-loss, FIB-failure, and rollback drills;
- dashboards/alerts for peer state, update rate, policy rejection, FIB failure,
  event-loop latency, task health, and resource saturation;
- known deviations accepted by the operator, with owner and expiry date.

No single percentage or test count makes the daemon production ready. Readiness
is the combination of protocol evidence, a bounded supported envelope, secure
operation, recoverability, and deployment history.

---

## Maintaining this document

- Keep this file focused on release/deployment gates. Put implementation detail
  and optional feature design in [`TODO.md`](TODO.md) or `plans/`.
- A gate is closed only when both implementation and production-shaped evidence
  exist.
- If a gate is mitigated rather than fixed, record the exact supported deployment
  boundary here.
- Reassess this document before every minor release until the project reaches a
  stable production support policy.
