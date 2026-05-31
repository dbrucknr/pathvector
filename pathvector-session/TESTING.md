# Testing

## Running the tests

```bash
# All unit tests (155 tests across the codec, FSM, and framing layers)
cargo test --lib

# Integration tests (9 tests; require a real loopback TCP connection)
cargo test --test transport

# Everything
cargo test
```

## Coverage

```bash
cargo llvm-cov
cargo llvm-cov --show-missing-lines   # show uncovered line numbers
```

Current coverage is **99.48% lines / 98.82% branches** (measured on M2 Max).

## Intentionally uncovered lines

Nine lines are not covered by any test. Each one falls into a category where
writing a reliable test is either impossible or would produce a test that is
more fragile than useful.

### `fsm/mod.rs` — lines 619 and 927

Both are `panic!` branches inside test-only helper functions (`find_send` and
the `else` arm of `establish`). They are only reachable when the helper itself
is called incorrectly, which would mean a bug in the test, not in production
code. Covering them would require intentionally breaking a test.

### `message/mod.rs` — line 64

`Cursor::read_u32` returns a truncated-read error when fewer than 4 bytes
remain. Every call site in the codebase guards the call with an explicit
remaining-byte check first (e.g., `if cur.remaining() < 4 { return Err(...) }`),
so the error path inside `read_u32` itself is structurally unreachable. The
guard is the intentional error surface; the inner check is defence-in-depth.

### `transport.rs` — lines 144–145

```rust
let recovery = self.fsm.process(FsmInput::TcpFailed);  // 144
self.execute(recovery).await;                           // 145
```

This recovery path runs when `execute` returns `false`, which only happens when
a TCP `send` fails on an apparently-live connection. Producing that condition
reliably on loopback requires the OS to reject a write after the socket appears
writable — a scenario that cannot be triggered deterministically without
low-level socket manipulation (e.g., `SO_LINGER` with `l_linger = 0`).

### `transport.rs` — lines 197–198

```rust
FsmInput::ConnectRetryTimerExpired  // 198
```

The connect-retry timer is hardcoded to 120 seconds (`CONNECT_RETRY_INTERVAL`
in the FSM). Covering this path requires either waiting two minutes or using
`tokio::time::pause` + `advance`. The paused-time approach deadlocks on macOS
because re-binding a just-released loopback port interacts badly with
`start_paused = true`; the real-I/O TCP accept and the virtual-clock advance
cannot make forward progress simultaneously. The existing
`test_connect_retry_on_refused_connection` test does verify the session stays
alive and in Active state after a refused connect, which exercises the
immediately adjacent code paths.

### `transport.rs` — lines 220–221 and 223

```rust
if let Some(w) = &mut self.writer {
    if w.send(msg).await.is_err() {
        self.drop_connection();  // 220
        return false;            // 221
    }
}                                // 223 — writer was None, send skipped
```

Line 223 (the `None` arm of the `if let`) is unreachable in practice: the FSM
always emits `SendMessage` before `CloseTcpConnection`, so `writer` is always
`Some` when a send is attempted. Lines 220–221 (send failure) require the same
conditions as lines 144–145 above — a write error on an apparently-live socket
— which cannot be produced deterministically on loopback without socket-level
manipulation.
