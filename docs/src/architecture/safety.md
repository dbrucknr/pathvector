# Safety

## The unsafe enclave

All `unsafe` code in the workspace lives in `pathvector-sys` and nowhere else.

```toml
# workspace Cargo.toml
[workspace.lints.rust]
unsafe_code = "forbid"

# pathvector-sys/Cargo.toml
[lints.rust]
unsafe_code = "allow"   # single override; the only one in the workspace
```

The isolation means a security reviewer can audit the entire unsafe surface by
reading one file: `pathvector-sys/src/tcp.rs`. The unsafe function is
`apply_linux` — 60 lines of `setsockopt(TCP_MD5SIG)` with three `unsafe` blocks,
each with a `// SAFETY:` comment explaining the invariant being upheld.

## Why `TcpMd5Sig` is defined locally

`libc::tcp_md5sig` is not available on all Linux target architectures in all
released versions of the `libc` crate (specifically absent on `aarch64` in
`libc 0.2.x`). `pathvector-sys` defines the struct locally as `#[repr(C)]`,
matching the kernel ABI from `<linux/tcp.h>` exactly, with the layout documented
field-by-field. This is safer than relying on a crate that may not expose the
type for the target architecture.

## Platform behaviour

| Platform | `setsockopt(TCP_MD5SIG)` | Enforcement |
|---|---|---|
| Linux (native, `CAP_NET_ADMIN`) | Succeeds | Kernel enforces on every segment |
| Linux in Docker Desktop VM | Returns `ENOPROTOOPT` (no `CONFIG_TCP_MD5SIG`) | Not enforced; treated as non-fatal |
| macOS | No-op (`#[cfg(not(target_os = "linux"))]`) | Not enforced |

## Test coverage of the unsafe path

The unsafe path is covered at every layer:

- **Unit tests** in `pathvector-sys`: real `TcpListener` fd on Linux; EBADF
  on invalid fd; ENOPROTOOPT graceful degrade
- **Property tests**: all keys 0–80 bytes never produce `InvalidInput`; all
  keys > 80 bytes always produce `InvalidInput`; all IPv6 addresses always
  produce `Unsupported`
- **E2E test**: `md5_matching_key_session_establishes` — matching keys produce
  an Established BGP session against real GoBGP
- **E2E test (CI only)**: `md5_key_mismatch_session_never_establishes` — mismatched
  keys prevent session establishment on native Linux where `CONFIG_TCP_MD5SIG`
  is present

See [Testing](../testing.md) for the full coverage map.
