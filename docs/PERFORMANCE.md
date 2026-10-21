<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br><b>csrf-sec</b><br>
    <sub><sup>PERFORMANCE</sup></sub>
</h1>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./API.md" title="API"><b>API</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>PERFORMANCE</span>
    </sup>
</div>
<br>

Every number on this page is **measured** unless it says otherwise. Reproduce them with `cargo bench --bench csrf` (the crate) and `cargo bench --bench compare` in `dev/bench-compare` (the comparison).

## Method

- **Machine:** AMD Ryzen 9 9950X3D, Linux 6.6 (WSL2), Rust 1.99.0, `--release` with fat LTO and one codegen unit (the crate's release profile).
- **Harness:** `criterion` 0.7, 1 s warm-up, 3 to 4 s measurement, the median of the reported interval.
- **Inputs:** a 44-character session id, no scope unless stated, the default 12-hour lifetime.
- `issue_at` benchmarks use a deterministic pad source so they measure the token work; `issue` uses the system clock and `OsPads`, as a server does.
- Numbers taken on Windows with this machine's local linker setup (`rust-lld` against an older C runtime) ran up to 60 ns slower on paths that copy small buffers, because of that runtime's `memcpy`; the same code on Linux does not show it, and Windows builds with the standard MSVC linker do not use that runtime. Linux numbers are the reference.

## Per call

| Operation | Time | Notes |
|---|---|---|
| `verify_at` (valid token) | 110 ns | decode 30 ns + keyed BLAKE3 75 ns + the rest |
| `verify` (system clock) | 142 ns | adds one system clock read |
| `issue_at` | 112 ns | keyed BLAKE3 75 ns + encode 20 ns + masking |
| `issue` (system clock, `OsPads`) | 167 ns | adds one clock read and a 22-byte pad from the per-thread OS buffer |
| `check_at`, `Strict`, origin match + token | 150 ns | |
| `check_at`, cross-site refused | 23 ns | refused before any token work |
| layer 1, `Sec-Fetch-Site` | 1.3 ns | the modern-browser path |
| layer 1, `Origin` match (no Fetch Metadata) | 37 ns | two origin parses (`Origin` and `own_origin`) |
| layer 1, `Referer` match | 23 ns | byte-identical to `own_origin`: one parse |
| layer 1, cross-site refused | 19 ns | with an allowlist to consult; without one, no parsing at all |
| `RequestFacts` from raw headers | 2.9 ns | |
| one-time `issue_at` | 198 ns | a 16-byte nonce from the pad source, a second compression block |
| one-time `issue_at` + `verify_at`, allocation-free store | 429 ns | |
| one-time `issue_at` + `verify_at`, `MemoryStore` | 574 ns | adds a shard lock and a hash map insert; steady state, every verify passing, expired records dropped as the session reaches its quota |
| `OsPads`, 22 bytes | 28 ns | Linux `getrandom` throughput is the floor; about 8 ns on Windows |
| `Csrf::new` | 212 ns | subkey derivation, once per process |

### Rejections

| Reason | Time | Notes |
|---|---|---|
| `missing` | 3 ns | |
| `malformed` (wrong length) | 3.4 ns | length checked before any decoding |
| `malformed` (bad text) | 35 ns | the full constant-time decode runs; garbage costs the same as a real token |
| `bad_mac` | 116 ns | one MAC: a forgery costs no more than a valid token |
| `bad_mac` with scope and previous session | 193 ns | the bounded extra MACs that name the reason (at most two) |
| `expired` | 115 ns | MAC first, then the window |

### Session id length

The MAC input is the 8-byte header plus the session id and scope. Up to 56 bytes of session id and scope, it fits one 64-byte BLAKE3 block.

| Session id | `verify_at` |
|---|---|
| 16 bytes | 114 ns |
| 43 bytes | 114 ns |
| 56 bytes | 117 ns |
| 64 bytes | 181 ns (two blocks) |
| 128 bytes | 302 ns (three blocks) |
| 1024 bytes | 1.32 µs |

## Allocation

Zero allocations on issue, verify, check, every rejection path, and the one-time path with an allocation-free store, on every platform: asserted by a counting global allocator in `tests/no_alloc.rs`, which CI runs on Linux, macOS, and Windows.

## Against the `csrf` crate

`csrf` 0.5.0 is the standalone Rust CSRF primitive that framework middlewares build on. Each side does what a server does per request: **issue** produces the text sent to the browser (csrf-sec: one masked token; `csrf`: a token and a cookie, both base64), and **verify** checks what came back (csrf-sec: decode, unmask, MAC, window; `csrf`: decode both, check or decrypt both, compare, expiry).

| Operation | csrf-sec | `csrf` HMAC-SHA256 | `csrf` AES-256-GCM | `csrf` ChaCha20-Poly1305 |
|---|---|---|---|---|
| issue | **165 ns** | 530 ns (3.2× slower) | 1.11 µs (6.7×) | 3.34 µs (20×) |
| verify | **141 ns** | 430 ns (3.1× slower) | 407 ns (2.9×) | 2.46 µs (17×) |
| reject a forged token | **143 ns** | 245 ns (1.7× slower) | | |

These compare work per request, not equal designs. csrf-sec does more per token on the security side:

| | csrf-sec | `csrf` 0.5.0 |
|---|---|---|
| bound to the session | yes, the session id is inside the MAC | no: a token and cookie pair; a cookie planted from a subdomain carries its own valid pair |
| different text on every response (BREACH) | yes | only when a new pair is generated, which also changes the cookie |
| tag comparison | constant time | MAC check constant time; the token-to-cookie compare is a plain `!=` |
| secrets in errors | never | error messages include both token values |
| RNG failure | `Err`, no token | panics (`expect`) |
| allocation per call | none | several (`Vec`, `String`) |
| request origin policy | Fetch Metadata, `Origin`, `Referer` | none |

## What was tuned in 0.6.0

| Change | Effect (measured) |
|---|---|
| Tag comparison: one 128-bit XOR and one test instead of crypt-io's per-byte `Tag::ct_eq` | the compare itself from 50 ns to about 1 ns |
| base64url codec: eight lanes per `u64` (SWAR) for full blocks | encode 20 ns and decode 29 ns per token, still branch-free and table-free |
| both together | `verify_at` 245 to 185 ns on Windows, 22% |
| Origin parsing: first-colon scheme split, bit-set character classes, a byte-identical fast path for `own_origin` | `Referer` match 51 to 23 ns |
| Cross-site requests consult only the allowlist | cross-site refusal 45 to 19 ns, and no parsing at all without an allowlist |

Not taken: a user-space CSPRNG for pads. It would cut `issue` by about 20 ns on Linux, but the operating system's generator stays the only source of randomness in the crate (PLAN D-055).
