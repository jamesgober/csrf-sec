<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>csrf-sec</b>
    <br>
    <sub><sup>REQUEST-FORGERY PROTECTION</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/csrf-sec"><img alt="Crates.io" src="https://img.shields.io/crates/v/csrf-sec"></a>
    <a href="https://crates.io/crates/csrf-sec"><img alt="Downloads" src="https://img.shields.io/crates/d/csrf-sec?color=%230099ff"></a>
    <a href="https://docs.rs/csrf-sec"><img alt="docs.rs" src="https://img.shields.io/docsrs/csrf-sec"></a>
    <a href="https://github.com/jamesgober/csrf-sec/actions"><img alt="CI" src="https://github.com/jamesgober/csrf-sec/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>csrf-sec</strong> answers one question for every state-changing request: did this request come from our own page, for this session? It answers with independent checks, so one failing defence does not open the door: a request origin policy over the browser's Fetch Metadata and <code>Origin</code> headers, a signed token bound to the session and masked differently on every response, and cookie guidance for the session cookie.
    </p>
    <p>
        It is protocol-free and stateless: adapters hand it plain values, and any node holding the key ring verifies any token, with nothing to store or replicate. Issuing and verifying allocate nothing and take no lock.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). <code>#![forbid(unsafe_code)]</code>. <code>no_std</code> core (with <code>alloc</code>).
    </p>
    <blockquote>
        <strong>Status: <code>0.7.0</code>, hardened.</strong> Every feature is built, measured, and attacked: an attack test for each of the fifteen threats, property tests, four invariant-checking fuzz targets, and statistical constant-time tests, all in CI. Next is the <code>0.8.0</code> alpha (API review against real adapters), then the <code>0.9</code> release candidates and <code>1.0</code>. The schedule is <a href="./dev/ROADMAP.md"><code>dev/ROADMAP.md</code></a>.
    </blockquote>
</div>

<hr>
<br>

## Installation

```toml
[dependencies]
csrf-sec = "0.7.0"
```

## Quick Start

```rust
use csrf_sec::{Csrf, RequestFacts};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key: [u8; 32] = load_persisted_key();
    let csrf = Csrf::new(key)?;

    // Rendering a form: 59 characters, different on every call.
    let token = csrf.issue(session_id)?;

    // Handling the POST: request policy and token.
    let facts = RequestFacts::new("POST")
        .fetch_site(sec_fetch_site)        // Sec-Fetch-Site header
        .origin(origin)                    // Origin header
        .own_origin("https://example.com");
    csrf.check(&facts, session_id, submitted_token)?;   // Err: send a generic 403
    Ok(())
}
```

A refusal carries a reason (`bad_mac`, `cross_site`, `expired`, ...) and a severity hint for your logs and detection layer; the client gets a plain 403.

<br>

## How it works

| Layer | Stops | Cost (measured) |
|---|---|---|
| **Request origin policy.** `Sec-Fetch-Site: cross-site` on an unsafe request is refused unless its origin is allowlisted; without Fetch Metadata, `Origin` (then `Referer`) must match this site. Script cannot forge these headers. | cross-site form posts, `Origin: null` tricks, top-level cross-site POST navigation | 1.3 ns on Fetch Metadata, 19 to 37 ns on `Origin` and `Referer` |
| **Signed, session-bound token.** Keyed BLAKE3 over the session id (and optionally one action), 128-bit tag, compared in constant time; the session id never appears in the token. | forged and replayed-across-session tokens, tokens taken from another form | verify 110 ns, issue 112 ns |
| **Per-response masking.** Every page shows different token text (fresh CSPRNG pad), all of it valid. | BREACH-style recovery from compressed pages | 28 ns per pad on Linux, 8 ns on Windows |
| **Cookie guidance.** `__Host-` prefix, `SameSite=Lax`, `Secure`, `HttpOnly` on the session cookie, applied by your cookie layer. Tokens are never compared to a cookie. | cookie tossing from a subdomain | none |

Measured on Linux (Ryzen 9 9950X3D); method and every number in [`docs/PERFORMANCE.md`](./docs/PERFORMANCE.md). Zero allocation on issue, verify, check, and every rejection path, asserted by a counting-allocator test on Linux, macOS, and Windows.

### Against the `csrf` crate

| Per request | csrf-sec | `csrf` 0.5 HMAC | `csrf` 0.5 AES-GCM | `csrf` 0.5 ChaCha20 |
|---|---|---|---|---|
| issue | **165 ns** | 530 ns | 1.11 µs | 3.34 µs |
| verify | **141 ns** | 430 ns | 407 ns | 2.46 µs |

Measured, same machine and harness (`dev/bench-compare`). csrf-sec is also session-bound, masked per response, allocation-free, and never puts token values into errors; `csrf` 0.5 is none of those (details in `docs/PERFORMANCE.md`).

<br>

## Features

- **Three API tiers.** Tier 1: `Csrf::new`, `issue`, `verify`, `check`. Tier 2: a `Binding` (scope, previous session) and a builder. Tier 3: explicit time and randomness, no `std` required.
- **Accurate reasons.** The MAC is checked first, so a forged token is never reported as expired, and an expired real token is never reported as forged. A tab opened before login reports `stale_session` (benign), not `bad_mac` (forgery).
- **One-time tokens** for high-value actions, through a `NonceStore` you choose. Issuing never touches the store, which records only used tokens; the MAC is checked first, so a forged request can neither burn a user's token nor load a shared store.
- **Rotation that logs nobody out.** Signing, accepted (staged), and retired keys; two-step rotation for clusters, so no node ever sees a token from a key it does not know; public key fingerprints to confirm every node holds the same ring.
- **Stateless by default.** Any node with the key ring verifies any session token; no shared store, no replication, no bottleneck. Only one-time tokens use a store.
- **Constant time where it matters.** The tag comparison and the base64url codec (no lookup tables); canonical text only, so any changed character fails.
- **Fail closed.** If the clock or the random generator fails, no token is issued; nothing panics.
- **Attacked, not just tested.** Each of the fifteen threats in the plan has a test that plays the attacker; fuzz targets assert that nothing forged verifies and that a changed token never passes; Welch t-tests show the tag comparison and the decoder take the same time whatever the data.
- **Ours.** No third-party runtime dependency of its own: keyed BLAKE3 through `crypt-io`, randomness through `mod-rand`. No async runtime.

<br>

## What it does not stop

Cross-site scripting defeats every CSRF defence, because script on the page can read the token; that is stopped by output encoding and a content security policy. Clickjacking is stopped by `frame-ancestors`. csrf-sec does not parse HTTP, manage sessions, or set cookies.

<br>

## Documentation

- [`docs/API.md`](./docs/API.md): the API by task, with recipes (no server session, single-page apps, tenants, logging), every example compiled as a test.
- [`docs/PERFORMANCE.md`](./docs/PERFORMANCE.md): measured costs of every call and rejection, and the comparison with the `csrf` crate.
- [docs.rs/csrf-sec](https://docs.rs/csrf-sec): item reference.
- [`dev/PLAN.md`](./dev/PLAN.md): the design, threats T1-T15 with defence and cost, and the decision log.
- [`CHANGELOG.md`](./CHANGELOG.md).

<hr>
<br>

## Contributing

See <a href="./dev/DIRECTIVES.md"><code>dev/DIRECTIVES.md</code></a> for engineering standards and the definition of done. Before a PR: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b> &mdash; <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b> &mdash; <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
