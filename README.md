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
        <strong>csrf-sec</strong> answers one question for every state-changing request: did this request come from our own page, for this session? It answers with three independent checks, so one failing defence does not open the door: a request origin policy over the browser's Fetch Metadata and <code>Origin</code> headers, a signed token bound to the session and masked differently on every response, and cookie guidance for the session cookie.
    </p>
    <p>
        It is protocol-free and stateless: adapters hand it plain values, and any node holding the key ring verifies any token, with nothing to store or replicate. Verification allocates nothing and takes no lock.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). <code>#![forbid(unsafe_code)]</code>.
    </p>
    <blockquote>
        <strong>Status: design lock (<code>0.2.0</code>).</strong> No functional code yet. The public API and the token format are locked in <a href="./docs/API.md"><code>docs/API.md</code></a>; the design and decisions are in <a href="./dev/PLAN.md"><code>dev/PLAN.md</code></a> and the schedule in <a href="./dev/ROADMAP.md"><code>dev/ROADMAP.md</code></a>. Code lands from <code>0.3.0</code>.
    </blockquote>
</div>

<hr>
<br>

## Scope

Issuing and verifying signed, session-bound tokens masked per response (BREACH-safe), optional scope binding to one action, a request origin policy over Fetch Metadata, <code>Origin</code>, and <code>Referer</code>, modes that combine the two, key rotation that logs nobody out, one-time tokens through an optional store seam, and rejection reasons with severity hints for logging and scoring. It does not parse HTTP, manage sessions, or set cookies, and it cannot stop cross-site scripting, which defeats every CSRF defence.

See [`dev/PLAN.md`](./dev/PLAN.md) for the full design, the threat list, and the decision log.

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
