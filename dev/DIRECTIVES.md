# csrf-sec &mdash; Engineering Directives

> Engineering standards and the definition of done for this project. Read alongside `REPS.md` (root, authoritative), [`PLAN.md`](./PLAN.md) (design and decisions), and [`ROADMAP.md`](./ROADMAP.md) (current phase). If anything here conflicts with `REPS.md`, `REPS.md` wins, except where `PLAN.md` records an approved exception.

---

## 0. Philosophy

This library is built and maintained to a production standard and treated as a flagship piece of work. Plan the full path, then build one verified step at a time. "Good enough" is treated as a defect. It is a member of the owner's `-sec` domain and part of the service security stack (net-io, bouncer-io, customs-sec, gate-net, gate-sec, csrf-sec, shield-sec, sentinel-sec, sandbox-sec). A security component that cannot name the attack it stops, and prove it with a test, does not ship.

---

## 1. What this is

csrf-sec decides whether a state-changing request came from our own page, for this session. It issues signed, session-bound tokens masked per response, verifies them, and applies a request origin policy over facts the adapter supplies. It does not parse HTTP, manage sessions, or set cookies. See `PLAN.md` sections 1 to 4.

---

## 2. Engineering law (non-negotiable)

- **Security first**, then performance, then efficiency, then simplicity. Never trade the first for the others, and never silently: every performance optimization states its security impact, and every security measure states its cost.
- **Ours, not rented.** No third-party runtime dependency, except audited cryptographic primitives reached through `crypt-io`. First-party crates are wired when first used, at published versions (no `path` dependencies across repositories). Dev-only test tooling (`criterion`, `proptest`) is allowed. If crypt-io lacks something, it is added to crypt-io in its own change rather than pulling a third-party crate here.
- **Protocol-free.** Nothing in this crate knows the wire format of the traffic it protects; adapters at the top translate.
- **Unsafe.** `#![forbid(unsafe_code)]`. This crate has no reason to touch raw memory or the OS directly.
- **Fail closed.** When a check cannot run, the answer is no. An unknown value is never read as a safe one.
- **Constant time.** Every comparison or transformation that depends on a secret runs in constant time: the tag comparison and the token codec. Secrets never appear in logs, errors, or `Debug` output, and are wiped after use (`crypt_io::Zeroizing`).
- **Hostile-input hardening.** Every input may be adversarial: lengths are checked before decoding, work per request is fixed and bounded, no reachable panics, no quadratic paths.
- **No allocation and no lock on the verify path.** Proved by a counting-allocator test and by benchmarks.
- **Performance.** Peak is the baseline: allocation-free hot paths, no shared mutable state, no "faster" claim without `criterion` numbers. Numbers are labelled published, measured, derived, or estimate.
- **Cross-platform.** Linux, macOS, and Windows are first-class, verified by CI on stable and MSRV 1.85. Platform differences are documented per feature.
- **Error handling.** Every fallible path returns `Result`; errors are `#[non_exhaustive]` and say what to do.
- **Production-ready.** `#![deny(missing_docs)]`; no `unwrap`/`expect`/`todo!`/`dbg!`/printing in library code; every public item has rustdoc with a runnable example; every claim in the docs maps to a test.

---

## 3. Definition of done

1. Compiles clean on Linux/macOS/Windows, stable and MSRV 1.85; the `no_std` core builds.
2. `fmt`, `clippy -D warnings` (all targets; default, all, and no default features), tests in the same three modes, `cargo doc -D warnings` (default and all features) clean.
3. `cargo audit` + `cargo deny check` pass.
4. No `unwrap`/`expect`/`todo!`/`dbg!` in shipping code.
5. A Tier-1 API exists and headlines the docs.
6. Property tests cover every section-4 invariant; a fuzz target exists for the decoder, the verifier, and the policy check; every threat listed in `PLAN.md` has an attack test that must fail to get through.
7. Hot-path changes carry benchmarks; no regression over 5%.
8. `README.md`, `docs/API.md`, and `CHANGELOG.md` updated; the matching `docs/release/vX.Y.Z.md` written before the tag.
9. `PLAN.md` decision log updated for every design decision made during the work.
10. v1.0.0 only after the full audit: every planned feature present, an adversarial security review with every finding fixed test-first, the constant-time checks run at length, and all docs accurate against the build.

---

## 4. Project-specific invariants

- A token verifies only under the session id, scope, and key it was issued for, within its lifetime.
- Any change to any bit of a token makes it fail.
- The reason for a failure is decided after the MAC: a forged token is never reported as expired, and an expired real token is never reported as forged.
- An unsafe request never passes on a safe-method code path; methods are classified case-sensitively, and anything not `GET`, `HEAD`, or `OPTIONS` is unsafe.
- `Sec-Fetch-Site: cross-site` on an unsafe request is refused unless its origin is allowlisted; `Origin: null` is refused.
- The verify path allocates nothing, takes no lock, and touches no shared counter.
- The token codec and the tag comparison run in time independent of the token's secret bytes.
- Nothing panics on arbitrary input.

---

## 5. Writing style

- Plain, specific, human prose in every shipping file. No marketing voice.
- Banned in shipping files: "comprehensive", "robust", "seamless", "leverage", and the em-dash character (U+2014) in prose.
- Commits: imperative present tense, descriptive subject line.
