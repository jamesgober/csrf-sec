<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>csrf-sec</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

---

## [0.6.0] - 2026-10-21

Measured and tuned.

### Added

- `criterion` benchmark suite (`benches/csrf.rs`): issue, verify, check, the
  request policy, every rejection, session id lengths, one-time tokens, pads,
  and setup.
- `dev/bench-compare`: the comparison with the `csrf` crate, outside the
  published crate.
- `docs/PERFORMANCE.md`: method, hardware, and every measured number.

### Changed

- The tag comparison is one 128-bit XOR, about 1 ns instead of 50 ns, still
  constant time.
- The base64url codec processes eight characters per 64-bit word for full
  blocks, still without tables or branches on token bytes: decode 29 ns,
  encode 20 ns.
- Origin parsing is faster (a `Referer` match 51 to 23 ns), and a value
  byte-identical to a well-formed `own_origin` needs one parse.
- With `Sec-Fetch-Site: same-site` or `cross-site`, only the allowlist can pass
  a request; the site's own origin no longer counts there. A cross-site refusal
  takes 19 ns, and no parsing at all without an allowlist.
- Every cost estimate in README, `docs/API.md`, and `dev/PLAN.md` is replaced
  by a measurement: `issue_at` 112 ns, `verify_at` 110 ns, strict `check_at`
  150 ns (Linux, Ryzen 9 9950X3D).

---

## [0.5.0] - 2026-10-21

Feature complete.

### Added

- `Csrf::keys()` lists the ring (signing key first) as `KeyInfo` (`id`,
  `role`, `fingerprint`); `Csrf::key_fingerprint(id)`; `KeyFingerprint`, a
  public 8-byte fingerprint (16 hex digits) for checking that every node of a
  cluster holds the same key under an id; `KeyRole` is now public.
- CI job building the `no_std` core for `thumbv7em-none-eabi`, a target with
  no standard library, on stable and 1.85.
- Example `tier3`: explicit time and randomness, runnable with
  `--no-default-features`.
- `docs/API.md` recipes: no server session, revoking a session's tokens
  without changing its id, tenants on one key ring, single-page applications,
  and what to log on a refusal.
- Test asserting `Send + Sync` for every public type.

### Changed

- Every idea in the plan is resolved: adopted with tests, or rejected with the
  reason recorded (PLAN D-041 to D-047).

---

## [0.4.0] - 2026-10-21

One-time tokens.

### Added

- `Binding::once(&store)` makes a token one-time: format version 2, a 128-bit
  nonce inside the MAC, its own subkey, 102 characters (`ONCE_TOKEN_LEN`).
  The MAC, validity window, and scope are checked before the store is
  consulted, so forged requests never reach it.
- `NonceStore` trait with one atomic call, `consume(&NonceUse)`, that records
  a used nonce and passes only its first use; `NonceUse` and `StoreError`.
  Issuing never touches the store.
- `MemoryStore` (feature `std`): 64 shards, bounded, expiring, refuses when
  full, and refuses tokens issued before it started so a restart cannot replay
  a used token. `MemoryStore::starting_at` for an explicit start.
- `Reason::AlreadyUsed` (severity 20) and `Reason::StoreUnavailable` (5); store
  failures fail closed.
- `NONCE_LEN` constant.
- Tests: single use, independence of many tokens, the record a store receives,
  a spy store proving forged and mismatched tokens never reach it and issuing
  never calls it, a failing store, a full store, a restarted store, exactly one
  winner among concurrent verifies, every mode, rotation, zero allocation on
  the one-time path, and an independent reimplementation of the version-2
  format.

### Changed

- The store design from the `0.2.0` design lock (`insert` on issue, `take` on
  verify) is replaced by `consume` on verify only: the MAC already proves
  issuance, so the store records only used tokens (PLAN D-035).
- In `PolicyOnly` mode, a one-time binding still checks the token.

---

## [0.3.0] - 2026-10-21

The core. Session tokens, the request origin policy, modes, the builder, key
rotation, and all three API tiers.

### Added

- `Csrf` with Tier 1 calls `new`, `issue`, `verify`, `check`; Tier 2
  `issue_with`, `verify_with`, `check_with` over a `Binding` (session, scope,
  previous session); Tier 3 `issue_at`, `verify_at`, `check_at` with explicit
  time and a `PadSource`, available without `std`.
- `Csrf::builder()` (`Builder`): signing, accepted, and retired keys
  (`KeyId`, up to `MAX_KEYS`), lifetime, skew, `Mode`, allowed origins, and
  sibling subdomains. `rotated` / `rotated_at` rotate keys without logging
  anyone out and promote a staged key; `policy` runs layer 1 alone.
- `Token`: inline (no heap), 59 characters of base64url, masked with fresh
  randomness on every issue, `Debug` redacted, no `PartialEq`.
- `RequestFacts`, `MethodClass`, `FetchSite`, `OriginCheck`: the layer-1
  decision over `Sec-Fetch-Site`, `Origin`, and `Referer`, with strict origin
  parsing and default-port normalization.
- `Verdict`, `Verified`, `Rejected`, and `Reason` with severities and stable
  names; `Error` with actionable messages.
- `OsPads`: a per-thread buffer refilled in bulk from the OS CSPRNG through
  `mod-rand`.
- Constant-time, canonical-only base64url codec.
- Constants `TOKEN_LEN`, `KEY_LEN`, `MAX_KEYS`, `FIELD_NAME`, `HEADER_NAME`,
  `DEFAULT_LIFETIME`, `DEFAULT_SKEW`.
- Dependencies: `crypt-io` 1.1 (keyed BLAKE3, constant-time tag compare,
  `Zeroizing`) and `mod-rand` 1 (`std` only).
- Tests: exhaustive character-change and single-bit-flip rejection,
  cross-session, cross-scope, and cross-key refusal, an independent
  reimplementation of the token format, a counting-allocator test proving zero
  allocations on issue, verify, check, and every rejection path, and every
  branch of the policy decision.
- Examples `basic` and `rotation`; `docs/API.md` is compiled as a doctest.

### Changed

- The policy layer, modes, and builder moved into this release from `0.4.0`;
  one-time tokens are now `0.4.0` (roadmap re-cut, PLAN D-027).
- The `--no-default-features` CI run covers library and integration tests.

---

## [0.2.0] - 2026-10-21

Design lock. The public API and the token format are written down; no
functional code yet.

### Added

- `docs/API.md`: the locked public surface. Tier 1 (`Csrf::new`, `issue`,
  `verify`, `check`), Tier 2 (`Binding`, `issue_with`, `verify_with`,
  `check_with`, the builder, rotation), Tier 3 (`issue_at`, `verify_at`,
  `check_at`, `PadSource`), `RequestFacts` and the layer-1 decision, modes,
  one-time tokens (`NonceStore`, `MemoryStore`), `Verdict`, `Reason` with
  severities, `Error`, constants, feature flags, cookie guidance, and the token
  format byte by byte.
- `dev/PLAN.md` decisions D-008 to D-026; every open decision answered.

### Changed

- The MAC input length-prefixes the session id and scope (the plain
  concatenation in `0.1.0`'s plan was ambiguous), and domain separation moves
  from a text prefix into per-key subkeys.
- One-time tokens are signed tokens with a nonce, checked before the store is
  touched, instead of a stored random value.
- `issue` returns `Result<Token, Error>` with an inline, allocation-free token.

---

## [0.1.0] - 2026-10-21

The scaffold and the plan. No functional code yet.

### Added

- Crate manifest (edition 2024, MSRV 1.85, no dependencies), `Apache-2.0 OR MIT`
  license, README, REPS, CI (Linux, macOS, Windows on stable and 1.85; audit
  and deny), `deny.toml`, `clippy.toml`, `rustfmt.toml`, `.gitattributes`.
- `dev/PLAN.md` (purpose, scope, the three layers of defence, token design,
  keys and rotation, verdicts, threats T1-T15, architecture, ecosystem, open
  decisions, decision log), `dev/DIRECTIVES.md`, and `dev/ROADMAP.md`.

[Unreleased]: https://github.com/jamesgober/csrf-sec/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/jamesgober/csrf-sec/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/jamesgober/csrf-sec/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jamesgober/csrf-sec/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jamesgober/csrf-sec/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/csrf-sec/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/csrf-sec/releases/tag/v0.1.0
