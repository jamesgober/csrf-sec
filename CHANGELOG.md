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

## [0.4.0] - 2026-10-21

One-time tokens.

### Added

- `Binding::once(&store)` makes a token one-time: format version 2, a 128-bit
  nonce inside the MAC, its own subkey, 102 characters (`ONCE_TOKEN_LEN`).
  The MAC, validity window, and scope are checked before the store is
  touched, so forged requests never reach it.
- `NonceStore` trait (`insert`, atomic `take`) and `StoreError`; `MemoryStore`
  (feature `std`): 64 shards, bounded, expiring, refuses when full.
- `Reason::AlreadyUsed` (severity 20), `Reason::StoreUnavailable` (5), and
  `Error::Store`; store failures fail closed.
- `NONCE_LEN` constant.
- Tests: single use, independence of many tokens, a spy store proving forged
  and mismatched tokens never reach `take`, fail-closed store errors, a full
  store refusing to issue, exactly one winner among concurrent verifies,
  every mode, rotation, zero allocation on the one-time path, and an
  independent reimplementation of the version-2 format.

### Changed

- `NonceStore::insert` takes `now` as well as `expires_at` (design-lock
  signature had only `expires_at`), so bounded stores can purge before
  refusing.
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

[Unreleased]: https://github.com/jamesgober/csrf-sec/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/jamesgober/csrf-sec/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jamesgober/csrf-sec/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/csrf-sec/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/csrf-sec/releases/tag/v0.1.0
