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

## [0.9.1] - 2026-10-21

The 1.0 audit, the design checked against OWASP's CSRF Prevention Cheat Sheet,
and optional expiry. Additions only.

### Added

- `Builder::no_expiry` and `Csrf::expires`: a token can live as long as its
  session (OWASP's per-session token) instead of expiring after the lifetime.
  The issue time is still checked against the skew, rotation still retires old
  keys after one lifetime plus skew, and one-time tokens always expire.
- Tests: property tests for every section-4 invariant that lacked one (a
  one-time token fails on any character change, a forgery is never reported
  as expired or another benign reason, every method other than `GET`, `HEAD`,
  and `OPTIONS` is unsafe, `Origin: null` is refused, the no-expiry window);
  the no-allocation test now reaches every refusal reason and the streamed MAC
  for long inputs.
- The README Quick Start is compiled as a doctest; CI checks `cargo doc` with
  default, no default, and all features.
- Recipes and guidance from OWASP's cheat sheet: trying a stricter policy
  before enforcing it, `Vary: Sec-Fetch-Site, Origin`, trusting forwarded
  headers, `allow_same_site` and subdomain takeover, HTTPS with HSTS,
  attaching the token only to your own origin, and client-side CSRF.

### Fixed

- `Error::InvalidLifetime` names the one-time lifetime case in its docs and
  message.
- Documentation corrected where the audit found it disagreed with the build:
  the `MemoryStore` per-session floor in very small stores and the reason a
  full session gets (`TooManyUses`), the Tier 1 cost difference, `key_id()` on
  passes (not refusals), the cost of issue, `OriginCheck::NotRun` in
  `TokenOnly` mode, the empty session id rule, and links that broke without
  `std`.

---

## [0.9.0] - 2026-10-21

Release candidate. Two independent adversarial reviews, the second of the
first one's fixes, found no way to forge a pass; every finding is fixed here,
each with a test that failed first (`tests/review.rs`).

### Upgrading from 0.8

- Nodes that share a one-time store must use the same one-time lifetime. 0.8's
  one-time tokens lived the whole lifetime and 0.9's default is one hour: set
  `.once_lifetime(lifetime)` on 0.9 nodes until no 0.8 node is left, then
  lower it everywhere at once.
- An `own_origin` that does not parse (a trailing slash, a Unicode host)
  refuses requests that carry `Origin` or `Referer` but no Fetch Metadata,
  where 0.8 left them to the token. Pass the serialized origin
  (`https://xn--bcher-kva.example`, no path).
- With nothing configured, a `Referer` that is not a URL is refused.
- `MemoryStore`: size it at 512 times the session limit (32,768 for the
  default); smaller stores lower the limit to fit.

### Security

- `MemoryStore` limits each session to 64 records at once
  (`with_session_limit`), so one session can no longer fill the one-time store
  and refuse everyone else's one-time actions; a full shard with nothing
  expired refuses at once instead of scanning under its lock.
- A malformed `own_origin` (a trailing slash, say) refuses instead of turning
  the `Origin` and `Referer` checks off.
- A malformed or `null` `Referer` is refused even with nothing configured.
- `MemoryStore::new` starts one minute ahead of the clock, so a clock that
  steps back by up to a minute across a restart cannot let a used token pass
  again; a clock before 2020 makes it refuse everything.
- Times past the range a token can reach (milliseconds where seconds were
  meant) fail closed: `Builder::retired` returns `Error::InvalidRetireTime`,
  `rotated_at` returns `Error::Clock`, `purge_expired` does nothing.
- `MemoryStore` remembers the latest expiry it has dropped, so a used token
  cannot pass again on a node whose clock stepped back after a purge.
- A session may hold at most an eighth of a `MemoryStore` shard whatever its
  limit, so an undersized store cannot let one session fill a shard.
- The builder's key buffer never reallocates (no copy of a key is left in
  freed memory), and the expected tag is wiped after each comparison.

### Added

- `Builder::once_lifetime` and `Csrf::once_lifetime`: one-time tokens live one
  hour by default (`DEFAULT_ONCE_LIFETIME`), never longer than the lifetime.
- `MemoryStore::with_session_limit`, `MemoryStore::session_limit`,
  `StoreError::SessionLimit`, `Error::InvalidRetireTime`, and `NonceUse::new`
  (for testing custom stores).
- `Reason::TooManyUses` (`too_many_uses`, severity 10): a session over its
  one-time store quota, reported apart from `StoreUnavailable`.

### Changed

- Rotation keeps the old key one second longer, through the last valid second
  of a token a peer up to the skew ahead could have signed.
- `MemoryStore` keeps each session's records in one shard; size it at 512
  times the session limit or more.
- The subkey comparison used for promotion no longer copies key material, and
  the unsent half of each MAC output is wiped.

### Fixed

- Documentation: a planted session cookie is stopped by the `__Host-` prefix
  and the request policy, not by the MAC; adapters must pass the effective
  method after overrides; `policy()` returning `Ok(NoFacts)` is not a pass;
  detection layers should score every non-benign reason, since a forger can
  choose `malformed` or `unknown_key`; example keys are public placeholders.
- Documentation: `rotated` refuses on a broken clock (build a new `Csrf` for an
  emergency rotation); many sessions can still fill a one-time store, so
  rate-limit one-time issuing.

---

## [0.8.0] - 2026-10-21

Alpha. The API is unchanged.

### Added

- `examples/server.rs`: a complete adapter with no dependencies, serving a
  form, an "attacker" page on another origin, and logging every verdict.
  Checked in a real browser: same-origin passes, cross-site and same-site
  posts are refused.
- `docs/API.md`: "Writing an adapter", with where each value comes from, a
  checklist, and the cache and URL rules for pages that carry a token.
- Mutation testing (cargo-mutants): `.cargo/mutants.toml` with the proven
  equivalent mutants; CI runs the changed code of every pull request, and a
  weekly workflow runs the full set. Every mutant is caught.
- Tests from mutation testing: two invalid characters anywhere in a token are
  refused, an even number of equal key deviations is not a weak key, a garbage
  own origin cannot match through the `Referer` fast path, the 4 KiB header
  limit boundary, the default lifetime's value, `accepts`, builder settings,
  token views, the pad pool's threshold, and more.

### Changed

- The decoder accumulates one error flag per character, so a flag can never
  be cancelled; its byte packing moved into small helpers. Same speed
  (measured).

---

## [0.7.0] - 2026-10-21

Hardened. No change to the library's behaviour or API.

### Added

- `tests/attacks.rs`: one attack per threat T1 to T15 (classic CSRF, login
  CSRF, forced logout, BREACH, cross-session and cross-action replay, cookie
  tossing, forgery, timing, key compromise, oversized input, clock skew,
  method look-alikes, `Origin: null`, cross-site navigation), each of which
  must fail.
- `tests/properties.rs` (proptest): round trip, character changes, another
  session, scope, or key, arbitrary input, the policy, and the exact validity
  window.
- `tests/timing.rs`: dudect-style statistical tests showing the tag comparison
  and the decoder take the same time whatever the data, with a control that
  must detect a real difference. Run with `--release --ignored`.
- `fuzz/`: four cargo-fuzz targets that assert security invariants (`verify`,
  `mutate`, `policy`, `once`).
- CI jobs: timing smoke test, and a 30-second fuzz run per target.

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

[Unreleased]: https://github.com/jamesgober/csrf-sec/compare/v0.9.1...HEAD
[0.9.1]: https://github.com/jamesgober/csrf-sec/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/jamesgober/csrf-sec/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/jamesgober/csrf-sec/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/jamesgober/csrf-sec/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/jamesgober/csrf-sec/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/jamesgober/csrf-sec/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jamesgober/csrf-sec/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jamesgober/csrf-sec/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/csrf-sec/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/csrf-sec/releases/tag/v0.1.0
