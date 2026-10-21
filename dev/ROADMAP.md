# csrf-sec - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md).
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE, 2026-10-21)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - Design lock (DONE, 2026-10-21)
Exit: the full public API (types, signatures, errors, reasons, examples) written in `docs/API.md`; every open decision in `PLAN.md` answered and logged; the token format frozen on paper.
- [x] Open decisions O-1 to O-7 answered and logged (D-008 to D-014).
- [x] Token format, MAC input encoding, and masking written byte by byte.
- [x] Tier 1, Tier 2, and Tier 3 signatures; `Binding`; `RequestFacts`; `Verdict`, `Reason`, `Rejected`; errors (D-015 to D-026).
- [x] Feature flags (`std`, `alloc`) and what each adds.

## v0.3.0 - Core (DONE, 2026-10-21)
Exit: tokens issue and verify end to end under a key ring with rotation; `check` applies layer 1 and layer 2 per mode; every verify-path reason and every branch of the policy diagram has a test.

The policy layer, modes, and builder moved here from `0.4.0` (PLAN D-027).
- [x] Constant-time base64url codec, canonical only.
- [x] Key ids, key ring (signing, accepted, retired), subkey derivation, wiping, rotation and promotion.
- [x] Raw token, MAC input encoding, masking, issue and verify; lifetime and skew; `StaleSession`; scopes and `WrongScope`.
- [x] `RequestFacts`, method classification, Fetch Metadata, `Origin`, `Referer` origin, allowlist, sibling subdomains, `Origin: null`.
- [x] `Strict`, `TokenOnly`, `PolicyOnly`.
- [x] Tier 1, Tier 2 (`Binding`, builder), Tier 3 (`_at` calls, `PadSource`, `OsPads`).
- [x] Zero-allocation test on issue, verify, check, and every rejection path.
- [x] Independent reimplementation test of the token format.
- [x] Examples (`basic`, `rotation`); `docs/API.md` compiled as a doctest.

## v0.4.0 - One-time tokens (DONE, 2026-10-21)
Exit: a one-time token passes exactly once; forged one-time tokens never reach the store; a failing store fails closed.
- [x] Format version 2 (nonce), its own subkey label; independent reimplementation test.
- [x] `NonceStore` (`consume`, records used nonces only; issue never touches it), `NonceUse`, `StoreError`, `Binding::once`, `AlreadyUsed`, `StoreUnavailable`.
- [x] `MemoryStore`: sharded, bounded, expiring, restart-safe; concurrency tests (exactly one of eight concurrent verifies passes).
- [x] A spy store proves forged, wrong-session, wrong-scope, expired, and malformed tokens never reach `consume`, and issuing never calls it.
- [x] Zero allocation on the one-time path with an allocation-free store.

## v0.5.0 - Feature complete (DONE, 2026-10-21)
Exit: every planned feature present and tested; the `no_std` core builds for a bare-metal target in CI.
- [x] Bare-metal `no_std` build check in CI (`thumbv7em-none-eabi`, stable and 1.85).
- [x] Ideas from `PLAN.md` section 15 resolved: key fingerprints and ring introspection adopted; detection guidance adopted as docs; session epoch, audience, custom-header, simple-content-type, and store-free replay filter rejected with reasons (D-041 to D-047).
- [x] Recipes: no server session, revoking a session's tokens, tenants, single-page applications, logging.
- [x] README in full form; examples for each tier (`basic`, `rotation`, `tier3`).
- [x] `Send + Sync` asserted for every public type.

## v0.6.0 - Optimization (DONE, 2026-10-21)
Exit: measured numbers replace every estimate in the docs; at least 20% faster than the best competitor at equal or stronger security.
- [x] `criterion` benchmarks for issue, verify, check, the policy, rejections, session lengths, one-time tokens, pads, and setup (`benches/csrf.rs`).
- [x] Competitor comparison harness (`dev/bench-compare`, outside the published crate): 3.2x faster issue, 3.1x faster verify than `csrf` 0.5 HMAC, the fastest variant.
- [x] Allocation-counting test on the verify path (done in `0.3.0`).
- [x] Tuning pass with each change measured: tag compare, SWAR codec, origin parsing, cross-site path (D-050 to D-055).
- [x] `docs/PERFORMANCE.md`; every estimate in README, API, and PLAN replaced by a measurement.

## v0.7.0 - Hardening (DONE, 2026-10-21)
Exit: an attack test for every threat T1-T15 that fails to get through; fuzz targets run clean; the constant-time smoke test runs in CI.
- [x] Attack tests T1-T15 (`tests/attacks.rs`).
- [x] Property tests: round trip, character changes, wrong session, scope, key, arbitrary input, policy, validity window (`tests/properties.rs`).
- [x] Fuzz targets with invariants: `verify`, `mutate`, `policy`, `once`; CI smoke run of 30 seconds each.
- [x] Statistical timing test (dudect method) for the tag comparison and the codec, with a control; CI smoke run; 2,000,000-sample run at \|t\| < 4.5 passed locally.

## v0.8.0 - Alpha (DONE, 2026-10-21)
Exit: the API holds up in a complete adapter and against real browsers; every mutant of the crate is caught.
- [x] API review against a complete adapter (`examples/server.rs`): no public change needed (PLAN D-061).
- [x] Real-browser check: same-origin passes, cross-site and same-site posts are refused, with the browser's own headers.
- [x] Docs complete: the adapter guide in `docs/API.md` (values, checklist, caching, URLs); examples for each tier (`basic`, `rotation`, `tier3`, `server`).
- [x] Mutation testing: every mutant caught; two real test gaps found and closed; CI on changed code, weekly full run (D-059, D-062).

## v0.9.0 - Release candidate (DONE, 2026-10-21)
Exit: an independent adversarial review with every finding fixed test-first; the long constant-time run passes; the API is the 1.0 candidate.
- [x] Adversarial review: no forgery found; medium (one session filling the one-time store) and low findings fixed test-first (`tests/review.rs`, PLAN D-065 to D-074).
- [x] Second adversarial review of those fixes: no forgery; two one-time replay paths, a store sizing gap, and key-copy hygiene fixed test-first (PLAN D-075 to D-081).
- [x] One-time lifetime, per-session store quota, fail-closed time ranges, rotation boundary, malformed own origin and `Referer`.
- [x] Documentation corrected where the review found it overstated.
- [x] Long constant-time run (2,000,000 samples per class, \|t\| < 4.5).

## v1.0.0 - Stable (DONE, 2026-10-21)
Exit: the full audit in `DIRECTIVES.md` section 3, item 10.
- [x] Every planned feature present, or its outcome recorded (PLAN D-082 to D-086).
- [x] Two adversarial reviews, every finding fixed test-first (`tests/review.rs`).
- [x] Constant-time checks run at length (2,000,000 samples per class) on the 1.0 code.
- [x] Every doc claim compared with the build and corrected where it differed; README and `docs/API.md` compiled as doctests; `cargo doc` clean with default, no default, and all features.
- [x] A property test for every invariant in `DIRECTIVES.md` section 4; the no-allocation test reaches every refusal reason.
- [x] API frozen until 2.0; token format frozen for 1.x (README, Stability).
