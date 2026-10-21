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

## v0.3.0 - Core
Exit: tokens issue and verify end to end under a key ring with rotation; Tier 1 works; every verify-path reason has a test.
- [ ] Constant-time base64url codec.
- [ ] Key, key ids, key ring, subkey derivation, wiping.
- [ ] Raw token, MAC, masking, issue and verify.
- [ ] Lifetime and skew; retired keys; previous-session (`StaleSession`) check.
- [ ] Tier 1 (`Csrf::new`, `issue`, `verify`).

## v0.4.0 - Policy layer and modes
Exit: `check` applies layer 1 and layer 2 per mode; every branch of the policy diagram has a test.
- [ ] `RequestFacts`, method classification, Fetch Metadata, `Origin`, `Referer` origin.
- [ ] Allowlist, sibling subdomains, `Origin: null`.
- [ ] `Strict`, `TokenOnly`, `PolicyOnly`.
- [ ] Tier 2 builder.

## v0.5.0 - Feature complete
Exit: every planned feature present and tested; the `no_std` core builds in CI.
- [ ] Scopes and `WrongScope`.
- [ ] One-time tokens and the `NonceStore` seam, with `MemoryStore`.
- [ ] Tier 3 (`issue_at`, `verify_at`, `check_at`, `PadSource`).
- [ ] `no_std` build check in CI.

## v0.6.0 - Optimization
Exit: measured numbers replace every estimate in the docs; at least 20% faster than the best competitor at equal or stronger security.
- [ ] `criterion` benchmarks for issue, verify, policy, codec.
- [ ] Competitor comparison harness (dev only, outside the published crate).
- [ ] Allocation-counting test on the verify path.
- [ ] Tuning pass with each change measured.

## v0.7.0 - Hardening
Exit: an attack test for every threat T1-T15 that fails to get through; fuzz targets run clean; the constant-time smoke test runs in CI.
- [ ] Attack tests T1-T15.
- [ ] Property tests: round trip, single-bit flips, wrong session, scope, key.
- [ ] Fuzz targets: decode, verify, policy.
- [ ] Statistical timing test (dudect method) for the tag comparison and the codec.

## v0.8.0 - Alpha
- [ ] API review against real adapter use; docs complete; examples for each tier.

## v0.9.0 - Beta / release candidate
- [ ] Adversarial review with every finding fixed test-first; long constant-time run; API frozen candidate.

## v1.0.0 - Stable
- [ ] The full audit in `DIRECTIVES.md` section 3, item 10.
