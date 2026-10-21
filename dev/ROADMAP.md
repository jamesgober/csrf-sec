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

## v0.5.0 - Feature complete
Exit: every planned feature present and tested; the `no_std` core builds for a bare-metal target in CI.
- [ ] Bare-metal `no_std` build check in CI.
- [ ] Ideas from `PLAN.md` section 15 tried: key fingerprints, the simple-content-type fact, session epoch binding; each adopted with tests or rejected with the reason recorded.
- [ ] README in full form; examples for each tier, including `no_std`.

## v0.6.0 - Optimization
Exit: measured numbers replace every estimate in the docs; at least 20% faster than the best competitor at equal or stronger security.
- [ ] `criterion` benchmarks for issue, verify, policy, codec.
- [ ] Competitor comparison harness (dev only, outside the published crate).
- [x] Allocation-counting test on the verify path (done in `0.3.0`).
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
