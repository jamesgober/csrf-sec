# csrf-sec - Project Plan

> The design, strategy, and decision record for `csrf-sec`. A living document: every design decision, idea, or open question about csrf-sec is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Read order:** [`../REPS.md`](../REPS.md) &rarr; [`DIRECTIVES.md`](./DIRECTIVES.md) &rarr; **this file** &rarr; [`ROADMAP.md`](./ROADMAP.md).
>
> **Status:** `0.6.0`, feature complete and measured ([`../docs/PERFORMANCE.md`](../docs/PERFORMANCE.md)). Next: `0.7.0` hardening. The public surface is [`../docs/API.md`](../docs/API.md), compiled as a doctest.

---

## Contents

1. [Purpose](#1-purpose)
2. [Where it sits](#2-where-it-sits)
3. [Scope](#3-scope)
4. [The three layers of defence](#4-the-three-layers-of-defence)
5. [Token design](#5-token-design)
6. [Keys and rotation](#6-keys-and-rotation)
7. [Verification and verdicts](#7-verification-and-verdicts)
8. [API shape](#8-api-shape)
9. [Threats](#9-threats)
10. [Architecture](#10-architecture)
11. [Performance, efficiency, and scale](#11-performance-efficiency-and-scale)
12. [Ecosystem and dependencies](#12-ecosystem-and-dependencies)
13. [Testing](#13-testing)
14. [Open decisions](#14-open-decisions)
15. [Ideas parking lot](#15-ideas-parking-lot)
16. [Decision log](#16-decision-log)

---

## 1. Purpose

A cross-site request forgery makes a victim's browser send a state-changing request (change email, transfer, delete, log in, log out) to a site where the victim is signed in, from a page the attacker controls. The browser attaches the victim's cookies, so the site sees a valid session.

csrf-sec answers one question for every state-changing request: **did this request come from our own page, for this session?** It answers with three independent checks (request origin policy, a signed session-bound token, and cookie guidance) so that one failing defence does not open the door.

Goals, in order: security, then performance, then efficiency, then simplicity of use. Security is never traded for the others.

- **Protocol-free.** Adapters (WASP's HTTP service, web-net, any framework) hand it the facts it needs as plain values. Nothing in this crate parses HTTP.
- **Stateless by default.** Any node holding the key ring verifies any token. Nothing to store, replicate, or lose, and no shared bottleneck between nodes.
- **No allocation and no lock on the verify path.**
- **Cross-platform.** Linux, macOS, and Windows; a `no_std` core.

---

## 2. Where it sits

```
 request ─▶ gateway-io ─▶ service gate block (authenticate ─▶ authorize)
                                  │
                                  ▼  state-changing route?
                         csrf-sec: policy check (origin facts) + token verify (session-bound)
                                  │ pass                      │ reject (reason + severity)
                                  ▼                           ▼
                               handler            403, generic message; event to sentinel/bouncer

 page render ─▶ csrf-sec: issue masked token ─▶ form field or meta tag
```

- **Called by:** WASP services (login, logout, every unsafe route), web-net's form layer, and any HTTP framework built on the stack.
- **Moved here from gate-net.** `gate-net/dev/PLAN.md` (anti-forgery primitive) and `WEB-STACK-DELIVERABLES.md` section 5 (CSRF token primitive from gate-net) planned it inside gate-net. It is its own crate now (D-001); the move is recorded in both places.

---

## 3. Scope

### 3.1 In scope

- Issuing and verifying signed, session-bound, per-response masked tokens.
- Optional scope binding (a token valid for one action only).
- The request origin policy over Fetch Metadata, `Origin`, and `Referer`, supplied by the adapter as plain values.
- Modes combining the policy and the token.
- A key ring with rotation that logs nobody out.
- One-time tokens for high-value actions through an optional store seam.
- Rejection reasons with severity hints for logging and scoring.
- Cookie guidance (documented, enforced by cookie-net).

### 3.2 Out of scope, and where it goes

| Not here | Where |
|---|---|
| HTTP parsing, header extraction | the adapter (`http-net`, web-net, the framework) |
| sessions, session ids, the stale-session window | gate-net and WASP's gates |
| setting cookies, `SameSite`, the `__Host-` prefix | cookie-net (guidance documented here) |
| cross-site scripting | output encoding and the content security policy (shield-sec, web-net); script on the page can read any token, so XSS defeats every CSRF defence |
| clickjacking | frame options and CSP `frame-ancestors` |
| key custody | key-vault (optional feature) |

---

## 4. The three layers of defence

### 4.1 Layer 1: request origin policy (no token needed)

Browsers send `Sec-Fetch-Site` (`same-origin`, `same-site`, `cross-site`, `none`) and `Origin` on unsafe requests. Neither can be set by script on an attacker's page (they are forbidden request headers). The adapter passes them as plain values in `RequestFacts`.

```
 unsafe method (POST, PUT, PATCH, DELETE, anything not GET/HEAD/OPTIONS)?
   no  ─▶ policy passes (safe methods must never change state; documented and tested)
   yes ─▶ Sec-Fetch-Site present?
            same-origin                 ─▶ pass
            same-site                   ─▶ pass only if the policy allows sibling subdomains
            none                        ─▶ pass (typed URL, bookmark: no attacker page involved)
            cross-site                  ─▶ refuse, unless the origin is on the allowlist
          absent (older browser or non-browser client) ─▶ Origin present?
            matches an allowed origin   ─▶ pass
            "null" or mismatch          ─▶ refuse
            absent ─▶ Referer origin matches? pass : decided by the token alone (layer 2)
```

### 4.2 Layer 2: signed, session-bound token

The token proves the request was built from a page we rendered for this session. Design in section 5.

### 4.3 Layer 3: cookie guidance

`SameSite=Lax` (or `Strict`) and the `__Host-` prefix on the session cookie, enforced by cookie-net and documented here. Defence in depth: modern browsers already block most cross-site cookie sending under `Lax`.

### 4.4 Modes

| Mode | Unsafe request passes when | Use |
|---|---|---|
| `Strict` (default) | layer 1 passes **and** layer 2 passes | browsers, the normal case |
| `TokenOnly` | layer 2 passes | clients that send no browser headers (some native apps) |
| `PolicyOnly` | layer 1 passes and `Sec-Fetch-Site` was present | API endpoints called only from modern browsers with no forms; never the default |

---

## 5. Token design

### 5.1 Per-session tokens, masked per response

One token per session (re-issued at login, so a pre-login token cannot be reused after login), shown differently on every response by masking. This keeps multi-tab browsing and the back button working, unlike one-time tokens, while defeating BREACH.

One-time tokens (consumed on use) are available for high-value actions through the optional store seam (5.5).

### 5.2 Raw token (22 bytes)

| Field | Bytes | Meaning |
|---|---|---|
| version | 1 | format version (1) |
| key id | 1 | which key in the ring signed it |
| issued at | 4 | UTC seconds since 2020-01-01 (good until 2156) |
| tag | 16 | keyed BLAKE3 over the fields below, truncated to 128 bits |

MAC input (nothing secret appears in the token itself), little-endian integers, lengths as LEB128 varints (D-008):

```
 version | key id | issued at | varint(len session) | varint(len scope) | session id | scope (empty if none)
```

The tag is the first 16 bytes of keyed BLAKE3 under a **subkey** derived from the application key, the key id, and a label per token kind (D-009). Domain separation lives in the key, not in a text prefix of every MAC input, so a 43-character session id with no scope fits in one 64-byte BLAKE3 block.

The session id is inside the MAC, not inside the token: the token reveals nothing about the session.

### 5.3 Masked form (what is sent to the browser)

```
 pad    = 22 fresh random bytes (per response)
 masked = pad || (raw XOR pad)                       44 bytes
 text   = base64url without padding                  59 characters
```

Every page shows a different string for the same token, so a compression side channel cannot recover it. The pad travels with the token, so it is not secret once sent; what matters is that an attacker cannot **predict** it before the response is built (a predictable pad turns the second half of the text back into a fixed string that BREACH can recover). Pads therefore come from a cryptographically secure generator.

### 5.4 Scope (optional)

A token can be issued for one action (`"POST /account/email"`). It then passes only for that action. Use for high-value forms; the default per-session token has no scope.

### 5.5 Stateful mode (optional seam)

One-time tokens for high-value actions (D-011, D-035). A one-time token is a signed token with a 128-bit random nonce inside the MAC (raw 38 bytes, text 102 characters, version 2, its own subkey label). The MAC already proves the token was issued by this key ring, so a `NonceStore` records only **used** nonces: issuing never touches it; verify checks the MAC, lifetime, and scope **first**, and only then asks the store to record the nonce atomically (set-if-absent), passing only on first use. Forged requests never reach the store, so they cannot burn a user's token or put load on a shared store. A store that cannot answer fails closed. Default: none (stateless). `MemoryStore` (sharded, bounded, refusing tokens older than itself so a restart cannot replay) serves single nodes and tests; WASP implements the trait over the gates' session store.

---

## 6. Keys and rotation

- Keys are 32 bytes. The recommended source is a master secret held in key-vault, with the CSRF key derived by HKDF (`info = "csrf-sec v1"`, crypt-io), so CSRF never shares a key with anything else.
- **Persist the key or derive it from a persisted master.** Random keys created at boot make every open form fail after a restart.
- The ring holds up to 16 keys in three roles (D-017): one **signing** key; **accepted** keys (verify only, no end: a new key staged on every node before any node signs with it); and **retired** keys (verify only, until their retire time). Rotation adds a new signing key; old tokens keep verifying until the token lifetime passes, so nobody is logged out or loses a form.
- In a cluster, rotation is two steps: deploy the new key as accepted everywhere, then promote it to signing. No node ever receives a token signed with a key it does not know.
- The application key is never used as a MAC key and is not kept: subkeys are derived at construction and wiped on drop (D-009). Keys whose bytes are all equal are refused (D-024).
- Key ids are 1 byte; a retired id is never reused while tokens signed by it can still be presented.
- The library holds no mutable state: rotation builds a new `Csrf` value (`csrf.rotated(new_key)`), and the application swaps it (WASP: a `Snapshot`). The verify path therefore takes no lock and touches no shared counter.

---

## 7. Verification and verdicts

### 7.1 Order

```
 1 length within bounds?                       (before any decoding: T11)
 2 decode base64url (branch-free)
 3 unmask
 4 version known?
 5 key id in the ring?                          unknown id ─▶ UnknownKey
 6 MAC verifies (constant time)?               no ─▶ BadMac (forgery)
 7 issued at within lifetime and skew?         no ─▶ Expired
 8 scope matches?                              no ─▶ WrongScope
 9 pass (signed by a retired key ─▶ pass, reported as RetiredKey for metrics)
```

The MAC is checked before expiry and scope so the reason is accurate: an expired real token (a glitch) and a forged token (an attack) are told apart, which WASP's severity scoring needs (`WASP.md` section 7.6). The work is fixed and bounded either way.

A session mismatch shows up as `BadMac`, because the session id is inside the MAC. To separate "stale token after re-login" (benign) from forgery, the verifier optionally accepts the **previous** session id (the gates keep it for a short window after login) and reports `StaleSession` when that one matches.

### 7.2 Reasons and severity

| Reason | Most likely | Severity hint |
|---|---|---|
| `Missing` | a client bug or a forged form without a token | 5 |
| `Malformed` | tampering or truncation | 10 |
| `UnknownKey` | a very old token, or tampering | 5 |
| `RetiredKey` | rotation (passes) | 0 |
| `BadMac` | forgery | 40 |
| `StaleSession` | the user signed in again in another tab | 1 |
| `Expired` | an old tab | 1 |
| `WrongScope` | a token taken from another form | 20 |
| `CrossSite` | layer 1: a cross-site unsafe request | 30 |
| `OriginMismatch` | layer 1: a foreign origin | 30 |
| `NotYetValid` | a node clock ahead by more than the skew (D-012) | 5 |
| `Unverifiable` | the check cannot run: no session id, or no Fetch Metadata in `PolicyOnly` (D-012) | 5 |
| `AlreadyUsed` | a one-time token presented twice (D-012) | 20 |
| `StoreUnavailable` | the one-time store could not answer (D-012) | 5 |

The reason is for logs and scoring only. Clients receive a generic refusal. `RetiredKey` is not a rejection: a token signed by a retired key passes and reports it through `Verified::retired_key()`.

`WrongScope` is reported when a token issued without a scope is presented to a scoped binding (found by a second MAC over the empty scope, only on the failure path). A token issued for a **different** scope fails as `BadMac`: its scope is inside the MAC and cannot be recovered, so it is indistinguishable from a forgery (D-012).

### 7.3 Validity window

Expired when `now > issued_at + lifetime`; not yet valid when `issued_at > now + skew`; both boundaries are inclusive of the valid side. `issue` refuses to mint a token when the clock is outside 2020-01-01 to 2156-02-07 (D-023).

---

## 8. API shape

The locked surface is [`docs/API.md`](../docs/API.md). This section is the original sketch; where they differ, `docs/API.md` and the decision log win (D-015, D-016).

### 8.1 Tier 1 (covers most uses, no configuration)

```rust
use csrf_sec::Csrf;

let csrf = Csrf::new(key)?;                              // key: [u8; 32]

// Rendering a form:
let token = csrf.issue(session_id);                      // 59 chars, different every call

// Handling the POST:
csrf.verify(session_id, submitted_token)?;               // Ok or Err(Rejected { reason })

// With the browser's request facts as well (recommended):
csrf.check(&facts, session_id, submitted_token)?;        // layer 1 + layer 2
```

### 8.2 Tier 2 (builder)

```rust
let csrf = Csrf::builder()
    .key(KeyId(3), key)
    .retired(KeyId(2), old_key, retire_at)
    .lifetime(Duration::from_secs(12 * 3600))
    .skew(Duration::from_secs(60))
    .mode(Mode::Strict)
    .allow_origin("https://example.com")
    .allow_same_site(false)
    .build()?;

let token = csrf.issue_scoped(session_id, Scope::action("POST /account/email"));
```

### 8.3 Tier 3 (no allocation, `no_std`)

```rust
let mut out = [0u8; csrf_sec::TOKEN_LEN];                // 59
csrf.issue_into(session_id, Scope::NONE, &mut pad_source, &mut out)?;
let verdict: Verdict = csrf.verify_bytes(session_id, Scope::NONE, &bytes);
```

`RequestFacts` is a plain value the adapter fills: method class (safe or unsafe), `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Origin`, `Referer` origin, and the request's own origin.

All public enums and structs that may grow are `#[non_exhaustive]`.

---

## 9. Threats

| Id | Threat | Defence | Cost (measured unless marked) |
|---|---|---|---|
| T1 | classic CSRF: an attacker page auto-submits a form with the victim's cookies | policy check + session-bound token | 150 ns per unsafe request (`check_at`); a cross-site attempt is refused in 23 ns |
| T2 | login CSRF: the victim is signed in to the attacker's account | token bound to the pre-session (WASP's lazy guest session) | same |
| T3 | forced logout | token on logout | same |
| T4 | token recovered from compressed responses (BREACH) | per-response masking | 28 ns per issue on Linux (the pad), plus the XOR |
| T5 | token reused in another session | MAC binds the session id | none extra |
| T6 | token reused for another action | optional scope binding | none while session id and scope fit one 64-byte block (56 bytes together); a second block adds about 65 ns |
| T7 | cookie tossing from a subdomain defeats naive double-submit | tokens are signed and session-bound, not compared to a cookie; `__Host-` cookie guidance | none |
| T8 | token forgery | 256-bit key, keyed BLAKE3, 128-bit tag | none extra |
| T9 | timing attack on the comparison | constant-time tag comparison | none extra |
| T10 | key compromise | key ids, rotation without logouts, short lifetimes, keys derived per purpose | rotation is operational |
| T11 | denial of service through verification | length checked before decoding; fixed work; no allocation | a wrong length is refused in 3.4 ns; garbage text in 35 ns; a forgery costs the same 116 ns as a valid token |
| T12 | clocks differ between nodes | skew tolerance on issue time | none |
| T13 | state change through a "safe" method (GET with side effects) | method classification; safe methods never pass as state-changing | part of building `RequestFacts`, 2.9 ns |
| T14 | `Origin: null` and stripped `Referer` | explicit policy for each case | 37 ns or less (an `Origin` parse) |
| T15 | cross-site top-level POST navigation | Fetch Metadata: `Sec-Fetch-Site: cross-site` on an unsafe method is refused | 19 ns with an allowlist to consult, about 2 ns [est.] without |

Measurements: [`docs/PERFORMANCE.md`](../docs/PERFORMANCE.md) (Linux, Ryzen 9 9950X3D, `0.6.0`).

Out of scope, named so nobody assumes otherwise: cross-site scripting defeats every CSRF defence, because script on the page can read the token; that is stopped by output encoding and the content security policy (shield-sec, web-net). Clickjacking is stopped by frame options and CSP `frame-ancestors`.

---

## 10. Architecture

```
src/
  lib.rs        crate docs, constants, re-exports
  csrf.rs       Csrf (immutable, cheap to share), Builder, rotation, the three verbs at three tiers
  key.rs        KeyId, the key ring, subkey derivation, wiping
  token.rs      Token, raw layouts, MAC input encoding, issue and verify core
  pad.rs        PadSource, OsPads (per-thread buffer, std)
  b64.rs        base64url codec (constant time, canonical, fixed length)
  binding.rs    Binding
  policy.rs     RequestFacts, MethodClass, FetchSite, origin matching, Mode, OriginCheck
  verdict.rs    Verdict, Verified, Rejected, Reason, severity
  once.rs       NonceStore, StoreError, MemoryStore (std)
  error.rs      Error (#[non_exhaustive])
```

- `Csrf` is immutable after construction. Rotation builds a new value; the application swaps it. No interior mutability on any shared path.
- Verify works on stack buffers only; token lengths are fixed, so every buffer size is a constant.
- The `std` feature adds the system clock, `OsPads`, `MemoryStore`, and the plain and `_with` calls; the `no_std` core has the `_at` calls.

---

## 11. Performance, efficiency, and scale

| Operation | Target | Measured (`0.6.0`) | How |
|---|---|---|---|
| `issue` | ≤ 300 ns | 112 ns (`issue_at`), 167 ns with clock and `OsPads` | keyed BLAKE3 over ~51 bytes (one block), a 22-byte pad from a buffered CSPRNG, SWAR base64url into an inline buffer |
| `verify` | ≤ 300 ns | 110 ns (`verify_at`), 142 ns with clock | SWAR fixed-length decode, one MAC, a 128-bit XOR compare |
| layer 1 policy | ≤ 50 ns | 1.3 ns (Fetch Metadata) to 37 ns (`Origin`) | byte comparisons on values the adapter already parsed |
| allocations on verify | 0 | 0 | stack buffers only (counting-allocator test) |
| locks or shared atomics on verify | 0 | 0 | immutable `Csrf`, swapped by the application on rotation |
| scale-out | linear | linear | stateless; any node verifies any token with the same key ring |
| against the best competitor | ≥ 20% faster | 3.2× faster issue, 3.1× faster verify (`csrf` 0.5 HMAC) | see `docs/PERFORMANCE.md` |

- Pad randomness: a per-thread buffer filled in bulk from the OS CSPRNG (mod-rand), so a mask costs nanoseconds, not a system call.
- Benchmarks (`criterion`) against the best existing Rust CSRF crates as dev-only comparisons. The target is at least 20% faster than the best competitor at equal or stronger security.
- No background threads, no timers, no I/O: nothing to slow down or fail under load.

---

## 12. Ecosystem and dependencies

### 12.1 Uses

| Crate | For | Status |
|---|---|---|
| `crypt-io` 1.1 | keyed BLAKE3 (`mac::blake3_keyed`), `Tag<N>` constant-time compare, HKDF, `Zeroizing` | published; no free-standing `ct_eq` for slices (`Tag<16>` covers the tag compare; anything more goes into crypt-io in its own change rather than pulling `subtle` directly) |
| `mod-rand` 1.0 | OS CSPRNG (`tier3::fill_bytes`) for pads and key generation | published; edition 2021, MSRV 1.75 (fine as a dependency) |
| `key-vault` 1.1 | optional key custody, behind a feature | published; has third-party dependencies, so optional only |
| `clock-lib` | mocked time in tests, if the time seam needs it (O-3) | published |

No third-party runtime dependency of our own (crypt-io's audited primitives are the accepted exception). No async runtime. Version dependencies only, never `path`.

### 12.2 Needs (not built yet)

| Crate | For |
|---|---|
| `encode-lib` | base64url; until it exists the codec lives inside csrf-sec (D-005) |

### 12.3 Talks to

WASP's gates (session ids, the stale-session window, severity events), cookie-net (`__Host-` session cookie, `SameSite`), web-net and form-net (hidden field and header names), sentinel-sec (reasons as events), bouncer-io (strikes).

---

## 13. Testing

- Unit tests for every function and every `Ok` and `Err` path; names `test_<subject>_<condition>_<expected>`.
- Property tests: issue-then-verify always passes; **any** single-bit change anywhere in a token is rejected; a token never verifies under another session id, scope, or key.
- An attack test for each threat T1-T15 that must fail to get through.
- Fuzz targets: decode, verify, and the policy check with arbitrary facts.
- Timing check: a statistical constant-time test of the tag comparison and the codec (dudect method), run in CI as a smoke test and at length before 1.0.
- Rotation tests: tokens signed by retired keys pass until retirement, then fail as `UnknownKey`.
- Clock tests: expiry boundaries, skew tolerance, issue times in the future.
- An allocation-counting test proves the verify path allocates nothing.
- Cross-platform CI: Linux, macOS, Windows on stable and MSRV; a `no_std` build check.

---

## 14. Open decisions

Technical questions are decided at design lock (`0.2.0`) and recorded in the decision log.

| Id | Question | Recommendation |
|---|---|---|
All seven questions from `0.1.0` are answered (D-008 to D-014). None is open.

| Id | Question | Answer |
|---|---|---|
| O-1 | MAC input encoding | varint length prefixes (D-008) |
| O-2 | Where domain separation lives | per-key, per-kind subkeys (D-009) |
| O-3 | Time | Tier 3 takes `now`; Tier 1 and 2 read the system clock (D-010) |
| O-4 | One-time tokens | signed token with a nonce; MAC before store (D-011) |
| O-5 | Missing reasons | `NotYetValid`, `Unverifiable`, `AlreadyUsed`, `StoreUnavailable` (D-012) |
| O-6 | Codec | constant-time arithmetic, canonical only (D-013) |
| O-7 | Publish `0.1.0` | done, 2026-10-21 (D-014) |

---

## 15. Ideas parking lot

Each idea is a hypothesis with a method and an expected cost, tried in the phase noted or later.

Outcomes so far: key fingerprints adopted (D-041); forgery-rate feedback adopted as documentation (D-047); session epoch, audience, custom-header, simple-content-type, and store-free replay filter rejected with reasons (D-042 to D-046).

- **Shadow mode for policy changes (0.5).** Hypothesis: operators moving from `TokenOnly` to `Strict`, or tightening the allowlist, need to see what the new policy would refuse before enforcing it, or they will not tighten it at all. Method: a `check` variant that enforces the current configuration and also reports the verdict a candidate configuration would give, for logging only. Cost [est.]: one extra layer-1 decision (≤ 50 ns) when enabled; nothing otherwise.
- **Session epoch binding.** Hypothesis: binding a session generation counter (bumped by the gates on password change or privilege change) into the MAC revokes every outstanding token for a session without changing the session id. Method: optional `epoch: u64` in the MAC input. Cost [est.]: 8 bytes of MAC input, ~0 ns. **Outcome:** rejected as a field, kept as a recipe (D-043).
- **Custom-header fact.** Hypothesis: for JSON APIs, requiring a non-simple request header (which forces a CORS preflight) blocks cross-site form posts with no token at all, as a layer-1 fact for `PolicyOnly`. Method: `RequestFacts::custom_header(bool)`. Cost [est.]: ~1 ns. **Outcome:** rejected (D-045).
- **Audience binding.** Hypothesis: multi-tenant hosts sharing one key ring can bind the target origin into the MAC so a token rendered for tenant A never verifies on tenant B, even with a colliding session id. Method: an optional audience field in the MAC input. Cost [est.]: one extra BLAKE3 block only when the audience pushes the input past 64 bytes. **Outcome:** rejected as a field, kept as a recipe (D-044).
- **Key-commitment check on rotation (0.2).** Hypothesis: a misdeployed cluster (two nodes holding different bytes under the same key id) fails silently as `BadMac` storms that look like an attack. Method: expose a short public fingerprint per key id (keyed BLAKE3 of a fixed label under the subkey, 8 bytes) so deployment tooling can compare rings across nodes without revealing keys. Cost [est.]: one BLAKE3 per key at construction; nothing per request. **Outcome:** adopted as `KeyFingerprint` and `Csrf::keys()` (D-041).
- **Simple-content-type fact (0.3).** Hypothesis: a cross-site form post needs no CORS preflight only when its content type is "simple" (`application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`). JSON APIs that refuse simple content types on unsafe requests close the no-preflight path even for browsers without Fetch Metadata, with no token at all. Method: `RequestFacts::content_type(value)` and a `PolicyOnly` rule that refuses simple types when `Sec-Fetch-Site` is absent. Cost [est.]: ~5 ns, a few byte comparisons. **Outcome:** rejected (D-042).
- **Store-free single use for short windows (0.4).** Hypothesis: for one-time tokens with very short lifetimes (seconds), a per-node replay filter over recently consumed nonces (a rotating pair of fixed-size bit sets, cleared every lifetime) gives single use without a shared store when requests are pinned to one node. Method: a `NonceStore` implementation with a bounded false-positive rate (a false positive refuses a fresh token, fail closed). Cost [est.]: two bit-set probes per verify, fixed memory; no allocation after start. **Outcome:** rejected (D-046).
- **Forgery-rate feedback.** Hypothesis: `BadMac` rates per session are a strong signal of an active attack against that user. Method: document the event shape for sentinel-sec; no state in this crate. Cost: none here. **Outcome:** adopted as documentation (D-047).

---

## 16. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-21 | The anti-forgery primitive moves out of gate-net into this crate | it is protocol-free, needed by web-net and WASP alike, and has its own threat model; gate-net keeps sessions |
| D-002 | 2026-10-21 | Stateless signed tokens by default; stateful one-time tokens behind a `TokenStore` seam | nothing to store or replicate on the common path, so verification scales linearly across nodes |
| D-003 | 2026-10-21 | Keyed BLAKE3 with a 128-bit tag | a 128-bit tag puts online forgery out of reach; BLAKE3 keyed mode is the fastest audited MAC available through crypt-io |
| D-004 | 2026-10-21 | Per-session tokens, masked per response | multi-tab browsing and the back button keep working, while BREACH cannot recover the token |
| D-005 | 2026-10-21 | In-house base64url until `encode-lib` exists | a fixed-length codec is small, and no third-party dependency is taken for it |
| D-006 | 2026-10-21 | No async runtime; approved exception to the REPS tokio clause | the crate does no I/O and never blocks; a runtime would be dead weight |
| D-007 | 2026-10-21 | Name `csrf-sec`, home `sec-collection` | every security control in the stack is `-sec`; the crate is protocol-free like customs-sec |
| D-008 | 2026-10-21 | MAC input length-prefixes the session id and the scope with LEB128 varints (O-1) | plain concatenation is ambiguous: (`"ab"`, `"c"`) and (`"a"`, `"bc"`) give the same input. Varints are canonical for any length, cost one byte for short values, and need no length limit or error path |
| D-009 | 2026-10-21 | Domain separation by subkey: one subkey per key id and token kind, derived at construction as keyed BLAKE3(application key, label, key id); the application key is not kept (O-2) | separation in the key is stronger than a text prefix in the input; dropping the 11-byte prefix keeps a 43-character session id in one BLAKE3 block (derived: 8 + 43 = 51 bytes); one derivation per key, once |
| D-010 | 2026-10-21 | Tier 3 takes `now` as unix seconds; Tier 1 and 2 read the system clock under `std`; no clock-lib dependency (O-3) | the `no_std` core has no clock; clock-lib's `Clock` trait needs `std`; explicit time makes every boundary test deterministic without a mock |
| D-011 | 2026-10-21 | One-time tokens are signed tokens with a 128-bit nonce; the `NonceStore` (renamed from `TokenStore`) holds outstanding nonces and is consulted only after MAC, lifetime, and scope pass (O-4) | the stored-value design let a cross-site attacker submit a wrong token with the victim's cookies and burn the victim's one-time token, and sent every forged request to the shared store; checking the MAC first closes both |
| D-012 | 2026-10-21 | Reasons added: `NotYetValid` (5), `Unverifiable` (5), `AlreadyUsed` (20), `StoreUnavailable` (5). `RetiredKey` is a pass flag, not a reason. `WrongScope` means "unscoped token on a scoped binding"; a different scope is `BadMac` (O-5) | every failure needs an accurate name; a scope inside the MAC cannot be recovered, so claiming `WrongScope` for it would let a forgery lower its own severity |
| D-013 | 2026-10-21 | base64url codec in constant-time arithmetic (no lookup tables), canonical text only (O-6) | table lookups indexed by token bytes leak through the cache to a co-located attacker; non-canonical decoding would let a changed character still verify |
| D-014 | 2026-10-21 | `0.1.0` published to claim the name (O-7) | the name is the public identity of the crate |
| D-015 | 2026-10-21 | `issue` returns `Result<Token, Error>`; `Token` is an inline buffer, not a `String` | if the CSPRNG or the clock fails, no token is minted and nothing panics (fail closed); an inline token makes issue allocation-free and works without `std` |
| D-016 | 2026-10-21 | A `Binding` value (session, scope, previous session, one-time store) replaces the `Scope` type and per-variant methods: three verbs (`issue`, `verify`, `check`) at three tiers (plain, `_with`, `_at`) | one small surface instead of a method for every combination; adding a binding field later is not a breaking change |
| D-017 | 2026-10-21 | Key roles: signing, accepted (verify only, staged), retired (verify only until a time); at most 16 keys | clusters need the new key on every node before any node signs with it; single-node rotation keeps `rotated()` |
| D-018 | 2026-10-21 | With no Fetch Metadata and no `Origin`, a present `Referer` whose origin does not match is refused (`OriginMismatch`), not handed to the token | a foreign `Referer` on an unsafe request is evidence of a cross-site form post; the OWASP CSRF guidance blocks it |
| D-019 | 2026-10-21 | Unknown `Sec-Fetch-Site` values are treated as absent, never as same-origin | fail closed: the request falls through to the `Origin` and `Referer` checks and the token |
| D-020 | 2026-10-21 | An empty session id cannot be bound: `issue` refuses (`EmptySession`), verify refuses (`Unverifiable`) | a token bound to nothing would be valid for every anonymous visitor, which is login CSRF (T2) |
| D-021 | 2026-10-21 | `no_std` means `no_std` with `alloc` | crypt-io needs `alloc`; the verify path still allocates nothing, proven by test |
| D-022 | 2026-10-21 | Origins compare scheme and host ASCII case-insensitively with default ports normalized; anything that is not a well-formed serialized origin never matches; user information in a `Referer` never matches | browsers serialize origins in lowercase without default ports, but adapters may not; a lenient parser is a bypass |
| D-023 | 2026-10-21 | Validity window: expired when `now > issued_at + lifetime`, not yet valid when `issued_at > now + skew`; `issue` refuses clocks outside 2020 to 2156 | exact, testable boundaries; no token is minted with a meaningless time |
| D-024 | 2026-10-21 | Keys whose 32 bytes are all equal are refused | catches an unset or zeroed key buffer, the most common key bug, at construction |
| D-025 | 2026-10-21 | `FIELD_NAME` (`csrf_token`) and `HEADER_NAME` (`x-csrf-token`) constants | adapters, web-net, and form-net agree on names without a convention document |
| D-026 | 2026-10-21 | `Token` has no `PartialEq`, and its `Debug` is redacted; `Csrf`'s `Debug` shows key ids and settings only | tokens are bearer values for a session: no variable-time comparison by accident, nothing secret in logs |
| D-027 | 2026-10-21 | Phases re-cut: the request policy, modes, and builder join `0.3.0` (they share `Verdict`, `OriginCheck`, and `check`); one-time tokens become `0.4.0`; `0.5.0` is feature completion (bare-metal `no_std` check, remaining ideas tried, docs) | nothing moves later; work moves earlier, so `0.3.0` ships a complete `check` instead of a half API |
| D-028 | 2026-10-21 | The `--no-default-features` CI run tests the library and integration tests, not doctests | doctests show the default (`std`) API; the `no_std` surface is covered by unit and integration tests that use the `_at` calls |
| D-029 | 2026-10-21 | MAC inputs up to 128 bytes are hashed in one call from a stack buffer, which is then cleared (best effort: zeroing kept by `black_box`, since the crate forbids `unsafe`); longer inputs are streamed through crypt-io's `Blake3Mac`, which wipes its state on drop | one call is the fast path for real session ids; the cleared copy may be the session secret; stack residue inside the hash function is outside what safe Rust can reach |
| D-030 | 2026-10-21 | In `RequestFacts`, an empty header value counts as absent | adapters commonly pass `""` for a missing header; treating it as present-but-foreign would refuse every such request, while treating it as absent still leaves the token to decide |
| D-031 | 2026-10-21 | `OsPads`: a 2 KiB buffer per thread, refilled from the OS through `mod-rand`, used bytes cleared, wiped at thread exit; requests over 512 bytes read the OS directly; `OsPads::refill()` for forked workers | about 90 pads per system call [derived]; no lock; after `fork`, repeated pads cannot help an attacker (see `pad.rs`), and `refill` removes even that |
| D-032 | 2026-10-21 | When nothing is configured to compare against (no `own_origin`, no allowlist), a present `Origin` or `Referer` cannot be judged and the token decides; `null` and malformed values are still refused | refusing would break every deployment whose adapter omits `own_origin`, and the token still has to pass in `Strict`; `null` is never an allowed origin, so refusing it needs no configuration |
| D-033 | 2026-10-21 | `FetchSite::parse` ignores surrounding spaces and tabs; the value itself must match exactly | HTTP parsers strip optional whitespace, but an adapter might not; script cannot set this header, so trimming widens nothing |
| D-034 | 2026-10-21 | `docs/API.md` is compiled as a doctest (`#[doc = include_str!]` under `cfg(doctest)`) | every example in the reference is checked against the build on every CI run |
| D-035 | 2026-10-21 | The `NonceStore` records **used** nonces, not outstanding ones: one atomic `consume(&NonceUse)` (set-if-absent) on a verify whose MAC passed; issuing never touches the store. Supersedes the insert-on-issue half of D-011 before any release shipped it | the MAC already proves issuance, so remembering issued tokens is redundant. Pages are rendered far more often than forms are submitted, so issue-time writes and records for never-submitted tokens were the bulk of the store's load and memory; now the issue path is stateless, cannot fail on a store, and the store holds only submitted tokens. `NonceUse` is `#[non_exhaustive]` so fields can be added without a breaking change |
| D-036 | 2026-10-21 | A one-time binding always checks the token, whatever the mode; in `PolicyOnly` the policy runs first, then the token | binding a store asks for single use; skipping the token in `PolicyOnly` would silently drop that guarantee (fail closed) |
| D-037 | 2026-10-21 | `MemoryStore`: 64 shards behind their own locks, keyed by nonce with an unkeyed hash of its first eight bytes, at most `capacity / 64` per shard; a full shard drops expired records and otherwise refuses (`StoreError::Full`, so `StoreUnavailable`); a poisoned lock is used as is | nonces are random and never client-chosen (`consume` runs only after the MAC), so a flood-resistant hash buys nothing; refusing beats evicting, because evicting an unexpired record would let a used token pass again; no critical section can leave the map half-updated |
| D-039 | 2026-10-21 | `MemoryStore` refuses (as already used) every token issued at or before the second it started; `MemoryStore::starting_at` sets the start explicitly | a used-nonce memory forgets on restart, which would let a token used before the restart pass once more; refusing older tokens keeps a restart fail-closed. The boundary second is refused too, because a sub-second restart could otherwise replay a token from that second; the cost is that a page rendered in the store's first second must be reloaded |
| D-040 | 2026-10-21 | Records are kept until `issued_at + lifetime + skew` | a node whose clock lags by up to the skew still accepts the token, so the record must outlive it there too |
| D-041 | 2026-10-21 | Adopted from the ideas list: `KeyFingerprint` (8 bytes of keyed BLAKE3 over a fixed label under the session subkey), `Csrf::keys()` with `KeyInfo`, and `Csrf::key_fingerprint(id)` | clusters need to confirm every node holds the same ring without moving keys around; the fingerprint input starts with `c`, never a token version byte, so it can never equal a tag computation, and a PRF output reveals nothing about the key; cost is one BLAKE3 call per key when asked |
| D-042 | 2026-10-21 | Rejected: a simple-content-type fact in layer 1 | every browser that enforces the CORS preflight also sends `Origin` on cross-origin unsafe requests, which layer 1 already checks; content-type gates have a history of bypasses (Flash, `sendBeacon` with a `Blob`, servers parsing `text/plain` as JSON), and offering one would invite relying on it |
| D-043 | 2026-10-21 | Rejected as a field: session epoch binding. Documented as a recipe instead: bind `session id + generation` | the existing session binding already does it with no new surface and no format change |
| D-044 | 2026-10-21 | Rejected as a field: audience binding. Documented as a recipe: prefix the scope or session id with the tenant, or give each tenant its own key id | same capability through existing, length-prefixed fields |
| D-045 | 2026-10-21 | Rejected: a custom-header fact (`X-Requested-With` style) | it only forces a CORS preflight, which `Origin` and Fetch Metadata already cover for every browser that preflights; it adds a second, weaker way to pass layer 1 |
| D-046 | 2026-10-21 | Rejected: a store-free replay filter (rotating bit sets) | it is single use only on the node that saw the first use, so behind a load balancer it silently is not; false positives refuse fresh tokens; `MemoryStore` already gives exact single-node semantics at about 40 bytes per used token |
| D-047 | 2026-10-21 | Adopted as documentation: what to log on a refusal (`reason`, `severity`, `key_id`, never the token or session id) and how detection layers use reason rates | no state belongs in this crate; the verdict already carries everything a detection layer needs |
| D-048 | 2026-10-21 | `KeyRole` is public and `#[non_exhaustive]` | `KeyInfo` reports it; new roles stay a non-breaking change |
| D-049 | 2026-10-21 | CI builds the `no_std` core for `thumbv7em-none-eabi` on stable and 1.85, with and without `alloc` | a host build with `no_std` set can still link `std` through a dependency by accident; a target without `std` cannot |
| D-050 | 2026-10-21 | The tag comparison is one 128-bit XOR tested once, behind `black_box`, instead of crypt-io's `Tag::ct_eq` | measured 50 ns for `Tag::ct_eq` (subtle's per-byte barriers) against about 1 ns; there is no loop to exit early and no branch on a byte, so the time does not depend on the data; the statistical timing test in `0.7.0` checks it. A faster `Tag::ct_eq` belongs in crypt-io as its own change |
| D-051 | 2026-10-21 | The base64url codec handles full blocks eight lanes per `u64` (SWAR), with the one-character code for the tail; still no table and no branch on token bytes | decode 44 to 29 ns, encode to 20 ns (measured); every lane is tested against the scalar code for every byte value, and every intermediate lane value stays within 0 to 255, so lanes never carry into each other |
| D-052 | 2026-10-21 | Benchmarks of record run on Linux; `dev/bench-compare` (outside the published crate) holds the competitor comparison | this machine's local Windows linker setup adds up to 60 ns to small `memcpy` calls; the comparison's third-party crates must never reach the published crate or its dependency audit |
| D-053 | 2026-10-21 | With `Sec-Fetch-Site: same-site` or `cross-site`, only the allowlist can pass a request; the site's own origin no longer counts there | the browser has already said another site sent it, so the own origin cannot vouch for it; the attack path becomes the cheapest one (19 ns, and no parsing at all without an allowlist) |
| D-054 | 2026-10-21 | Origin parsing splits the scheme at the first `:`, checks character classes with 128-bit sets, and passes a value byte-identical to a well-formed `own_origin` without a second parse | `Referer` match 51 to 23 ns; origins are public, so a bit-set lookup indexed by them leaks nothing |
| D-055 | 2026-10-21 | Pads keep coming from the OS generator, even though a user-space generator seeded from it would cut `issue` by about 20 ns on Linux | the operating system's generator stays the only source of randomness in the crate; 28 ns is far inside the budget |
| D-038 | 2026-10-21 | The nonce is drawn from the same `PadSource` as the pad, before it | one randomness seam for Tier 3 and `no_std`; the order is part of the documented format so the independent reimplementation test can rebuild a token exactly |
