# csrf-sec - Project Plan

> The design, strategy, and decision record for `csrf-sec`. A living document: every design decision, idea, or open question about csrf-sec is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Read order:** [`../REPS.md`](../REPS.md) &rarr; [`DIRECTIVES.md`](./DIRECTIVES.md) &rarr; **this file** &rarr; [`ROADMAP.md`](./ROADMAP.md).
>
> **Status:** scaffold, `0.1.0`. Design lock is `0.2.0`.

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

MAC input (nothing secret appears in the token itself):

```
 "csrf-sec/v1" (domain separation) | version | key id | issued at | session id | scope (empty if none)
```

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

A `TokenStore` trait for one-time tokens: issue stores a random 32-byte value in the session record; verify compares in constant time and deletes it. Default: none (stateless). WASP implements the trait over the gates' session store. The exact shape of the seam is settled at design lock (O-4).

---

## 6. Keys and rotation

- Keys are 32 bytes. The recommended source is a master secret held in key-vault, with the CSRF key derived by HKDF (`info = "csrf-sec v1"`, crypt-io), so CSRF never shares a key with anything else.
- **Persist the key or derive it from a persisted master.** Random keys created at boot make every open form fail after a restart.
- `KeyRing`: one current key (signs) plus retired keys (verify only, until their retire time). Rotation adds a new current key; old tokens keep verifying until the token lifetime passes, so nobody is logged out or loses a form.
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

The reason is for logs and scoring only. Clients receive a generic refusal.

---

## 8. API shape

The planned shape; the exact surface is written into `docs/API.md` at design lock (`0.2.0`).

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

| Id | Threat | Defence | Cost [est.] |
|---|---|---|---|
| T1 | classic CSRF: an attacker page auto-submits a form with the victim's cookies | policy check + session-bound token | ~0.3-0.5 µs per unsafe request |
| T2 | login CSRF: the victim is signed in to the attacker's account | token bound to the pre-session (WASP's lazy guest session) | same |
| T3 | forced logout | token on logout | same |
| T4 | token recovered from compressed responses (BREACH) | per-response masking | ~20 ns per issue |
| T5 | token reused in another session | MAC binds the session id | none extra |
| T6 | token reused for another action | optional scope binding | ~10 ns |
| T7 | cookie tossing from a subdomain defeats naive double-submit | tokens are signed and session-bound, not compared to a cookie; `__Host-` cookie guidance | none |
| T8 | token forgery | 256-bit key, keyed BLAKE3, 128-bit tag | none extra |
| T9 | timing attack on the comparison | constant-time tag comparison | none extra |
| T10 | key compromise | key ids, rotation without logouts, short lifetimes, keys derived per purpose | rotation is operational |
| T11 | denial of service through verification | length checked before decoding; fixed work; no allocation | bounded per request |
| T12 | clocks differ between nodes | skew tolerance on issue time | none |
| T13 | state change through a "safe" method (GET with side effects) | method classification; safe methods never pass as state-changing | ~1 ns |
| T14 | `Origin: null` and stripped `Referer` | explicit policy for each case | ~1 ns |
| T15 | cross-site top-level POST navigation | Fetch Metadata: `Sec-Fetch-Site: cross-site` on an unsafe method is refused | ~20 ns |

Every cost is an estimate until `0.6.0` benchmarks replace it with a measurement.

Out of scope, named so nobody assumes otherwise: cross-site scripting defeats every CSRF defence, because script on the page can read the token; that is stopped by output encoding and the content security policy (shield-sec, web-net). Clickjacking is stopped by frame options and CSP `frame-ancestors`.

---

## 10. Architecture

```
src/
  lib.rs        crate docs, Tier-1 entry points, re-exports
  csrf.rs       Csrf (immutable, cheap to share), builder, rotation
  key.rs        Key, KeyId, KeyRing; per-key MAC state, wiped on drop
  token.rs      raw token layout, MAC input, issue and verify core
  mask.rs       pad generation and masking
  b64.rs        base64url codec (no padding, fixed length, branch-free)
  policy.rs     RequestFacts, layer-1 decision, modes
  scope.rs      Scope
  verdict.rs    Verdict, Reason, severity, Rejected
  store.rs      one-time token seam (optional)
  error.rs      construction errors (#[non_exhaustive])
```

- `Csrf` is immutable after construction. Rotation builds a new value; the application swaps it. No interior mutability on any shared path.
- Verify works on stack buffers only; the token length is fixed, so every buffer size is a constant.
- `std` and `alloc` features add the `String`-returning conveniences and the thread-local pad source; the core works without them.

---

## 11. Performance, efficiency, and scale

| Operation | Target [est.] | How |
|---|---|---|
| `issue` | ≤ 300 ns | keyed BLAKE3 over ~60 bytes, a 22-byte pad from a buffered CSPRNG, base64url into a stack buffer |
| `verify` | ≤ 300 ns | fixed-length decode, one MAC, constant-time compare of 16 bytes |
| layer 1 policy | ≤ 50 ns | byte comparisons on values the adapter already parsed |
| allocations on verify | 0 | stack buffers only |
| locks or shared atomics on verify | 0 | immutable `Csrf`, swapped by the application on rotation |
| scale-out | linear | stateless; any node verifies any token with the same key ring |

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
| O-1 | MAC input encoding: the plan concatenates session id and scope with no lengths, so (`"ab"`, `"c"`) and (`"a"`, `"bc"`) produce the same MAC input | length-prefix both; canonical encoding costs nothing |
| O-2 | Where domain separation lives: a text prefix in every MAC input, or a per-key subkey derived once at construction | derive a subkey per key id; keeps short MAC inputs inside one BLAKE3 block |
| O-3 | Time: read the clock inside the crate, or take `now` as a value on the Tier-3 path | Tier 3 takes `now`; Tier 1 reads the system clock; tests need no mock clock |
| O-4 | One-time tokens: a stored random value (5.5), or a signed token carrying a nonce with the store holding outstanding nonces | signed token with a nonce: forged requests are refused before the store is touched, so they cannot burn a user's token or load the store |
| O-5 | Reasons the plan does not name: a token issued in the future beyond skew; `PolicyOnly` without Fetch Metadata; a store that cannot answer | add `NotYetValid`, `Unverifiable`, `StoreUnavailable` (all fail closed) |
| O-6 | Codec: lookup tables indexed by token bytes leak through the cache to a co-located attacker | constant-time arithmetic codec |
| O-7 | Publish `0.1.0` to crates.io to claim the name? | yes |

---

## 15. Ideas parking lot

Each idea is a hypothesis with a method and an expected cost, tried in the phase noted or later.

- **Session epoch binding.** Hypothesis: binding a session generation counter (bumped by the gates on password change or privilege change) into the MAC revokes every outstanding token for a session without changing the session id. Method: optional `epoch: u64` in the MAC input. Cost [est.]: 8 bytes of MAC input, ~0 ns.
- **Custom-header fact.** Hypothesis: for JSON APIs, requiring a non-simple request header (which forces a CORS preflight) blocks cross-site form posts with no token at all, as a layer-1 fact for `PolicyOnly`. Method: `RequestFacts::custom_header(bool)`. Cost [est.]: ~1 ns.
- **Audience binding.** Hypothesis: multi-tenant hosts sharing one key ring can bind the target origin into the MAC so a token rendered for tenant A never verifies on tenant B, even with a colliding session id. Method: an optional audience field in the MAC input. Cost [est.]: one extra BLAKE3 block only when the audience pushes the input past 64 bytes.
- **Forgery-rate feedback.** Hypothesis: `BadMac` rates per session are a strong signal of an active attack against that user. Method: document the event shape for sentinel-sec; no state in this crate. Cost: none here.

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
