<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br><b>csrf-sec</b><br>
    <sub><sup>API REFERENCE</sup></sub>
</h1>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>API</span>
        <span>&nbsp;│&nbsp;</span>
        <a href="../CHANGELOG.md" title="Changelog"><b>CHANGELOG</b></a>
    </sup>
</div>
<br>

> **Status: design lock (`0.2.0`).** This file is the locked public surface. The code lands in `0.3.0` (tokens, keys, Tier 1), `0.4.0` (request policy, modes, builder), and `0.5.0` (one-time tokens, Tier 3, `no_std`); until then the examples describe the API, not the build. From `0.3.0` on, every example here is compiled and run as a doctest.

A task-oriented tour of the API, Tier 1 first. The rustdoc on [docs.rs](https://docs.rs/csrf-sec) is the item-by-item reference.

- [Setup](#setup)
- [Tier 1: three calls](#tier-1-three-calls)
- [Tokens](#tokens)
- [Bindings: session, scope, previous session](#bindings-session-scope-previous-session)
- [Request policy (layer 1)](#request-policy-layer-1)
  - [`RequestFacts`](#requestfacts)
  - [The decision](#the-decision)
  - [Modes](#modes)
- [Keys, the builder, and rotation](#keys-the-builder-and-rotation)
- [One-time tokens](#one-time-tokens)
- [Tier 3: explicit time and randomness](#tier-3-explicit-time-and-randomness)
- [Verdicts and reasons](#verdicts-and-reasons)
- [Errors](#errors)
- [Constants](#constants)
- [Feature flags](#feature-flags)
- [Cookie guidance](#cookie-guidance)
- [Token format](#token-format)

## Setup

```toml
[dependencies]
csrf-sec = "0.2.0"
```

`csrf-sec` has one job: decide whether a state-changing request came from your own page, for this session. It never parses HTTP. Your adapter (a framework middleware, web-net, a WASP service) hands it plain values: the session id, the submitted token, and the request's origin facts.

## Tier 1: three calls

```rust
use csrf_sec::{Csrf, RequestFacts};

let csrf = Csrf::new(key)?;                     // key: [u8; 32], persisted (see Keys)

// Rendering a page with a form:
let token = csrf.issue(session_id)?;            // 59 characters, different on every call

// Handling the POST (token only):
csrf.verify(session_id, submitted)?;

// Handling the POST (recommended: request policy and token):
let facts = RequestFacts::new(method)
    .fetch_site(sec_fetch_site_header)
    .origin(origin_header)
    .own_origin("https://example.com");
csrf.check(&facts, session_id, submitted)?;
```

| Call | Returns | Cost [est.] |
|---|---|---|
| `Csrf::new(key)` | `Result<Csrf, Error>` | one keyed BLAKE3 per key, once |
| `csrf.issue(session)` | `Result<Token, Error>` | ≤ 300 ns; no allocation |
| `csrf.verify(session, token)` | `Verdict` = `Result<Verified, Rejected>` | ≤ 300 ns; no allocation, no lock |
| `csrf.check(&facts, session, token)` | `Verdict` | ≤ 350 ns; no allocation, no lock |

`session` and `token` accept anything that is `AsRef<[u8]>`: `&str`, `String`, `&[u8]`, `Vec<u8>`, or a `Token`. An empty token is reported as `Reason::Missing`; an empty session id can never pass (`Reason::Unverifiable`), because a token bound to nothing protects nothing.

`Csrf` is immutable, `Send + Sync`, and cheap to share behind an `Arc`. Nothing on the issue or verify path takes a lock or touches a shared counter.

## Tokens

```rust
pub struct Token { /* inline buffer, no heap */ }

impl Token {
    pub fn as_str(&self) -> &str;
    pub fn as_bytes(&self) -> &[u8];
    pub fn len(&self) -> usize;          // TOKEN_LEN (59) or ONCE_TOKEN_LEN (102)
    pub fn is_empty(&self) -> bool;      // always false
}
// Deref<Target = str>, AsRef<str>, AsRef<[u8]>, Display (the token text),
// Debug (redacted), Clone, From<Token> for String (feature `alloc`).
```

A `Token` is the masked text you put in a hidden form field (`FIELD_NAME`) or a request header (`HEADER_NAME`). Its alphabet is base64url (`A-Z a-z 0-9 - _`), so it is safe in HTML attributes, headers, URLs, and cookies without escaping.

```rust
let token = csrf.issue(session_id)?;
let html = format!(r#"<input type="hidden" name="{}" value="{}">"#, csrf_sec::FIELD_NAME, token);
```

Every call to `issue` returns a different string for the same session: the token is masked with fresh randomness each time, so a compression side channel (BREACH) cannot recover it from pages. All of them verify. `Token` does not implement `PartialEq`, so it cannot be compared in variable time by accident; `Debug` prints `Token(59 chars)`, never the value.

## Bindings: session, scope, previous session

Tier 2 calls take a `Binding`, which says what the token is bound to:

```rust
pub struct Binding<'a> { /* borrowed */ }

impl<'a> Binding<'a> {
    pub fn new(session: &'a (impl AsRef<[u8]> + ?Sized)) -> Self;
    pub fn scope(self, scope: &'a (impl AsRef<[u8]> + ?Sized)) -> Self;
    pub fn previous_session(self, previous: &'a (impl AsRef<[u8]> + ?Sized)) -> Self;
    pub fn once(self, store: &'a dyn NonceStore) -> Self;
}

impl Csrf {
    pub fn issue_with(&self, binding: &Binding<'_>) -> Result<Token, Error>;
    pub fn verify_with(&self, binding: &Binding<'_>, token: impl AsRef<[u8]>) -> Verdict;
    pub fn check_with(&self, facts: &RequestFacts<'_>, binding: &Binding<'_>, token: impl AsRef<[u8]>) -> Verdict;
}
```

- **Session.** The value every token is bound to: your session id, or any per-session secret. It goes into the MAC and never into the token, so the token reveals nothing about the session. Bind to the pre-login (guest) session on login forms, and issue a new token after login (T2, login CSRF).
- **Scope.** Binds a token to one action, for high-value forms:

  ```rust
  let change_email = Binding::new(session_id).scope("POST /account/email");
  let token = csrf.issue_with(&change_email)?;
  // later:
  csrf.verify_with(&change_email, submitted)?;
  ```

  A token issued without a scope and presented to a scoped binding fails as `WrongScope`. A token issued for a different scope fails as `BadMac`: its scope is inside the MAC, so it cannot be told apart from a forgery.
- **Previous session.** Your session layer rotates the session id at login. Tabs opened before the login still hold tokens for the old id; pass it here for the short window your gates keep it, and those tokens fail as `StaleSession` (benign, severity 1) instead of `BadMac` (forgery, severity 40). A token bound to the previous session never passes.
- **Once.** Makes the token one-time; see [One-time tokens](#one-time-tokens).

Cost of a scope or previous session: only failing tokens pay for the extra MAC used to tell the reasons apart, at most three extra keyed BLAKE3 calls [est. ~60 ns each], so verify work stays fixed and bounded.

## Request policy (layer 1)

### `RequestFacts`

```rust
pub struct RequestFacts<'a> { /* borrowed */ }

impl<'a> RequestFacts<'a> {
    pub fn new(method: &(impl AsRef<[u8]> + ?Sized)) -> Self;     // classifies the method
    pub fn with_class(class: MethodClass) -> Self;
    pub fn fetch_site(self, value: &(impl AsRef<[u8]> + ?Sized)) -> Self;   // Sec-Fetch-Site
    pub fn origin(self, value: &'a (impl AsRef<[u8]> + ?Sized)) -> Self;    // Origin
    pub fn referer(self, value: &'a (impl AsRef<[u8]> + ?Sized)) -> Self;   // Referer (full URL)
    pub fn own_origin(self, value: &'a (impl AsRef<[u8]> + ?Sized)) -> Self; // this site, e.g. "https://example.com"
}

#[non_exhaustive]
pub enum MethodClass { Safe, Unsafe }
impl MethodClass { pub fn classify(method: &[u8]) -> MethodClass; }

#[non_exhaustive]
pub enum FetchSite { SameOrigin, SameSite, CrossSite, None }
impl FetchSite { pub fn parse(value: &[u8]) -> Option<FetchSite>; }
```

The adapter fills only what the request carried. Values are raw header bytes; nothing needs to be decoded first.

- Methods are classified case-sensitively: exactly `GET`, `HEAD`, and `OPTIONS` are safe; everything else, including `get`, `TRACE`, and unknown methods, is unsafe. A handler that changes state must be reached only through an unsafe method (T13); csrf-sec cannot see your routes, so this is your router's contract.
- `Sec-Fetch-Site` values other than the four defined ones are treated as absent, never as same-origin.

### The decision

```
 safe method                                   ─▶ pass (no token needed)
 Sec-Fetch-Site: same-origin | none            ─▶ pass
 Sec-Fetch-Site: same-site                     ─▶ pass if allow_same_site, or Origin is allowlisted; else CrossSite
 Sec-Fetch-Site: cross-site                    ─▶ pass if Origin is allowlisted; else CrossSite
 no Fetch Metadata, Origin present             ─▶ "null" or no match: OriginMismatch; match: pass
 no Fetch Metadata, no Origin, Referer present ─▶ its origin matches: pass; else OriginMismatch
 nothing at all                                ─▶ the token decides (Strict), Unverifiable (PolicyOnly)
```

An origin matches when it equals `own_origin` or an allowlisted origin: scheme and host compared ASCII case-insensitively, default ports (`:80` for http, `:443` for https) normalized, anything that is not a well-formed serialized origin refused. A `Referer` with user information (`https://a@b/`) never matches. Cost [est.]: ≤ 50 ns, no allocation.

```rust
impl Csrf {
    pub fn policy(&self, facts: &RequestFacts<'_>) -> Result<OriginCheck, Rejected>;   // layer 1 alone
}

#[non_exhaustive]
pub enum OriginCheck { SafeMethod, FetchMetadata, Origin, Referer, NoFacts, NotRun }
```

### Modes

| Mode | An unsafe request passes when | Use |
|---|---|---|
| `Mode::Strict` (default) | layer 1 does not refuse **and** the token verifies | browsers, the normal case |
| `Mode::TokenOnly` | the token verifies | clients that send no browser headers |
| `Mode::PolicyOnly` | `Sec-Fetch-Site` was sent and layer 1 passes | endpoints called only from modern browsers, with no forms; never the default |

In `Strict`, layer 1 runs first and a refusal returns at once, before any token work.

## Keys, the builder, and rotation

```rust
pub struct KeyId(pub u8);

impl Csrf {
    pub fn builder() -> Builder;
    pub fn rotated(&self, id: KeyId, key: [u8; 32]) -> Result<Csrf, Error>;
    pub fn rotated_at(&self, id: KeyId, key: [u8; 32], now: u64) -> Result<Csrf, Error>;
    pub fn signing_key(&self) -> KeyId;
    pub fn accepts(&self, id: KeyId) -> bool;
    pub fn mode(&self) -> Mode;
    pub fn lifetime(&self) -> Duration;
    pub fn skew(&self) -> Duration;
}

impl Builder {
    pub fn key(self, id: KeyId, key: [u8; 32]) -> Self;                     // signs and verifies
    pub fn accept(self, id: KeyId, key: [u8; 32]) -> Self;                  // verifies only
    pub fn retired(self, id: KeyId, key: [u8; 32], retire_at: u64) -> Self; // verifies until retire_at (unix seconds)
    pub fn lifetime(self, lifetime: Duration) -> Self;                      // default 12 hours
    pub fn skew(self, skew: Duration) -> Self;                              // default 60 seconds
    pub fn mode(self, mode: Mode) -> Self;                                  // default Strict
    pub fn allow_origin(self, origin: &str) -> Self;
    pub fn allow_same_site(self, allow: bool) -> Self;                      // default false
    pub fn build(self) -> Result<Csrf, Error>;
}
```

```rust
let csrf = Csrf::builder()
    .key(KeyId(3), current_key)
    .retired(KeyId(2), old_key, retire_at)
    .lifetime(Duration::from_secs(12 * 3600))
    .skew(Duration::from_secs(60))
    .mode(Mode::Strict)
    .allow_origin("https://example.com")
    .allow_same_site(false)
    .build()?;
```

- **Keys are 32 bytes and must be persisted** (or derived from a persisted master, for example a key-vault secret through HKDF). A key generated at boot makes every open form fail after a restart. Keys whose bytes are all equal (an unset buffer) are refused.
- csrf-sec never MACs with your key directly: it derives one subkey per key id and token kind at construction, keeps only those, and wipes them when the `Csrf` is dropped.
- **Rotation on one node:** `csrf.rotated(KeyId(4), new_key)?` returns a new `Csrf` that signs with key 4 and keeps the old signing key as retired until one token lifetime (plus skew) from now. Swap it in; nobody is logged out and no open form fails.
- **Rotation across a cluster, in two steps:** first deploy the new key everywhere with `.accept(id, key)` (verify only); once every node has it, make it the signing key with `.key(id, key)` and move the old one to `.retired(..)`. A node never receives a token signed with a key it does not know.
- Key ids are never reused while tokens signed under them can still be presented; the builder and `rotated` refuse a duplicate id. Up to `MAX_KEYS` (16) keys at once.

## One-time tokens

For actions where a token must not be usable twice (a payment, deleting an account):

```rust
pub trait NonceStore {
    fn insert(&self, session: &[u8], nonce: &[u8; 16], expires_at: u64) -> Result<(), StoreError>;
    fn take(&self, session: &[u8], nonce: &[u8; 16], now: u64) -> Result<bool, StoreError>;
}

pub struct MemoryStore { /* sharded, bounded */ }       // feature `std`
impl MemoryStore { pub fn new(capacity: usize) -> Self; }
```

```rust
let store = MemoryStore::new(100_000);
let pay = Binding::new(session_id).scope("POST /pay").once(&store);
let token = csrf.issue_with(&pay)?;          // 102 characters
csrf.verify_with(&pay, submitted)?;          // passes once; a second use fails as AlreadyUsed
```

A one-time token is a signed token with a 128-bit random nonce inside the MAC; the store holds the outstanding nonces. **The MAC, lifetime, and scope are checked before the store is touched**, so forged requests never reach the store: they cannot burn a user's token and cannot load a shared store. `take` must remove the entry atomically and report whether it was present and unexpired; a store that cannot answer fails closed (`StoreUnavailable`). For clusters, implement `NonceStore` over your shared session store. Cost: one store round trip on verify, plus the normal verify.

## Tier 3: explicit time and randomness

The core works without `std` (it needs `alloc`). Time is passed in as unix seconds, and randomness comes from a `PadSource` you supply:

```rust
pub trait PadSource {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error>;
}

pub struct OsPads;      // feature `std`: per-thread buffer refilled in bulk from the OS CSPRNG

impl Csrf {
    pub fn issue_at(&self, binding: &Binding<'_>, now: u64, pads: &mut impl PadSource) -> Result<Token, Error>;
    pub fn verify_at(&self, binding: &Binding<'_>, token: &[u8], now: u64) -> Verdict;
    pub fn check_at(&self, facts: &RequestFacts<'_>, binding: &Binding<'_>, token: &[u8], now: u64) -> Verdict;
}
```

A `PadSource` must be a cryptographically secure generator. The pad travels with the token, but it must not be predictable before the response is built: a predictable pad lets a compression attack recover the token again. Tier 1 and Tier 2 use `OsPads` and the system clock.

## Verdicts and reasons

```rust
pub type Verdict = Result<Verified, Rejected>;

pub struct Verified { /* Copy */ }
impl Verified {
    pub fn key_id(&self) -> Option<KeyId>;      // None when no token was needed
    pub fn retired_key(&self) -> bool;          // signed by a retired key (rotation in progress)
    pub fn token_checked(&self) -> bool;
    pub fn origin_check(&self) -> OriginCheck;
}

pub struct Rejected { /* Copy */ }
impl Rejected {
    pub fn reason(&self) -> Reason;
    pub fn severity(&self) -> u8;
}
// Display ("request forgery check failed: bad_mac"), Error (feature `std`).

#[non_exhaustive]
pub enum Reason { /* see table */ }
impl Reason {
    pub const fn severity(self) -> u8;
    pub const fn as_str(self) -> &'static str;
}
```

| Reason | `as_str` | Most likely | Severity |
|---|---|---|---|
| `Missing` | `missing` | a client bug, or a forged form without a token | 5 |
| `Malformed` | `malformed` | tampering or truncation | 10 |
| `UnknownKey` | `unknown_key` | a very old token, or tampering | 5 |
| `BadMac` | `bad_mac` | forgery | 40 |
| `StaleSession` | `stale_session` | the user signed in again in another tab | 1 |
| `Expired` | `expired` | an old tab | 1 |
| `NotYetValid` | `not_yet_valid` | a node clock ahead by more than the skew | 5 |
| `WrongScope` | `wrong_scope` | an unscoped token presented to a scoped action | 20 |
| `CrossSite` | `cross_site` | layer 1: a cross-site unsafe request | 30 |
| `OriginMismatch` | `origin_mismatch` | layer 1: a foreign origin | 30 |
| `Unverifiable` | `unverifiable` | the check cannot run: no session id, or no Fetch Metadata in `PolicyOnly` | 5 |
| `AlreadyUsed` | `already_used` | a one-time token presented twice | 20 |
| `StoreUnavailable` | `store_unavailable` | the one-time store could not answer | 5 |

The reason is decided **after** the MAC: a forged token is never reported as expired, and an expired real token is never reported as forged. Reasons are for logs and scoring (sentinel-sec, bouncer-io); clients get a generic refusal (HTTP 403). A token signed by a retired key passes, with `retired_key()` set.

## Errors

```rust
#[non_exhaustive]
pub enum Error {
    WeakKey(KeyId),          // key bytes all equal
    DuplicateKeyId(KeyId),   // id already in the ring
    NoSigningKey,            // builder without .key(..)
    MultipleSigningKeys,     // .key(..) given twice
    TooManyKeys,             // more than MAX_KEYS
    InvalidLifetime,         // zero, or longer than u32::MAX seconds
    InvalidSkew,             // longer than the lifetime
    InvalidOrigin,           // allow_origin value is not a serialized origin, or is "null"
    EmptySession,            // issue with an empty session id
    Clock,                   // clock outside 2020-01-01 .. 2156-02-07
    Random,                  // the CSPRNG failed; no token is issued
    Store(StoreError),       // the one-time store refused the insert
}
// Display (says what to do), Error (feature `std`), Clone, PartialEq, Eq.
```

`issue` is fallible on purpose: if randomness or the clock fails, no token is minted (fail closed) and nothing panics.

## Constants

| Constant | Value | Meaning |
|---|---|---|
| `VERSION` | `env!("CARGO_PKG_VERSION")` | crate version |
| `TOKEN_LEN` | 59 | session token text length |
| `ONCE_TOKEN_LEN` | 102 | one-time token text length |
| `KEY_LEN` | 32 | key length in bytes |
| `MAX_KEYS` | 16 | keys a ring holds at once |
| `FIELD_NAME` | `"csrf_token"` | suggested hidden form field name |
| `HEADER_NAME` | `"x-csrf-token"` | suggested request header name |
| `DEFAULT_LIFETIME` | 12 hours | token lifetime |
| `DEFAULT_SKEW` | 60 seconds | tolerated clock difference between nodes |

## Feature flags

| Feature | Default | Adds |
|---|---|---|
| `std` | yes | Tier 1 and Tier 2 calls (system clock, `OsPads`), `rotated`, `MemoryStore`, `std::error::Error` impls; implies `alloc` |
| `alloc` | via `std` | `From<Token> for String` |

With `default-features = false` the crate is `no_std` and needs an allocator (crypt-io does); the verify path still allocates nothing.

## Cookie guidance

csrf-sec does not set cookies; cookie-net does. For the session cookie that tokens are bound to:

- `__Host-` prefix (forces `Secure`, `Path=/`, and no `Domain`, so a sibling subdomain cannot plant or overwrite it),
- `SameSite=Lax` (or `Strict` where cross-site links into signed-in pages are not needed),
- `Secure` and `HttpOnly`.

Tokens are not compared to a cookie (they are not double-submit tokens), so cookie tossing from a subdomain cannot defeat them (T7).

## Token format

Little-endian integers throughout.

```
 raw session token (22 bytes):   version=1 (1) | key id (1) | issued at (4) | tag (16)
 raw one-time token (38 bytes):  version=2 (1) | key id (1) | issued at (4) | nonce (16) | tag (16)
 issued at:                      seconds since 2020-01-01T00:00:00Z

 MAC input:  version | key id | issued at | [nonce] | varint(len session) | varint(len scope) | session | scope
 tag:        first 16 bytes of keyed BLAKE3(subkey, MAC input)
 subkey:     keyed BLAKE3(application key, label | key id), one label per token kind, derived once

 masked:     pad (len raw) | raw XOR pad          pad: fresh CSPRNG bytes per issue
 text:       base64url, no padding, canonical     59 or 102 characters
```

Lengths are LEB128 varints, so the encoding is canonical for any length and short inputs (a 43-character session id with no scope) fit in one 64-byte BLAKE3 block. Decoding is constant time and accepts only canonical text: any change to any character of a token makes it fail.
