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

A task-oriented tour of the API, Tier 1 first. The rustdoc on [docs.rs](https://docs.rs/csrf-sec) is the item-by-item reference. Every `rust` example in this file is compiled and run as a doctest, so it matches the build; lines starting with `#` are setup hidden in rustdoc.

> **Status: `0.4.0`.** Session tokens, one-time tokens, the request policy, modes, the builder, key rotation, and all three tiers are built.

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
csrf-sec = "0.4.0"
```

`csrf-sec` has one job: decide whether a state-changing request came from your own page, for this session. It never parses HTTP. Your adapter (a framework middleware, web-net, a WASP service) hands it plain values: the session id, the submitted token, and the request's origin facts.

## Tier 1: three calls

```rust
use csrf_sec::{Csrf, RequestFacts};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let key = *b"an example key, 32 bytes long!!!";
# let session_id = "session-1";

let csrf = Csrf::new(key)?;                     // key: [u8; 32], persisted (see Keys)

// Rendering a page with a form:
let token = csrf.issue(session_id)?;            // 59 characters, different on every call
# let submitted = token.as_str();

// Handling the POST (token only):
csrf.verify(session_id, submitted)?;

// Handling the POST (recommended: request policy and token):
let facts = RequestFacts::new("POST")
    .fetch_site("same-origin")
    .origin("https://example.com")
    .own_origin("https://example.com");
csrf.check(&facts, session_id, submitted)?;
# Ok(())
# }
```

| Call | Returns | Cost [est.] |
|---|---|---|
| `Csrf::new(key)` | `Result<Csrf, Error>` | one keyed BLAKE3 per key, once |
| `csrf.issue(session)` | `Result<Token, Error>` | ≤ 300 ns; no allocation |
| `csrf.verify(session, token)` | `Verdict` = `Result<Verified, Rejected>` | ≤ 300 ns; no allocation, no lock |
| `csrf.check(&facts, session, token)` | `Verdict` | ≤ 350 ns; no allocation, no lock |

Costs are estimates until the `0.6.0` benchmarks replace them with measurements. "No allocation" is measured: a counting-allocator test (`tests/no_alloc.rs`) runs issue, verify, check, and every rejection path and asserts zero allocations.

`session` and `token` accept anything that is `AsRef<[u8]>`: `&str`, `String`, `&[u8]`, `Vec<u8>`, or a `&Token`. An empty token is reported as `Reason::Missing`; an empty session id can never pass (`Reason::Unverifiable`), because a token bound to nothing protects nothing.

`Csrf` is immutable, `Send + Sync`, and cheap to share behind an `Arc`. Nothing on the issue or verify path takes a lock or touches a shared counter.

## Tokens

```rust,ignore
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
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let csrf = csrf_sec::Csrf::new(*b"an example key, 32 bytes long!!!")?;
# let session_id = "session-1";
let token = csrf.issue(session_id)?;
let html = format!(r#"<input type="hidden" name="{}" value="{}">"#, csrf_sec::FIELD_NAME, token);
# assert!(html.contains(token.as_str()));
assert_eq!(format!("{token:?}"), "Token(59 chars)");
# Ok(())
# }
```

Every call to `issue` returns a different string for the same session: the token is masked with fresh randomness each time, so a compression side channel (BREACH) cannot recover it from pages. All of them verify. `Token` does not implement `PartialEq`, so it cannot be compared in variable time by accident; `Debug` prints `Token(59 chars)`, never the value.

## Bindings: session, scope, previous session

Tier 2 calls take a `Binding`, which says what the token is bound to:

```rust,ignore
pub struct Binding<'a> { /* borrowed */ }

impl<'a> Binding<'a> {
    pub fn new<S: AsRef<[u8]> + ?Sized>(session: &'a S) -> Self;
    pub fn scope<S: AsRef<[u8]> + ?Sized>(self, scope: &'a S) -> Self;
    pub fn previous_session<S: AsRef<[u8]> + ?Sized>(self, previous: &'a S) -> Self;
    pub fn once(self, store: &'a dyn NonceStore) -> Self;
}

impl Csrf {
    pub fn issue_with(&self, binding: &Binding<'_>) -> Result<Token, Error>;
    pub fn verify_with<T: AsRef<[u8]>>(&self, binding: &Binding<'_>, token: T) -> Verdict;
    pub fn check_with<T: AsRef<[u8]>>(&self, facts: &RequestFacts<'_>, binding: &Binding<'_>, token: T) -> Verdict;
}
```

- **Session.** The value every token is bound to: your session id, or any per-session secret. It goes into the MAC and never into the token, so the token reveals nothing about the session. Bind to the pre-login (guest) session on login forms, and issue a new token after login (T2, login CSRF).
- **Scope.** Binds a token to one action, for high-value forms:

  ```rust
  # use csrf_sec::{Binding, Csrf, Reason};
  # fn main() -> Result<(), Box<dyn std::error::Error>> {
  # let csrf = Csrf::new(*b"an example key, 32 bytes long!!!")?;
  # let session_id = "session-1";
  let change_email = Binding::new(session_id).scope("POST /account/email");
  let token = csrf.issue_with(&change_email)?;
  csrf.verify_with(&change_email, &token)?;

  let unscoped = csrf.issue(session_id)?;
  assert_eq!(csrf.verify_with(&change_email, &unscoped).unwrap_err().reason(), Reason::WrongScope);
  # Ok(())
  # }
  ```

  A token issued without a scope and presented to a scoped binding fails as `WrongScope`. A token issued for a different scope fails as `BadMac`: its scope is inside the MAC, so it cannot be told apart from a forgery.
- **Previous session.** Your session layer rotates the session id at login. Tabs opened before the login still hold tokens for the old id; pass it here for the short window your gates keep it, and those tokens fail as `StaleSession` (benign, severity 1) instead of `BadMac` (forgery, severity 40). A token bound to the previous session never passes.

  ```rust
  # use csrf_sec::{Binding, Csrf, Reason};
  # fn main() -> Result<(), Box<dyn std::error::Error>> {
  # let csrf = Csrf::new(*b"an example key, 32 bytes long!!!")?;
  let old_tab = csrf.issue("guest-session")?;
  let after_login = Binding::new("user-session").previous_session("guest-session");
  let refused = csrf.verify_with(&after_login, &old_tab).unwrap_err();
  assert_eq!(refused.reason(), Reason::StaleSession);
  # Ok(())
  # }
  ```
- **Once.** Makes the token one-time; see [One-time tokens](#one-time-tokens).

Cost of a scope or previous session: only failing tokens pay for the extra MACs used to tell the reasons apart, at most two extra keyed BLAKE3 calls [est. ~60 ns each], so verify work stays fixed and bounded.

## Request policy (layer 1)

### `RequestFacts`

```rust,ignore
pub struct RequestFacts<'a> { /* borrowed */ }

impl<'a> RequestFacts<'a> {
    pub fn new<M: AsRef<[u8]> + ?Sized>(method: &M) -> Self;          // classifies the method
    pub const fn with_class(class: MethodClass) -> Self;
    pub fn fetch_site<V: AsRef<[u8]> + ?Sized>(self, value: &V) -> Self;     // Sec-Fetch-Site
    pub fn origin<V: AsRef<[u8]> + ?Sized>(self, value: &'a V) -> Self;      // Origin
    pub fn referer<V: AsRef<[u8]> + ?Sized>(self, value: &'a V) -> Self;     // Referer (full URL)
    pub fn own_origin<V: AsRef<[u8]> + ?Sized>(self, value: &'a V) -> Self;  // this site, e.g. "https://example.com"
    pub const fn method(&self) -> MethodClass;
}

#[non_exhaustive]
pub enum MethodClass { Safe, Unsafe }
impl MethodClass { pub const fn classify(method: &[u8]) -> MethodClass; }

#[non_exhaustive]
pub enum FetchSite { SameOrigin, SameSite, CrossSite, None }
impl FetchSite { pub fn parse(value: &[u8]) -> Option<FetchSite>; }
```

The adapter fills only what the request carried. Values are raw header bytes; nothing needs to be decoded first. An empty value counts as absent.

- Methods are classified case-sensitively: exactly `GET`, `HEAD`, and `OPTIONS` are safe; everything else, including `get`, `TRACE`, and unknown methods, is unsafe. A handler that changes state must be reached only through an unsafe method (T13); csrf-sec cannot see your routes, so this is your router's contract.
- `Sec-Fetch-Site` values other than the four defined ones are treated as absent, never as same-origin. Surrounding spaces and tabs are ignored.

### The decision

```text
 safe method                                   -> pass (no token needed)
 Sec-Fetch-Site: same-origin | none            -> pass
 Sec-Fetch-Site: same-site                     -> pass if allow_same_site, or Origin is allowed; else CrossSite
 Sec-Fetch-Site: cross-site                    -> pass if Origin is allowed; else CrossSite
 no Fetch Metadata, Origin present             -> "null" or no match: OriginMismatch; match: pass
 no Fetch Metadata, no Origin, Referer present -> its origin matches: pass; else OriginMismatch
 nothing at all                                -> the token decides (Strict), Unverifiable (PolicyOnly)
```

An origin is allowed when it equals `own_origin` or an origin added with `Builder::allow_origin`: scheme and host compared ASCII case-insensitively, default ports (`:80` for http and ws, `:443` for https and wss) normalized, anything that is not a well-formed serialized origin refused. A `Referer` with user information (`https://a@b/`) never matches. When nothing is configured to compare against (no `own_origin`, no allowlist), an `Origin` or `Referer` cannot be judged and the token decides, except that `null` and malformed values are still refused. Values longer than 4 KiB never match. Cost [est.]: ≤ 50 ns, no allocation.

```rust
# use csrf_sec::{Csrf, OriginCheck, Reason, RequestFacts};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let csrf = Csrf::new(*b"an example key, 32 bytes long!!!")?;
let attack = RequestFacts::new("POST")
    .fetch_site("cross-site")
    .origin("https://evil.example")
    .own_origin("https://example.com");
assert_eq!(csrf.policy(&attack).unwrap_err().reason(), Reason::CrossSite);

let old_browser = RequestFacts::new("POST")
    .origin("https://example.com")
    .own_origin("https://example.com");
assert_eq!(csrf.policy(&old_browser)?, OriginCheck::Origin);
# Ok(())
# }
```

`Csrf::policy(&facts) -> Result<OriginCheck, Rejected>` runs layer 1 alone, whatever the mode. `OriginCheck` says what it found:

| `OriginCheck` | Meaning |
|---|---|
| `NotRun` | the policy was not run (token-only calls, `TokenOnly` mode) |
| `SafeMethod` | `GET`, `HEAD`, `OPTIONS`: nothing to check |
| `FetchMetadata` | passed on `Sec-Fetch-Site` |
| `Origin` | passed on the `Origin` header |
| `Referer` | passed on the origin of the `Referer` header |
| `NoFacts` | the request carried no origin facts; the token decided |

### Modes

| Mode | An unsafe request passes when | Use |
|---|---|---|
| `Mode::Strict` (default) | layer 1 does not refuse **and** the token verifies | browsers, the normal case |
| `Mode::TokenOnly` | the token verifies | clients that send no browser headers |
| `Mode::PolicyOnly` | `Sec-Fetch-Site` was sent and layer 1 passes | endpoints called only from modern browsers, with no forms; never the default |

In `Strict`, layer 1 runs first and a refusal returns at once, before any token work. In every mode, safe methods pass without a token.

## Keys, the builder, and rotation

```rust,ignore
pub struct KeyId(pub u8);

impl Csrf {
    pub fn builder() -> Builder;
    pub fn rotated(&self, id: KeyId, key: [u8; 32]) -> Result<Csrf, Error>;          // std
    pub fn rotated_at(&self, id: KeyId, key: [u8; 32], now: u64) -> Result<Csrf, Error>;
    pub fn signing_key(&self) -> KeyId;
    pub fn accepts(&self, id: KeyId) -> bool;                                          // std
    pub fn accepts_at(&self, id: KeyId, now: u64) -> bool;
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
use std::time::Duration;
use csrf_sec::{Csrf, KeyId, Mode};
# fn main() -> Result<(), csrf_sec::Error> {
# let (current_key, old_key) = (*b"current key, 32 bytes long!!!!!!", *b"previous key, 32 bytes long!!!!!");
# let retire_at = 1_900_000_000;

let csrf = Csrf::builder()
    .key(KeyId(3), current_key)
    .retired(KeyId(2), old_key, retire_at)
    .lifetime(Duration::from_secs(12 * 3600))
    .skew(Duration::from_secs(60))
    .mode(Mode::Strict)
    .allow_origin("https://example.com")
    .allow_same_site(false)
    .build()?;
# assert_eq!(csrf.signing_key(), KeyId(3));
# Ok(())
# }
```

- **Keys are 32 bytes and must be persisted** (or derived from a persisted master, for example a key-vault secret through HKDF). A key generated at boot makes every open form fail after a restart. Keys whose bytes are all equal (an unset buffer) are refused.
- csrf-sec never MACs with your key directly: it derives one subkey per key id at construction, keeps only that, and wipes it when the `Csrf` is dropped. The key bytes handed to the builder are wiped when the builder is dropped.
- **Rotation on one node:** `csrf.rotated(KeyId(4), new_key)?` returns a new `Csrf` that signs with key 4 and keeps the old signing key as retired until one token lifetime plus skew from now. Swap it in; nobody is logged out and no open form fails.
- **Rotation across a cluster, in two steps:** first deploy the new key everywhere with `.accept(id, key)` (verify only); once every node has it, make it the signing key with `.key(id, key)` and move the old one to `.retired(..)`. A node never receives a token signed with a key it does not know. On a node built with the accepted key, `rotated(id, same_key)` promotes it.
- Key ids are never reused while tokens signed under them can still be presented: the builder and `rotated` refuse an id still in use. Up to `MAX_KEYS` (16) keys at once.

```rust
# use csrf_sec::{Csrf, KeyId};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let csrf = Csrf::new(*b"first key, thirty-two bytes long")?;
let token = csrf.issue("session-1")?;

let csrf = csrf.rotated(KeyId(1), *b"second key, 32 bytes long......!")?;
let passed = csrf.verify("session-1", &token)?;
assert!(passed.retired_key());            // still valid: signed by the retired key
assert_eq!(csrf.signing_key(), KeyId(1));
# Ok(())
# }
```

## One-time tokens

For actions where a token must not be usable twice (a payment, deleting an account):

```rust
use csrf_sec::{Binding, Csrf, MemoryStore, Reason};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let csrf = Csrf::new(*b"an example key, 32 bytes long!!!")?;
# let session_id = "session-1";

let store = MemoryStore::new(100_000);
let pay = Binding::new(session_id).scope("POST /pay").once(&store);

let token = csrf.issue_with(&pay)?;          // 102 characters
# let submitted = token.as_str();
csrf.verify_with(&pay, submitted)?;          // passes once
assert_eq!(csrf.verify_with(&pay, submitted).unwrap_err().reason(), Reason::AlreadyUsed);
# Ok(())
# }
```

A one-time token is a signed token with a 128-bit random nonce inside the MAC (format version 2, its own subkey); the store holds the outstanding nonces. **The MAC, lifetime, and scope are checked before the store is touched**, so forged requests never reach the store: they cannot burn a user's token and cannot load a shared store. A one-time binding always checks the token, whatever the mode.

```rust,ignore
pub trait NonceStore {
    fn insert(&self, session: &[u8], nonce: &[u8; 16], now: u64, expires_at: u64) -> Result<(), StoreError>;
    fn take(&self, session: &[u8], nonce: &[u8; 16], now: u64) -> Result<bool, StoreError>;
}

#[non_exhaustive]
pub enum StoreError { Unavailable, Full }

pub struct MemoryStore { /* feature `std` */ }
impl MemoryStore {
    pub fn new(capacity: usize) -> Self;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn purge_expired(&self, now: u64);
}
```

The store contract:

- `insert` records the nonce until `expires_at` (issue time plus lifetime, unix seconds, inclusive). `now` is the issue time, for stores that purge.
- `take` **atomically** removes the record and returns `true` only if it existed and had not expired. Two concurrent `take` calls for one nonce must not both return `true`.
- A `StoreError` fails closed: no token on issue (`Error::Store`), a refusal on verify (`Reason::StoreUnavailable`).
- Nonces are random values csrf-sec generated, never chosen by a client.

`MemoryStore` serves one node and tests: 64 shards, each behind its own short-held lock; at most `capacity / 64` (rounded up) nonces per shard; a full shard drops expired entries and otherwise refuses to issue (`StoreError::Full`) rather than forgetting an outstanding token. About 40 bytes per outstanding nonce [est.]. Its nonces live in this process only: for a cluster, implement `NonceStore` over a store every node reaches (WASP: the gates' session store).

```rust
use std::{collections::HashSet, sync::Mutex};
use csrf_sec::{NonceStore, StoreError};

struct Simple(Mutex<HashSet<[u8; 16]>>);

impl NonceStore for Simple {
    fn insert(&self, _session: &[u8], nonce: &[u8; 16], _now: u64, _expires_at: u64)
        -> Result<(), StoreError> {
        self.0.lock().map_err(|_| StoreError::Unavailable)?.insert(*nonce);
        Ok(())
    }
    fn take(&self, _session: &[u8], nonce: &[u8; 16], _now: u64) -> Result<bool, StoreError> {
        Ok(self.0.lock().map_err(|_| StoreError::Unavailable)?.remove(nonce))
    }
}
```

Cost: one store round trip on issue and on a verify whose MAC passed, plus the normal issue and verify. One-time tokens are the one stateful feature; session tokens never touch a store.

## Tier 3: explicit time and randomness

The core works without `std` (it needs `alloc`). Time is passed in as unix seconds, and randomness comes from a `PadSource` you supply:

```rust,ignore
pub trait PadSource {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error>;
}

pub struct OsPads;      // feature `std`: per-thread buffer refilled in bulk from the OS CSPRNG

impl Csrf {
    pub fn issue_at<P: PadSource + ?Sized>(&self, binding: &Binding<'_>, now: u64, pads: &mut P) -> Result<Token, Error>;
    pub fn verify_at(&self, binding: &Binding<'_>, token: &[u8], now: u64) -> Verdict;
    pub fn check_at(&self, facts: &RequestFacts<'_>, binding: &Binding<'_>, token: &[u8], now: u64) -> Verdict;
    pub fn policy(&self, facts: &RequestFacts<'_>) -> Result<OriginCheck, Rejected>;
}
```

```rust
# use csrf_sec::{Binding, Csrf, OsPads, Reason};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let csrf = Csrf::new(*b"an example key, 32 bytes long!!!")?;
let now = 1_800_000_000; // unix seconds, from your clock
let binding = Binding::new("session-1");
let token = csrf.issue_at(&binding, now, &mut OsPads)?;
csrf.verify_at(&binding, token.as_bytes(), now + 60)?;

let much_later = now + 13 * 3600;          // past the 12-hour default lifetime
let refused = csrf.verify_at(&binding, token.as_bytes(), much_later).unwrap_err();
assert_eq!(refused.reason(), Reason::Expired);
# Ok(())
# }
```

A `PadSource` must be a cryptographically secure generator. The pad travels with the token, but it must not be predictable before the response is built: a predictable pad lets a compression attack recover the token again. Tier 1 and Tier 2 use `OsPads` and the system clock.

`OsPads` keeps a 2 KiB buffer per thread, refilled in bulk from the OS generator through `mod-rand` (about 90 pads per system call), takes no lock, and wipes the buffer when the thread exits. After a `fork` without `exec`, parent and child would share the unused part of the buffer; `OsPads::refill()` discards it.

## Verdicts and reasons

```rust,ignore
pub type Verdict = Result<Verified, Rejected>;

impl Verified {
    pub const fn key_id(&self) -> Option<KeyId>;      // None when no token was checked
    pub const fn retired_key(&self) -> bool;          // signed by a retired key (rotation in progress)
    pub const fn token_checked(&self) -> bool;
    pub const fn origin_check(&self) -> OriginCheck;
}

impl Rejected {
    pub const fn reason(&self) -> Reason;
    pub const fn severity(&self) -> u8;
}
// Display ("request forgery check failed: bad_mac"), core::error::Error.

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
| `AlreadyUsed` | `already_used` | a one-time token presented again, or its record expired | 20 |
| `StoreUnavailable` | `store_unavailable` | the one-time store could not answer | 5 |

The reason is decided **after** the MAC: a forged token is never reported as expired, and an expired real token is never reported as forged. Reasons are for logs and scoring (sentinel-sec, bouncer-io); clients get a generic refusal (HTTP 403). A token signed by a retired key passes, with `retired_key()` set.

```rust
# use csrf_sec::{Csrf, Reason};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let csrf = Csrf::new(*b"an example key, 32 bytes long!!!")?;
# let token = csrf.issue("session-1")?;
match csrf.verify("session-2", &token) {
    Ok(_) => unreachable!(),
    Err(refused) => {
        assert_eq!(refused.reason(), Reason::BadMac);
        assert_eq!(refused.severity(), 40);
        assert_eq!(refused.to_string(), "request forgery check failed: bad_mac");
    }
}
# Ok(())
# }
```

## Errors

```rust,ignore
#[non_exhaustive]
pub enum Error {
    WeakKey(KeyId),          // key bytes all equal
    DuplicateKeyId(KeyId),   // id still in use in the ring
    NoSigningKey,            // builder without .key(..)
    MultipleSigningKeys,     // .key(..) given twice
    TooManyKeys,             // more than MAX_KEYS
    InvalidLifetime,         // under 1 second, or over u32::MAX seconds
    InvalidSkew,             // longer than the lifetime
    InvalidOrigin,           // allow_origin value is not a serialized origin, or is "null"
    EmptySession,            // issue with an empty session id
    Clock,                   // clock outside 2020-01-01 .. 2156-02-07
    Random,                  // the CSPRNG failed; no token is issued
    Store(StoreError),       // the one-time store refused the nonce; no token is issued
}
// Display (says what to do), core::error::Error, Clone, Copy, PartialEq, Eq.
```

`issue` is fallible on purpose: if randomness or the clock fails, no token is minted (fail closed) and nothing panics.

```rust
# use csrf_sec::{Csrf, Error, KeyId};
assert_eq!(Csrf::new([0u8; 32]).unwrap_err(), Error::WeakKey(KeyId(0)));
assert_eq!(Csrf::builder().build().unwrap_err(), Error::NoSigningKey);
```

## Constants

| Constant | Value | Meaning |
|---|---|---|
| `VERSION` | `env!("CARGO_PKG_VERSION")` | crate version |
| `TOKEN_LEN` | 59 | session token text length |
| `ONCE_TOKEN_LEN` | 102 | one-time token text length |
| `NONCE_LEN` | 16 | one-time token nonce length in bytes |
| `KEY_LEN` | 32 | key length in bytes |
| `MAX_KEYS` | 16 | keys a ring holds at once |
| `FIELD_NAME` | `"csrf_token"` | suggested hidden form field name |
| `HEADER_NAME` | `"x-csrf-token"` | suggested request header name |
| `DEFAULT_LIFETIME` | 12 hours | token lifetime |
| `DEFAULT_SKEW` | 60 seconds | tolerated clock difference between nodes |

## Feature flags

| Feature | Default | Adds |
|---|---|---|
| `std` | yes | Tier 1 and Tier 2 calls (system clock, `OsPads`), `rotated`, `accepts`, `MemoryStore`; implies `alloc` |
| `alloc` | via `std` | `From<Token> for String` |

With `default-features = false` the crate is `no_std` and needs an allocator (crypt-io does); the `_at` calls, `policy`, `rotated_at`, and `accepts_at` are available, and the verify path still allocates nothing.

## Cookie guidance

csrf-sec does not set cookies; cookie-net does. For the session cookie that tokens are bound to:

- `__Host-` prefix (forces `Secure`, `Path=/`, and no `Domain`, so a sibling subdomain cannot plant or overwrite it),
- `SameSite=Lax` (or `Strict` where cross-site links into signed-in pages are not needed),
- `Secure` and `HttpOnly`.

Tokens are not compared to a cookie (they are not double-submit tokens), so cookie tossing from a subdomain cannot defeat them (T7).

## Token format

Little-endian integers throughout.

```text
 raw session token (22 bytes):   version=1 (1) | key id (1) | issued at (4) | tag (16)
 raw one-time token (38 bytes):  version=2 (1) | key id (1) | issued at (4) | nonce (16) | tag (16)
 issued at:                      seconds since 2020-01-01T00:00:00Z

 MAC input:  version | key id | issued at | [nonce] | varint(len session) | varint(len scope) | session | scope
 tag:        first 16 bytes of keyed BLAKE3(subkey, MAC input)
 subkey:     keyed BLAKE3(application key, label | key id), derived once
 labels:     "csrf-sec/v1 session-token mac key", "csrf-sec/v1 one-time-token mac key"

 masked:     pad (len raw) | raw XOR pad           pad: fresh CSPRNG bytes per issue
 text:       base64url, no padding, canonical      59 or 102 characters
 one-time:   the nonce is drawn from the PadSource before the pad
```

Lengths are LEB128 varints, so the encoding is canonical for any length and short inputs (a 43-character session id with no scope) fit in one 64-byte BLAKE3 block. Decoding is constant time and accepts only canonical text: any change to any character of a token makes it fail. `tests/tokens.rs` and `tests/once.rs` rebuild both formats from this description with crypt-io directly and compare them byte for byte with what the crate issues.
