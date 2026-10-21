//! # csrf_sec
//!
//! Request-forgery protection for Rust services: signed, session-bound tokens
//! masked per response, plus Fetch Metadata and Origin policy. Stateless,
//! protocol-free, no allocation on verify.
//!
//! csrf-sec answers one question for every state-changing request: **did this
//! request come from our own page, for this session?** It answers with
//! independent checks, so one failing defence does not open the door:
//!
//! 1. **Request origin policy.** Browsers send `Sec-Fetch-Site` and `Origin`
//!    on unsafe requests, and an attacker's page cannot set either. A
//!    cross-site unsafe request is refused before any token work.
//! 2. **A signed, session-bound token.** Keyed BLAKE3 over the session id
//!    (and optionally a scope), masked with fresh randomness on every
//!    response so a compression side channel (BREACH) cannot recover it.
//! 3. **Cookie guidance** for the session cookie (`__Host-`, `SameSite`),
//!    applied by your cookie layer.
//!
//! It never parses HTTP: your adapter hands it the session id, the submitted
//! token, and the request's origin facts as plain values. Any node holding the
//! key ring verifies any token; there is nothing to store or replicate.
//!
//! ## Tier 1
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use csrf_sec::{Csrf, RequestFacts};
//!
//! # let key = *b"an example key, 32 bytes long!!!";
//! let csrf = Csrf::new(key)?; // a persisted 32-byte secret
//!
//! // Rendering a form: 59 characters, different on every call.
//! let token = csrf.issue("session-id")?;
//!
//! // Handling the POST: request policy and token.
//! let facts = RequestFacts::new("POST")
//!     .fetch_site("same-origin")
//!     .origin("https://example.com")
//!     .own_origin("https://example.com");
//! csrf.check(&facts, "session-id", &token)?;
//!
//! // Token only, for clients that send no browser headers:
//! csrf.verify("session-id", &token)?;
//! # Ok(())
//! # }
//! ```
//!
//! A refusal is a [`Rejected`] with a [`Reason`] and a severity hint for logs
//! and scoring; send the client a generic 403.
//!
//! ## Tier 2
//!
//! A [`Binding`] adds a scope (one action), the previous session id, or a
//! [`NonceStore`] for one-time tokens, and [`Csrf::builder`] configures keys,
//! rotation, lifetime, skew, [`Mode`], and allowed origins.
//!
//! ## Tier 3
//!
//! The `_at` calls take the time and the randomness source explicitly and
//! work without `std` (with `alloc`).
//!
//! ## Cost
//!
//! Issue and verify are each one keyed BLAKE3 compression, a fixed-length
//! constant-time base64url pass, and a 16-byte constant-time compare: 112 ns
//! and 110 ns (measured, Linux, Ryzen 9 9950X3D; the Tier 1 calls add a clock
//! read), no allocation, no lock. The request policy is byte comparisons on
//! values the adapter already has: 1.3 ns on Fetch Metadata. Every number is
//! in `docs/PERFORMANCE.md`.
//!
//! ## What it does not stop
//!
//! Cross-site scripting defeats every CSRF defence, because script on the page
//! can read the token: that is stopped by output encoding and a content
//! security policy. Clickjacking is stopped by `frame-ancestors`.
//!
//! ## Cookie guidance
//!
//! Give the session cookie the `__Host-` prefix (so a sibling subdomain cannot
//! plant or overwrite it), `SameSite=Lax` (or `Strict`), `Secure`, and
//! `HttpOnly`. Tokens are not compared to a cookie, so cookie tossing cannot
//! defeat them.

#![doc(html_root_url = "https://docs.rs/csrf-sec")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

mod b64;
mod binding;
mod csrf;
mod error;
mod key;
mod once;
mod pad;
mod policy;
mod token;
mod verdict;

pub use crate::{
    binding::Binding,
    csrf::{Builder, Csrf, DEFAULT_LIFETIME, DEFAULT_SKEW},
    error::Error,
    key::{KEY_LEN, KeyFingerprint, KeyId, KeyInfo, KeyRole, MAX_KEYS},
    once::{NONCE_LEN, NonceStore, NonceUse, ONCE_TOKEN_LEN, StoreError},
    pad::PadSource,
    policy::{FetchSite, MethodClass, Mode, RequestFacts},
    token::{TOKEN_LEN, Token},
    verdict::{OriginCheck, Reason, Rejected, Verdict, Verified},
};

#[cfg(feature = "std")]
pub use crate::{once::MemoryStore, pad::OsPads};

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Suggested name of the hidden form field that carries the token.
pub const FIELD_NAME: &str = "csrf_token";

/// Suggested name of the request header that carries the token (for
/// `fetch` and XHR callers).
pub const HEADER_NAME: &str = "x-csrf-token";

/// Compiles and runs every `rust` example in `docs/API.md`, so the reference
/// cannot drift from the build.
#[cfg(all(doctest, feature = "std"))]
#[doc = include_str!("../docs/API.md")]
struct ApiReference;

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
