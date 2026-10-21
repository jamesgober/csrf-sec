//! # csrf_sec
//!
//! Request-forgery protection for Rust services: signed, session-bound tokens masked per response, plus Fetch Metadata and Origin policy. Stateless, protocol-free, no allocation on verify.
//!
//! ## Status
//!
//! Design lock. The public API and the token format are written down in
//! `docs/API.md`, the design and decisions in `dev/PLAN.md`, and the
//! milestone schedule in `dev/ROADMAP.md` (all in the
//! [repository](https://github.com/jamesgober/csrf-sec)); code lands from
//! `0.3.0`.

#![doc(html_root_url = "https://docs.rs/csrf-sec")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
