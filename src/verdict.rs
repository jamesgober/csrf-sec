//! Verdicts: what a check decided, and why a request was refused.

use core::fmt;

use crate::key::KeyId;

/// The result of every verify and check call.
///
/// `Ok` carries what passed; `Err` carries why the request was refused. Use
/// `?` to refuse: the reason is for logs and scoring, and the client should
/// get a generic refusal (HTTP 403).
pub type Verdict = Result<Verified, Rejected>;

/// Why a request was refused.
///
/// The reason is decided after the MAC: a forged token is never reported as
/// expired, and an expired real token is never reported as forged.
/// [`severity`](Self::severity) is a hint for detection and scoring (0 to 40).
///
/// ```
/// use csrf_sec::Reason;
///
/// assert_eq!(Reason::BadMac.severity(), 40);
/// assert_eq!(Reason::Expired.as_str(), "expired");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Reason {
    /// No token was submitted: a client bug, or a forged form without one.
    Missing,
    /// The token has the wrong length, is not canonical base64url, or has an
    /// unknown format version: tampering or truncation.
    Malformed,
    /// The token names a key the ring does not hold (or no longer accepts): a
    /// very old token, or tampering.
    UnknownKey,
    /// The MAC does not verify for this session (and scope): a forgery, or a
    /// token from another session.
    BadMac,
    /// The token was issued for the previous session id: the user signed in
    /// again in another tab. Benign, but never accepted.
    StaleSession,
    /// The token is older than the lifetime: an old tab.
    Expired,
    /// The token was issued further in the future than the skew allows: a
    /// node clock ahead of this one.
    NotYetValid,
    /// A token issued without a scope was presented to a scoped binding.
    WrongScope,
    /// Fetch Metadata says the unsafe request came from another site (or a
    /// sibling subdomain the policy does not allow).
    CrossSite,
    /// The `Origin` (or `Referer`) of the unsafe request is not allowed, or is
    /// `null`.
    OriginMismatch,
    /// The check cannot run: no session id was given, or `PolicyOnly` mode
    /// got a request without Fetch Metadata.
    Unverifiable,
    /// A one-time token was presented again (or the store cannot vouch that
    /// it was not, for example after a restart).
    AlreadyUsed,
    /// The one-time token store could not answer.
    StoreUnavailable,
}

impl Reason {
    /// Severity hint for detection and scoring, from 0 (benign) to 40
    /// (forgery).
    ///
    /// | Reason | Severity |
    /// |---|---|
    /// | `BadMac` | 40 |
    /// | `CrossSite`, `OriginMismatch` | 30 |
    /// | `WrongScope`, `AlreadyUsed` | 20 |
    /// | `Malformed` | 10 |
    /// | `Missing`, `UnknownKey`, `NotYetValid`, `Unverifiable`, `StoreUnavailable` | 5 |
    /// | `StaleSession`, `Expired` | 1 |
    #[must_use]
    pub const fn severity(self) -> u8 {
        match self {
            Self::BadMac => 40,
            Self::CrossSite | Self::OriginMismatch => 30,
            Self::WrongScope | Self::AlreadyUsed => 20,
            Self::Malformed => 10,
            Self::Missing
            | Self::UnknownKey
            | Self::NotYetValid
            | Self::Unverifiable
            | Self::StoreUnavailable => 5,
            Self::StaleSession | Self::Expired => 1,
        }
    }

    /// A stable, lowercase name for logs and metrics, such as `bad_mac`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Malformed => "malformed",
            Self::UnknownKey => "unknown_key",
            Self::BadMac => "bad_mac",
            Self::StaleSession => "stale_session",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::WrongScope => "wrong_scope",
            Self::CrossSite => "cross_site",
            Self::OriginMismatch => "origin_mismatch",
            Self::Unverifiable => "unverifiable",
            Self::AlreadyUsed => "already_used",
            Self::StoreUnavailable => "store_unavailable",
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refused request.
///
/// `Display` reads `request forgery check failed: <reason>`, which is fine for
/// logs. Do not send the reason to the client.
///
/// ```
/// # fn main() -> Result<(), csrf_sec::Error> {
/// use csrf_sec::{Csrf, Reason};
///
/// let csrf = Csrf::new(*b"an example key, 32 bytes long!!!")?;
/// let refused = csrf.verify("session-1", "not a token").unwrap_err();
/// assert_eq!(refused.reason(), Reason::Malformed);
/// assert_eq!(refused.to_string(), "request forgery check failed: malformed");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rejected {
    reason: Reason,
}

impl Rejected {
    #[inline]
    pub(crate) const fn new(reason: Reason) -> Self {
        Self { reason }
    }

    /// Why the request was refused.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        self.reason
    }

    /// The reason's severity hint (see [`Reason::severity`]).
    #[must_use]
    pub const fn severity(&self) -> u8 {
        self.reason.severity()
    }
}

impl From<Reason> for Rejected {
    fn from(reason: Reason) -> Self {
        Self::new(reason)
    }
}

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "request forgery check failed: {}", self.reason)
    }
}

impl core::error::Error for Rejected {}

/// What the request origin policy (layer 1) found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OriginCheck {
    /// The policy was not run (token-only calls and `TokenOnly` mode).
    NotRun,
    /// A safe method (`GET`, `HEAD`, `OPTIONS`): nothing to check.
    SafeMethod,
    /// Passed on `Sec-Fetch-Site`.
    FetchMetadata,
    /// Passed on the `Origin` header.
    Origin,
    /// Passed on the origin of the `Referer` header.
    Referer,
    /// The request carried no origin facts; the token decided.
    NoFacts,
}

/// A request that passed.
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use csrf_sec::{Csrf, KeyId};
///
/// let csrf = Csrf::new(*b"an example key, 32 bytes long!!!")?;
/// let token = csrf.issue("session-1")?;
/// let ok = csrf.verify("session-1", &token)?;
/// assert_eq!(ok.key_id(), Some(KeyId(0)));
/// assert!(ok.token_checked());
/// assert!(!ok.retired_key());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Verified {
    key_id: Option<KeyId>,
    retired_key: bool,
    origin_check: OriginCheck,
}

impl Verified {
    /// A pass on a token signed by `key_id`.
    #[inline]
    pub(crate) const fn token(key_id: KeyId, retired_key: bool) -> Self {
        Self {
            key_id: Some(key_id),
            retired_key,
            origin_check: OriginCheck::NotRun,
        }
    }

    /// A pass on the request policy alone (no token needed or checked).
    #[inline]
    pub(crate) const fn policy(origin_check: OriginCheck) -> Self {
        Self {
            key_id: None,
            retired_key: false,
            origin_check,
        }
    }

    /// The same pass, with the policy result attached.
    #[inline]
    pub(crate) const fn with_origin_check(mut self, origin_check: OriginCheck) -> Self {
        self.origin_check = origin_check;
        self
    }

    /// The key that signed the token, or `None` when no token was checked.
    #[must_use]
    pub const fn key_id(&self) -> Option<KeyId> {
        self.key_id
    }

    /// `true` when the token was signed by a retired key: it passed, and the
    /// rotation that retired the key is still within one token lifetime.
    #[must_use]
    pub const fn retired_key(&self) -> bool {
        self.retired_key
    }

    /// `true` when a token was verified.
    #[must_use]
    pub const fn token_checked(&self) -> bool {
        self.key_id.is_some()
    }

    /// What the request origin policy found.
    #[must_use]
    pub const fn origin_check(&self) -> OriginCheck {
        self.origin_check
    }
}

#[cfg(test)]
mod tests {
    use super::{OriginCheck, Reason, Rejected, Verified};
    use crate::KeyId;

    const ALL: [Reason; 13] = [
        Reason::Missing,
        Reason::Malformed,
        Reason::UnknownKey,
        Reason::BadMac,
        Reason::StaleSession,
        Reason::Expired,
        Reason::NotYetValid,
        Reason::WrongScope,
        Reason::CrossSite,
        Reason::OriginMismatch,
        Reason::Unverifiable,
        Reason::AlreadyUsed,
        Reason::StoreUnavailable,
    ];

    #[test]
    fn test_reason_severity_matches_plan_table() {
        let expected = [5, 10, 5, 40, 1, 1, 5, 20, 30, 30, 5, 20, 5];
        for (r, s) in ALL.iter().zip(expected) {
            assert_eq!(r.severity(), s, "{r:?}");
        }
    }

    #[test]
    fn test_reason_as_str_unique_snake_case() {
        for (i, a) in ALL.iter().enumerate() {
            let s = a.as_str();
            assert!(
                s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{s}"
            );
            assert_eq!(a.to_string(), s);
            for b in &ALL[..i] {
                assert_ne!(s, b.as_str());
            }
        }
    }

    #[test]
    fn test_rejected_display_and_severity() {
        let r = Rejected::from(Reason::CrossSite);
        assert_eq!(r.reason(), Reason::CrossSite);
        assert_eq!(r.severity(), 30);
        assert_eq!(r.to_string(), "request forgery check failed: cross_site");
    }

    #[test]
    fn test_verified_constructors() {
        let t = Verified::token(KeyId(7), true);
        assert_eq!(t.key_id(), Some(KeyId(7)));
        assert!(t.retired_key() && t.token_checked());
        assert_eq!(t.origin_check(), OriginCheck::NotRun);
        let t = t.with_origin_check(OriginCheck::Origin);
        assert_eq!(t.origin_check(), OriginCheck::Origin);
        let p = Verified::policy(OriginCheck::SafeMethod);
        assert_eq!(p.key_id(), None);
        assert!(!p.token_checked() && !p.retired_key());
    }
}
