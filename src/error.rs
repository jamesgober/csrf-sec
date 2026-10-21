//! Errors from building a [`Csrf`](crate::Csrf) and from issuing tokens.
//!
//! Verification never returns an [`Error`]; it returns a
//! [`Rejected`](crate::Rejected) with a [`Reason`](crate::Reason).

use core::fmt;

use crate::key::KeyId;

/// Why a [`Csrf`](crate::Csrf) could not be built, rotated, or could not issue
/// a token.
///
/// Every message says what to change. Nothing secret is ever included.
///
/// ```
/// use csrf_sec::{Csrf, Error};
///
/// assert_eq!(Csrf::new([0u8; 32]).unwrap_err(), Error::WeakKey(csrf_sec::KeyId(0)));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The key's 32 bytes are all equal (for example an unset, zeroed
    /// buffer). Load the real key.
    WeakKey(KeyId),
    /// The key id is already in the ring. Key ids must not be reused while
    /// tokens signed under them can still be presented.
    DuplicateKeyId(KeyId),
    /// The builder has no signing key. Add one with
    /// [`Builder::key`](crate::Builder::key).
    NoSigningKey,
    /// The builder was given more than one signing key. Use
    /// [`Builder::accept`](crate::Builder::accept) or
    /// [`Builder::retired`](crate::Builder::retired) for the others.
    MultipleSigningKeys,
    /// The ring would hold more than [`MAX_KEYS`](crate::MAX_KEYS) keys.
    /// Drop retired keys whose tokens have expired.
    TooManyKeys,
    /// The lifetime is under one second or over `u32::MAX` seconds.
    InvalidLifetime,
    /// The skew is longer than the lifetime.
    InvalidSkew,
    /// An allowed origin is not a serialized origin such as
    /// `https://example.com`, or is `null`.
    InvalidOrigin,
    /// A token cannot be bound to an empty session id: it would be valid for
    /// every visitor. Bind to the guest session before login.
    EmptySession,
    /// A retired key's retire time is past 2156, beyond any token's reach:
    /// most likely a time in milliseconds where seconds were meant.
    InvalidRetireTime,
    /// The clock reads outside 2020-01-01 to 2156-02-07, which a token cannot
    /// represent. Fix the system clock; no token was issued.
    Clock,
    /// The operating system's random generator failed. No token was issued.
    Random,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WeakKey(id) => write!(
                f,
                "key {} has all 32 bytes equal; load the real key",
                id.0
            ),
            Self::DuplicateKeyId(id) => write!(
                f,
                "key id {} is already in the ring; use a new id",
                id.0
            ),
            Self::NoSigningKey => f.write_str("no signing key; add one with Builder::key"),
            Self::MultipleSigningKeys => f.write_str(
                "more than one signing key; add the others with Builder::accept or Builder::retired",
            ),
            Self::TooManyKeys => write!(
                f,
                "more than {} keys in the ring; drop expired retired keys",
                crate::MAX_KEYS
            ),
            Self::InvalidLifetime => {
                f.write_str("token lifetime must be at least 1 second and at most u32::MAX seconds")
            }
            Self::InvalidSkew => f.write_str("clock skew must not be longer than the token lifetime"),
            Self::InvalidOrigin => f.write_str(
                "allowed origin must be a serialized origin such as https://example.com, not null",
            ),
            Self::EmptySession => f.write_str("cannot bind a token to an empty session id"),
            Self::InvalidRetireTime => f.write_str(
                "retire time is past 2156; give it in unix seconds, not milliseconds",
            ),
            Self::Clock => {
                f.write_str("system clock is outside 2020-01-01 to 2156-02-07; no token was issued")
            }
            Self::Random => f.write_str("the OS random generator failed; no token was issued"),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::Error;
    use crate::KeyId;

    #[test]
    fn test_error_display_every_variant_is_actionable_and_secret_free() {
        let all = [
            Error::WeakKey(KeyId(1)),
            Error::DuplicateKeyId(KeyId(2)),
            Error::NoSigningKey,
            Error::MultipleSigningKeys,
            Error::TooManyKeys,
            Error::InvalidLifetime,
            Error::InvalidSkew,
            Error::InvalidOrigin,
            Error::EmptySession,
            Error::InvalidRetireTime,
            Error::Clock,
            Error::Random,
        ];
        for e in all {
            let text = e.to_string();
            assert!(text.len() > 10, "{e:?}");
            assert!(!text.contains('\n'));
        }
    }
}
