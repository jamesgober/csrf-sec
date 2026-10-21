//! What a token is bound to.

use core::fmt;

use crate::once::NonceStore;

/// What a token is bound to: a session id, and optionally a scope and the
/// previous session id.
///
/// Tier 2 and Tier 3 calls take a `Binding`; Tier 1 calls build one from the
/// session id alone.
///
/// - **Session.** Your session id, or any per-session secret. It goes into the
///   MAC and never into the token, so the token reveals nothing about it.
///   Bind login forms to the guest session, and issue a new token after login.
/// - **Scope.** Binds a token to one action (`"POST /account/email"`). It then
///   verifies only for that scope.
/// - **Previous session.** After a login rotates the session id, tabs opened
///   before it hold tokens for the old id. Passing it lets those fail as
///   `StaleSession` (benign) instead of `BadMac` (forgery). They never pass.
/// - **Once.** Makes the token one-time, through a [`NonceStore`].
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use csrf_sec::{Binding, Csrf};
///
/// let csrf = Csrf::new(*b"an example key, 32 bytes long!!!")?;
/// let change_email = Binding::new("session-1").scope("POST /account/email");
///
/// let token = csrf.issue_with(&change_email)?;
/// csrf.verify_with(&change_email, &token)?;
/// assert!(csrf.verify("session-1", &token).is_err(), "scoped token, unscoped check");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy)]
pub struct Binding<'a> {
    pub(crate) session: &'a [u8],
    pub(crate) scope: &'a [u8],
    pub(crate) previous: Option<&'a [u8]>,
    pub(crate) store: Option<&'a dyn NonceStore>,
}

impl<'a> Binding<'a> {
    /// Bind to `session`.
    #[must_use]
    pub fn new<S: AsRef<[u8]> + ?Sized>(session: &'a S) -> Self {
        Self {
            session: session.as_ref(),
            scope: &[],
            previous: None,
            store: None,
        }
    }

    /// Also bind to `scope`, one action. An empty scope means no scope.
    #[must_use]
    pub fn scope<S: AsRef<[u8]> + ?Sized>(mut self, scope: &'a S) -> Self {
        self.scope = scope.as_ref();
        self
    }

    /// The session id this one replaced, for the short window your session
    /// layer keeps it after login. Tokens bound to it fail as
    /// [`Reason::StaleSession`](crate::Reason::StaleSession).
    #[must_use]
    pub fn previous_session<S: AsRef<[u8]> + ?Sized>(mut self, previous: &'a S) -> Self {
        let previous = previous.as_ref();
        self.previous = if previous.is_empty() {
            None
        } else {
            Some(previous)
        };
        self
    }

    /// Make the token one-time: `issue_with` records its nonce in `store`, and
    /// the first successful verify removes it, so a second use fails as
    /// [`Reason::AlreadyUsed`](crate::Reason::AlreadyUsed). One-time tokens
    /// are [`ONCE_TOKEN_LEN`](crate::ONCE_TOKEN_LEN) characters. A one-time
    /// binding always checks the token, whatever the [`Mode`](crate::Mode).
    #[must_use]
    pub fn once(mut self, store: &'a dyn NonceStore) -> Self {
        self.store = Some(store);
        self
    }
}

impl fmt::Debug for Binding<'_> {
    /// Session ids may be secrets, so only lengths are shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Binding")
            .field("session_len", &self.session.len())
            .field("scope_len", &self.scope.len())
            .field("previous_session", &self.previous.is_some())
            .field("once", &self.store.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::Binding;

    #[test]
    fn test_binding_defaults_have_no_scope_or_previous() {
        let b = Binding::new("abc");
        assert_eq!(b.session, b"abc");
        assert!(b.scope.is_empty());
        assert!(b.previous.is_none());
    }

    #[test]
    fn test_binding_accepts_str_string_and_bytes() {
        let owned = String::from("s");
        let bytes = [1u8, 2];
        let b = Binding::new(&owned)
            .scope(&bytes[..])
            .previous_session(b"old");
        assert_eq!(b.session, b"s");
        assert_eq!(b.scope, &[1, 2]);
        assert_eq!(b.previous, Some(&b"old"[..]));
    }

    #[test]
    fn test_binding_empty_previous_is_none() {
        assert!(Binding::new("s").previous_session("").previous.is_none());
    }

    #[test]
    fn test_binding_debug_hides_values() {
        let text = format!("{:?}", Binding::new("secret-session").scope("POST /x"));
        assert!(!text.contains("secret"));
        assert!(text.contains("session_len: 14"));
    }
}
