//! Tier 2: scoped tokens, the stale-session window, and key rotation that
//! logs nobody out.
//!
//! Run with `cargo run --example rotation`.

use std::{sync::Arc, time::Duration};

use csrf_sec::{Binding, Csrf, KeyId, Mode, Reason};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let csrf = Arc::new(
        Csrf::builder()
            .key(KeyId(1), *b"first key, thirty-two bytes long")
            .lifetime(Duration::from_secs(8 * 3600))
            .skew(Duration::from_secs(30))
            .mode(Mode::Strict)
            .allow_origin("https://app.example.com")
            .build()?,
    );

    // A high-value form gets a token bound to its action.
    let change_email = Binding::new("user-session").scope("POST /account/email");
    let token = csrf.issue_with(&change_email)?;
    csrf.verify_with(&change_email, &token)?;
    println!("scoped token verified");

    // An unscoped token is not enough for the scoped action.
    let plain = csrf.issue("user-session")?;
    let refused = csrf.verify_with(&change_email, &plain).unwrap_err();
    assert_eq!(refused.reason(), Reason::WrongScope);
    println!("unscoped token on a scoped form: {}", refused.reason());

    // After login the session id rotates. A tab opened before login still
    // holds a guest token: it fails as StaleSession (benign), not BadMac.
    let guest_token = csrf.issue("guest-session")?;
    let after_login = Binding::new("user-session").previous_session("guest-session");
    let refused = csrf.verify_with(&after_login, &guest_token).unwrap_err();
    println!(
        "pre-login tab: {} (severity {})",
        refused.reason(),
        refused.severity()
    );

    // Rotate the key. The old key keeps verifying for one lifetime plus skew,
    // so the token issued above still passes.
    let rotated = Arc::new(csrf.rotated(KeyId(2), *b"second key, 32 bytes long......!")?);
    let passed = rotated.verify("user-session", &plain)?;
    println!(
        "old token after rotation: passes, retired key = {}",
        passed.retired_key()
    );
    let fresh = rotated.issue("user-session")?;
    println!(
        "new tokens are signed by key {:?}",
        rotated.verify("user-session", &fresh)?.key_id()
    );
    Ok(())
}
