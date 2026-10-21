//! Tier 1: protect a form in three calls.
//!
//! Run with `cargo run --example basic`.

use csrf_sec::{Csrf, FIELD_NAME, RequestFacts};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // In a real service the key is a persisted 32-byte secret (for example
    // derived from a key-vault master). A key generated at boot would make
    // every open form fail after a restart.
    let key = *b"example key: load yours securely";
    let csrf = Csrf::new(key)?;

    // The session id your session layer assigned (the guest session before
    // login, the user session after).
    let session_id = "3f1c9d0e-5b7a-4c2e-9a1d-7e8f6b5c4d3a";

    // GET /account: render the form with a fresh token.
    let token = csrf.issue(session_id)?;
    println!(r#"<input type="hidden" name="{FIELD_NAME}" value="{token}">"#);

    // POST /account: the adapter collects the facts from the request headers.
    let facts = RequestFacts::new("POST")
        .fetch_site("same-origin")
        .origin("https://example.com")
        .own_origin("https://example.com");
    let submitted = token.as_str(); // from the form body

    match csrf.check(&facts, session_id, submitted) {
        Ok(passed) => println!("allowed ({:?})", passed.origin_check()),
        Err(refused) => println!("403 ({refused}, severity {})", refused.severity()),
    }

    // The same token posted from another site is refused before any token work.
    let attack = RequestFacts::new("POST")
        .fetch_site("cross-site")
        .origin("https://evil.example")
        .own_origin("https://example.com");
    let refused = csrf.check(&attack, session_id, submitted).unwrap_err();
    println!("cross-site post: 403 ({})", refused.reason());

    // A token stolen for another session never verifies.
    let refused = csrf.verify("another-session", submitted).unwrap_err();
    println!("other session: 403 ({})", refused.reason());
    Ok(())
}
