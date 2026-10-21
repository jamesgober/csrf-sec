//! Tier 3: explicit time and randomness, the surface that works without `std`.
//!
//! The calls used here (`issue_at`, `verify_at`, `check_at`, `policy`,
//! `rotated_at`, `key_fingerprint`) are all available with
//! `default-features = false`; only `main` and the printing use `std`.
//!
//! Run with `cargo run --example tier3` (or add `--no-default-features`).

use csrf_sec::{Binding, Csrf, Error, KeyId, PadSource, Reason, RequestFacts};

/// Stand-in for a platform CSPRNG (a hardware generator on an embedded
/// target, an OS call elsewhere). This one is a fixed sequence so the example
/// is reproducible: never use a predictable source in production, because a
/// predictable pad lets a compression attack recover the token.
struct DemoRng(u64);

impl PadSource for DemoRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        for b in out {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *b = (self.0 >> 56) as u8;
        }
        Ok(())
    }
}

fn main() -> Result<(), Error> {
    let csrf = Csrf::builder()
        .key(KeyId(7), *b"tier three example key, 32 bytes")
        .allow_origin("https://example.com")
        .build()?;
    let mut rng = DemoRng(42);

    // The caller supplies the time (unix seconds) from whatever clock it has.
    let now = 1_800_000_000;
    let binding = Binding::new("session-1").scope("POST /settings");
    let token = csrf.issue_at(&binding, now, &mut rng)?;
    println!("token: {token}");

    let facts = RequestFacts::new("POST").origin("https://example.com");
    match csrf.check_at(&facts, &binding, token.as_bytes(), now + 30) {
        Ok(passed) => println!("passed: {:?}", passed.origin_check()),
        Err(refused) => println!("refused: {}", refused.reason()),
    }

    // Twelve hours and a second later, the default lifetime is over.
    let late = csrf.verify_at(&binding, token.as_bytes(), now + 12 * 3600 + 1);
    assert_eq!(late.unwrap_err().reason(), Reason::Expired);
    println!("after the lifetime: expired");

    // Rotation with an explicit time; the fingerprint lets other nodes check
    // they hold the same key under the same id.
    let rotated = csrf.rotated_at(KeyId(8), *b"the next key in line, 32 bytes!!", now)?;
    for key in rotated.keys() {
        println!(
            "key {}: {:?}, fingerprint {}",
            key.id(),
            key.role(),
            key.fingerprint()
        );
    }
    Ok(())
}
