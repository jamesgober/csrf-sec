//! Optional expiry: `Builder::no_expiry` makes a token live as long as the
//! session it is bound to (OWASP's per-session token), or until its key is
//! retired. One-time tokens always expire.

use std::time::Duration;

use csrf_sec::{Binding, Csrf, Error, KeyId, NonceStore, NonceUse, PadSource, Reason, StoreError};

const KEY: [u8; 32] = *b"optional expiry tests, 32 bytes!";
const NOW: u64 = 1_792_540_800;
const YEAR: u64 = 365 * 86_400;

struct Pads(u64);

impl PadSource for Pads {
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

/// A store that has never seen any nonce.
struct Fresh;

impl NonceStore for Fresh {
    fn consume(&self, _: &NonceUse<'_>) -> Result<bool, StoreError> {
        Ok(true)
    }
}

fn no_expiry() -> Csrf {
    Csrf::builder()
        .key(KeyId(1), KEY)
        .no_expiry()
        .build()
        .unwrap()
}

#[test]
fn tokens_expire_by_default() {
    let c = Csrf::new(KEY).unwrap();
    assert!(c.expires());
    let b = Binding::new("s");
    let t = c.issue_at(&b, NOW, &mut Pads(1)).unwrap();
    assert!(c.verify_at(&b, t.as_bytes(), NOW + 12 * 3_600).is_ok());
    assert_eq!(
        c.verify_at(&b, t.as_bytes(), NOW + 12 * 3_600 + 1)
            .unwrap_err()
            .reason(),
        Reason::Expired
    );
}

#[test]
fn without_expiry_a_token_lives_as_long_as_its_session() {
    let c = no_expiry();
    assert!(!c.expires());
    let b = Binding::new("s").scope("POST /x");
    let t = c.issue_at(&b, NOW, &mut Pads(2)).unwrap();
    for later in [12 * 3_600 + 1, YEAR, 10 * YEAR] {
        assert!(
            c.verify_at(&b, t.as_bytes(), NOW + later).is_ok(),
            "{later}"
        );
    }
    // Still bound to its session and scope: the MAC decides.
    assert_eq!(
        c.verify_at(
            &Binding::new("other").scope("POST /x"),
            t.as_bytes(),
            NOW + YEAR
        )
        .unwrap_err()
        .reason(),
        Reason::BadMac
    );
}

#[test]
fn without_expiry_a_token_from_the_future_is_still_refused() {
    let c = no_expiry();
    let b = Binding::new("s");
    let t = c.issue_at(&b, NOW + 61, &mut Pads(3)).unwrap();
    assert_eq!(
        c.verify_at(&b, t.as_bytes(), NOW).unwrap_err().reason(),
        Reason::NotYetValid
    );
    assert!(
        c.verify_at(&b, t.as_bytes(), NOW + 1).is_ok(),
        "within the skew"
    );
}

#[test]
fn without_expiry_one_time_tokens_still_expire() {
    let c = no_expiry();
    assert_eq!(c.once_lifetime(), Duration::from_secs(3_600));
    let b = Binding::new("s").once(&Fresh);
    let t = c.issue_at(&b, NOW, &mut Pads(4)).unwrap();
    assert!(c.verify_at(&b, t.as_bytes(), NOW + 3_600).is_ok());
    assert_eq!(
        c.verify_at(&b, t.as_bytes(), NOW + 3_601)
            .unwrap_err()
            .reason(),
        Reason::Expired
    );
}

#[test]
fn without_expiry_rotation_keeps_the_old_key_for_one_lifetime() {
    let c = Csrf::builder()
        .key(KeyId(1), KEY)
        .no_expiry()
        .lifetime(Duration::from_secs(600))
        .skew(Duration::from_secs(30))
        .build()
        .unwrap();
    let b = Binding::new("s");
    let old = c.issue_at(&b, NOW - YEAR, &mut Pads(5)).unwrap();
    let c = c
        .rotated_at(KeyId(2), *b"the next key, thirty-two bytes!!", NOW)
        .unwrap();
    assert!(!c.expires(), "rotation keeps the setting");
    let passed = c.verify_at(&b, old.as_bytes(), NOW + 630).unwrap();
    assert!(passed.retired_key());
    assert_eq!(
        c.verify_at(&b, old.as_bytes(), NOW + 631)
            .unwrap_err()
            .reason(),
        Reason::UnknownKey,
        "the retired key is gone after one lifetime plus skew"
    );
}

#[test]
fn without_expiry_one_time_lifetime_is_not_capped_by_the_lifetime() {
    // The lifetime only sets the rotation grace here; a one-time lifetime
    // longer than it is allowed.
    let c = Csrf::builder()
        .key(KeyId(1), KEY)
        .no_expiry()
        .lifetime(Duration::from_secs(600))
        .once_lifetime(Duration::from_secs(3_600))
        .build()
        .unwrap();
    assert_eq!(c.once_lifetime(), Duration::from_secs(3_600));
    // With expiry it is still capped.
    assert_eq!(
        Csrf::builder()
            .key(KeyId(1), KEY)
            .lifetime(Duration::from_secs(600))
            .once_lifetime(Duration::from_secs(3_600))
            .build()
            .unwrap_err(),
        Error::InvalidLifetime
    );
}

#[test]
fn debug_shows_the_setting() {
    assert!(format!("{:?}", no_expiry()).contains("expires: false"));
    assert!(format!("{:?}", Csrf::new(KEY).unwrap()).contains("expires: true"));
    assert!(format!("{:?}", Csrf::builder().no_expiry()).contains("expires: false"));
}
