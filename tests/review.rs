//! Findings of the `0.9.0` adversarial reviews, each pinned by a test that
//! failed before its fix (dev/PLAN.md D-065 to D-074 for the first review,
//! D-075 to D-081 for the second, which reviewed the first's fixes).

#![cfg(feature = "std")]

use std::time::Duration;

use csrf_sec::{
    Binding, Csrf, Error, KeyId, MemoryStore, Mode, NonceStore, NonceUse, PadSource, Reason,
    RequestFacts, StoreError,
};

const KEY: [u8; 32] = *b"review finding tests, 32 bytes!!";
const NOW: u64 = 1_792_540_800;

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

fn csrf() -> Csrf {
    Csrf::new(KEY).unwrap()
}

/// Finding 1: one session filling the one-time store must not lock everyone
/// else out. Each session has its own quota.
#[test]
fn f1_one_session_cannot_fill_the_store_for_others() {
    let c = csrf();
    let store = MemoryStore::starting_at(6_400, NOW - 3_600).with_session_limit(8);
    let attacker = Binding::new("attacker-session").once(&store);
    let mut pads = Pads(1);
    let mut accepted = 0;
    for _ in 0..100 {
        let t = c.issue_at(&attacker, NOW, &mut pads).unwrap();
        if c.verify_at(&attacker, t.as_bytes(), NOW).is_ok() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 8, "the attacker's session stops at its quota");
    for i in 0..100 {
        let session = format!("victim-{i}");
        let victim = Binding::new(&session).once(&store);
        let t = c.issue_at(&victim, NOW, &mut pads).unwrap();
        assert!(
            c.verify_at(&victim, t.as_bytes(), NOW).is_ok(),
            "victim {i}"
        );
    }
}

/// Finding 1: one-time tokens have their own, shorter lifetime, so their
/// records (and any abuse) last an hour by default, not twelve.
#[test]
fn f1_one_time_tokens_have_their_own_lifetime() {
    let c = csrf();
    assert_eq!(c.once_lifetime(), Duration::from_secs(3_600));
    let store = MemoryStore::starting_at(100, NOW - 60);
    let b = Binding::new("s").once(&store);
    let t = c.issue_at(&b, NOW, &mut Pads(2)).unwrap();
    assert_eq!(
        c.verify_at(&b, t.as_bytes(), NOW + 3_601)
            .unwrap_err()
            .reason(),
        Reason::Expired
    );
    let t = c.issue_at(&b, NOW, &mut Pads(3)).unwrap();
    assert!(c.verify_at(&b, t.as_bytes(), NOW + 3_600).is_ok());
    // Session tokens keep the general lifetime.
    let s = c.issue_at(&Binding::new("s"), NOW, &mut Pads(4)).unwrap();
    assert!(
        c.verify_at(&Binding::new("s"), s.as_bytes(), NOW + 3_601)
            .is_ok()
    );
    // Configurable, and never longer than the general lifetime.
    let short = Csrf::builder()
        .key(KeyId(0), KEY)
        .once_lifetime(Duration::from_secs(300))
        .build()
        .unwrap();
    assert_eq!(short.once_lifetime(), Duration::from_secs(300));
    assert_eq!(
        Csrf::builder()
            .key(KeyId(0), KEY)
            .lifetime(Duration::from_secs(600))
            .once_lifetime(Duration::from_secs(601))
            .build()
            .unwrap_err(),
        Error::InvalidLifetime
    );
}

/// Finding 1: the store reports a session over its quota distinctly.
#[test]
fn f1_session_limit_is_reported_by_the_store() {
    let store = MemoryStore::starting_at(100, 0).with_session_limit(1);
    let mut nonce = [0u8; 16];
    let mut use_ = |n: u8| {
        nonce[0] = n;
        let u = NonceUse::new(b"s", nonce, 10, 100, 20);
        store.consume(&u)
    };
    assert_eq!(use_(1), Ok(true));
    assert_eq!(use_(2), Err(StoreError::SessionLimit));
    assert_eq!(use_(1), Ok(false), "a used nonce is still reported as used");
}

/// Finding 2: a malformed own origin fails closed instead of switching the
/// Origin check off.
#[test]
fn f2_malformed_own_origin_fails_closed() {
    let c = csrf();
    for own in [
        "https://example.com/",
        "example.com",
        "https://example.com:443/",
        "https://Example.com ",
    ] {
        let f = RequestFacts::new("POST")
            .origin("https://evil.example")
            .own_origin(own);
        assert_eq!(
            c.policy(&f).unwrap_err().reason(),
            Reason::OriginMismatch,
            "own {own:?}"
        );
        let f = RequestFacts::new("POST")
            .referer("https://evil.example/x")
            .own_origin(own);
        assert_eq!(
            c.policy(&f).unwrap_err().reason(),
            Reason::OriginMismatch,
            "own {own:?}"
        );
    }
}

/// Finding 3: a malformed or null Referer is refused whatever is configured,
/// as the docs say and as `Origin` already was.
#[test]
fn f3_malformed_referer_is_refused_without_configuration() {
    let c = csrf();
    for referer in [
        "garbage",
        "https://user@evil.example/",
        "https://evil.example%2f/",
        "null",
    ] {
        let f = RequestFacts::new("POST").referer(referer);
        assert_eq!(
            c.policy(&f).unwrap_err().reason(),
            Reason::OriginMismatch,
            "{referer:?}"
        );
    }
    // A well-formed Referer with nothing to compare against still leaves it
    // to the token.
    let f = RequestFacts::new("POST").referer("https://example.com/x");
    assert!(c.policy(&f).is_ok());
}

/// Finding 4: a restarted `MemoryStore` must not accept a token used before
/// the restart even if the clock stepped back a little; it starts one skew
/// (60 s) ahead of the clock.
#[test]
fn f4_memory_store_starts_ahead_of_the_clock() {
    let c = csrf();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let store = MemoryStore::new(100);
    let b = Binding::new("s").once(&store);
    // Issued 30 seconds after the store started: within the margin, refused.
    let t = c.issue_at(&b, now + 30, &mut Pads(5)).unwrap();
    assert_eq!(
        c.verify_at(&b, t.as_bytes(), now + 40)
            .unwrap_err()
            .reason(),
        Reason::AlreadyUsed
    );
    // Issued after the margin: accepted once.
    let t = c.issue_at(&b, now + 61, &mut Pads(6)).unwrap();
    assert!(c.verify_at(&b, t.as_bytes(), now + 62).is_ok());
}

/// Finding 5: times in milliseconds (or anything past 2156) are refused or
/// ignored, never taken as "far in the future".
#[test]
fn f5_out_of_range_times_fail_closed() {
    let ms = NOW * 1_000;
    assert_eq!(
        Csrf::builder()
            .key(KeyId(1), KEY)
            .retired(KeyId(2), *b"an old key, thirty-two bytes!!!!", ms)
            .build()
            .unwrap_err(),
        Error::InvalidRetireTime
    );
    let c = csrf();
    assert_eq!(
        c.rotated_at(KeyId(1), *b"a new key, thirty-two bytes long", ms)
            .unwrap_err(),
        Error::Clock
    );
    // purge_expired with a time in milliseconds keeps every record.
    let store = MemoryStore::starting_at(100, NOW - 60);
    let b = Binding::new("s").once(&store);
    let t = c.issue_at(&b, NOW, &mut Pads(7)).unwrap();
    assert!(c.verify_at(&b, t.as_bytes(), NOW).is_ok());
    store.purge_expired(ms);
    assert_eq!(
        c.verify_at(&b, t.as_bytes(), NOW).unwrap_err().reason(),
        Reason::AlreadyUsed
    );
}

/// Finding 6: binding to a cookie value does not stop an attacker who can
/// plant that cookie; the `__Host-` prefix and layer 1 do. In `TokenOnly`
/// mode the planted pair passes; in `Strict` the cross-site request is refused.
#[test]
fn f6_planted_cookie_is_stopped_by_layer_one_not_the_mac() {
    let planted = "attacker-chosen-cookie-value";
    let token_only = Csrf::builder()
        .key(KeyId(0), KEY)
        .mode(Mode::TokenOnly)
        .build()
        .unwrap();
    let t = token_only
        .issue_at(&Binding::new(planted), NOW, &mut Pads(8))
        .unwrap();
    let attack = RequestFacts::new("POST")
        .fetch_site("cross-site")
        .origin("https://evil.example");
    assert!(
        token_only
            .check_at(&attack, &Binding::new(planted), t.as_bytes(), NOW)
            .is_ok(),
        "TokenOnly cannot tell: this is why the docs require __Host- cookies"
    );
    let strict = Csrf::builder().key(KeyId(0), KEY).build().unwrap();
    let t = strict
        .issue_at(&Binding::new(planted), NOW, &mut Pads(9))
        .unwrap();
    assert_eq!(
        strict
            .check_at(&attack, &Binding::new(planted), t.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::CrossSite
    );
}

/// Finding 10: after a rotation, a token from a peer whose clock runs up to
/// the skew ahead stays valid to the last second of its lifetime.
#[test]
fn f10_rotation_keeps_the_last_second() {
    let c = Csrf::builder()
        .key(KeyId(1), KEY)
        .lifetime(Duration::from_secs(600))
        .skew(Duration::from_secs(60))
        .build()
        .unwrap();
    let b = Binding::new("s");
    let from_peer = c.issue_at(&b, NOW + 60, &mut Pads(10)).unwrap();
    let rotated = c
        .rotated_at(KeyId(2), *b"a new key, thirty-two bytes long", NOW)
        .unwrap();
    assert!(
        rotated
            .verify_at(&b, from_peer.as_bytes(), NOW + 60 + 600)
            .is_ok()
    );
    // One second later the token has expired and its key has retired; the key
    // is checked first.
    assert_eq!(
        rotated
            .verify_at(&b, from_peer.as_bytes(), NOW + 60 + 601)
            .unwrap_err()
            .reason(),
        Reason::UnknownKey
    );
}

// ------------------------------------------------- second review (D-075 to D-081)

/// Second review, finding 2: once a record is purged at time `P`, a verify
/// whose clock reads earlier (a clock stepped back, or a request time older
/// than the purger's) must not find the nonce unused.
#[test]
fn r2_purged_record_cannot_pass_again_on_an_earlier_clock() {
    let c = csrf();
    let store = MemoryStore::starting_at(1 << 16, NOW - 60);
    let b = Binding::new("s").once(&store);
    let t = c.issue_at(&b, NOW, &mut Pads(20)).unwrap();
    assert!(c.verify_at(&b, t.as_bytes(), NOW + 3_000).is_ok());
    // The clock ran ahead, a purge dropped the record, then the clock stepped back.
    store.purge_expired(NOW + 3_661);
    assert_eq!(
        c.verify_at(&b, t.as_bytes(), NOW + 3_600)
            .unwrap_err()
            .reason(),
        Reason::AlreadyUsed
    );
}

/// Second review, finding 2, with no skew: a one-second race between the
/// purger's clock and the verifier's.
#[test]
fn r2_purged_record_cannot_pass_again_with_zero_skew() {
    let c = Csrf::builder()
        .key(KeyId(1), KEY)
        .skew(Duration::ZERO)
        .build()
        .unwrap();
    let store = MemoryStore::starting_at(1 << 16, NOW - 60);
    let b = Binding::new("s").once(&store);
    let t = c.issue_at(&b, NOW, &mut Pads(21)).unwrap();
    assert!(c.verify_at(&b, t.as_bytes(), NOW + 3_599).is_ok());
    store.purge_expired(NOW + 3_601);
    assert_eq!(
        c.verify_at(&b, t.as_bytes(), NOW + 3_600)
            .unwrap_err()
            .reason(),
        Reason::AlreadyUsed
    );
}

/// Second review, finding 2: the record a purge forgets is exactly what it
/// dropped. Tokens that expire after everything dropped still pass.
#[test]
fn r2_forgetting_refuses_nothing_newer_than_what_was_dropped() {
    let store = MemoryStore::starting_at(1 << 16, 0);
    let mut n = [0u8; 16];
    let mut use_ = |i: u8, expires_at: u64, now: u64| {
        n[0] = i;
        store.consume(&NonceUse::new(b"s", n, 10, expires_at, now))
    };
    assert_eq!(use_(1, 100, 20), Ok(true));
    store.purge_expired(150);
    assert_eq!(
        use_(2, 100, 20),
        Ok(false),
        "expired no later than a dropped record"
    );
    assert_eq!(
        use_(3, 101, 20),
        Ok(true),
        "expires after every dropped record"
    );
}

/// Second review, finding 3: an undersized store must not let one session
/// take its whole shard. The session limit is capped at an eighth of a shard.
#[test]
fn r2_session_limit_is_capped_by_the_shard_size() {
    let store = MemoryStore::starting_at(1_000, 0); // 16 records per shard
    assert_eq!(store.session_limit(), 2);
    assert_eq!(MemoryStore::starting_at(1 << 20, 0).session_limit(), 64);
    assert_eq!(MemoryStore::starting_at(0, 0).session_limit(), 1);
    assert_eq!(
        MemoryStore::starting_at(1 << 20, 0)
            .with_session_limit(500)
            .session_limit(),
        500
    );
    let c = csrf();
    let store = MemoryStore::starting_at(1_000, NOW - 60);
    let attacker = Binding::new("attacker").once(&store);
    let mut pads = Pads(22);
    let mut accepted = 0;
    for _ in 0..50 {
        let t = c.issue_at(&attacker, NOW, &mut pads).unwrap();
        if c.verify_at(&attacker, t.as_bytes(), NOW).is_ok() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 2);
    for i in 0..200 {
        let session = format!("victim-{i}");
        let victim = Binding::new(&session).once(&store);
        let t = c.issue_at(&victim, NOW, &mut pads).unwrap();
        assert!(
            c.verify_at(&victim, t.as_bytes(), NOW).is_ok(),
            "victim {i}"
        );
    }
}

/// Second review, finding 4: a session over its quota is reported apart from
/// a store outage, so operators can tell abuse from failure.
#[test]
fn r2_session_over_its_quota_has_its_own_reason() {
    let c = csrf();
    let store = MemoryStore::starting_at(1 << 16, NOW - 60).with_session_limit(1);
    let b = Binding::new("s").once(&store);
    let t = c.issue_at(&b, NOW, &mut Pads(23)).unwrap();
    assert!(c.verify_at(&b, t.as_bytes(), NOW).is_ok());
    let t = c.issue_at(&b, NOW, &mut Pads(24)).unwrap();
    let refused = c.verify_at(&b, t.as_bytes(), NOW).unwrap_err();
    assert_eq!(refused.reason(), Reason::TooManyUses);
    assert_eq!(refused.reason().as_str(), "too_many_uses");
}

/// Second review, finding 1: nodes sharing a store must agree on the one-time
/// lifetime. During a rolling upgrade from 0.8 (whose one-time tokens lived
/// the whole lifetime), new nodes set `once_lifetime(lifetime)`; then a token
/// used on one node is refused on the other, even after a purge.
#[test]
fn r2_upgrade_path_keeps_one_time_tokens_single_use() {
    let lifetime = Duration::from_secs(12 * 3_600);
    // A 0.8 node: one-time tokens lived the whole (default) lifetime.
    let old = Csrf::builder()
        .key(KeyId(0), KEY)
        .once_lifetime(lifetime)
        .build()
        .unwrap();
    // A 0.9 node during the rollout, configured as the upgrade notes say.
    let new = Csrf::builder()
        .key(KeyId(0), KEY)
        .once_lifetime(lifetime)
        .build()
        .unwrap();
    let store = MemoryStore::starting_at(1 << 16, NOW - 60);
    let b = Binding::new("s").once(&store);
    let t = old.issue_at(&b, NOW, &mut Pads(25)).unwrap();
    assert!(new.verify_at(&b, t.as_bytes(), NOW + 10).is_ok());
    store.purge_expired(NOW + 4_000);
    assert_eq!(
        old.verify_at(&b, t.as_bytes(), NOW + 4_000)
            .unwrap_err()
            .reason(),
        Reason::AlreadyUsed
    );
}
