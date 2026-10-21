//! Property tests for the invariants in `dev/DIRECTIVES.md` section 4.

use csrf_sec::{
    Binding, Csrf, Error, KeyId, NonceStore, NonceUse, PadSource, Reason, RequestFacts, StoreError,
};
use proptest::prelude::*;

const NOW: u64 = 1_792_540_800;

struct SeedPads(u64);

impl PadSource for SeedPads {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        for b in out {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *b = (self.0 >> 56) as u8;
        }
        Ok(())
    }
}

fn csrf(key_byte: u8) -> Csrf {
    let mut key = [key_byte; 32];
    key[0] ^= 0x5a; // never all-equal
    Csrf::new(key).unwrap()
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..=max)
}

/// A store that has never seen any nonce: isolates the token checks.
struct Fresh;

impl NonceStore for Fresh {
    fn consume(&self, _: &NonceUse<'_>) -> Result<bool, StoreError> {
        Ok(true)
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Issue then verify always passes, for any session, scope, time, and pads.
    #[test]
    fn prop_issue_then_verify_passes(
        session in proptest::collection::vec(any::<u8>(), 1..300),
        scope in bytes(200),
        offset in 0u64..3_000_000_000,
        seed in any::<u64>(),
        key_byte in any::<u8>(),
    ) {
        let c = csrf(key_byte);
        let now = 1_577_836_800 + offset;
        let b = Binding::new(&session).scope(&scope);
        let t = c.issue_at(&b, now, &mut SeedPads(seed)).unwrap();
        prop_assert!(c.verify_at(&b, t.as_bytes(), now).is_ok());
    }

    /// Any change to any character makes a token fail.
    #[test]
    fn prop_any_character_change_fails(
        session in proptest::collection::vec(any::<u8>(), 1..64),
        seed in any::<u64>(),
        pos in 0usize..59,
        replacement in any::<u8>(),
    ) {
        let c = csrf(1);
        let b = Binding::new(&session);
        let t = c.issue_at(&b, NOW, &mut SeedPads(seed)).unwrap();
        let mut forged = t.as_bytes().to_vec();
        prop_assume!(forged[pos] != replacement);
        forged[pos] = replacement;
        prop_assert!(c.verify_at(&b, &forged, NOW).is_err());
    }

    /// Any change to any character of a one-time token makes it fail.
    #[test]
    fn prop_any_character_change_fails_one_time(
        seed in any::<u64>(),
        pos in 0usize..102,
        replacement in any::<u8>(),
    ) {
        let c = csrf(6);
        let b = Binding::new("s").scope("POST /pay").once(&Fresh);
        let t = c.issue_at(&b, NOW, &mut SeedPads(seed)).unwrap();
        prop_assert_eq!(t.as_str().len(), 102);
        let mut forged = t.as_bytes().to_vec();
        prop_assume!(forged[pos] != replacement);
        forged[pos] = replacement;
        prop_assert!(c.verify_at(&b, &forged, NOW).is_err());
    }

    /// A forged token is never reported as expired, not yet valid, stale, or
    /// wrongly scoped, at any time: those reasons are decided only after the
    /// MAC passed.
    #[test]
    fn prop_forgery_never_named_as_benign(
        seed in any::<u64>(),
        pos in 0usize..59,
        replacement in any::<u8>(),
        at in 0u64..4_000_000_000,
    ) {
        let c = csrf(7);
        let b = Binding::new("s").scope("POST /x").previous_session("old");
        let t = c.issue_at(&b, NOW, &mut SeedPads(seed)).unwrap();
        let mut forged = t.as_bytes().to_vec();
        prop_assume!(forged[pos] != replacement);
        forged[pos] = replacement;
        let r = c.verify_at(&b, &forged, 1_577_836_800 + at).unwrap_err().reason();
        prop_assert!(
            matches!(r, Reason::Malformed | Reason::UnknownKey | Reason::BadMac),
            "{r:?}"
        );
    }

    /// Only exactly `GET`, `HEAD`, and `OPTIONS` are safe: any other method,
    /// in any case, is refused without a token.
    #[test]
    fn prop_every_other_method_is_unsafe(method in bytes(12)) {
        let c = csrf(8);
        let facts = RequestFacts::new(&method);
        let safe = matches!(method.as_slice(), b"GET" | b"HEAD" | b"OPTIONS");
        let verdict = c.check_at(&facts, &Binding::new("s"), b"", NOW);
        prop_assert_eq!(verdict.is_ok(), safe);
    }

    /// `Origin: null` on an unsafe request is refused, whatever else is
    /// configured, when Fetch Metadata is absent.
    #[test]
    fn prop_null_origin_refused(own in bytes(40), referer in bytes(60), allow in any::<bool>()) {
        let mut builder = Csrf::builder().key(KeyId(0), *b"null-origin property key, 32 b!!");
        if allow {
            builder = builder.allow_origin("https://partner.example");
        }
        let c = builder.build().unwrap();
        let facts = RequestFacts::new("POST").origin("null").referer(&referer).own_origin(&own);
        prop_assert_eq!(c.policy(&facts).unwrap_err().reason(), Reason::OriginMismatch);
    }

    /// A token never verifies under another session id.
    #[test]
    fn prop_other_session_fails(
        a in proptest::collection::vec(any::<u8>(), 1..64),
        b in proptest::collection::vec(any::<u8>(), 1..64),
        seed in any::<u64>(),
    ) {
        prop_assume!(a != b);
        let c = csrf(2);
        let t = c.issue_at(&Binding::new(&a), NOW, &mut SeedPads(seed)).unwrap();
        let r = c.verify_at(&Binding::new(&b), t.as_bytes(), NOW).unwrap_err().reason();
        prop_assert_eq!(r, Reason::BadMac);
    }

    /// A token never verifies under another scope; an unscoped token on a
    /// scoped binding is named `WrongScope`.
    #[test]
    fn prop_other_scope_fails(
        s1 in bytes(40),
        s2 in bytes(40),
        seed in any::<u64>(),
    ) {
        prop_assume!(s1 != s2);
        let c = csrf(3);
        let t = c.issue_at(&Binding::new("s").scope(&s1), NOW, &mut SeedPads(seed)).unwrap();
        let r = c.verify_at(&Binding::new("s").scope(&s2), t.as_bytes(), NOW).unwrap_err().reason();
        if s1.is_empty() {
            prop_assert_eq!(r, Reason::WrongScope);
        } else {
            prop_assert_eq!(r, Reason::BadMac);
        }
    }

    /// A token never verifies under another key, whatever its id.
    #[test]
    fn prop_other_key_fails(k1 in any::<u8>(), k2 in any::<u8>(), id in any::<u8>(), seed in any::<u64>()) {
        prop_assume!(k1 != k2);
        let issuer = Csrf::builder().key(KeyId(id), { let mut k = [k1; 32]; k[0] ^= 0x5a; k }).build().unwrap();
        let verifier = Csrf::builder().key(KeyId(id), { let mut k = [k2; 32]; k[0] ^= 0x5a; k }).build().unwrap();
        let b = Binding::new("s");
        let t = issuer.issue_at(&b, NOW, &mut SeedPads(seed)).unwrap();
        prop_assert_eq!(verifier.verify_at(&b, t.as_bytes(), NOW).unwrap_err().reason(), Reason::BadMac);
    }

    /// Arbitrary bytes as a token never panic and never verify.
    #[test]
    fn prop_arbitrary_token_never_verifies(token in bytes(300), session in bytes(40)) {
        let c = csrf(4);
        let b = Binding::new(&session);
        prop_assert!(c.verify_at(&b, &token, NOW).is_err());
    }

    /// Arbitrary request facts never panic; safe methods always pass the
    /// policy; a cross-site unsafe request with no allowlist never passes.
    #[test]
    fn prop_policy_total_and_fail_closed(
        method in bytes(10),
        site in bytes(16),
        origin in bytes(60),
        referer in bytes(80),
        own in bytes(40),
    ) {
        let c = csrf(5);
        let facts = RequestFacts::new(&method)
            .fetch_site(&site)
            .origin(&origin)
            .referer(&referer)
            .own_origin(&own);
        let decision = c.policy(&facts);
        if matches!(method.as_slice(), b"GET" | b"HEAD" | b"OPTIONS") {
            prop_assert!(decision.is_ok());
        }
        let cross = RequestFacts::new("POST").fetch_site("cross-site").origin(&origin).own_origin(&own);
        prop_assert!(c.policy(&cross).is_err());
        let _ = c.check_at(&facts, &Binding::new("s"), b"", NOW);
    }

    /// The validity window is exact: valid from `issued - skew` to
    /// `issued + lifetime`, refused one second outside either end.
    #[test]
    fn prop_window_is_exact(lifetime in 1u64..1_000_000, skew_frac in 0u64..=100, issued in 0u64..1_000_000_000) {
        let skew = lifetime * skew_frac / 100;
        let c = Csrf::builder()
            .key(KeyId(0), *b"window property key, 32 bytes!!!")
            .lifetime(std::time::Duration::from_secs(lifetime))
            .skew(std::time::Duration::from_secs(skew))
            .build()
            .unwrap();
        let at = 1_577_836_800 + issued;
        let b = Binding::new("s");
        let t = c.issue_at(&b, at, &mut SeedPads(issued)).unwrap();
        prop_assert!(c.verify_at(&b, t.as_bytes(), at + lifetime).is_ok());
        prop_assert_eq!(c.verify_at(&b, t.as_bytes(), at + lifetime + 1).unwrap_err().reason(), Reason::Expired);
        prop_assert!(c.verify_at(&b, t.as_bytes(), at - skew).is_ok());
        prop_assert_eq!(c.verify_at(&b, t.as_bytes(), at - skew - 1).unwrap_err().reason(), Reason::NotYetValid);
    }
}
