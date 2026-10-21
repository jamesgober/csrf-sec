//! One attack per threat in `dev/PLAN.md` section 9 (T1 to T15). Each test
//! plays the attacker and must fail to get through.

#![cfg(feature = "std")]

use std::{collections::HashSet, time::Duration};

use csrf_sec::{
    Binding, Csrf, Error, FetchSite, KeyId, MethodClass, Mode, PadSource, Reason, RequestFacts,
    TOKEN_LEN,
};

const KEY: [u8; 32] = *b"attack test key, thirty-two byte";
const NOW: u64 = 1_792_540_800;
const SITE: &str = "https://bank.example";

struct Pads(u64);

impl PadSource for Pads {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        for b in out {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            *b = (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8;
        }
        Ok(())
    }
}

fn csrf() -> Csrf {
    Csrf::new(KEY).unwrap()
}

fn post<'a>() -> RequestFacts<'a> {
    RequestFacts::new("POST").own_origin(SITE)
}

/// T1: an attacker page auto-submits a form to the bank. The victim's browser
/// adds the victim's cookies (so the session id is the victim's), but the
/// attacker cannot read a token from the bank's pages.
#[test]
fn t1_classic_csrf_is_refused() {
    let c = csrf();
    let victim = Binding::new("victim-session");
    // Modern browser: Fetch Metadata says cross-site; refused before the token.
    let modern = post()
        .fetch_site("cross-site")
        .origin("https://evil.example");
    assert_eq!(
        c.check_at(&modern, &victim, b"", NOW).unwrap_err().reason(),
        Reason::CrossSite
    );
    // Older browser: no Fetch Metadata, foreign Origin.
    let older = post().origin("https://evil.example");
    assert_eq!(
        c.check_at(&older, &victim, b"", NOW).unwrap_err().reason(),
        Reason::OriginMismatch
    );
    // No headers at all (a privacy proxy stripped them): the token decides,
    // and the attacker has none, or only one for their own session.
    let bare = post();
    assert_eq!(
        c.check_at(&bare, &victim, b"", NOW).unwrap_err().reason(),
        Reason::Missing
    );
    let attackers_own = c
        .issue_at(&Binding::new("attacker-session"), NOW, &mut Pads(1))
        .unwrap();
    assert_eq!(
        c.check_at(&bare, &victim, attackers_own.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::BadMac
    );
}

/// T2: login CSRF. The attacker logs the victim into the attacker's account by
/// submitting the attacker's credentials from the victim's browser. The login
/// form's token is bound to the guest session, which differs per browser.
#[test]
fn t2_login_csrf_is_refused() {
    let c = csrf();
    let attackers_login_token = c
        .issue_at(&Binding::new("guest-attacker"), NOW, &mut Pads(2))
        .unwrap();
    let victims_guest = Binding::new("guest-victim");
    let facts = post(); // headers stripped: the token alone must stop it
    assert_eq!(
        c.check_at(
            &facts,
            &victims_guest,
            attackers_login_token.as_bytes(),
            NOW
        )
        .unwrap_err()
        .reason(),
        Reason::BadMac
    );
    // A token cannot be bound to "no session", which every visitor shares.
    assert_eq!(
        c.issue_at(&Binding::new(""), NOW, &mut Pads(3))
            .unwrap_err(),
        Error::EmptySession
    );
    assert_eq!(
        c.verify_at(&Binding::new(""), attackers_login_token.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::Unverifiable
    );
}

/// T3: forced logout from another site.
#[test]
fn t3_forced_logout_is_refused() {
    let c = csrf();
    let logout = Binding::new("victim-session").scope("POST /logout");
    let cross = post().fetch_site("cross-site");
    assert_eq!(
        c.check_at(&cross, &logout, b"", NOW).unwrap_err().reason(),
        Reason::CrossSite
    );
    // A logout link (GET) must not log out: GET passes the check because it
    // must never change state. The scoped token is what a logout POST needs.
    let get = RequestFacts::new("GET").fetch_site("cross-site");
    let passed = c.check_at(&get, &logout, b"", NOW).unwrap();
    assert!(
        !passed.token_checked(),
        "a GET carries no state-changing permission"
    );
}

/// T4: BREACH. A compression side channel recovers a secret that repeats
/// unchanged in many responses. The token text must differ on every response
/// at every position.
#[test]
fn t4_breach_has_no_repeating_text_to_recover() {
    let c = csrf();
    let b = Binding::new("victim-session");
    let tokens: Vec<_> = (0..2_000)
        .map(|i| c.issue_at(&b, NOW, &mut Pads(100 + i)).unwrap())
        .collect();
    for pos in 0..TOKEN_LEN - 1 {
        let distinct: HashSet<u8> = tokens.iter().map(|t| t.as_bytes()[pos]).collect();
        assert!(
            distinct.len() >= 60,
            "position {pos} takes only {} values",
            distinct.len()
        );
    }
    // The last character carries 4 data bits: 16 values.
    let last: HashSet<u8> = tokens.iter().map(|t| t.as_bytes()[TOKEN_LEN - 1]).collect();
    assert_eq!(last.len(), 16);
    // No two responses share any 8-character window at the same position.
    for pos in 0..TOKEN_LEN - 8 {
        let windows: HashSet<&[u8]> = tokens.iter().map(|t| &t.as_bytes()[pos..pos + 8]).collect();
        assert_eq!(
            windows.len(),
            tokens.len(),
            "a repeated 8-character run at {pos}"
        );
    }
    // And every one of them verifies.
    assert!(
        tokens
            .iter()
            .all(|t| c.verify_at(&b, t.as_bytes(), NOW).is_ok())
    );
}

/// T5: a token stolen from one session (for example from a log) is replayed
/// in another session.
#[test]
fn t5_token_from_another_session_is_refused() {
    let c = csrf();
    let stolen = c
        .issue_at(&Binding::new("alice-session"), NOW, &mut Pads(4))
        .unwrap();
    for other in [
        "bob-session",
        "alice-session ",
        "Alice-session",
        "alice-sessio",
        "alice-session\0",
    ] {
        assert_eq!(
            c.verify_at(&Binding::new(other), stolen.as_bytes(), NOW)
                .unwrap_err()
                .reason(),
            Reason::BadMac,
            "{other:?}"
        );
    }
}

/// T6: a token for one action is replayed on another.
#[test]
fn t6_token_from_another_action_is_refused() {
    let c = csrf();
    let comment = c
        .issue_at(&Binding::new("s").scope("POST /comment"), NOW, &mut Pads(5))
        .unwrap();
    let transfer = Binding::new("s").scope("POST /transfer");
    assert_eq!(
        c.verify_at(&transfer, comment.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::BadMac
    );
    let unscoped = c.issue_at(&Binding::new("s"), NOW, &mut Pads(6)).unwrap();
    assert_eq!(
        c.verify_at(&transfer, unscoped.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::WrongScope
    );
}

/// T7: cookie tossing. An attacker controlling a sibling subdomain plants a
/// cookie for the target. Naive double-submit compares the token with a cookie
/// the attacker can set; csrf-sec compares nothing with a cookie: the token is
/// a MAC over the session, and the attacker's own valid token is for the
/// attacker's session.
#[test]
fn t7_cookie_tossing_has_nothing_to_toss() {
    let c = csrf();
    // The attacker obtains a perfectly valid token for a session they control
    // and arranges for the victim's request to carry it.
    let attackers = c
        .issue_at(&Binding::new("attacker-session"), NOW, &mut Pads(7))
        .unwrap();
    let victim = Binding::new("victim-session");
    assert_eq!(
        c.verify_at(&victim, attackers.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::BadMac
    );
    // A sibling subdomain is "same-site" and refused unless explicitly allowed.
    let sibling = post()
        .fetch_site("same-site")
        .origin("https://attacker.bank.example");
    assert_eq!(c.policy(&sibling).unwrap_err().reason(), Reason::CrossSite);
}

/// T8: token forgery without the key.
#[test]
fn t8_forgery_without_the_key_fails() {
    let c = csrf();
    let b = Binding::new("victim-session");
    // Random well-formed tokens never verify.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut rng = Pads(8);
    let mut text = [0u8; TOKEN_LEN];
    for _ in 0..50_000 {
        rng.fill(&mut text).unwrap();
        for ch in &mut text {
            *ch = alphabet[usize::from(*ch & 63)];
        }
        text[TOKEN_LEN - 1] = b'A'; // canonical tail
        let r = c.verify_at(&b, &text, NOW).unwrap_err().reason();
        assert!(
            matches!(r, Reason::BadMac | Reason::Malformed | Reason::UnknownKey),
            "{r:?}"
        );
    }
    // Tokens made with another key fail, whatever the key id claims.
    for id in [0u8, 1, 255] {
        let other = Csrf::builder()
            .key(KeyId(id), *b"the attacker's own key, 32 bytes")
            .build()
            .unwrap();
        let forged = other.issue_at(&b, NOW, &mut Pads(9)).unwrap();
        assert!(
            c.verify_at(&b, forged.as_bytes(), NOW).is_err(),
            "key id {id}"
        );
    }
}

/// T9: a timing attack on the tag comparison. The comparison is one 128-bit
/// XOR with no early exit; `tests/timing.rs` measures it statistically. Here:
/// a tag right in 15 of 16 bytes is refused exactly like one right in none.
#[test]
fn t9_nearly_right_tags_are_refused_like_wrong_ones() {
    let c = csrf();
    let b = Binding::new("victim-session");
    let real = c.issue_at(&b, NOW, &mut Pads(10)).unwrap();
    // Decode with a reference codec, flip one tag byte, re-encode.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let decode = |t: &[u8]| -> Vec<u8> {
        let mut bits = 0u32;
        let mut n = 0;
        let mut out = Vec::new();
        for &ch in t {
            bits = (bits << 6) | alphabet.iter().position(|&a| a == ch).unwrap() as u32;
            n += 6;
            if n >= 8 {
                n -= 8;
                out.push((bits >> n) as u8);
            }
        }
        out
    };
    let encode = |bytes: &[u8]| -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in bytes.chunks(3) {
            let x = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let v = (u32::from(x[0]) << 16) | (u32::from(x[1]) << 8) | u32::from(x[2]);
            for i in 0..=chunk.len() {
                out.push(alphabet[((v >> (18 - 6 * i)) & 63) as usize]);
            }
        }
        out
    };
    let bytes = decode(real.as_bytes());
    for tag_byte in 0..16 {
        let mut forged = bytes.clone();
        forged[22 + 6 + tag_byte] ^= 0x01; // body = raw XOR pad; raw tag starts at 6
        assert_eq!(
            c.verify_at(&b, &encode(&forged), NOW).unwrap_err().reason(),
            Reason::BadMac,
            "tag byte {tag_byte}"
        );
    }
}

/// T10: key compromise. After rotation, the old key stops verifying at its
/// retire time, and it never signs again.
#[test]
fn t10_compromised_key_is_retired() {
    let c = Csrf::builder()
        .key(KeyId(1), KEY)
        .lifetime(Duration::from_secs(600))
        .skew(Duration::from_secs(30))
        .build()
        .unwrap();
    let b = Binding::new("s");
    // The attacker stole key 1 and can mint tokens with it.
    let stolen_ring = Csrf::builder().key(KeyId(1), KEY).build().unwrap();
    let rotated = c
        .rotated_at(KeyId(2), *b"a fresh key after the breach!!!!", NOW)
        .unwrap();
    // New tokens are signed only by key 2.
    let fresh = rotated.issue_at(&b, NOW, &mut Pads(11)).unwrap();
    assert_eq!(
        rotated
            .verify_at(&b, fresh.as_bytes(), NOW)
            .unwrap()
            .key_id(),
        Some(KeyId(2))
    );
    // Minted with the stolen key: passes only until key 1 retires...
    let minted = stolen_ring.issue_at(&b, NOW + 100, &mut Pads(12)).unwrap();
    assert!(
        rotated
            .verify_at(&b, minted.as_bytes(), NOW + 100)
            .unwrap()
            .retired_key()
    );
    // ...which an emergency rotation can make immediate:
    let emergency = Csrf::builder()
        .key(KeyId(2), *b"a fresh key after the breach!!!!")
        .build()
        .unwrap();
    assert_eq!(
        emergency
            .verify_at(&b, minted.as_bytes(), NOW + 100)
            .unwrap_err()
            .reason(),
        Reason::UnknownKey
    );
    // And at the retire time, key 1 is gone everywhere.
    assert_eq!(
        rotated
            .verify_at(&b, minted.as_bytes(), NOW + 631)
            .unwrap_err()
            .reason(),
        Reason::UnknownKey
    );
}

/// T11: denial of service through verification. Oversized, empty, and
/// garbage inputs are refused without allocating or doing work proportional
/// to their size.
#[test]
fn t11_oversized_and_garbage_inputs_are_cheap_to_refuse() {
    let c = csrf();
    let b = Binding::new("s");
    let huge = vec![b'A'; 16 << 20];
    let start = std::time::Instant::now();
    for _ in 0..1_000 {
        assert_eq!(
            c.verify_at(&b, &huge, NOW).unwrap_err().reason(),
            Reason::Malformed
        );
    }
    // 1,000 refusals of a 16 MiB token in well under a millisecond each: the
    // length is checked before anything reads the bytes.
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "{:?}",
        start.elapsed()
    );
    for len in [0usize, 1, 58, 60, 101, 102, 103] {
        let t = vec![b'A'; len];
        assert!(c.verify_at(&b, &t, NOW).is_err(), "length {len}");
    }
    let huge_origin = "https://".to_owned() + &"a".repeat(1 << 20);
    let f = post().origin(&huge_origin);
    assert_eq!(c.policy(&f).unwrap_err().reason(), Reason::OriginMismatch);
}

/// T12: clocks differ between nodes. A token from a node whose clock is ahead
/// passes within the skew and is refused beyond it; it never passes as a
/// token from the future that never expires.
#[test]
fn t12_clock_skew_is_bounded() {
    let c = Csrf::builder()
        .key(KeyId(0), KEY)
        .lifetime(Duration::from_secs(3600))
        .skew(Duration::from_secs(60))
        .build()
        .unwrap();
    let b = Binding::new("s");
    let ahead = c.issue_at(&b, NOW + 60, &mut Pads(13)).unwrap();
    assert!(c.verify_at(&b, ahead.as_bytes(), NOW).is_ok());
    let far_ahead = c.issue_at(&b, NOW + 61, &mut Pads(14)).unwrap();
    assert_eq!(
        c.verify_at(&b, far_ahead.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::NotYetValid
    );
    let decade = c
        .issue_at(&b, NOW + 10 * 365 * 86_400, &mut Pads(15))
        .unwrap();
    assert_eq!(
        c.verify_at(&b, decade.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::NotYetValid
    );
}

/// T13: state change through a "safe" method. Only exact `GET`, `HEAD`, and
/// `OPTIONS` are safe; look-alikes are checked like any unsafe method.
#[test]
fn t13_method_look_alikes_are_unsafe() {
    let c = csrf();
    let b = Binding::new("s");
    for method in [
        "get", "Get", "GET ", " GET", "GET\0", "GE", "GETS", "HEAD\t", "options", "TRACE", "POST",
    ] {
        assert_eq!(
            MethodClass::classify(method.as_bytes()),
            MethodClass::Unsafe,
            "{method:?}"
        );
        let f = RequestFacts::new(method).fetch_site("cross-site");
        assert!(c.check_at(&f, &b, b"", NOW).is_err(), "{method:?}");
    }
}

/// T14: `Origin: null` (sandboxed frames, some redirects) and stripped
/// `Referer` headers.
#[test]
fn t14_null_origin_and_stripped_referer() {
    let c = csrf();
    let b = Binding::new("s");
    let null = post().origin("null");
    assert_eq!(
        c.check_at(&null, &b, b"", NOW).unwrap_err().reason(),
        Reason::OriginMismatch
    );
    // Even with a valid token, a null origin is refused in Strict.
    let token = c.issue_at(&b, NOW, &mut Pads(16)).unwrap();
    assert_eq!(
        c.check_at(&null, &b, token.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::OriginMismatch
    );
    // "null" can never be allowlisted.
    assert_eq!(
        Csrf::builder()
            .key(KeyId(0), KEY)
            .allow_origin("null")
            .build()
            .unwrap_err(),
        Error::InvalidOrigin
    );
    // A stripped Referer is not a pass: the token still decides.
    let stripped = post();
    assert_eq!(
        c.check_at(&stripped, &b, b"", NOW).unwrap_err().reason(),
        Reason::Missing
    );
    // A Referer that points at the site through user information is refused.
    let trick = post().referer("https://bank.example@evil.example/");
    assert_eq!(
        c.check_at(&trick, &b, token.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::OriginMismatch
    );
}

/// T15: cross-site top-level POST navigation (a form that navigates the whole
/// window). Fetch Metadata marks it cross-site, and it is refused in every mode
/// that runs the policy.
#[test]
fn t15_cross_site_navigation_post_is_refused() {
    let b = Binding::new("s");
    let nav = post()
        .fetch_site("cross-site")
        .origin("https://evil.example");
    for mode in [Mode::Strict, Mode::PolicyOnly] {
        let c = Csrf::builder()
            .key(KeyId(0), KEY)
            .mode(mode)
            .build()
            .unwrap();
        let token = c.issue_at(&b, NOW, &mut Pads(17)).unwrap();
        assert_eq!(
            c.check_at(&nav, &b, token.as_bytes(), NOW)
                .unwrap_err()
                .reason(),
            Reason::CrossSite,
            "{mode:?}"
        );
    }
    assert_eq!(FetchSite::parse(b"cross-site"), Some(FetchSite::CrossSite));
}
