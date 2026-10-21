//! Token invariants, tested exhaustively where the space is small enough and
//! with a seeded generator where it is not.
//!
//! - issue-then-verify always passes;
//! - any change to any character, and any single-bit change to the decoded
//!   token, is rejected;
//! - a token never verifies under another session id, scope, or key;
//! - failure reasons are decided after the MAC.

use std::time::Duration;

use csrf_sec::{Binding, Csrf, Error, KeyId, PadSource, Reason, TOKEN_LEN};

const KEY: [u8; 32] = *b"integration test key, 32 bytes!!";
const OTHER_KEY: [u8; 32] = *b"a different key of 32 bytes!!!!!";
/// 2026-10-21T00:00:00Z.
const NOW: u64 = 1_792_540_800;

/// Deterministic pad source for reproducible tests (xorshift64*). Not a CSPRNG:
/// only for tests.
struct TestPads(u64);

impl PadSource for TestPads {
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

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn value(c: u8) -> u8 {
    ALPHABET.iter().position(|&a| a == c).unwrap() as u8
}

fn decode(text: &[u8]) -> Vec<u8> {
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for &c in text {
        bits = (bits << 6) | u32::from(value(c));
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    out
}

fn encode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let v = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((v >> (18 - 6 * i)) & 63) as usize]);
        }
    }
    out
}

fn csrf() -> Csrf {
    Csrf::new(KEY).unwrap()
}

#[test]
fn test_issue_verify_round_trip_many_sessions_and_scopes() {
    let c = csrf();
    let mut pads = TestPads(0x9e37_79b9_7f4a_7c15);
    for i in 0..500u32 {
        let session = format!("session-{i}-{}", "x".repeat((i % 70) as usize));
        let scope = if i % 3 == 0 {
            String::new()
        } else {
            format!("POST /form/{i}")
        };
        let b = Binding::new(&session).scope(&scope);
        let t = c.issue_at(&b, NOW, &mut pads).unwrap();
        assert_eq!(t.len(), TOKEN_LEN);
        assert!(t.bytes().all(|ch| ALPHABET.contains(&ch)));
        assert!(c.verify_at(&b, t.as_bytes(), NOW).is_ok(), "{i}");
    }
}

#[test]
fn test_issue_every_token_text_is_different() {
    let c = csrf();
    let mut pads = TestPads(7);
    let b = Binding::new("one session");
    let mut seen = std::collections::HashSet::new();
    for _ in 0..2_000 {
        let t = c.issue_at(&b, NOW, &mut pads).unwrap();
        assert!(seen.insert(t.as_str().to_owned()));
    }
}

#[cfg(feature = "std")]
#[test]
fn test_issue_tier1_uses_os_randomness_and_verifies() {
    let c = csrf();
    let a = c.issue("s").unwrap();
    let b = c.issue("s").unwrap();
    assert_ne!(a.as_str(), b.as_str());
    assert!(c.verify("s", &a).is_ok());
    assert!(c.verify("s", b.as_str()).is_ok());
    assert!(
        c.verify(String::from("s"), String::from(b.as_str()))
            .is_ok()
    );
    assert!(c.verify(b"s", b.as_bytes()).is_ok());
}

#[test]
fn test_any_character_change_is_rejected() {
    let c = csrf();
    let b = Binding::new("victim-session");
    let t = c.issue_at(&b, NOW, &mut TestPads(3)).unwrap();
    let text = t.as_bytes().to_vec();
    for pos in 0..text.len() {
        for replacement in 0u8..=255 {
            if replacement == text[pos] {
                continue;
            }
            let mut forged = text.clone();
            forged[pos] = replacement;
            let r = c.verify_at(&b, &forged, NOW);
            assert!(
                r.is_err(),
                "position {pos} byte {replacement:#04x} verified"
            );
        }
    }
}

#[test]
fn test_any_single_bit_flip_in_decoded_token_is_rejected() {
    let c = csrf();
    let b = Binding::new("victim-session").scope("POST /pay");
    let t = c.issue_at(&b, NOW, &mut TestPads(11)).unwrap();
    let bytes = decode(t.as_bytes());
    assert_eq!(bytes.len(), 44);
    assert_eq!(encode(&bytes), t.as_bytes(), "test codec agrees");
    for bit in 0..bytes.len() * 8 {
        let mut flipped = bytes.clone();
        flipped[bit / 8] ^= 1 << (bit % 8);
        let forged = encode(&flipped);
        let reason = c.verify_at(&b, &forged, NOW).unwrap_err().reason();
        // Flipping a pad bit and the same body bit together is the only way to
        // keep the raw token intact; one bit alone always changes it.
        assert!(
            matches!(
                reason,
                Reason::BadMac | Reason::Malformed | Reason::UnknownKey
            ),
            "bit {bit}: {reason:?}"
        );
    }
}

#[test]
fn test_remasking_a_token_with_another_pad_still_verifies() {
    // Masking is not a secret: anyone holding a token can remask it. This is
    // expected and harmless (it only proves the holder already had a valid
    // token); the test pins the property so nobody mistakes it for a bug.
    let c = csrf();
    let b = Binding::new("s");
    let t = c.issue_at(&b, NOW, &mut TestPads(5)).unwrap();
    let bytes = decode(t.as_bytes());
    let (pad, body) = bytes.split_at(22);
    let raw: Vec<u8> = body.iter().zip(pad).map(|(m, p)| m ^ p).collect();
    let new_pad = [0x42u8; 22];
    let mut remasked = new_pad.to_vec();
    remasked.extend(raw.iter().zip(new_pad).map(|(r, p)| r ^ p));
    assert!(c.verify_at(&b, &encode(&remasked), NOW).is_ok());
}

#[test]
fn test_token_never_verifies_for_another_session() {
    let c = csrf();
    let mut pads = TestPads(13);
    for i in 0..200 {
        let mine = format!("session-{i}");
        let t = c.issue_at(&Binding::new(&mine), NOW, &mut pads).unwrap();
        for other in [
            format!("session-{}", i + 1),
            format!("{mine} "),
            mine[1..].to_string(),
            mine.to_uppercase(),
        ] {
            let r = c.verify_at(&Binding::new(&other), t.as_bytes(), NOW);
            assert_eq!(r.unwrap_err().reason(), Reason::BadMac, "{mine} vs {other}");
        }
    }
}

#[test]
fn test_session_scope_boundary_is_canonical() {
    // ("ab", "c") and ("a", "bc") must be different bindings.
    let c = csrf();
    let t = c
        .issue_at(&Binding::new("ab").scope("c"), NOW, &mut TestPads(17))
        .unwrap();
    assert_eq!(
        c.verify_at(&Binding::new("a").scope("bc"), t.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::BadMac
    );
    assert!(
        c.verify_at(&Binding::new("ab").scope("c"), t.as_bytes(), NOW)
            .is_ok()
    );
}

#[test]
fn test_token_never_verifies_under_another_key() {
    let c = csrf();
    let other = Csrf::new(OTHER_KEY).unwrap();
    let b = Binding::new("s");
    let t = c.issue_at(&b, NOW, &mut TestPads(19)).unwrap();
    assert_eq!(
        other.verify_at(&b, t.as_bytes(), NOW).unwrap_err().reason(),
        Reason::BadMac
    );
    // Same key bytes under another id: still refused.
    let other_id = Csrf::builder().key(KeyId(9), KEY).build().unwrap();
    assert_eq!(
        other_id
            .verify_at(&b, t.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::UnknownKey
    );
}

#[test]
fn test_scope_reasons() {
    let c = csrf();
    let mut pads = TestPads(23);
    let email = Binding::new("s").scope("POST /account/email");
    let pay = Binding::new("s").scope("POST /pay");
    let plain = Binding::new("s");

    let unscoped = c.issue_at(&plain, NOW, &mut pads).unwrap();
    assert_eq!(
        c.verify_at(&email, unscoped.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::WrongScope
    );

    let for_pay = c.issue_at(&pay, NOW, &mut pads).unwrap();
    assert_eq!(
        c.verify_at(&email, for_pay.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::BadMac
    );
    assert_eq!(
        c.verify_at(&plain, for_pay.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::BadMac
    );
    assert!(c.verify_at(&pay, for_pay.as_bytes(), NOW).is_ok());
}

#[test]
fn test_previous_session_reports_stale_and_never_passes() {
    let c = csrf();
    let mut pads = TestPads(29);
    let old = c
        .issue_at(&Binding::new("guest-session"), NOW, &mut pads)
        .unwrap();
    let after_login = Binding::new("user-session").previous_session("guest-session");
    assert_eq!(
        c.verify_at(&after_login, old.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::StaleSession
    );
    let forged_for_other = c
        .issue_at(&Binding::new("someone-else"), NOW, &mut pads)
        .unwrap();
    assert_eq!(
        c.verify_at(&after_login, forged_for_other.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::BadMac
    );
    let fresh = c
        .issue_at(&Binding::new("user-session"), NOW, &mut pads)
        .unwrap();
    assert!(c.verify_at(&after_login, fresh.as_bytes(), NOW).is_ok());
}

#[test]
fn test_mac_is_checked_before_expiry() {
    let c = Csrf::builder()
        .key(KeyId(0), KEY)
        .lifetime(Duration::from_secs(60))
        .build()
        .unwrap();
    let b = Binding::new("s");
    let t = c.issue_at(&b, NOW, &mut TestPads(31)).unwrap();
    // An expired real token is Expired; the same token for another session is
    // a forgery, not Expired.
    assert_eq!(
        c.verify_at(&b, t.as_bytes(), NOW + 61)
            .unwrap_err()
            .reason(),
        Reason::Expired
    );
    assert_eq!(
        c.verify_at(&Binding::new("x"), t.as_bytes(), NOW + 61)
            .unwrap_err()
            .reason(),
        Reason::BadMac
    );
}

#[test]
fn test_malformed_inputs() {
    let c = csrf();
    let b = Binding::new("s");
    let t = c.issue_at(&b, NOW, &mut TestPads(37)).unwrap();
    let text = t.as_bytes();
    assert_eq!(
        c.verify_at(&b, b"", NOW).unwrap_err().reason(),
        Reason::Missing
    );
    assert_eq!(
        c.verify_at(&b, &text[..58], NOW).unwrap_err().reason(),
        Reason::Malformed
    );
    let mut long = text.to_vec();
    long.push(b'A');
    assert_eq!(
        c.verify_at(&b, &long, NOW).unwrap_err().reason(),
        Reason::Malformed
    );
    let mut padded = text.to_vec();
    padded.push(b'=');
    assert_eq!(
        c.verify_at(&b, &padded, NOW).unwrap_err().reason(),
        Reason::Malformed
    );
    assert_eq!(
        c.verify_at(&b, &[b'A'; 59], NOW).unwrap_err().reason(),
        Reason::Malformed
    );
    assert_eq!(
        c.verify_at(&b, &vec![b'x'; 1 << 20], NOW)
            .unwrap_err()
            .reason(),
        Reason::Malformed
    );
    let mut spaced = text.to_vec();
    spaced[0] = b' ';
    assert_eq!(
        c.verify_at(&b, &spaced, NOW).unwrap_err().reason(),
        Reason::Malformed
    );
}

#[test]
fn test_unknown_version_is_malformed() {
    let c = csrf();
    let b = Binding::new("s");
    let t = c.issue_at(&b, NOW, &mut TestPads(41)).unwrap();
    let mut bytes = decode(t.as_bytes());
    for version in [0u8, 2, 3, 0x80, 0xff] {
        // raw[0] = body[0] ^ pad[0]
        bytes[22] = version ^ bytes[0];
        let r = c.verify_at(&b, &encode(&bytes), NOW);
        assert_eq!(
            r.unwrap_err().reason(),
            Reason::Malformed,
            "version {version}"
        );
    }
}

#[cfg(feature = "std")]
#[test]
fn test_empty_session_never_binds() {
    let c = csrf();
    assert_eq!(c.issue("").unwrap_err(), Error::EmptySession);
    let t = c.issue("s").unwrap();
    assert_eq!(c.verify("", &t).unwrap_err().reason(), Reason::Unverifiable);
}

#[test]
fn test_long_session_and_scope_values() {
    let c = csrf();
    let session = vec![0xa5u8; 100_000];
    let scope = vec![b'/'; 70_000];
    let b = Binding::new(&session).scope(&scope);
    let t = c.issue_at(&b, NOW, &mut TestPads(43)).unwrap();
    assert!(c.verify_at(&b, t.as_bytes(), NOW).is_ok());
    let mut other = session.clone();
    other[99_999] ^= 1;
    assert_eq!(
        c.verify_at(&Binding::new(&other).scope(&scope), t.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::BadMac
    );
}

#[test]
fn test_token_matches_independent_implementation_of_the_format() {
    // Rebuild a token from docs/API.md "Token format" using crypt-io directly,
    // and compare byte for byte. Any drift between the documented format and
    // the code fails here.
    let session = b"kat-session";
    let scope = b"POST /kat";
    let c = csrf();
    let token = c
        .issue_at(&Binding::new(session).scope(scope), NOW, &mut TestPads(1))
        .unwrap();

    let mut label = b"csrf-sec/v1 session-token mac key".to_vec();
    label.push(0); // key id 0
    let subkey = crypt_io::mac::blake3_keyed(&KEY, &label);

    let issued_at = (NOW - 1_577_836_800) as u32;
    let mut raw = vec![1u8, 0];
    raw.extend_from_slice(&issued_at.to_le_bytes());
    let mut input = raw.clone();
    input.push(session.len() as u8); // varint, < 128
    input.push(scope.len() as u8);
    input.extend_from_slice(session);
    input.extend_from_slice(scope);
    let tag = crypt_io::mac::blake3_keyed(&subkey, &input);
    raw.extend_from_slice(&tag[..16]);
    assert_eq!(raw.len(), 22);

    let mut pad = [0u8; 22];
    TestPads(1).fill(&mut pad).unwrap();
    let mut masked = pad.to_vec();
    masked.extend(raw.iter().zip(pad).map(|(r, p)| r ^ p));
    assert_eq!(token.as_bytes(), encode(&masked).as_slice());
}
