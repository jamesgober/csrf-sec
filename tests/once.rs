//! One-time tokens: pass exactly once, forged tokens never reach the store,
//! issuing never touches it, and a failing store fails closed.

#![cfg(feature = "std")]

use std::{
    collections::HashSet,
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use csrf_sec::{
    Binding, Csrf, Error, KeyId, MemoryStore, Mode, NonceStore, NonceUse, ONCE_TOKEN_LEN,
    PadSource, Reason, RequestFacts, StoreError,
};

const KEY: [u8; 32] = *b"one-time token tests, 32 bytes!!";
const NOW: u64 = 1_792_540_800;

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

/// Session, issued at, expires at, now: the last record a store received.
type LastUse = Option<(Vec<u8>, u64, u64, u64)>;

/// A store that records every call, to prove what reaches it.
#[derive(Default)]
struct SpyStore {
    used: Mutex<HashSet<[u8; 16]>>,
    calls: AtomicUsize,
    last: Mutex<LastUse>,
    fail: bool,
}

impl NonceStore for SpyStore {
    fn consume(&self, u: &NonceUse<'_>) -> Result<bool, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last.lock().unwrap() = Some((u.session.to_vec(), u.issued_at, u.expires_at, u.now));
        if self.fail {
            return Err(StoreError::Unavailable);
        }
        Ok(self.used.lock().unwrap().insert(u.nonce))
    }
}

fn csrf() -> Csrf {
    Csrf::new(KEY).unwrap()
}

fn store() -> MemoryStore {
    MemoryStore::starting_at(64_000, NOW - 3600)
}

#[test]
fn test_once_token_passes_exactly_once() {
    let c = csrf();
    let store = store();
    let b = Binding::new("s").scope("POST /pay").once(&store);
    let t = c.issue_at(&b, NOW, &mut TestPads(1)).unwrap();
    assert_eq!(t.len(), ONCE_TOKEN_LEN);
    assert!(store.is_empty(), "issuing never touches the store");
    assert!(c.verify_at(&b, t.as_bytes(), NOW).is_ok());
    assert_eq!(store.len(), 1);
    assert_eq!(
        c.verify_at(&b, t.as_bytes(), NOW).unwrap_err().reason(),
        Reason::AlreadyUsed
    );
}

#[test]
fn test_once_tokens_are_independent() {
    let c = csrf();
    let store = store();
    let b = Binding::new("s").once(&store);
    let mut pads = TestPads(2);
    let tokens: Vec<_> = (0..20)
        .map(|_| c.issue_at(&b, NOW, &mut pads).unwrap())
        .collect();
    for t in tokens.iter().rev() {
        assert!(c.verify_at(&b, t.as_bytes(), NOW).is_ok());
    }
    for t in &tokens {
        assert_eq!(
            c.verify_at(&b, t.as_bytes(), NOW).unwrap_err().reason(),
            Reason::AlreadyUsed
        );
    }
}

#[test]
fn test_store_receives_the_documented_record() {
    let c = Csrf::builder()
        .key(KeyId(0), KEY)
        .lifetime(std::time::Duration::from_secs(600))
        .skew(std::time::Duration::from_secs(30))
        .build()
        .unwrap();
    let spy = SpyStore::default();
    let b = Binding::new("victim").once(&spy);
    let t = c.issue_at(&b, NOW, &mut TestPads(3)).unwrap();
    assert_eq!(spy.calls.load(Ordering::SeqCst), 0);
    assert!(c.verify_at(&b, t.as_bytes(), NOW + 5).is_ok());
    let (session, issued_at, expires_at, now) = spy.last.lock().unwrap().clone().unwrap();
    assert_eq!(session, b"victim");
    assert_eq!(issued_at, NOW);
    assert_eq!(expires_at, NOW + 600 + 30, "lifetime plus skew");
    assert_eq!(now, NOW + 5);
}

#[test]
fn test_forged_and_wrong_tokens_never_reach_the_store() {
    let c = csrf();
    let store = SpyStore::default();
    let b = Binding::new("victim").scope("POST /pay").once(&store);
    let t = c.issue_at(&b, NOW, &mut TestPads(4)).unwrap();

    // Every single-character change.
    let text = t.as_bytes().to_vec();
    for pos in 0..text.len() {
        for replacement in *b"Az0-_= " {
            if replacement == text[pos] {
                continue;
            }
            let mut forged = text.clone();
            forged[pos] = replacement;
            assert!(c.verify_at(&b, &forged, NOW).is_err());
        }
    }
    // Another session, another scope, expired, from the future, another key,
    // a session token, nothing.
    let other = Binding::new("attacker").scope("POST /pay").once(&store);
    assert_eq!(
        c.verify_at(&other, t.as_bytes(), NOW).unwrap_err().reason(),
        Reason::BadMac
    );
    let other_scope = Binding::new("victim").scope("POST /other").once(&store);
    assert_eq!(
        c.verify_at(&other_scope, t.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::BadMac
    );
    let late = NOW + 13 * 3600;
    assert_eq!(
        c.verify_at(&b, t.as_bytes(), late).unwrap_err().reason(),
        Reason::Expired
    );
    assert_eq!(
        c.verify_at(&b, t.as_bytes(), NOW - 3600)
            .unwrap_err()
            .reason(),
        Reason::NotYetValid
    );
    let foreign = Csrf::new(*b"another key entirely, 32 bytes!!").unwrap();
    assert_eq!(
        foreign
            .verify_at(&b, t.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::BadMac
    );
    let session_token = c
        .issue_at(
            &Binding::new("victim").scope("POST /pay"),
            NOW,
            &mut TestPads(5),
        )
        .unwrap();
    assert_eq!(
        c.verify_at(&b, session_token.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::Malformed
    );
    assert_eq!(
        c.verify_at(&b, b"", NOW).unwrap_err().reason(),
        Reason::Missing
    );

    assert_eq!(
        store.calls.load(Ordering::SeqCst),
        0,
        "nothing forged reached the store"
    );
    // The genuine token still works afterwards: nobody burned it.
    assert!(c.verify_at(&b, t.as_bytes(), NOW).is_ok());
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn test_once_token_is_not_a_session_token() {
    let c = csrf();
    let store = store();
    let once = Binding::new("s").once(&store);
    let t = c.issue_at(&once, NOW, &mut TestPads(6)).unwrap();
    assert_eq!(
        c.verify_at(&Binding::new("s"), t.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::Malformed
    );
}

#[test]
fn test_store_failure_fails_closed() {
    let c = csrf();
    let failing = SpyStore {
        fail: true,
        ..SpyStore::default()
    };
    let b = Binding::new("s").once(&failing);
    let t = c.issue_at(&b, NOW, &mut TestPads(7)).unwrap();
    assert_eq!(
        c.verify_at(&b, t.as_bytes(), NOW).unwrap_err().reason(),
        Reason::StoreUnavailable
    );
}

#[test]
fn test_full_store_refuses_rather_than_forgets() {
    let c = csrf();
    let store = MemoryStore::starting_at(0, NOW - 3600); // one record per shard
    let mut pads = TestPads(8);
    let mut passed = 0;
    let mut refused = 0;
    for i in 0..1000 {
        // Many sessions: one session alone is stopped by its own quota first.
        let session = format!("s{i}");
        let b = Binding::new(&session).once(&store);
        let t = c.issue_at(&b, NOW, &mut pads).unwrap();
        match c.verify_at(&b, t.as_bytes(), NOW) {
            Ok(_) => passed += 1,
            Err(r) if r.reason() == Reason::StoreUnavailable => refused += 1,
            Err(r) => panic!("{r}"),
        }
    }
    assert!(
        passed <= 64 && refused > 0,
        "passed {passed}, refused {refused}"
    );
    assert_eq!(store.len(), passed);
}

#[test]
fn test_restarted_memory_store_refuses_older_tokens() {
    let c = csrf();
    let before = store();
    let b = Binding::new("s").once(&before);
    let t = c.issue_at(&b, NOW, &mut TestPads(9)).unwrap();
    assert!(c.verify_at(&b, t.as_bytes(), NOW).is_ok());
    // The process restarts: a new, empty store that started after the token.
    let after = MemoryStore::starting_at(1000, NOW + 10);
    let b = Binding::new("s").once(&after);
    assert_eq!(
        c.verify_at(&b, t.as_bytes(), NOW + 20)
            .unwrap_err()
            .reason(),
        Reason::AlreadyUsed
    );
    // Tokens issued after the restart work.
    let fresh = c.issue_at(&b, NOW + 11, &mut TestPads(10)).unwrap();
    assert!(c.verify_at(&b, fresh.as_bytes(), NOW + 20).is_ok());
}

#[test]
fn test_concurrent_verifies_of_one_token_exactly_one_passes() {
    let c = Arc::new(csrf());
    let store = Arc::new(store());
    for round in 0..20u64 {
        let token = {
            let b = Binding::new("s").once(&*store);
            c.issue_at(&b, NOW, &mut TestPads(100 + round)).unwrap()
        };
        let threads = 8;
        let barrier = Arc::new(Barrier::new(threads));
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let (c, store, barrier, token) = (
                    Arc::clone(&c),
                    Arc::clone(&store),
                    Arc::clone(&barrier),
                    token.clone(),
                );
                std::thread::spawn(move || {
                    let b = Binding::new("s").once(&*store);
                    barrier.wait();
                    c.verify_at(&b, token.as_bytes(), NOW).is_ok()
                })
            })
            .collect();
        let passes = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|&p| p)
            .count();
        assert_eq!(passes, 1, "round {round}");
    }
}

#[test]
fn test_once_binding_checks_the_token_in_every_mode() {
    let store = store();
    let b = Binding::new("s").once(&store);
    let same = RequestFacts::new("POST").fetch_site("same-origin");
    for (i, mode) in [Mode::Strict, Mode::TokenOnly, Mode::PolicyOnly]
        .into_iter()
        .enumerate()
    {
        let c = Csrf::builder()
            .key(KeyId(0), KEY)
            .mode(mode)
            .build()
            .unwrap();
        assert_eq!(
            c.check_at(&same, &b, b"", NOW).unwrap_err().reason(),
            Reason::Missing,
            "{mode:?}"
        );
        let t = c.issue_at(&b, NOW, &mut TestPads(11 + i as u64)).unwrap();
        let v = c.check_at(&same, &b, t.as_bytes(), NOW).unwrap();
        assert!(v.token_checked(), "{mode:?}");
        assert_eq!(
            c.check_at(&same, &b, t.as_bytes(), NOW)
                .unwrap_err()
                .reason(),
            Reason::AlreadyUsed,
            "{mode:?}"
        );
    }
    // A safe method needs nothing on a plain binding, but a one-time binding
    // always checks its token (D-093).
    let c = Csrf::builder()
        .key(KeyId(0), KEY)
        .mode(Mode::PolicyOnly)
        .build()
        .unwrap();
    let get = RequestFacts::new("GET");
    assert!(c.check_at(&get, &Binding::new("s"), b"", NOW).is_ok());
    assert_eq!(
        c.check_at(&get, &b, b"", NOW).unwrap_err().reason(),
        Reason::Missing
    );
}

#[test]
fn test_once_rotation_keeps_outstanding_tokens() {
    let c = csrf();
    let store = store();
    let b = Binding::new("s").once(&store);
    let t = c.issue_at(&b, NOW, &mut TestPads(12)).unwrap();
    let c2 = c
        .rotated_at(KeyId(1), *b"rotated key for once tests......", NOW)
        .unwrap();
    assert!(
        c2.verify_at(&b, t.as_bytes(), NOW + 10)
            .unwrap()
            .retired_key()
    );
}

#[test]
fn test_once_token_matches_independent_implementation_of_the_format() {
    // Rebuild a version-2 token from docs/API.md "Token format" with crypt-io.
    let session = b"kat-session";
    let scope = b"POST /kat";
    let store = store();
    let c = csrf();
    let token = c
        .issue_at(
            &Binding::new(session).scope(scope).once(&store),
            NOW,
            &mut TestPads(1),
        )
        .unwrap();

    // The nonce is drawn first, then the pad, from the same source.
    let mut pads = TestPads(1);
    let mut nonce = [0u8; 16];
    pads.fill(&mut nonce).unwrap();

    let mut label = b"csrf-sec/v1 one-time-token mac key".to_vec();
    label.push(0);
    let subkey = crypt_io::mac::blake3_keyed(&KEY, &label);
    let mut raw = vec![2u8, 0];
    raw.extend_from_slice(&((NOW - 1_577_836_800) as u32).to_le_bytes());
    raw.extend_from_slice(&nonce);
    let mut input = raw.clone();
    input.push(session.len() as u8);
    input.push(scope.len() as u8);
    input.extend_from_slice(session);
    input.extend_from_slice(scope);
    raw.extend_from_slice(&crypt_io::mac::blake3_keyed(&subkey, &input)[..16]);
    assert_eq!(raw.len(), 38);

    let mut pad = [0u8; 38];
    pads.fill(&mut pad).unwrap();
    let mut masked = pad.to_vec();
    masked.extend(raw.iter().zip(pad).map(|(r, p)| r ^ p));
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut text = Vec::new();
    for chunk in masked.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let v = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            text.push(ALPHABET[((v >> (18 - 6 * i)) & 63) as usize]);
        }
    }
    assert_eq!(token.as_bytes(), text.as_slice());
}

#[test]
fn test_tier2_once_with_a_store_that_started_earlier() {
    let c = csrf();
    // MemoryStore::new refuses tokens issued in its own first second; a store
    // that started a minute ago accepts tokens issued now.
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 60;
    let store = MemoryStore::starting_at(100, started);
    let pay = Binding::new("session-1").scope("POST /pay").once(&store);
    let t = c.issue_with(&pay).unwrap();
    assert!(c.verify_with(&pay, &t).is_ok());
    assert_eq!(
        c.verify_with(&pay, &t).unwrap_err().reason(),
        Reason::AlreadyUsed
    );
}
