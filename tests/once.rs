//! One-time tokens: pass exactly once, forged tokens never reach the store,
//! and a failing store fails closed.

#![cfg(feature = "std")]

use std::{
    collections::HashMap,
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use csrf_sec::{
    Binding, Csrf, Error, KeyId, MemoryStore, Mode, NonceStore, ONCE_TOKEN_LEN, PadSource, Reason,
    RequestFacts, StoreError,
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

/// A store that records every call, to prove what reaches it.
#[derive(Default)]
struct SpyStore {
    nonces: Mutex<HashMap<[u8; 16], u64>>,
    inserts: AtomicUsize,
    takes: AtomicUsize,
    fail_take: bool,
    fail_insert: bool,
}

impl NonceStore for SpyStore {
    fn insert(
        &self,
        _: &[u8],
        nonce: &[u8; 16],
        _: u64,
        expires_at: u64,
    ) -> Result<(), StoreError> {
        self.inserts.fetch_add(1, Ordering::SeqCst);
        if self.fail_insert {
            return Err(StoreError::Unavailable);
        }
        self.nonces.lock().unwrap().insert(*nonce, expires_at);
        Ok(())
    }

    fn take(&self, _: &[u8], nonce: &[u8; 16], now: u64) -> Result<bool, StoreError> {
        self.takes.fetch_add(1, Ordering::SeqCst);
        if self.fail_take {
            return Err(StoreError::Unavailable);
        }
        Ok(self
            .nonces
            .lock()
            .unwrap()
            .remove(nonce)
            .is_some_and(|e| e >= now))
    }
}

fn csrf() -> Csrf {
    Csrf::new(KEY).unwrap()
}

#[test]
fn test_once_token_passes_exactly_once() {
    let c = csrf();
    let store = MemoryStore::new(1000);
    let b = Binding::new("s").scope("POST /pay").once(&store);
    let t = c.issue_at(&b, NOW, &mut TestPads(1)).unwrap();
    assert_eq!(t.len(), ONCE_TOKEN_LEN);
    assert_eq!(store.len(), 1);
    assert!(c.verify_at(&b, t.as_bytes(), NOW).is_ok());
    assert_eq!(
        c.verify_at(&b, t.as_bytes(), NOW).unwrap_err().reason(),
        Reason::AlreadyUsed
    );
    assert!(store.is_empty());
}

#[test]
fn test_once_tokens_are_independent() {
    let c = csrf();
    let store = MemoryStore::new(1000);
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
fn test_forged_and_wrong_tokens_never_reach_the_store() {
    let c = csrf();
    let store = SpyStore::default();
    let b = Binding::new("victim").scope("POST /pay").once(&store);
    let t = c.issue_at(&b, NOW, &mut TestPads(3)).unwrap();
    assert_eq!(store.inserts.load(Ordering::SeqCst), 1);

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
    // Another session, another scope, no scope, expired, from the future,
    // another key, a session token.
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
            &mut TestPads(4),
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
        store.takes.load(Ordering::SeqCst),
        0,
        "nothing forged reached the store"
    );
    // The genuine token still works afterwards: nobody burned it.
    assert!(c.verify_at(&b, t.as_bytes(), NOW).is_ok());
    assert_eq!(store.takes.load(Ordering::SeqCst), 1);
}

#[test]
fn test_once_token_is_not_a_session_token() {
    let c = csrf();
    let store = MemoryStore::new(10);
    let once = Binding::new("s").once(&store);
    let t = c.issue_at(&once, NOW, &mut TestPads(5)).unwrap();
    assert_eq!(
        c.verify_at(&Binding::new("s"), t.as_bytes(), NOW)
            .unwrap_err()
            .reason(),
        Reason::Malformed
    );
}

#[test]
fn test_store_failures_fail_closed() {
    let c = csrf();
    let failing_insert = SpyStore {
        fail_insert: true,
        ..SpyStore::default()
    };
    let b = Binding::new("s").once(&failing_insert);
    assert_eq!(
        c.issue_at(&b, NOW, &mut TestPads(6)).unwrap_err(),
        Error::Store(StoreError::Unavailable)
    );

    let failing_take = SpyStore {
        fail_take: true,
        ..SpyStore::default()
    };
    let b = Binding::new("s").once(&failing_take);
    let t = c.issue_at(&b, NOW, &mut TestPads(7)).unwrap();
    assert_eq!(
        c.verify_at(&b, t.as_bytes(), NOW).unwrap_err().reason(),
        Reason::StoreUnavailable
    );
}

#[test]
fn test_full_store_refuses_to_issue() {
    let c = csrf();
    let store = MemoryStore::new(0); // one nonce per shard
    let b = Binding::new("s").once(&store);
    let mut pads = TestPads(8);
    let mut issued = 0;
    let mut full = 0;
    for _ in 0..1000 {
        match c.issue_at(&b, NOW, &mut pads) {
            Ok(_) => issued += 1,
            Err(Error::Store(StoreError::Full)) => full += 1,
            Err(e) => panic!("{e}"),
        }
    }
    assert!(issued <= 64 && full > 0, "issued {issued}, refused {full}");
    assert_eq!(store.len(), issued);
}

#[test]
fn test_concurrent_verifies_of_one_token_exactly_one_passes() {
    let c = Arc::new(csrf());
    let store = Arc::new(MemoryStore::new(1000));
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
    let store = MemoryStore::new(100);
    let b = Binding::new("s").once(&store);
    let same = RequestFacts::new("POST").fetch_site("same-origin");
    for mode in [Mode::Strict, Mode::TokenOnly, Mode::PolicyOnly] {
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
        let t = c.issue_at(&b, NOW, &mut TestPads(9)).unwrap();
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
    // A safe method still needs nothing.
    let c = Csrf::builder()
        .key(KeyId(0), KEY)
        .mode(Mode::PolicyOnly)
        .build()
        .unwrap();
    assert!(c.check_at(&RequestFacts::new("GET"), &b, b"", NOW).is_ok());
}

#[test]
fn test_once_rotation_keeps_outstanding_tokens() {
    let c = csrf();
    let store = MemoryStore::new(100);
    let b = Binding::new("s").once(&store);
    let t = c.issue_at(&b, NOW, &mut TestPads(10)).unwrap();
    let c2 = c
        .rotated_at(KeyId(1), *b"rotated key for once tests......", NOW)
        .unwrap();
    let v = c2.verify_at(&b, t.as_bytes(), NOW + 10).unwrap();
    assert!(v.retired_key());
}

#[test]
fn test_once_token_matches_independent_implementation_of_the_format() {
    // Rebuild a version-2 token from docs/API.md "Token format" with crypt-io.
    struct Recorder(Mutex<Option<[u8; 16]>>);
    impl NonceStore for Recorder {
        fn insert(&self, _: &[u8], n: &[u8; 16], _: u64, _: u64) -> Result<(), StoreError> {
            *self.0.lock().unwrap() = Some(*n);
            Ok(())
        }
        fn take(&self, _: &[u8], _: &[u8; 16], _: u64) -> Result<bool, StoreError> {
            Ok(true)
        }
    }
    let store = Recorder(Mutex::new(None));
    let session = b"kat-session";
    let scope = b"POST /kat";
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
    assert_eq!(store.0.lock().unwrap().unwrap(), nonce);

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
fn test_tier2_once_with_memory_store() {
    let c = csrf();
    let store = MemoryStore::new(100);
    let pay = Binding::new("session-1").scope("POST /pay").once(&store);
    let t = c.issue_with(&pay).unwrap();
    assert!(c.verify_with(&pay, &t).is_ok());
    assert_eq!(
        c.verify_with(&pay, &t).unwrap_err().reason(),
        Reason::AlreadyUsed
    );
}
