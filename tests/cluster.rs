//! Clusters: several nodes, each its own `Csrf` built from the same
//! configuration (as on separate machines), sharing one one-time store.
//!
//! The shared store here has the contract of a networked key-value store
//! (Redis `SET key NX PX ttl`, say): set-if-absent with an expiry, nothing
//! more. The tests show that contract is enough: every one-time token passes
//! exactly once across the cluster, under concurrency, clock differences
//! within the skew, two-step key rotation, and store outages.

#![cfg(feature = "std")]

use std::{
    collections::HashMap,
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use csrf_sec::{
    Binding, Csrf, Error, KeyId, MemoryStore, NonceStore, NonceUse, PadSource, Reason, StoreError,
    Token,
};

const KEY_0: [u8; 32] = *b"cluster tests, key zero, 32 b..!";
const KEY_1: [u8; 32] = *b"cluster tests, key one, 32 by..!";
const NOW: u64 = 1_792_540_800;
const LIFETIME: u64 = 3600;
const ONCE: u64 = 600;
const SKEW: u64 = 60;

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

/// A shared store with only set-if-absent and expiry, the contract of a
/// networked key-value store. It can be switched off to model an outage.
#[derive(Default)]
struct SharedStore {
    records: Mutex<HashMap<[u8; 16], u64>>,
    calls: AtomicUsize,
    down: AtomicBool,
}

impl NonceStore for SharedStore {
    fn consume(&self, u: &NonceUse<'_>) -> Result<bool, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.down.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable);
        }
        let mut records = self.records.lock().unwrap();
        // The store's own expiry: a record is gone once its time has passed.
        records.retain(|_, expires_at| *expires_at >= u.now);
        if records.contains_key(&u.nonce) {
            return Ok(false);
        }
        records.insert(u.nonce, u.expires_at);
        Ok(true)
    }
}

/// One node's configuration, built the way every node in the cluster builds it.
fn node(keys: impl FnOnce(csrf_sec::Builder) -> csrf_sec::Builder) -> Csrf {
    keys(Csrf::builder())
        .lifetime(Duration::from_secs(LIFETIME))
        .once_lifetime(Duration::from_secs(ONCE))
        .skew(Duration::from_secs(SKEW))
        .build()
        .unwrap()
}

fn node_on_key_0() -> Csrf {
    node(|b| b.key(KeyId(0), KEY_0))
}

/// Every node tries every token at once; returns how often each token passed
/// and every reason a refused attempt gave.
fn race<S: NonceStore + Send + Sync + 'static>(
    nodes: &[Arc<Csrf>],
    store: &Arc<S>,
    tokens: &Arc<Vec<(String, Token)>>,
) -> (Vec<usize>, Vec<Reason>) {
    let barrier = Arc::new(Barrier::new(nodes.len()));
    let handles: Vec<_> = nodes
        .iter()
        .enumerate()
        .map(|(n, node)| {
            let (node, store, tokens, barrier) = (
                Arc::clone(node),
                Arc::clone(store),
                Arc::clone(tokens),
                Arc::clone(&barrier),
            );
            std::thread::spawn(move || {
                let mut passed = vec![false; tokens.len()];
                let mut refused = Vec::new();
                barrier.wait();
                // Each node walks the tokens from a different starting point,
                // so every token is contended.
                for k in 0..tokens.len() {
                    let i = (k + n * 7) % tokens.len();
                    let (session, token) = &tokens[i];
                    let b = Binding::new(session.as_str()).once(&*store);
                    match node.verify_at(&b, token.as_bytes(), NOW) {
                        Ok(_) => passed[i] = true,
                        Err(e) => refused.push(e.reason()),
                    }
                }
                (passed, refused)
            })
        })
        .collect();
    let mut passes = vec![0; tokens.len()];
    let mut reasons = Vec::new();
    for h in handles {
        let (passed, refused) = h.join().unwrap();
        for (count, p) in passes.iter_mut().zip(passed) {
            *count += usize::from(p);
        }
        reasons.extend(refused);
    }
    (passes, reasons)
}

fn issue_round_robin(
    nodes: &[Arc<Csrf>],
    store: &dyn NonceStore,
    count: u64,
) -> Vec<(String, Token)> {
    let mut pads = TestPads(0x5eed);
    (0..count)
        .map(|i| {
            let session = format!("session-{}", i % 10);
            let b = Binding::new(session.as_str()).once(store);
            let token = nodes[(i % nodes.len() as u64) as usize]
                .issue_at(&b, NOW, &mut pads)
                .unwrap();
            (session, token)
        })
        .collect()
}

#[test]
fn test_cluster_every_one_time_token_passes_exactly_once() {
    let nodes: Vec<_> = (0..6).map(|_| Arc::new(node_on_key_0())).collect();
    let store = Arc::new(SharedStore::default());
    let tokens = Arc::new(issue_round_robin(&nodes, &*store, 300));
    assert_eq!(
        store.calls.load(Ordering::SeqCst),
        0,
        "issuing never touches the store"
    );

    let (passes, reasons) = race(&nodes, &store, &tokens);
    assert!(
        passes.iter().all(|&p| p == 1),
        "each token passes exactly once: {passes:?}"
    );
    assert_eq!(reasons.len(), 300 * 5);
    assert!(
        reasons.iter().all(|&r| r == Reason::AlreadyUsed),
        "{reasons:?}"
    );
}

#[test]
fn test_cluster_memory_store_shared_by_nodes_passes_each_token_once() {
    // MemoryStore shared in one process by several independently built nodes.
    let nodes: Vec<_> = (0..6).map(|_| Arc::new(node_on_key_0())).collect();
    let store = Arc::new(MemoryStore::starting_at(64_000, NOW - 3600));
    let tokens = Arc::new(issue_round_robin(&nodes, &*store, 300));
    let (passes, reasons) = race(&nodes, &store, &tokens);
    assert!(passes.iter().all(|&p| p == 1), "{passes:?}");
    assert!(
        reasons.iter().all(|&r| r == Reason::AlreadyUsed),
        "{reasons:?}"
    );
}

#[test]
fn test_cluster_rotation_in_two_steps_under_traffic() {
    let store = SharedStore::default();
    let mut pads = TestPads(7);
    let all_nodes = 3;

    // Before: every node signs with key 0.
    let before = node_on_key_0();
    let plain = Binding::new("s");
    let once = Binding::new("s").once(&store);
    let old_plain = before.issue_at(&plain, NOW, &mut pads).unwrap();
    let old_once = before.issue_at(&once, NOW, &mut pads).unwrap();

    // Step 1, on every node: key 1 is accepted, not yet used to sign.
    let staged: Vec<_> = (0..all_nodes)
        .map(|_| node(|b| b.key(KeyId(0), KEY_0).accept(KeyId(1), KEY_1)))
        .collect();
    let fingerprint = staged[0].key_fingerprint(KeyId(1)).unwrap();
    for n in &staged {
        assert_eq!(n.signing_key(), KeyId(0));
        assert_eq!(
            n.key_fingerprint(KeyId(1)),
            Some(fingerprint),
            "same ring on every node"
        );
        assert_eq!(
            n.once_lifetime(),
            staged[0].once_lifetime(),
            "same one-time lifetime"
        );
    }

    // Step 2, rolling: node 0 is promoted while 1 and 2 are still staged.
    let promoted = node(|b| {
        b.key(KeyId(1), KEY_1)
            .retired(KeyId(0), KEY_0, NOW + LIFETIME.max(ONCE) + SKEW + 1)
    });
    assert_eq!(promoted.key_fingerprint(KeyId(1)), Some(fingerprint));
    let new_plain = promoted.issue_at(&plain, NOW, &mut pads).unwrap();
    let new_once = promoted.issue_at(&once, NOW, &mut pads).unwrap();

    // Mid-rollout, every node verifies every outstanding token, old and new.
    for (i, n) in staged.iter().enumerate() {
        assert!(
            n.verify_at(&plain, old_plain.as_bytes(), NOW + 1).is_ok(),
            "staged {i}, old"
        );
        assert!(
            n.verify_at(&plain, new_plain.as_bytes(), NOW + 1).is_ok(),
            "staged {i}, new"
        );
    }
    assert!(
        promoted
            .verify_at(&plain, old_plain.as_bytes(), NOW + 1)
            .unwrap()
            .retired_key()
    );
    assert!(
        promoted
            .verify_at(&plain, new_plain.as_bytes(), NOW + 1)
            .is_ok()
    );

    // One-time tokens from either key pass once across the mixed cluster.
    assert!(
        staged[1]
            .verify_at(&once, new_once.as_bytes(), NOW + 2)
            .is_ok()
    );
    assert!(
        promoted
            .verify_at(&once, old_once.as_bytes(), NOW + 2)
            .is_ok()
    );
    for n in staged.iter().chain([&promoted]) {
        for t in [&new_once, &old_once] {
            assert_eq!(
                n.verify_at(&once, t.as_bytes(), NOW + 3)
                    .unwrap_err()
                    .reason(),
                Reason::AlreadyUsed
            );
        }
    }

    // Why two steps: a node that skipped step 1 cannot read the new key.
    assert_eq!(
        before
            .verify_at(&plain, new_plain.as_bytes(), NOW + 1)
            .unwrap_err()
            .reason(),
        Reason::UnknownKey
    );
}

#[test]
fn test_cluster_misdeployed_key_is_visible_and_never_reaches_the_store() {
    let store = SharedStore::default();
    let good = node(|b| b.key(KeyId(1), KEY_1));
    let mut wrong_bytes = KEY_1;
    wrong_bytes[31] ^= 1;
    let bad = node(|b| b.key(KeyId(1), wrong_bytes));

    // Deployment tooling sees it before any traffic does.
    assert_ne!(
        good.key_fingerprint(KeyId(1)),
        bad.key_fingerprint(KeyId(1))
    );

    let once = Binding::new("s").once(&store);
    let mut pads = TestPads(9);
    for issuer_is_bad in [true, false] {
        let (issuer, verifier) = if issuer_is_bad {
            (&bad, &good)
        } else {
            (&good, &bad)
        };
        let t = issuer.issue_at(&once, NOW, &mut pads).unwrap();
        assert_eq!(
            verifier
                .verify_at(&once, t.as_bytes(), NOW)
                .unwrap_err()
                .reason(),
            Reason::BadMac
        );
    }
    assert_eq!(
        store.calls.load(Ordering::SeqCst),
        0,
        "no unverified nonce reaches the store"
    );
}

/// A used one-time token never passes again on any node whose clock is within
/// the skew, at any time from issue until well past its end, including after
/// the store has dropped the record.
fn never_passes_twice(store: &dyn NonceStore) {
    let nodes = [node_on_key_0(), node_on_key_0()];
    // Node 1's clock runs ahead of node 0's by just under the skew.
    let offsets = [0, SKEW - 1];
    let b = Binding::new("s").once(store);
    let t = nodes[1]
        .issue_at(&b, NOW + offsets[1], &mut TestPads(3))
        .unwrap();

    // Node 0 sees a token from its future (within the skew) and consumes it.
    assert!(nodes[0].verify_at(&b, t.as_bytes(), NOW).is_ok());

    for later in (0..=ONCE + 3 * SKEW + 60).step_by(5) {
        for (n, node) in nodes.iter().enumerate() {
            let now = NOW + later + offsets[n];
            let v = node.verify_at(&b, t.as_bytes(), now);
            assert!(
                matches!(
                    v.as_ref().map_err(|e| e.reason()),
                    Err(Reason::AlreadyUsed | Reason::Expired)
                ),
                "node {n} at +{later}s: {v:?}"
            );
        }
    }
}

#[test]
fn test_cluster_clock_differences_never_let_a_token_pass_twice() {
    never_passes_twice(&SharedStore::default());
    never_passes_twice(&MemoryStore::starting_at(64_000, NOW - 3600));
}

#[test]
fn test_cluster_store_outage_fails_closed_then_recovers() {
    let nodes: Vec<_> = (0..4).map(|_| Arc::new(node_on_key_0())).collect();
    let store = Arc::new(SharedStore::default());
    let tokens = Arc::new(issue_round_robin(&nodes, &*store, 40));

    store.down.store(true, Ordering::SeqCst);
    let (passes, reasons) = race(&nodes, &store, &tokens);
    assert!(
        passes.iter().all(|&p| p == 0),
        "nothing passes while the store is down"
    );
    assert!(
        reasons.iter().all(|&r| r == Reason::StoreUnavailable),
        "{reasons:?}"
    );

    // The outage consumed nothing: once the store is back, each token passes once.
    store.down.store(false, Ordering::SeqCst);
    let (passes, reasons) = race(&nodes, &store, &tokens);
    assert!(passes.iter().all(|&p| p == 1), "{passes:?}");
    assert!(
        reasons.iter().all(|&r| r == Reason::AlreadyUsed),
        "{reasons:?}"
    );
}
