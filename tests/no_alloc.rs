//! The verify, check, and issue paths allocate nothing.
//!
//! A counting global allocator records allocations made by the current thread;
//! each path runs after a warm-up (thread-local initialisation is allowed to
//! allocate once) and must add zero.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use std::sync::Mutex;

use csrf_sec::{
    Binding, Csrf, Error, KeyId, NonceStore, NonceUse, PadSource, Reason, RequestFacts, StoreError,
};

struct Counting;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call is forwarded unchanged to the system allocator; the
// counter is a plain thread-local cell with a const initializer, so touching
// it never allocates or recurses.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|c| c.set(c.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|c| c.set(c.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocations_during(f: impl FnOnce()) -> usize {
    let before = ALLOCATIONS.with(Cell::get);
    f();
    ALLOCATIONS.with(Cell::get) - before
}

struct FixedPads;

impl PadSource for FixedPads {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        out.iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = (i as u8).wrapping_mul(29) ^ 0x5c);
        Ok(())
    }
}

const NOW: u64 = 1_792_540_800;

/// A fixed-capacity store that never allocates.
struct ArrayStore(Mutex<[Option<[u8; 16]>; 8]>);

impl NonceStore for ArrayStore {
    fn consume(&self, u: &NonceUse<'_>) -> Result<bool, StoreError> {
        let mut slots = self.0.lock().map_err(|_| StoreError::Unavailable)?;
        if slots.iter().any(|s| s.as_ref() == Some(&u.nonce)) {
            return Ok(false);
        }
        let free = slots
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(StoreError::Full)?;
        *free = Some(u.nonce);
        Ok(true)
    }
}

/// A store that always fails with the given error.
struct FailingStore(StoreError);

impl NonceStore for FailingStore {
    fn consume(&self, _: &NonceUse<'_>) -> Result<bool, StoreError> {
        Err(self.0)
    }
}

#[test]
fn test_hot_paths_allocate_nothing() {
    let csrf = Csrf::builder()
        .key(KeyId(2), *b"no-alloc test key, 32 bytes!!!!!")
        .retired(KeyId(1), *b"retired test key, 32 bytes!!!!!!", NOW + 3600)
        .allow_origin("https://partner.example")
        .build()
        .unwrap();
    let session = "a-43-character-session-id-xxxxxxxxxxxxxxxx";
    let binding = Binding::new(session)
        .scope("POST /account/email")
        .previous_session("old");
    let facts = RequestFacts::new("POST")
        .fetch_site("same-origin")
        .origin("https://example.com")
        .own_origin("https://example.com");
    let cross = RequestFacts::new("POST")
        .origin("https://evil.example")
        .own_origin("https://example.com");

    // Warm-up: thread-local pad buffer, lazy statics.
    let token = csrf.issue_at(&binding, NOW, &mut FixedPads).unwrap();
    #[cfg(feature = "std")]
    {
        let _ = csrf.issue_with(&binding).unwrap();
        let _ = csrf.verify_with(&binding, &token);
    }

    let n = allocations_during(|| {
        let t = csrf.issue_at(&binding, NOW, &mut FixedPads).unwrap();
        assert!(csrf.verify_at(&binding, t.as_bytes(), NOW).is_ok());
    });
    assert_eq!(n, 0, "issue_at + verify_at");

    let n = allocations_during(|| {
        assert!(
            csrf.check_at(&facts, &binding, token.as_bytes(), NOW)
                .is_ok()
        );
        assert!(
            csrf.check_at(&cross, &binding, token.as_bytes(), NOW)
                .is_err()
        );
    });
    assert_eq!(n, 0, "check_at, pass and refuse");

    let store = ArrayStore(Mutex::new([None; 8]));
    let once = Binding::new(session).scope("POST /pay").once(&store);
    // Warm-up: on macOS a std Mutex allocates its pthread mutex on first lock.
    let warm = csrf.issue_at(&once, NOW, &mut FixedPads).unwrap();
    assert!(csrf.verify_at(&once, warm.as_bytes(), NOW).is_ok());
    *store.0.lock().unwrap() = [None; 8];
    let n = allocations_during(|| {
        let t = csrf.issue_at(&once, NOW, &mut FixedPads).unwrap();
        assert!(csrf.verify_at(&once, t.as_bytes(), NOW).is_ok());
        assert!(csrf.verify_at(&once, t.as_bytes(), NOW).is_err());
    });
    assert_eq!(n, 0, "one-time issue, verify, reuse");

    let n = allocations_during(|| {
        assert!(
            csrf.verify_at(&Binding::new("other"), token.as_bytes(), NOW)
                .is_err()
        );
        assert!(csrf.verify_at(&binding, b"garbage", NOW).is_err());
        assert!(csrf.verify_at(&binding, &[b'A'; 59], NOW).is_err());
        assert!(
            csrf.verify_at(&binding, token.as_bytes(), NOW + 10 * 86_400)
                .is_err()
        );
    });
    assert_eq!(n, 0, "rejections");

    #[cfg(feature = "std")]
    let n = allocations_during(|| {
        let t = csrf.issue_with(&binding).unwrap();
        assert!(csrf.verify_with(&binding, &t).is_ok());
        assert!(csrf.check_with(&facts, &binding, &t).is_ok());
    });
    #[cfg(feature = "std")]
    assert_eq!(n, 0, "Tier 2 with the system clock and OsPads");

    every_reason_allocates_nothing(&csrf, &binding, session);
}

/// Each refusal reason, reached as a real request would reach it, allocates
/// nothing; so does the streamed MAC for long inputs.
fn every_reason_allocates_nothing(csrf: &Csrf, binding: &Binding<'_>, session: &str) {
    let other_ring = Csrf::builder()
        .key(KeyId(9), *b"another ring's key, 32 bytes!!!!")
        .build()
        .unwrap();
    // Built before measuring: tokens that each reach one reason.
    let token = csrf.issue_at(binding, NOW, &mut FixedPads).unwrap();
    let unknown_key = other_ring.issue_at(binding, NOW, &mut FixedPads).unwrap();
    let unscoped = csrf
        .issue_at(&Binding::new(session), NOW, &mut FixedPads)
        .unwrap();
    let for_previous = csrf
        .issue_at(
            &Binding::new("old").scope("POST /account/email"),
            NOW,
            &mut FixedPads,
        )
        .unwrap();
    let foreign = csrf
        .issue_at(
            &Binding::new("someone else").scope("POST /account/email"),
            NOW,
            &mut FixedPads,
        )
        .unwrap();
    let long_session = [b's'; 300];
    let long = Binding::new(&long_session[..]).scope(&long_session[..200]);
    let cross_site = RequestFacts::new("POST").fetch_site("cross-site");
    let unavailable = FailingStore(StoreError::Unavailable);
    let quota = FailingStore(StoreError::SessionLimit);
    let once_down = Binding::new(session).once(&unavailable);
    let once_quota = Binding::new(session).once(&quota);
    let down_token = csrf.issue_at(&once_down, NOW, &mut FixedPads).unwrap();
    let quota_token = csrf.issue_at(&once_quota, NOW, &mut FixedPads).unwrap();
    let mut reasons = [None; 12];

    let n = allocations_during(|| {
        let reason = |v: csrf_sec::Verdict| v.err().map(|r| r.reason());
        reasons[0] = reason(csrf.verify_at(binding, b"", NOW));
        reasons[1] = reason(csrf.verify_at(binding, unknown_key.as_bytes(), NOW));
        reasons[2] = reason(csrf.verify_at(binding, token.as_bytes(), NOW - 1_000));
        reasons[3] = reason(csrf.verify_at(binding, unscoped.as_bytes(), NOW));
        reasons[4] = reason(csrf.verify_at(binding, for_previous.as_bytes(), NOW));
        reasons[5] = reason(csrf.verify_at(binding, foreign.as_bytes(), NOW));
        reasons[6] = reason(csrf.check_at(&cross_site, binding, token.as_bytes(), NOW));
        reasons[7] = reason(csrf.check_at(
            &RequestFacts::new("POST"),
            &Binding::new(""),
            token.as_bytes(),
            NOW,
        ));
        reasons[8] = reason(csrf.verify_at(&once_down, down_token.as_bytes(), NOW));
        reasons[9] = reason(csrf.verify_at(&once_quota, quota_token.as_bytes(), NOW));
        let t = csrf.issue_at(&long, NOW, &mut FixedPads).unwrap();
        reasons[10] = reason(csrf.verify_at(&long, t.as_bytes(), NOW));
        reasons[11] = reason(csrf.verify_at(&long, token.as_bytes(), NOW));
    });
    assert_eq!(n, 0, "every refusal reason");
    assert_eq!(
        reasons,
        [
            Some(Reason::Missing),
            Some(Reason::UnknownKey),
            Some(Reason::NotYetValid),
            Some(Reason::WrongScope),
            Some(Reason::StaleSession),
            Some(Reason::BadMac),
            Some(Reason::CrossSite),
            Some(Reason::Unverifiable),
            Some(Reason::StoreUnavailable),
            Some(Reason::TooManyUses),
            None,
            Some(Reason::BadMac),
        ]
    );
}
