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

use csrf_sec::{Binding, Csrf, Error, KeyId, NonceStore, PadSource, RequestFacts, StoreError};

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
    fn insert(&self, _: &[u8], nonce: &[u8; 16], _: u64, _: u64) -> Result<(), StoreError> {
        let mut slots = self.0.lock().map_err(|_| StoreError::Unavailable)?;
        let free = slots
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(StoreError::Full)?;
        *free = Some(*nonce);
        Ok(())
    }

    fn take(&self, _: &[u8], nonce: &[u8; 16], _: u64) -> Result<bool, StoreError> {
        let mut slots = self.0.lock().map_err(|_| StoreError::Unavailable)?;
        Ok(slots
            .iter_mut()
            .find(|s| s.as_ref() == Some(nonce))
            .map(|s| *s = None)
            .is_some())
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
    let n = allocations_during(|| {
        let t = csrf.issue_at(&once, NOW, &mut FixedPads).unwrap();
        assert!(csrf.verify_at(&once, t.as_bytes(), NOW).is_ok());
        assert!(csrf.verify_at(&once, t.as_bytes(), NOW).is_err());
    });
    assert_eq!(n, 0, "one-time issue, verify, reuse");

    let n = allocations_during(|| {
        // Failure paths, including the extra MACs that name the reason.
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
}
