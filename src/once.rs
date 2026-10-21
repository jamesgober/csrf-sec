//! One-time tokens: the store seam and an in-memory store.
//!
//! A one-time token is a signed token with a 128-bit random nonce inside the
//! MAC (format version 2). Issuing records the nonce in a [`NonceStore`];
//! verifying checks the MAC, the validity window, and the scope **first**, and
//! only then asks the store to remove the nonce. Forged requests therefore
//! never reach the store: a cross-site attacker cannot burn a user's one-time
//! token with a wrong one, and cannot put load on a shared store.

use core::fmt;

/// Length of a one-time token's text, in characters.
pub const ONCE_TOKEN_LEN: usize = 102;

/// Length of a one-time token's nonce, in bytes.
pub const NONCE_LEN: usize = 16;

/// Why a [`NonceStore`] could not answer.
///
/// On issue this becomes [`Error::Store`](crate::Error::Store) (no token is
/// issued); on verify it becomes
/// [`Reason::StoreUnavailable`](crate::Reason::StoreUnavailable) (the request
/// is refused). Either way the answer is no.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StoreError {
    /// The store could not be reached or failed.
    Unavailable,
    /// The store is full of unexpired nonces.
    Full,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "the one-time token store is unavailable",
            Self::Full => "the one-time token store is full of unexpired tokens",
        })
    }
}

impl core::error::Error for StoreError {}

/// Where one-time tokens' nonces live between issue and use.
///
/// Implement it over your session store (for a cluster, a store every node
/// reaches). [`MemoryStore`] serves one node and tests.
///
/// # Contract
///
/// - `insert` records `nonce` for `session` until `expires_at` (unix seconds,
///   inclusive). Nonces are 128-bit random values that csrf-sec generated; they
///   never collide in practice and are never chosen by a client.
/// - `take` **atomically** removes the record and returns `true` only if it
///   existed and had not expired at `now`. Two concurrent `take` calls for the
///   same nonce must not both return `true`.
/// - `take` is called only for tokens whose MAC, validity window, and scope
///   already passed, so it never sees forged input.
/// - Any failure returns a [`StoreError`]; csrf-sec then fails closed.
///
/// ```
/// use std::{collections::HashSet, sync::Mutex};
/// use csrf_sec::{NonceStore, StoreError};
///
/// struct Simple(Mutex<HashSet<[u8; 16]>>);
///
/// impl NonceStore for Simple {
///     fn insert(&self, _session: &[u8], nonce: &[u8; 16], _now: u64, _expires_at: u64)
///         -> Result<(), StoreError> {
///         self.0.lock().map_err(|_| StoreError::Unavailable)?.insert(*nonce);
///         Ok(())
///     }
///     fn take(&self, _session: &[u8], nonce: &[u8; 16], _now: u64) -> Result<bool, StoreError> {
///         Ok(self.0.lock().map_err(|_| StoreError::Unavailable)?.remove(nonce))
///     }
/// }
/// ```
pub trait NonceStore {
    /// Record `nonce` for `session` until `expires_at`. `now` is the issue
    /// time, for stores that purge expired entries.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the nonce could not be recorded; no token is issued.
    fn insert(
        &self,
        session: &[u8],
        nonce: &[u8; NONCE_LEN],
        now: u64,
        expires_at: u64,
    ) -> Result<(), StoreError>;

    /// Atomically remove `nonce` and report whether it was present and
    /// unexpired at `now`.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the store cannot answer; the request is refused.
    fn take(&self, session: &[u8], nonce: &[u8; NONCE_LEN], now: u64) -> Result<bool, StoreError>;
}

#[cfg(feature = "std")]
pub use memory::MemoryStore;

#[cfg(feature = "std")]
mod memory {
    use std::{
        collections::HashMap,
        hash::{BuildHasherDefault, Hasher},
        sync::{Mutex, PoisonError},
    };

    use super::{NONCE_LEN, NonceStore, StoreError};

    /// Number of independently locked shards.
    const SHARDS: usize = 64;

    /// Hashes a nonce by its first eight bytes.
    ///
    /// Nonces are uniformly random values csrf-sec generated, and `take` is
    /// only reached after the MAC passed, so a client can never choose the keys
    /// this map sees: a keyed (flood-resistant) hash would buy nothing here.
    #[derive(Default)]
    struct NonceHasher(u64);

    impl Hasher for NonceHasher {
        fn finish(&self) -> u64 {
            self.0
        }

        fn write(&mut self, bytes: &[u8]) {
            for (i, &b) in bytes.iter().take(8).enumerate() {
                self.0 ^= u64::from(b) << (8 * i);
            }
        }

        fn write_usize(&mut self, _: usize) {}
    }

    type Shard = HashMap<[u8; NONCE_LEN], u64, BuildHasherDefault<NonceHasher>>;

    /// An in-memory [`NonceStore`]: sharded, bounded, and expiring.
    ///
    /// 64 shards, each behind its own short-held lock, so concurrent issue and
    /// verify calls rarely contend. Each shard holds at most
    /// `capacity / 64` (rounded up) nonces; a full shard first drops expired
    /// entries, then refuses with [`StoreError::Full`] (fail closed: the form
    /// cannot be rendered rather than an older token being forgotten).
    ///
    /// It serves a single node and tests. Nonces live only in this process: a
    /// restart forgets them (outstanding one-time tokens then fail as
    /// `AlreadyUsed`), and other nodes cannot see them. For a cluster,
    /// implement [`NonceStore`] over a shared store.
    ///
    /// Memory: about 40 bytes per outstanding nonce [est.].
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use csrf_sec::{Binding, Csrf, MemoryStore, Reason};
    ///
    /// let csrf = Csrf::new(*b"an example key, 32 bytes long!!!")?;
    /// let store = MemoryStore::new(100_000);
    /// let pay = Binding::new("session-1").scope("POST /pay").once(&store);
    ///
    /// let token = csrf.issue_with(&pay)?;
    /// csrf.verify_with(&pay, &token)?;
    /// assert_eq!(csrf.verify_with(&pay, &token).unwrap_err().reason(), Reason::AlreadyUsed);
    /// # Ok(())
    /// # }
    /// ```
    pub struct MemoryStore {
        shards: Box<[Mutex<Shard>]>,
        shard_capacity: usize,
    }

    impl MemoryStore {
        /// A store for up to about `capacity` outstanding nonces (at least
        /// one per shard).
        #[must_use]
        pub fn new(capacity: usize) -> Self {
            let shards = (0..SHARDS)
                .map(|_| Mutex::new(Shard::default()))
                .collect::<Vec<_>>()
                .into_boxed_slice();
            Self {
                shards,
                shard_capacity: capacity.div_ceil(SHARDS).max(1),
            }
        }

        /// Outstanding nonces, including expired ones not yet purged.
        #[must_use]
        pub fn len(&self) -> usize {
            self.shards.iter().map(|s| lock(s).len()).sum()
        }

        /// `true` when no nonce is outstanding.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        /// Drop every nonce that expired before `now`. Optional: full shards
        /// purge themselves.
        pub fn purge_expired(&self, now: u64) {
            for shard in self.shards.iter() {
                lock(shard).retain(|_, expires_at| *expires_at >= now);
            }
        }

        fn shard(&self, nonce: &[u8; NONCE_LEN]) -> &Mutex<Shard> {
            // Nonces are uniformly random; the last byte picks the shard, the
            // first eight feed the in-shard hash.
            &self.shards[usize::from(nonce[NONCE_LEN - 1]) % SHARDS]
        }
    }

    /// Lock a shard. A poisoned lock still holds a consistent map (no
    /// critical section here can leave it half-updated), so it is used as is.
    fn lock(shard: &Mutex<Shard>) -> std::sync::MutexGuard<'_, Shard> {
        shard.lock().unwrap_or_else(PoisonError::into_inner)
    }

    impl NonceStore for MemoryStore {
        fn insert(
            &self,
            _session: &[u8],
            nonce: &[u8; NONCE_LEN],
            now: u64,
            expires_at: u64,
        ) -> Result<(), StoreError> {
            let mut shard = lock(self.shard(nonce));
            if shard.len() >= self.shard_capacity {
                shard.retain(|_, e| *e >= now);
                if shard.len() >= self.shard_capacity {
                    return Err(StoreError::Full);
                }
            }
            shard.insert(*nonce, expires_at);
            Ok(())
        }

        fn take(
            &self,
            _session: &[u8],
            nonce: &[u8; NONCE_LEN],
            now: u64,
        ) -> Result<bool, StoreError> {
            let removed = lock(self.shard(nonce)).remove(nonce);
            Ok(removed.is_some_and(|expires_at| expires_at >= now))
        }
    }

    impl core::fmt::Debug for MemoryStore {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("MemoryStore")
                .field("shards", &SHARDS)
                .field("shard_capacity", &self.shard_capacity)
                .finish_non_exhaustive()
        }
    }

    #[cfg(test)]
    mod tests {
        use std::sync::{Arc, Barrier};

        use super::{MemoryStore, SHARDS};
        use crate::{NonceStore, StoreError};

        fn nonce(i: u32) -> [u8; 16] {
            let mut n = [0u8; 16];
            n[..4].copy_from_slice(&i.to_le_bytes());
            n[15] = (i % 251) as u8;
            n
        }

        #[test]
        fn test_memory_store_take_once() {
            let s = MemoryStore::new(10);
            s.insert(b"s", &nonce(1), 0, 100).unwrap();
            assert_eq!(s.len(), 1);
            assert_eq!(s.take(b"s", &nonce(1), 50), Ok(true));
            assert_eq!(s.take(b"s", &nonce(1), 50), Ok(false));
            assert!(s.is_empty());
        }

        #[test]
        fn test_memory_store_expiry_inclusive() {
            let s = MemoryStore::new(10);
            s.insert(b"s", &nonce(1), 0, 100).unwrap();
            s.insert(b"s", &nonce(2), 0, 100).unwrap();
            assert_eq!(s.take(b"s", &nonce(1), 100), Ok(true));
            assert_eq!(s.take(b"s", &nonce(2), 101), Ok(false));
            assert_eq!(s.take(b"s", &nonce(3), 0), Ok(false));
        }

        #[test]
        fn test_memory_store_full_shard_purges_then_refuses() {
            let s = MemoryStore::new(SHARDS); // one per shard
            let a = [7u8; 16];
            let mut b = [9u8; 16];
            b[15] = 7; // same shard as `a`
            s.insert(b"s", &a, 0, 10).unwrap();
            assert_eq!(s.insert(b"s", &b, 5, 20), Err(StoreError::Full));
            // Once `a` expired, the shard makes room.
            s.insert(b"s", &b, 11, 20).unwrap();
            assert_eq!(s.take(b"s", &a, 11), Ok(false));
            assert_eq!(s.take(b"s", &b, 11), Ok(true));
        }

        #[test]
        fn test_memory_store_purge_expired() {
            let s = MemoryStore::new(1000);
            for i in 0..100 {
                s.insert(b"s", &nonce(i), 0, u64::from(i)).unwrap();
            }
            s.purge_expired(50);
            assert_eq!(s.len(), 50);
        }

        #[test]
        fn test_memory_store_concurrent_take_exactly_one_wins() {
            let s = Arc::new(MemoryStore::new(1000));
            for round in 0..50u32 {
                s.insert(b"s", &nonce(round), 0, 100).unwrap();
                let threads = 8;
                let barrier = Arc::new(Barrier::new(threads));
                let handles: Vec<_> = (0..threads)
                    .map(|_| {
                        let (s, barrier) = (Arc::clone(&s), Arc::clone(&barrier));
                        std::thread::spawn(move || {
                            barrier.wait();
                            s.take(b"s", &nonce(round), 1).unwrap()
                        })
                    })
                    .collect();
                let wins = handles
                    .into_iter()
                    .map(|h| h.join().unwrap())
                    .filter(|&w| w)
                    .count();
                assert_eq!(wins, 1, "round {round}");
            }
        }

        #[test]
        fn test_memory_store_debug_and_min_capacity() {
            let s = MemoryStore::new(0);
            assert!(format!("{s:?}").contains("shard_capacity: 1"));
            s.insert(b"s", &nonce(1), 0, 1).unwrap();
        }
    }
}
