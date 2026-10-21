//! One-time tokens: the store seam and an in-memory store.
//!
//! A one-time token is a signed token with a 128-bit random nonce inside the
//! MAC (format version 2). The MAC already proves the token was issued by this
//! key ring, so the store does not need to know which tokens were issued: it
//! only remembers which nonces were **used**. Issuing never touches the store.
//!
//! Verifying checks the MAC, the validity window, and the scope **first**, and
//! only then asks the store to record the nonce as used. Forged requests
//! therefore never reach the store: a cross-site attacker cannot burn a user's
//! one-time token with a wrong one, and cannot put load on a shared store.

use core::fmt;

/// Length of a one-time token's text, in characters.
pub const ONCE_TOKEN_LEN: usize = 102;

/// Length of a one-time token's nonce, in bytes.
pub const NONCE_LEN: usize = 16;

/// Why a [`NonceStore`] could not answer.
///
/// On verify this becomes
/// [`Reason::StoreUnavailable`](crate::Reason::StoreUnavailable): the request
/// is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StoreError {
    /// The store could not be reached or failed.
    Unavailable,
    /// The store is full of unexpired records.
    Full,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "the one-time token store is unavailable",
            Self::Full => "the one-time token store is full of unexpired records",
        })
    }
}

impl core::error::Error for StoreError {}

/// One use of a one-time token, handed to [`NonceStore::consume`] after the
/// token's MAC, validity window, and scope passed.
///
/// All times are unix seconds.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct NonceUse<'a> {
    /// The session the token is bound to (already proven by the MAC).
    pub session: &'a [u8],
    /// The token's nonce: 128 random bits csrf-sec generated at issue.
    pub nonce: [u8; NONCE_LEN],
    /// When the token was issued.
    pub issued_at: u64,
    /// Keep the record at least until this time: the token's lifetime plus
    /// the configured skew, so a node whose clock lags still finds it.
    pub expires_at: u64,
    /// The verifying node's current time.
    pub now: u64,
}

impl fmt::Debug for NonceUse<'_> {
    /// The session id may be a secret, so only its length is shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NonceUse")
            .field("session_len", &self.session.len())
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Remembers which one-time tokens were used.
///
/// Implement it over a store every node reaches for a cluster (WASP: the
/// gates' session store); [`MemoryStore`] serves one node and tests.
///
/// # Contract
///
/// `consume` **atomically** records `use_.nonce` as used and returns:
///
/// - `Ok(true)` when this is the first use: the request passes;
/// - `Ok(false)` when the nonce was already recorded, or when the store cannot
///   vouch that it was not (for example the token was issued before the store's
///   memory began): the request is refused as
///   [`AlreadyUsed`](crate::Reason::AlreadyUsed);
/// - `Err(_)` when the store cannot answer: the request is refused as
///   [`StoreUnavailable`](crate::Reason::StoreUnavailable).
///
/// Two concurrent calls for one nonce must not both return `Ok(true)` (in a
/// key-value store: set-if-absent with an expiry of `use_.expires_at`). The
/// record must be kept until `use_.expires_at`. `consume` is called only for
/// tokens whose MAC, validity window, and scope already passed, so it never
/// sees forged input, and nonces are never chosen by a client.
///
/// ```
/// use std::{collections::HashSet, sync::Mutex};
/// use csrf_sec::{NonceStore, NonceUse, StoreError};
///
/// struct Simple(Mutex<HashSet<[u8; 16]>>);
///
/// impl NonceStore for Simple {
///     fn consume(&self, use_: &NonceUse<'_>) -> Result<bool, StoreError> {
///         let mut used = self.0.lock().map_err(|_| StoreError::Unavailable)?;
///         Ok(used.insert(use_.nonce))
///     }
/// }
/// ```
pub trait NonceStore {
    /// Record the nonce as used; `Ok(true)` only for its first use.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the store cannot answer; the request is refused.
    fn consume(&self, use_: &NonceUse<'_>) -> Result<bool, StoreError>;
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

    use super::{NONCE_LEN, NonceStore, NonceUse, StoreError};

    /// Number of independently locked shards.
    const SHARDS: usize = 64;

    /// Hashes a nonce by its first eight bytes.
    ///
    /// Nonces are uniformly random values csrf-sec generated, and `consume` is
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

    /// Used nonces and the time each record may be dropped.
    type Shard = HashMap<[u8; NONCE_LEN], u64, BuildHasherDefault<NonceHasher>>;

    /// An in-memory [`NonceStore`]: sharded, bounded, and expiring.
    ///
    /// It remembers used nonces in 64 shards, each behind its own short-held
    /// lock, so concurrent verifies rarely contend. Each shard holds at most
    /// `capacity / 64` (rounded up) records; a full shard drops expired records
    /// first, then refuses with [`StoreError::Full`] (fail closed). Only
    /// submitted tokens take space: issuing never touches the store.
    ///
    /// Memory lives in this process only. So that a restart cannot let a used
    /// token pass again, the store refuses (as already used) every token issued
    /// at or before the second it started. For a cluster, implement
    /// [`NonceStore`] over a store every node reaches.
    ///
    /// Memory: about 40 bytes per record [est.].
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use csrf_sec::{Binding, Csrf, MemoryStore, OsPads, Reason};
    ///
    /// let csrf = Csrf::new(*b"an example key, 32 bytes long!!!")?;
    /// let started = 1_800_000_000; // MemoryStore::new reads the system clock
    /// let store = MemoryStore::starting_at(100_000, started);
    /// let pay = Binding::new("session-1").scope("POST /pay").once(&store);
    ///
    /// let token = csrf.issue_at(&pay, started + 5, &mut OsPads)?;
    /// csrf.verify_at(&pay, token.as_bytes(), started + 30)?;
    /// let again = csrf.verify_at(&pay, token.as_bytes(), started + 31);
    /// assert_eq!(again.unwrap_err().reason(), Reason::AlreadyUsed);
    /// # Ok(())
    /// # }
    /// ```
    pub struct MemoryStore {
        shards: Box<[Mutex<Shard>]>,
        shard_capacity: usize,
        started_at: u64,
    }

    impl MemoryStore {
        /// A store for about `capacity` used-token records (at least one per
        /// shard), starting now by the system clock.
        #[must_use]
        pub fn new(capacity: usize) -> Self {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            Self::starting_at(capacity, now)
        }

        /// A store whose memory begins at `started_at` (unix seconds): tokens
        /// issued at or before it are refused as already used.
        #[must_use]
        pub fn starting_at(capacity: usize, started_at: u64) -> Self {
            let shards = (0..SHARDS)
                .map(|_| Mutex::new(Shard::default()))
                .collect::<Vec<_>>()
                .into_boxed_slice();
            Self {
                shards,
                shard_capacity: capacity.div_ceil(SHARDS).max(1),
                started_at,
            }
        }

        /// Records held, including expired ones not yet dropped.
        #[must_use]
        pub fn len(&self) -> usize {
            self.shards.iter().map(|s| lock(s).len()).sum()
        }

        /// `true` when no record is held.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        /// Drop every record that expired before `now`. Optional: full shards
        /// drop their own expired records.
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
        fn consume(&self, use_: &NonceUse<'_>) -> Result<bool, StoreError> {
            if use_.issued_at <= self.started_at {
                // Possibly used before this store's memory began.
                return Ok(false);
            }
            let mut shard = lock(self.shard(&use_.nonce));
            if shard.contains_key(&use_.nonce) {
                return Ok(false);
            }
            if shard.len() >= self.shard_capacity {
                shard.retain(|_, expires_at| *expires_at >= use_.now);
                if shard.len() >= self.shard_capacity {
                    return Err(StoreError::Full);
                }
            }
            shard.insert(use_.nonce, use_.expires_at);
            Ok(true)
        }
    }

    impl core::fmt::Debug for MemoryStore {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("MemoryStore")
                .field("shards", &SHARDS)
                .field("shard_capacity", &self.shard_capacity)
                .field("started_at", &self.started_at)
                .finish_non_exhaustive()
        }
    }

    #[cfg(test)]
    mod tests {
        use std::sync::{Arc, Barrier};

        use super::{MemoryStore, SHARDS};
        use crate::{NonceStore, NonceUse, StoreError};

        fn nonce(i: u32) -> [u8; 16] {
            let mut n = [0u8; 16];
            n[..4].copy_from_slice(&i.to_le_bytes());
            n[15] = (i % 251) as u8;
            n
        }

        fn use_(nonce: [u8; 16], issued_at: u64, expires_at: u64, now: u64) -> NonceUse<'static> {
            NonceUse {
                session: b"s",
                nonce,
                issued_at,
                expires_at,
                now,
            }
        }

        #[test]
        fn test_memory_store_consume_once() {
            let s = MemoryStore::starting_at(10, 0);
            assert_eq!(s.consume(&use_(nonce(1), 5, 100, 10)), Ok(true));
            assert_eq!(s.consume(&use_(nonce(1), 5, 100, 11)), Ok(false));
            assert_eq!(s.consume(&use_(nonce(2), 5, 100, 11)), Ok(true));
            assert_eq!(s.len(), 2);
        }

        #[test]
        fn test_memory_store_refuses_tokens_from_before_its_start() {
            let s = MemoryStore::starting_at(10, 1000);
            assert_eq!(s.consume(&use_(nonce(1), 999, 2000, 1001)), Ok(false));
            assert_eq!(s.consume(&use_(nonce(2), 1000, 2000, 1001)), Ok(false));
            assert_eq!(s.consume(&use_(nonce(3), 1001, 2000, 1001)), Ok(true));
            assert!(s.len() == 1);
        }

        #[test]
        fn test_memory_store_full_shard_purges_then_refuses() {
            let s = MemoryStore::starting_at(SHARDS, 0); // one record per shard
            let a = [7u8; 16];
            let mut b = [9u8; 16];
            b[15] = 7; // same shard as `a`
            assert_eq!(s.consume(&use_(a, 1, 10, 5)), Ok(true));
            assert_eq!(s.consume(&use_(b, 1, 20, 5)), Err(StoreError::Full));
            // Once `a` expired, the shard makes room; `a` is forgotten, which
            // is safe because the token itself has expired by then.
            assert_eq!(s.consume(&use_(b, 1, 20, 11)), Ok(true));
            assert_eq!(s.len(), 1);
        }

        #[test]
        fn test_memory_store_purge_expired() {
            let s = MemoryStore::starting_at(1000, 0);
            for i in 0..100 {
                assert_eq!(s.consume(&use_(nonce(i), 1, u64::from(i), 0)), Ok(true));
            }
            s.purge_expired(50);
            assert_eq!(s.len(), 50);
            s.purge_expired(u64::MAX);
            assert!(s.is_empty());
        }

        #[test]
        fn test_memory_store_concurrent_consume_exactly_one_wins() {
            let s = Arc::new(MemoryStore::starting_at(1000, 0));
            for round in 0..50u32 {
                let threads = 8;
                let barrier = Arc::new(Barrier::new(threads));
                let handles: Vec<_> = (0..threads)
                    .map(|_| {
                        let (s, barrier) = (Arc::clone(&s), Arc::clone(&barrier));
                        std::thread::spawn(move || {
                            barrier.wait();
                            s.consume(&use_(nonce(round), 1, 100, 2)).unwrap()
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
        fn test_memory_store_new_uses_the_system_clock() {
            let s = MemoryStore::new(0);
            assert!(format!("{s:?}").contains("shard_capacity: 1"));
            // A token issued long ago predates this store.
            assert_eq!(
                s.consume(&use_(nonce(1), 1_600_000_000, u64::MAX, 0)),
                Ok(false)
            );
        }

        #[test]
        fn test_nonce_use_debug_hides_session() {
            let u = NonceUse {
                session: b"secret-session",
                nonce: [0; 16],
                issued_at: 1,
                expires_at: 2,
                now: 1,
            };
            let text = format!("{u:?}");
            assert!(!text.contains("secret"));
            assert!(text.contains("session_len: 14"));
        }
    }
}
