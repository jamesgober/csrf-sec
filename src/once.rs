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
/// On verify, [`SessionLimit`](Self::SessionLimit) becomes
/// [`Reason::TooManyUses`](crate::Reason::TooManyUses) and anything else
/// [`Reason::StoreUnavailable`](crate::Reason::StoreUnavailable): either way
/// the request is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StoreError {
    /// The store could not be reached or failed.
    Unavailable,
    /// The store is full of unexpired records.
    Full,
    /// This session already holds as many records as the store allows one
    /// session.
    SessionLimit,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "the one-time token store is unavailable",
            Self::Full => "the one-time token store is full of unexpired records",
            Self::SessionLimit => "this session has used its share of the one-time token store",
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
    /// Keep the record at least until this time: the token's one-time
    /// lifetime plus the configured skew, so a node whose clock lags still
    /// finds it. Nodes sharing a store must agree on the one-time lifetime.
    pub expires_at: u64,
    /// The verifying node's current time.
    pub now: u64,
}

impl<'a> NonceUse<'a> {
    /// A use, for testing a [`NonceStore`] implementation. csrf-sec builds
    /// these itself when it verifies a one-time token.
    #[must_use]
    pub const fn new(
        session: &'a [u8],
        nonce: [u8; NONCE_LEN],
        issued_at: u64,
        expires_at: u64,
        now: u64,
    ) -> Self {
        Self {
            session,
            nonce,
            issued_at,
            expires_at,
            now,
        }
    }
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
/// gates' session store); `MemoryStore` (feature `std`) serves one node and
/// tests.
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
///   [`StoreUnavailable`](crate::Reason::StoreUnavailable), or as
///   [`TooManyUses`](crate::Reason::TooManyUses) for
///   [`StoreError::SessionLimit`].
///
/// Two concurrent calls for one nonce must not both return `Ok(true)` (in a
/// key-value store: set-if-absent with an expiry of `use_.expires_at`). The
/// record must be kept until `use_.expires_at`. `consume` is called only for
/// tokens whose MAC, validity window, and scope already passed, so it never
/// sees forged input, and nonces are never chosen by a client.
///
/// The smallest correct store, for tests: it never forgets a nonce, so it grows
/// with every use and is empty again after a restart. A real store expires
/// records at `use_.expires_at` and refuses tokens issued before it started, as
/// `MemoryStore` (feature `std`) does.
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
        hash::{BuildHasher, BuildHasherDefault, Hasher, RandomState},
        sync::{Mutex, PoisonError},
    };

    use super::{NONCE_LEN, NonceStore, NonceUse, StoreError};
    use crate::token::{EPOCH, LATEST};

    /// Number of independently locked shards.
    const SHARDS: usize = 64;

    /// Default cap on records one session may hold at once.
    const DEFAULT_SESSION_LIMIT: u32 = 64;

    /// A session may hold at most this fraction of its shard, so at least this
    /// many sessions are needed to fill one.
    const SESSIONS_PER_SHARD: usize = 8;

    /// How far ahead of the clock `MemoryStore::new` starts (the default skew):
    /// a clock that steps back by up to this much across a restart cannot let a
    /// used token pass again.
    const START_MARGIN: u64 = 60;

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

    /// One shard: used nonces (with their expiry and session key), records per
    /// session, the earliest expiry, so a full shard with nothing expired
    /// refuses without scanning, and the latest expiry it has dropped.
    #[derive(Default)]
    struct Shard {
        records: HashMap<[u8; NONCE_LEN], (u64, u64), BuildHasherDefault<NonceHasher>>,
        per_session: HashMap<u64, u32>,
        earliest_expiry: u64,
        /// Records expiring before this may have been dropped, so a use
        /// expiring before it cannot be vouched for (0: nothing dropped).
        forgotten_below: u64,
    }

    impl Shard {
        /// Drop the records that expired before `now`, if any can have.
        fn purge(&mut self, now: u64) {
            if self.records.is_empty() || self.earliest_expiry >= now {
                return;
            }
            let per_session = &mut self.per_session;
            let mut earliest = u64::MAX;
            let mut forgotten = self.forgotten_below;
            self.records.retain(|_, &mut (expires_at, session)| {
                if expires_at >= now {
                    earliest = earliest.min(expires_at);
                    true
                } else {
                    forgotten = forgotten.max(expires_at.saturating_add(1));
                    if let Some(count) = per_session.get_mut(&session) {
                        *count = count.saturating_sub(1);
                    }
                    false
                }
            });
            per_session.retain(|_, count| *count > 0);
            self.earliest_expiry = earliest;
            self.forgotten_below = forgotten;
        }

        /// Records `session` holds in this shard.
        fn held(&self, session: u64) -> u32 {
            self.per_session.get(&session).copied().unwrap_or(0)
        }
    }

    /// An in-memory [`NonceStore`]: sharded, bounded per store and per
    /// session, and expiring.
    ///
    /// Records are kept in 64 shards, each behind its own short-held lock, so
    /// concurrent verifies rarely contend. A session's records all live in one
    /// shard, and each session may hold at most 64 records at once (change it
    /// with [`with_session_limit`](Self::with_session_limit)), so one session,
    /// even one an attacker controls, cannot fill the store for everyone else.
    /// Each shard holds at most `capacity / 64` (rounded up) records, and a
    /// session at most an eighth of a shard whatever its limit (but always at
    /// least one record), so in a store of 512 records or more filling a shard
    /// takes at least eight sessions. When a shard or a session is full,
    /// expired records are dropped first; if none has expired, the use is
    /// refused (fail closed) without scanning the shard. Only submitted tokens
    /// take space: issuing never touches the store, and records last the
    /// one-time lifetime plus skew (an hour and a minute by default).
    ///
    /// A dropped record is remembered by its expiry: a later use that expires
    /// no later than a record already dropped is refused as already used,
    /// since the store can no longer vouch for it. With a clock that only
    /// moves forward this never refuses a valid token; it stops a token used,
    /// purged, and then presented again by a node whose clock stepped back.
    ///
    /// Memory lives in this process only. So that a restart cannot let a used
    /// token pass again, the store refuses (as already used) every token issued
    /// at or before its start, and [`new`](Self::new) starts one minute ahead of
    /// the clock, which covers a clock that steps back by up to a minute across
    /// the restart. Where the clock can step back further, persist a
    /// high-water mark and use [`starting_at`](Self::starting_at). For a
    /// cluster, implement [`NonceStore`] over a store every node reaches.
    ///
    /// Memory: about 60 bytes per record [est.].
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
        session_limit: u32,
        started_at: u64,
        sessions: RandomState,
    }

    impl MemoryStore {
        /// A store for about `capacity` used-token records (at least one per
        /// shard), starting one minute ahead of the system clock. If the clock
        /// reads before 2020, the store refuses every token (fail closed).
        ///
        /// The capacity is split evenly over 64 shards, all of one session's
        /// records live in one shard, and a session may hold at most an eighth
        /// of its shard (at least one record): size the store at 512 times the
        /// session limit or more (the default limit of 64 wants at least
        /// 32,768, about 2 MB), or the limit is lowered to fit
        /// ([`session_limit`](Self::session_limit) reports it).
        #[must_use]
        pub fn new(capacity: usize) -> Self {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let started_at = if now < EPOCH {
                u64::MAX
            } else {
                now + START_MARGIN
            };
            Self::starting_at(capacity, started_at)
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
                session_limit: 0,
                started_at,
                sessions: RandomState::new(),
            }
            .with_session_limit(DEFAULT_SESSION_LIMIT)
        }

        /// The most records one session may hold at once (default 64). It is
        /// kept between 1 and an eighth of a shard (`capacity / 512`), so one
        /// session cannot fill its shard. A session at its limit gets
        /// [`StoreError::SessionLimit`] until some of its records expire.
        #[must_use]
        pub fn with_session_limit(mut self, limit: u32) -> Self {
            let share = u32::try_from(self.shard_capacity / SESSIONS_PER_SHARD).unwrap_or(u32::MAX);
            self.session_limit = limit.min(share).max(1);
            self
        }

        /// The most records one session may hold at once, after
        /// [`with_session_limit`](Self::with_session_limit)'s bounds.
        #[must_use]
        pub fn session_limit(&self) -> u32 {
            self.session_limit
        }

        /// Records held, including expired ones not yet dropped.
        #[must_use]
        pub fn len(&self) -> usize {
            self.shards.iter().map(|s| lock(s).records.len()).sum()
        }

        /// `true` when no record is held.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        /// Drop every record that expired before `now` (unix seconds).
        /// Optional: full shards drop their own expired records. A `now` past
        /// the range any token can reach (a time in milliseconds, say) is
        /// ignored rather than taken to expire everything.
        pub fn purge_expired(&self, now: u64) {
            if now > LATEST {
                return;
            }
            for shard in self.shards.iter() {
                lock(shard).purge(now);
            }
        }
    }

    /// Lock a shard. A poisoned lock still holds a consistent shard (no
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
            let session = self.sessions.hash_one(use_.session);
            let mut shard = lock(&self.shards[(session % SHARDS as u64) as usize]);
            if shard.records.contains_key(&use_.nonce) || use_.expires_at < shard.forgotten_below {
                // Used, or possibly used and since dropped.
                return Ok(false);
            }
            if shard.records.len() >= self.shard_capacity
                || shard.held(session) >= self.session_limit
            {
                shard.purge(use_.now);
            }
            if shard.held(session) >= self.session_limit {
                return Err(StoreError::SessionLimit);
            }
            if shard.records.len() >= self.shard_capacity {
                return Err(StoreError::Full);
            }
            shard.earliest_expiry = if shard.records.is_empty() {
                use_.expires_at
            } else {
                shard.earliest_expiry.min(use_.expires_at)
            };
            shard.records.insert(use_.nonce, (use_.expires_at, session));
            *shard.per_session.entry(session).or_insert(0) += 1;
            Ok(true)
        }
    }

    impl core::fmt::Debug for MemoryStore {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("MemoryStore")
                .field("shards", &SHARDS)
                .field("shard_capacity", &self.shard_capacity)
                .field("session_limit", &self.session_limit)
                .field("started_at", &self.started_at)
                .finish_non_exhaustive()
        }
    }

    #[cfg(test)]
    mod tests {
        use std::{
            hash::BuildHasher,
            sync::{Arc, Barrier},
        };

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

        /// A session other than `s` whose records share `s`'s shard.
        fn neighbour_of_s(store: &MemoryStore) -> Vec<u8> {
            let shard = |session: &[u8]| store.sessions.hash_one(session) % SHARDS as u64;
            (0u32..)
                .map(|i| format!("n{i}").into_bytes())
                .find(|session| shard(session) == shard(b"s"))
                .unwrap()
        }

        #[test]
        fn test_nonce_hasher_spreads_distinct_nonces() {
            use std::{
                collections::HashSet,
                hash::{BuildHasher, BuildHasherDefault},
            };
            let build = BuildHasherDefault::<super::NonceHasher>::default();
            let hashes: HashSet<u64> = (0..=255u8)
                .flat_map(|i| (0..8).map(move |pos| (i, pos)))
                .map(|(i, pos)| {
                    let mut n = [0u8; 16];
                    n[pos] = i;
                    build.hash_one(n)
                })
                .collect();
            // 8 positions x 255 nonzero values, plus the all-zero nonce.
            assert_eq!(hashes.len(), 8 * 255 + 1);
        }

        #[test]
        fn test_store_error_display() {
            assert!(StoreError::Unavailable.to_string().contains("unavailable"));
            assert!(StoreError::Full.to_string().contains("full"));
        }

        #[test]
        fn test_memory_store_consume_once() {
            let s = MemoryStore::starting_at(64 * 100, 0);
            assert!(s.is_empty());
            assert_eq!(s.consume(&use_(nonce(1), 5, 100, 10)), Ok(true));
            assert_eq!(s.consume(&use_(nonce(1), 5, 100, 11)), Ok(false));
            assert_eq!(s.consume(&use_(nonce(2), 5, 100, 11)), Ok(true));
            assert_eq!(s.len(), 2);
            assert!(!s.is_empty());
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
            let other = neighbour_of_s(&s);
            let b_use = |now| NonceUse::new(&other, [9u8; 16], 1, 20, now);
            assert_eq!(s.consume(&use_([7u8; 16], 1, 10, 5)), Ok(true));
            assert_eq!(s.consume(&b_use(5)), Err(StoreError::Full));
            // Once the first record expired, the shard makes room; it is
            // forgotten, which is safe because its token has expired by then.
            assert_eq!(s.consume(&b_use(11)), Ok(true));
            assert_eq!(s.len(), 1);
        }

        #[test]
        fn test_session_limit_is_checked_before_shard_space() {
            let s = MemoryStore::starting_at(SHARDS * 16, 0).with_session_limit(2);
            assert_eq!(s.session_limit(), 2);
            let other = neighbour_of_s(&s);
            for i in 0..2 {
                assert_eq!(s.consume(&use_(nonce(i), 1, 100, 5)), Ok(true));
            }
            assert_eq!(
                s.consume(&use_(nonce(9), 1, 100, 5)),
                Err(StoreError::SessionLimit)
            );
            // The neighbour still has room in the shared shard.
            assert_eq!(
                s.consume(&NonceUse::new(&other, nonce(10), 1, 100, 5)),
                Ok(true)
            );
        }

        #[test]
        fn test_session_limit_bounds() {
            // An eighth of a shard, rounded down, and never below one.
            assert_eq!(MemoryStore::starting_at(SHARDS * 8, 0).session_limit(), 1);
            assert_eq!(MemoryStore::starting_at(SHARDS * 16, 0).session_limit(), 2);
            assert_eq!(MemoryStore::starting_at(SHARDS * 15, 0).session_limit(), 1);
            assert_eq!(MemoryStore::starting_at(SHARDS * 7, 0).session_limit(), 1);
            let big = MemoryStore::starting_at(SHARDS * 8 * 1000, 0);
            assert_eq!(big.session_limit(), 64);
            assert_eq!(big.with_session_limit(0).session_limit(), 1);
            let big = MemoryStore::starting_at(SHARDS * 8 * 1000, 0);
            assert_eq!(big.with_session_limit(999).session_limit(), 999);
            let big = MemoryStore::starting_at(SHARDS * 8 * 1000, 0);
            assert_eq!(big.with_session_limit(1001).session_limit(), 1000);
        }

        #[test]
        fn test_dropped_records_are_remembered_by_expiry() {
            let s = MemoryStore::starting_at(SHARDS * 100, 0);
            assert_eq!(s.consume(&use_(nonce(1), 1, 30, 5)), Ok(true));
            assert_eq!(s.consume(&use_(nonce(2), 1, 40, 5)), Ok(true));
            // A purge at 35 drops the record expiring at 30, not the one at 40.
            s.purge_expired(35);
            assert_eq!(s.len(), 1);
            assert_eq!(s.consume(&use_(nonce(1), 1, 30, 20)), Ok(false));
            assert_eq!(s.consume(&use_(nonce(3), 1, 30, 20)), Ok(false));
            assert_eq!(s.consume(&use_(nonce(4), 1, 31, 20)), Ok(true));
            // A purge that drops nothing remembers nothing new.
            s.purge_expired(31);
            assert_eq!(s.consume(&use_(nonce(5), 1, 31, 20)), Ok(true));
            // The mark only moves forward.
            s.purge_expired(1_000);
            s.purge_expired(35);
            assert_eq!(s.consume(&use_(nonce(6), 1, 40, 20)), Ok(false));
        }

        #[test]
        fn test_session_limit_counts_survive_a_purge() {
            let s = MemoryStore::starting_at(64 * 100, 0).with_session_limit(3);
            assert_eq!(s.session_limit(), 3);
            // Three records, two expiring at 10, one at 100.
            assert_eq!(s.consume(&use_(nonce(1), 1, 10, 5)), Ok(true));
            assert_eq!(s.consume(&use_(nonce(2), 1, 10, 5)), Ok(true));
            assert_eq!(s.consume(&use_(nonce(3), 1, 100, 5)), Ok(true));
            assert_eq!(
                s.consume(&use_(nonce(4), 1, 100, 5)),
                Err(StoreError::SessionLimit)
            );
            // At 11 the two expired records are dropped: exactly two more fit.
            assert_eq!(s.consume(&use_(nonce(5), 1, 100, 11)), Ok(true));
            assert_eq!(s.consume(&use_(nonce(6), 1, 100, 11)), Ok(true));
            assert_eq!(
                s.consume(&use_(nonce(7), 1, 100, 11)),
                Err(StoreError::SessionLimit)
            );
            // A purge with nothing expired keeps the count.
            s.purge_expired(50);
            assert_eq!(
                s.consume(&use_(nonce(8), 1, 100, 50)),
                Err(StoreError::SessionLimit)
            );
            assert_eq!(s.len(), 3);
        }

        #[test]
        fn test_latest_is_the_last_reachable_second() {
            use crate::token::{EPOCH, LATEST};
            assert_eq!(LATEST, EPOCH + 3 * u64::from(u32::MAX));
            let s = MemoryStore::starting_at(64 * 10, 0);
            assert_eq!(s.consume(&use_(nonce(1), 1, LATEST - 1, 0)), Ok(true));
            s.purge_expired(LATEST);
            assert!(s.is_empty(), "a purge at the last reachable second runs");
        }

        #[test]
        fn test_memory_store_purge_expired() {
            let s = MemoryStore::starting_at(64 * 8 * 100, 0).with_session_limit(100);
            for i in 0..100 {
                assert_eq!(s.consume(&use_(nonce(i), 1, u64::from(i), 0)), Ok(true));
            }
            s.purge_expired(50);
            assert_eq!(s.len(), 50);
            s.purge_expired(u64::MAX); // out of range (not seconds): ignored
            assert_eq!(s.len(), 50);
            s.purge_expired(crate::token::LATEST);
            assert!(s.is_empty());
        }

        #[test]
        fn test_memory_store_concurrent_consume_exactly_one_wins() {
            let s = Arc::new(MemoryStore::starting_at(64 * 8 * 64, 0));
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
