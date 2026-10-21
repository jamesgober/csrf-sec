//! [`Csrf`]: the configured protector, and its [`Builder`].

use alloc::vec::Vec;
use core::{fmt, time::Duration};

use crypt_io::Zeroizing;

use crate::{
    binding::Binding,
    error::Error,
    key::{KEY_LEN, KeyFingerprint, KeyId, KeyInfo, KeyRole, MAX_KEYS, Ring, Slot},
    once::{NONCE_LEN, NonceUse, StoreError},
    pad::PadSource,
    policy::{Mode, Policy, RequestFacts},
    token::{self, ONCE, SESSION, Token, Window},
    verdict::{OriginCheck, Reason, Rejected, Verdict, Verified},
};

/// Default token lifetime: 12 hours.
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(12 * 3600);

/// Default tolerated clock difference between nodes: 60 seconds.
pub const DEFAULT_SKEW: Duration = Duration::from_secs(60);

/// Default lifetime of one-time tokens: 1 hour (never longer than the general
/// lifetime). One-time tokens protect single actions such as a payment, so a
/// short life keeps their store records, and any abuse of the store, short.
pub const DEFAULT_ONCE_LIFETIME: Duration = Duration::from_secs(3600);

/// Issues and verifies anti-forgery tokens, and applies the request origin
/// policy.
///
/// A `Csrf` is immutable once built: `Send + Sync`, cheap to share behind an
/// `Arc`, and nothing on the issue or verify path takes a lock or touches a
/// shared counter. Rotation builds a new value (`rotated`, or
/// [`rotated_at`](Self::rotated_at) without `std`) that the application swaps
/// in.
///
/// # Tier 1
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use csrf_sec::{Csrf, RequestFacts};
///
/// let csrf = Csrf::new(*b"an example key, 32 bytes long!!!")?;
///
/// // Rendering a form:
/// let token = csrf.issue("session-1")?;
///
/// // Handling the POST:
/// let facts = RequestFacts::new("POST")
///     .fetch_site("same-origin")
///     .own_origin("https://example.com");
/// csrf.check(&facts, "session-1", &token)?;
///
/// // A token never verifies for another session:
/// assert!(csrf.verify("session-2", &token).is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Csrf {
    ring: Ring,
    window: Window,
    once_window: Window,
    mode: Mode,
    policy: Policy,
}

impl Csrf {
    /// A `Csrf` with one signing key (id 0) and the defaults: 12-hour
    /// lifetime, 60-second skew, [`Mode::Strict`], no extra allowed origins.
    ///
    /// The key must be persisted (or derived from a persisted master): a key
    /// generated at boot makes every open form fail after a restart.
    ///
    /// # Errors
    ///
    /// [`Error::WeakKey`] if all 32 bytes are equal.
    pub fn new(key: [u8; KEY_LEN]) -> Result<Self, Error> {
        Self::builder().key(KeyId(0), key).build()
    }

    /// Start configuring keys, lifetime, skew, mode, and allowed origins.
    #[must_use]
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// The id of the key that signs new tokens.
    #[must_use]
    pub fn signing_key(&self) -> KeyId {
        self.ring.signing().id
    }

    /// Whether a token signed by `id` would verify at `now` (unix seconds).
    #[must_use]
    pub fn accepts_at(&self, id: KeyId, now: u64) -> bool {
        self.ring.accepts(id, now)
    }

    /// The keys in the ring, signing key first: id, role, and public
    /// fingerprint. For operations dashboards and cross-node consistency
    /// checks; no key material is exposed.
    pub fn keys(&self) -> impl Iterator<Item = KeyInfo> + '_ {
        self.ring.slots().iter().map(Slot::info)
    }

    /// The public fingerprint of key `id`, if it is in the ring (whatever its
    /// role or retire time).
    #[must_use]
    pub fn key_fingerprint(&self, id: KeyId) -> Option<KeyFingerprint> {
        self.ring
            .slots()
            .iter()
            .find(|s| s.id == id)
            .map(Slot::fingerprint)
    }

    /// The mode.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The token lifetime.
    #[must_use]
    pub fn lifetime(&self) -> Duration {
        Duration::from_secs(u64::from(self.window.lifetime))
    }

    /// The tolerated clock skew.
    #[must_use]
    pub fn skew(&self) -> Duration {
        Duration::from_secs(u64::from(self.window.skew))
    }

    /// The lifetime of one-time tokens.
    #[must_use]
    pub fn once_lifetime(&self) -> Duration {
        Duration::from_secs(u64::from(self.once_window.lifetime))
    }

    // ---------------------------------------------------------------- Tier 3

    /// Issue a token for `binding` at `now` (unix seconds), masked with bytes
    /// from `pads`. Works without `std`.
    ///
    /// For a one-time binding ([`Binding::once`]) the nonce also comes from
    /// `pads`. Issuing never touches the store.
    ///
    /// # Errors
    ///
    /// [`Error::EmptySession`] for an empty session id, [`Error::Clock`] when
    /// `now` is outside 2020 to 2156, [`Error::Random`] when `pads` fails. No
    /// token is issued on error.
    pub fn issue_at<P: PadSource + ?Sized>(
        &self,
        binding: &Binding<'_>,
        now: u64,
        pads: &mut P,
    ) -> Result<Token, Error> {
        if binding.session.is_empty() {
            return Err(Error::EmptySession);
        }
        let issued_at = token::issued_at(now)?;
        let slot = self.ring.signing();
        if binding.store.is_none() {
            return token::issue(SESSION, slot, binding, issued_at, &[], pads);
        }
        let mut nonce = [0u8; NONCE_LEN];
        pads.fill(&mut nonce)?;
        token::issue(ONCE, slot, binding, issued_at, &nonce, pads)
    }

    /// Verify a token against `binding` at `now` (unix seconds). Layer 2 only.
    /// Works without `std`.
    ///
    /// For a one-time binding, the store records the nonce as used only after
    /// the MAC, the validity window, and the scope passed.
    pub fn verify_at(&self, binding: &Binding<'_>, token: &[u8], now: u64) -> Verdict {
        let Some(store) = binding.store else {
            return token::verify_session(&self.ring, self.window, binding, token, now);
        };
        let opened = token::open(ONCE, &self.ring, self.once_window, binding, token, now)?;
        let issued_at = opened.issued_at();
        let use_ = NonceUse {
            session: binding.session,
            nonce: opened.nonce(),
            issued_at,
            expires_at: issued_at
                .saturating_add(u64::from(self.once_window.lifetime))
                .saturating_add(u64::from(self.once_window.skew)),
            now,
        };
        match store.consume(&use_) {
            Ok(true) => Ok(opened.verified()),
            Ok(false) => Err(Rejected::new(Reason::AlreadyUsed)),
            Err(StoreError::SessionLimit) => Err(Rejected::new(Reason::TooManyUses)),
            Err(_) => Err(Rejected::new(Reason::StoreUnavailable)),
        }
    }

    /// The request origin policy alone (layer 1), whatever the mode.
    ///
    /// `Ok` is not a pass on its own: `Ok(OriginCheck::NoFacts)` means the
    /// request carried nothing to judge (no Fetch Metadata, `Origin`, or
    /// `Referer`), and only a token can decide such a request. Use `check`
    /// (or [`check_at`](Self::check_at)) to gate requests; use `policy` for
    /// logging or for `PolicyOnly`-style decisions where you handle `NoFacts`
    /// yourself.
    ///
    /// # Errors
    ///
    /// The [`Rejected`](crate::Rejected) reason when the policy refuses the
    /// request.
    pub fn policy(&self, facts: &RequestFacts<'_>) -> Result<OriginCheck, crate::Rejected> {
        self.policy.decide(facts)
    }

    /// Check a request at `now` (unix seconds): the policy and the token,
    /// combined by the mode. Works without `std`.
    ///
    /// Safe methods (`GET`, `HEAD`, `OPTIONS`) pass without a token. A
    /// one-time binding always checks the token: in `PolicyOnly` mode it is
    /// checked after the policy, as in `Strict`.
    pub fn check_at(
        &self,
        facts: &RequestFacts<'_>,
        binding: &Binding<'_>,
        token: &[u8],
        now: u64,
    ) -> Verdict {
        match self.mode {
            Mode::Strict => {
                let origin = self.policy.decide(facts)?;
                if origin == OriginCheck::SafeMethod {
                    return Ok(Verified::policy(origin));
                }
                self.verify_at(binding, token, now)
                    .map(|v| v.with_origin_check(origin))
            }
            Mode::TokenOnly => {
                if facts.method() == crate::MethodClass::Safe {
                    return Ok(Verified::policy(OriginCheck::SafeMethod));
                }
                self.verify_at(binding, token, now)
            }
            Mode::PolicyOnly => {
                let origin = self.policy.decide_strict_metadata(facts)?;
                if binding.store.is_none() || origin == OriginCheck::SafeMethod {
                    return Ok(Verified::policy(origin));
                }
                self.verify_at(binding, token, now)
                    .map(|v| v.with_origin_check(origin))
            }
        }
    }

    /// A new `Csrf` that signs with `key` under `id`, keeping the current
    /// signing key as retired for one lifetime plus skew after `now` (to the
    /// last second of the last token it could have signed), so no open form
    /// fails. Retired keys already expired at `now` are dropped. If `id` is an
    /// accepted (staged) key with the same key bytes, it is promoted.
    ///
    /// # Errors
    ///
    /// [`Error::Clock`] when `now` is outside 2020 to 2156 (a time in
    /// milliseconds, say), [`Error::WeakKey`], [`Error::DuplicateKeyId`] when
    /// `id` is still in use by another key, [`Error::TooManyKeys`]. To rotate
    /// away from a compromised key on a host whose clock is broken, build a
    /// new `Csrf` with [`builder`](Self::builder) instead.
    pub fn rotated_at(&self, id: KeyId, key: [u8; KEY_LEN], now: u64) -> Result<Self, Error> {
        token::issued_at(now)?;
        let key = Zeroizing::new(key);
        let slot = Slot::derive(id, KeyRole::Signing, &key)?;
        // A peer whose clock runs `skew` ahead may sign with the old key until
        // `now + skew`; that token is valid through `+ lifetime`, inclusive,
        // and a retired key verifies while `now < retire_at`, hence the `+ 1`.
        let retire_at = now + u64::from(self.window.lifetime) + u64::from(self.window.skew) + 1;
        Ok(Self {
            ring: self.ring.rotated(slot, now, retire_at)?,
            window: self.window,
            once_window: self.once_window,
            mode: self.mode,
            policy: self.policy.clone(),
        })
    }
}

#[cfg(feature = "std")]
impl Csrf {
    // ---------------------------------------------------------------- Tier 1

    /// Issue a token bound to `session`. Different text on every call; all of
    /// it verifies.
    ///
    /// # Errors
    ///
    /// [`Error::EmptySession`], [`Error::Clock`], or [`Error::Random`]; no
    /// token is issued on error.
    pub fn issue<S: AsRef<[u8]>>(&self, session: S) -> Result<Token, Error> {
        self.issue_with(&Binding::new(session.as_ref()))
    }

    /// Verify a token submitted for `session` (layer 2 only).
    pub fn verify<S: AsRef<[u8]>, T: AsRef<[u8]>>(&self, session: S, token: T) -> Verdict {
        self.verify_with(&Binding::new(session.as_ref()), token)
    }

    /// Check a request: the request origin policy and the token, combined by
    /// the mode. The recommended call for browser traffic.
    pub fn check<S: AsRef<[u8]>, T: AsRef<[u8]>>(
        &self,
        facts: &RequestFacts<'_>,
        session: S,
        token: T,
    ) -> Verdict {
        self.check_with(facts, &Binding::new(session.as_ref()), token)
    }

    // ---------------------------------------------------------------- Tier 2

    /// Issue a token for `binding` (session, scope).
    ///
    /// # Errors
    ///
    /// As [`issue`](Self::issue).
    pub fn issue_with(&self, binding: &Binding<'_>) -> Result<Token, Error> {
        self.issue_at(binding, unix_now(), &mut crate::OsPads)
    }

    /// Verify a token against `binding` (layer 2 only).
    pub fn verify_with<T: AsRef<[u8]>>(&self, binding: &Binding<'_>, token: T) -> Verdict {
        self.verify_at(binding, token.as_ref(), unix_now())
    }

    /// Check a request against `binding`: policy and token, by mode.
    pub fn check_with<T: AsRef<[u8]>>(
        &self,
        facts: &RequestFacts<'_>,
        binding: &Binding<'_>,
        token: T,
    ) -> Verdict {
        self.check_at(facts, binding, token.as_ref(), unix_now())
    }

    /// Whether a token signed by `id` would verify now.
    #[must_use]
    pub fn accepts(&self, id: KeyId) -> bool {
        self.accepts_at(id, unix_now())
    }

    /// [`rotated_at`](Self::rotated_at) with the system clock.
    ///
    /// # Errors
    ///
    /// As [`rotated_at`](Self::rotated_at).
    pub fn rotated(&self, id: KeyId, key: [u8; KEY_LEN]) -> Result<Self, Error> {
        self.rotated_at(id, key, unix_now())
    }
}

/// Seconds since the Unix epoch from the system clock (0 if it reads before
/// 1970, which `issue` then refuses as `Error::Clock`).
#[cfg(feature = "std")]
#[inline]
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl fmt::Debug for Csrf {
    /// Key ids, roles, and settings only; never key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Csrf")
            .field("keys", &self.ring)
            .field("lifetime_secs", &self.window.lifetime)
            .field("once_lifetime_secs", &self.once_window.lifetime)
            .field("skew_secs", &self.window.skew)
            .field("mode", &self.mode)
            .field("policy", &self.policy)
            .finish()
    }
}

/// A key handed to the builder, wiped when the builder is dropped.
struct PendingKey {
    id: KeyId,
    role: KeyRole,
    key: Zeroizing<[u8; KEY_LEN]>,
}

/// Configures a [`Csrf`]: keys, lifetime, skew, mode, and allowed origins.
///
/// Every setter is infallible; problems are reported once, by
/// [`build`](Self::build).
///
/// ```
/// # fn main() -> Result<(), csrf_sec::Error> {
/// use std::time::Duration;
/// use csrf_sec::{Csrf, KeyId, Mode};
///
/// # let (current_key, old_key, retire_at) = (*b"current key, 32 bytes long!!!!!!", *b"previous key, 32 bytes long!!!!!", 1_900_000_000);
/// let csrf = Csrf::builder()
///     .key(KeyId(3), current_key)
///     .retired(KeyId(2), old_key, retire_at)
///     .lifetime(Duration::from_secs(12 * 3600))
///     .skew(Duration::from_secs(60))
///     .mode(Mode::Strict)
///     .allow_origin("https://example.com")
///     .allow_same_site(false)
///     .build()?;
/// assert_eq!(csrf.signing_key(), KeyId(3));
/// # Ok(())
/// # }
/// ```
pub struct Builder {
    /// Reserved for `MAX_KEYS` up front and never grown, so no reallocation
    /// leaves a copy of a key in freed memory.
    keys: Vec<PendingKey>,
    too_many_keys: bool,
    lifetime: Duration,
    once_lifetime: Option<Duration>,
    skew: Duration,
    mode: Mode,
    policy: Policy,
    invalid_origin: bool,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            keys: Vec::with_capacity(MAX_KEYS),
            too_many_keys: false,
            lifetime: DEFAULT_LIFETIME,
            once_lifetime: None,
            skew: DEFAULT_SKEW,
            mode: Mode::Strict,
            policy: Policy::default(),
            invalid_origin: false,
        }
    }
}

impl Builder {
    fn push(mut self, id: KeyId, role: KeyRole, key: [u8; KEY_LEN]) -> Self {
        let key = Zeroizing::new(key);
        if self.keys.len() == MAX_KEYS {
            // Refused by `build`; the key is wiped here rather than stored.
            self.too_many_keys = true;
        } else {
            self.keys.push(PendingKey { id, role, key });
        }
        self
    }

    /// The signing key: signs new tokens and verifies. Exactly one is
    /// required.
    #[must_use]
    pub fn key(self, id: KeyId, key: [u8; KEY_LEN]) -> Self {
        self.push(id, KeyRole::Signing, key)
    }

    /// A key that verifies but does not sign, with no end. Stage a new key on
    /// every node of a cluster with `accept` before any node signs with it.
    #[must_use]
    pub fn accept(self, id: KeyId, key: [u8; KEY_LEN]) -> Self {
        self.push(id, KeyRole::Accepted, key)
    }

    /// A key that verifies until `retire_at` (unix seconds, exclusive), then
    /// is refused as [`Reason::UnknownKey`](crate::Reason::UnknownKey). Set
    /// `retire_at` at least one lifetime plus skew plus one second after the
    /// key stopped signing. A time past 2156 (a time in milliseconds, say) is
    /// refused by [`build`](Self::build) as [`Error::InvalidRetireTime`].
    #[must_use]
    pub fn retired(self, id: KeyId, key: [u8; KEY_LEN], retire_at: u64) -> Self {
        self.push(id, KeyRole::Retired { until: retire_at }, key)
    }

    /// How long a token stays valid after it is issued (default 12 hours;
    /// whole seconds; 1 second to `u32::MAX` seconds).
    #[must_use]
    pub fn lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// How long a one-time token ([`Binding::once`]) stays valid (default 1
    /// hour, or the general lifetime if that is shorter; at most the general
    /// lifetime). The store keeps each used one-time token for this long plus
    /// the skew.
    ///
    /// Every node sharing a store must use the same value: the consuming
    /// node sets the record's expiry, and a node with a longer setting would
    /// accept the token again after that record expired.
    #[must_use]
    pub fn once_lifetime(mut self, lifetime: Duration) -> Self {
        self.once_lifetime = Some(lifetime);
        self
    }

    /// How far in the future a token's issue time may be, to tolerate clock
    /// differences between nodes (default 60 seconds; at most the lifetime).
    #[must_use]
    pub fn skew(mut self, skew: Duration) -> Self {
        self.skew = skew;
        self
    }

    /// How the policy and the token combine (default [`Mode::Strict`]).
    #[must_use]
    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Also allow requests from `origin`, a serialized origin such as
    /// `https://partner.example` (scheme, host, optional port; no path). The
    /// site's own origin comes from
    /// [`RequestFacts::own_origin`](crate::RequestFacts::own_origin); add it
    /// here too if the adapter cannot supply it.
    #[must_use]
    pub fn allow_origin(mut self, origin: &str) -> Self {
        if !self.policy.allow(origin) {
            self.invalid_origin = true;
        }
        self
    }

    /// Whether `Sec-Fetch-Site: same-site` (a sibling subdomain) passes
    /// layer 1 (default `false`).
    #[must_use]
    pub fn allow_same_site(mut self, allow: bool) -> Self {
        self.policy.set_allow_same_site(allow);
        self
    }

    /// Build the `Csrf`. Subkeys are derived here; the keys given to the
    /// builder are wiped when it is dropped.
    ///
    /// # Errors
    ///
    /// [`Error::NoSigningKey`], [`Error::MultipleSigningKeys`],
    /// [`Error::DuplicateKeyId`], [`Error::TooManyKeys`], [`Error::WeakKey`],
    /// [`Error::InvalidLifetime`], [`Error::InvalidSkew`],
    /// [`Error::InvalidOrigin`], [`Error::InvalidRetireTime`].
    pub fn build(self) -> Result<Csrf, Error> {
        if self.invalid_origin {
            return Err(Error::InvalidOrigin);
        }
        let lifetime =
            u32::try_from(self.lifetime.as_secs()).map_err(|_| Error::InvalidLifetime)?;
        if lifetime == 0 {
            return Err(Error::InvalidLifetime);
        }
        let skew = u32::try_from(self.skew.as_secs()).map_err(|_| Error::InvalidSkew)?;
        if skew > lifetime {
            return Err(Error::InvalidSkew);
        }
        let once = match self.once_lifetime {
            None => lifetime.min(DEFAULT_ONCE_LIFETIME.as_secs() as u32),
            Some(d) => match u32::try_from(d.as_secs()) {
                Ok(secs) if secs != 0 && secs <= lifetime => secs,
                _ => return Err(Error::InvalidLifetime),
            },
        };
        let latest = token::EPOCH + u64::from(u32::MAX) + u64::from(lifetime) + u64::from(skew) + 1;
        if self
            .keys
            .iter()
            .any(|k| matches!(k.role, KeyRole::Retired { until } if until > latest))
        {
            return Err(Error::InvalidRetireTime);
        }
        if self.too_many_keys {
            return Err(Error::TooManyKeys);
        }
        // Sized up front: a growing vector would leave subkeys in freed memory.
        let mut slots = Vec::with_capacity(self.keys.len());
        for k in &self.keys {
            slots.push(Slot::derive(k.id, k.role, &k.key)?);
        }
        Ok(Csrf {
            ring: Ring::new(slots)?,
            window: Window { lifetime, skew },
            once_window: Window {
                lifetime: once,
                skew,
            },
            mode: self.mode,
            policy: self.policy,
        })
    }
}

impl fmt::Debug for Builder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let keys: Vec<(KeyId, KeyRole)> = self.keys.iter().map(|k| (k.id, k.role)).collect();
        f.debug_struct("Builder")
            .field("keys", &keys)
            .field("lifetime", &self.lifetime)
            .field("skew", &self.skew)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::{Csrf, DEFAULT_LIFETIME, DEFAULT_SKEW};
    use crate::{Binding, Error, KeyId, Mode, OriginCheck, Reason, RequestFacts, token::EPOCH};

    const K1: [u8; 32] = *b"key one, thirty-two bytes long!!";
    const K2: [u8; 32] = *b"key two, thirty-two bytes long!!";
    const K3: [u8; 32] = *b"key three, 32 bytes long........";
    const NOW: u64 = EPOCH + 200_000_000;

    struct Counter(u8);
    impl crate::PadSource for Counter {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
            for b in out {
                self.0 = self.0.wrapping_add(37);
                *b = self.0;
            }
            Ok(())
        }
    }

    fn issue(c: &Csrf, b: &Binding<'_>, now: u64) -> crate::Token {
        c.issue_at(b, now, &mut Counter(1)).unwrap()
    }

    #[test]
    fn test_public_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Csrf>();
        assert_send_sync::<crate::Builder>();
        assert_send_sync::<crate::Token>();
        assert_send_sync::<crate::Rejected>();
        assert_send_sync::<crate::Verified>();
        assert_send_sync::<crate::RequestFacts<'static>>();
        assert_send_sync::<crate::KeyInfo>();
        #[cfg(feature = "std")]
        assert_send_sync::<crate::MemoryStore>();
    }

    #[test]
    fn test_keys_lists_ring_signing_first() {
        let c = Csrf::builder()
            .accept(KeyId(5), K2)
            .key(KeyId(4), K1)
            .retired(KeyId(3), K3, NOW)
            .build()
            .unwrap();
        let keys: Vec<_> = c.keys().collect();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].id(), KeyId(4));
        assert_eq!(keys[0].role(), crate::KeyRole::Signing);
        assert!(
            keys.iter()
                .any(|k| k.role() == crate::KeyRole::Retired { until: NOW })
        );
        assert_eq!(
            c.key_fingerprint(KeyId(5)),
            Some(
                keys.iter()
                    .find(|k| k.id() == KeyId(5))
                    .unwrap()
                    .fingerprint()
            )
        );
        assert_eq!(c.key_fingerprint(KeyId(9)), None);
    }

    #[test]
    fn test_default_constants_values() {
        assert_eq!(DEFAULT_LIFETIME, Duration::from_secs(43_200));
        assert_eq!(DEFAULT_SKEW, Duration::from_secs(60));
    }

    #[test]
    fn test_retire_time_limit_is_exact() {
        let latest = |lifetime: u64, skew: u64| EPOCH + u64::from(u32::MAX) + lifetime + skew + 1;
        let build = |retire_at: u64, lifetime: u64, skew: u64| {
            Csrf::builder()
                .key(KeyId(1), K1)
                .retired(KeyId(2), K2, retire_at)
                .lifetime(Duration::from_secs(lifetime))
                .skew(Duration::from_secs(skew))
                .build()
        };
        for (lifetime, skew) in [(600, 30), (43_200, 60), (7, 7)] {
            assert!(build(latest(lifetime, skew), lifetime, skew).is_ok());
            assert_eq!(
                build(latest(lifetime, skew) + 1, lifetime, skew).unwrap_err(),
                Error::InvalidRetireTime
            );
        }
    }

    #[test]
    fn test_builder_never_grows_its_key_buffer() {
        let key = |i: u8| {
            let mut k = K1;
            k[0] = i;
            k
        };
        let mut b = Csrf::builder().key(KeyId(0), key(0));
        let reserved = b.keys.capacity();
        assert!(reserved >= crate::MAX_KEYS);
        for i in 1..crate::MAX_KEYS as u8 {
            b = b.accept(KeyId(i), key(i));
        }
        assert_eq!(b.keys.capacity(), reserved);
        assert!(!b.too_many_keys);
        let full = b.keys.len();
        let b = b.accept(KeyId(99), key(99));
        assert_eq!((b.keys.len(), b.keys.capacity()), (full, reserved));
        assert!(b.too_many_keys);
        assert_eq!(b.build().unwrap_err(), Error::TooManyKeys);
        // Exactly MAX_KEYS keys build.
        let mut b = Csrf::builder().key(KeyId(0), key(0));
        for i in 1..crate::MAX_KEYS as u8 {
            b = b.accept(KeyId(i), key(i));
        }
        assert_eq!(b.build().unwrap().keys().count(), crate::MAX_KEYS);
    }

    #[test]
    fn test_builder_settings_are_kept() {
        let c = Csrf::builder()
            .key(KeyId(2), K1)
            .mode(Mode::TokenOnly)
            .lifetime(Duration::from_secs(900))
            .skew(Duration::from_secs(5))
            .allow_same_site(true)
            .build()
            .unwrap();
        assert_eq!(c.mode(), Mode::TokenOnly);
        assert_eq!(c.lifetime(), Duration::from_secs(900));
        assert_eq!(c.skew(), Duration::from_secs(5));
        assert_eq!(c.signing_key(), KeyId(2));
        let sibling = RequestFacts::new("POST").fetch_site("same-site");
        assert_eq!(c.policy(&sibling), Ok(OriginCheck::FetchMetadata));
        let strict = Csrf::builder().key(KeyId(2), K1).build().unwrap();
        assert_eq!(
            strict.policy(&sibling).unwrap_err().reason(),
            Reason::CrossSite
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_accepts_uses_the_system_clock() {
        let c = Csrf::builder()
            .key(KeyId(1), K1)
            .retired(KeyId(2), K2, crate::token::EPOCH + u64::from(u32::MAX))
            .retired(KeyId(3), K3, 1)
            .build()
            .unwrap();
        assert!(c.accepts(KeyId(1)));
        assert!(c.accepts(KeyId(2)));
        assert!(!c.accepts(KeyId(3)), "retired in 1970");
        assert!(!c.accepts(KeyId(4)));
    }

    #[test]
    fn test_new_defaults() {
        let c = Csrf::new(K1).unwrap();
        assert_eq!(c.signing_key(), KeyId(0));
        assert_eq!(c.lifetime(), DEFAULT_LIFETIME);
        assert_eq!(c.skew(), DEFAULT_SKEW);
        assert_eq!(c.mode(), Mode::Strict);
    }

    #[test]
    fn test_new_weak_key_rejects() {
        assert_eq!(Csrf::new([9; 32]).unwrap_err(), Error::WeakKey(KeyId(0)));
    }

    #[test]
    fn test_builder_errors() {
        assert_eq!(Csrf::builder().build().unwrap_err(), Error::NoSigningKey);
        assert_eq!(
            Csrf::builder()
                .key(KeyId(1), K1)
                .key(KeyId(2), K2)
                .build()
                .unwrap_err(),
            Error::MultipleSigningKeys
        );
        assert_eq!(
            Csrf::builder()
                .key(KeyId(1), K1)
                .accept(KeyId(1), K2)
                .build()
                .unwrap_err(),
            Error::DuplicateKeyId(KeyId(1))
        );
        assert_eq!(
            Csrf::builder()
                .key(KeyId(1), K1)
                .lifetime(Duration::ZERO)
                .build()
                .unwrap_err(),
            Error::InvalidLifetime
        );
        assert_eq!(
            Csrf::builder()
                .key(KeyId(1), K1)
                .lifetime(Duration::from_millis(999))
                .build()
                .unwrap_err(),
            Error::InvalidLifetime
        );
        assert_eq!(
            Csrf::builder()
                .key(KeyId(1), K1)
                .lifetime(Duration::from_secs(u64::from(u32::MAX) + 1))
                .build()
                .unwrap_err(),
            Error::InvalidLifetime
        );
        assert_eq!(
            Csrf::builder()
                .key(KeyId(1), K1)
                .lifetime(Duration::from_secs(10))
                .skew(Duration::from_secs(11))
                .build()
                .unwrap_err(),
            Error::InvalidSkew
        );
        assert_eq!(
            Csrf::builder()
                .key(KeyId(1), K1)
                .allow_origin("null")
                .build()
                .unwrap_err(),
            Error::InvalidOrigin
        );
        assert_eq!(
            Csrf::builder().key(KeyId(1), [0; 32]).build().unwrap_err(),
            Error::WeakKey(KeyId(1))
        );
    }

    #[test]
    fn test_builder_lifetime_max_and_skew_equal_lifetime_ok() {
        let c = Csrf::builder()
            .key(KeyId(1), K1)
            .lifetime(Duration::from_secs(u64::from(u32::MAX)))
            .skew(Duration::from_secs(u64::from(u32::MAX)))
            .build()
            .unwrap();
        assert_eq!(c.lifetime().as_secs(), u64::from(u32::MAX));
    }

    #[test]
    fn test_issue_at_verify_at_round_trip() {
        let c = Csrf::new(K1).unwrap();
        let b = Binding::new("sess");
        let t = issue(&c, &b, NOW);
        let v = c.verify_at(&b, t.as_bytes(), NOW).unwrap();
        assert_eq!(v.key_id(), Some(KeyId(0)));
        assert_eq!(v.origin_check(), OriginCheck::NotRun);
    }

    #[test]
    fn test_issue_at_empty_session_and_bad_clock_refuse() {
        let c = Csrf::new(K1).unwrap();
        assert_eq!(
            c.issue_at(&Binding::new(""), NOW, &mut Counter(0))
                .unwrap_err(),
            Error::EmptySession
        );
        assert_eq!(
            c.issue_at(&Binding::new("s"), EPOCH - 1, &mut Counter(0))
                .unwrap_err(),
            Error::Clock
        );
    }

    #[test]
    fn test_issue_at_pad_failure_issues_nothing() {
        struct Broken;
        impl crate::PadSource for Broken {
            fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
                Err(Error::Random)
            }
        }
        let c = Csrf::new(K1).unwrap();
        assert_eq!(
            c.issue_at(&Binding::new("s"), NOW, &mut Broken)
                .unwrap_err(),
            Error::Random
        );
    }

    #[test]
    fn test_verify_at_expiry_and_skew_boundaries() {
        let c = Csrf::builder()
            .key(KeyId(1), K1)
            .lifetime(Duration::from_secs(100))
            .skew(Duration::from_secs(5))
            .build()
            .unwrap();
        let b = Binding::new("s");
        let t = issue(&c, &b, NOW);
        assert!(c.verify_at(&b, t.as_bytes(), NOW + 100).is_ok());
        assert_eq!(
            c.verify_at(&b, t.as_bytes(), NOW + 101)
                .unwrap_err()
                .reason(),
            Reason::Expired
        );
        assert!(c.verify_at(&b, t.as_bytes(), NOW - 5).is_ok());
        assert_eq!(
            c.verify_at(&b, t.as_bytes(), NOW - 6).unwrap_err().reason(),
            Reason::NotYetValid
        );
    }

    #[test]
    fn test_rotation_keeps_old_tokens_until_retirement() {
        let c = Csrf::builder()
            .key(KeyId(1), K1)
            .lifetime(Duration::from_secs(100))
            .skew(Duration::from_secs(10))
            .build()
            .unwrap();
        let b = Binding::new("s");
        let old = issue(&c, &b, NOW);
        let c2 = c.rotated_at(KeyId(2), K2, NOW).unwrap();
        assert_eq!(c2.signing_key(), KeyId(2));
        let v = c2.verify_at(&b, old.as_bytes(), NOW + 50).unwrap();
        assert!(v.retired_key());
        assert_eq!(v.key_id(), Some(KeyId(1)));
        // Retired until NOW + 111: one lifetime, the skew, and the final
        // second. The old token has expired by then anyway.
        assert!(c2.accepts_at(KeyId(1), NOW + 110));
        assert!(!c2.accepts_at(KeyId(1), NOW + 111));
        assert_eq!(
            c2.verify_at(&b, old.as_bytes(), NOW + 111)
                .unwrap_err()
                .reason(),
            Reason::UnknownKey
        );
        let new = issue(&c2, &b, NOW);
        assert!(!c2.verify_at(&b, new.as_bytes(), NOW).unwrap().retired_key());
        assert_eq!(
            c.verify_at(&b, new.as_bytes(), NOW).unwrap_err().reason(),
            Reason::UnknownKey,
            "the old Csrf does not know key 2"
        );
    }

    #[test]
    fn test_cluster_two_step_rotation() {
        // Step 1: every node accepts key 2; node A still signs with key 1.
        let staged = Csrf::builder()
            .key(KeyId(1), K1)
            .accept(KeyId(2), K2)
            .build()
            .unwrap();
        // Step 2: node B already signs with key 2.
        let promoted = Csrf::builder()
            .key(KeyId(2), K2)
            .retired(KeyId(1), K1, NOW + 1_000_000)
            .build()
            .unwrap();
        let b = Binding::new("s");
        let from_b = issue(&promoted, &b, NOW);
        let from_a = issue(&staged, &b, NOW);
        assert!(staged.verify_at(&b, from_b.as_bytes(), NOW).is_ok());
        assert!(promoted.verify_at(&b, from_a.as_bytes(), NOW).is_ok());
        // Promotion by rotation on a staged node.
        let staged = staged.rotated_at(KeyId(2), K2, NOW).unwrap();
        assert_eq!(staged.signing_key(), KeyId(2));
        assert!(
            staged
                .verify_at(&b, from_a.as_bytes(), NOW)
                .unwrap()
                .retired_key()
        );
        assert_eq!(
            staged.rotated_at(KeyId(1), K3, NOW).unwrap_err(),
            Error::DuplicateKeyId(KeyId(1))
        );
    }

    #[test]
    fn test_check_at_modes() {
        let strict = Csrf::new(K1).unwrap();
        let b = Binding::new("s");
        let t = issue(&strict, &b, NOW);
        let same = RequestFacts::new("POST").fetch_site("same-origin");
        let cross = RequestFacts::new("POST").fetch_site("cross-site");
        let get = RequestFacts::new("GET").fetch_site("cross-site");

        let ok = strict.check_at(&same, &b, t.as_bytes(), NOW).unwrap();
        assert_eq!(ok.origin_check(), OriginCheck::FetchMetadata);
        assert!(ok.token_checked());
        assert_eq!(
            strict
                .check_at(&cross, &b, t.as_bytes(), NOW)
                .unwrap_err()
                .reason(),
            Reason::CrossSite
        );
        assert_eq!(
            strict.check_at(&same, &b, b"", NOW).unwrap_err().reason(),
            Reason::Missing
        );
        assert_eq!(
            strict.check_at(&get, &b, b"", NOW).unwrap().origin_check(),
            OriginCheck::SafeMethod
        );

        let token_only = Csrf::builder()
            .key(KeyId(0), K1)
            .mode(Mode::TokenOnly)
            .build()
            .unwrap();
        let v = token_only.check_at(&cross, &b, t.as_bytes(), NOW).unwrap();
        assert_eq!(v.origin_check(), OriginCheck::NotRun);
        assert_eq!(
            token_only
                .check_at(&cross, &b, b"", NOW)
                .unwrap_err()
                .reason(),
            Reason::Missing
        );
        assert!(token_only.check_at(&get, &b, b"", NOW).is_ok());

        let policy_only = Csrf::builder()
            .key(KeyId(0), K1)
            .mode(Mode::PolicyOnly)
            .build()
            .unwrap();
        let v = policy_only.check_at(&same, &b, b"", NOW).unwrap();
        assert!(!v.token_checked());
        assert_eq!(
            policy_only
                .check_at(&cross, &b, t.as_bytes(), NOW)
                .unwrap_err()
                .reason(),
            Reason::CrossSite
        );
        assert_eq!(
            policy_only
                .check_at(&RequestFacts::new("POST"), &b, t.as_bytes(), NOW)
                .unwrap_err()
                .reason(),
            Reason::Unverifiable
        );
    }

    #[test]
    fn test_debug_never_shows_key_material() {
        let c = Csrf::builder()
            .key(KeyId(1), K1)
            .allow_origin("https://a.example")
            .build()
            .unwrap();
        let text = format!("{c:?}");
        assert!(!text.contains("key one"));
        assert!(text.contains("KeyId(1)"));
        assert!(text.contains("https://a.example"));
        let builder = Csrf::builder().key(KeyId(1), K1);
        let text = format!("{builder:?}");
        assert!(!text.contains("key one"));
        assert!(
            text.contains("KeyId(1)") && text.contains("Signing"),
            "{text}"
        );
    }
}
