//! Key ids, the key ring, and subkey derivation.
//!
//! The application key is never used as a MAC key and is not kept. For every
//! key id, one subkey per token kind is derived once, at construction:
//!
//! ```text
//! subkey = keyed BLAKE3(application key, label | key id)
//! ```
//!
//! Domain separation therefore lives in the key, not in a prefix of every MAC
//! input (PLAN D-009). Subkeys are held in `Zeroizing` buffers and wiped when
//! the ring is dropped.

use alloc::vec::Vec;
use core::fmt;

use crypt_io::{Zeroizing, mac};

use crate::error::Error;

/// Length of an application key, in bytes.
pub const KEY_LEN: usize = 32;

/// Most keys a ring holds at once: one signing key plus accepted and retired
/// keys.
pub const MAX_KEYS: usize = 16;

/// Subkey label for session tokens.
const LABEL_SESSION: &[u8] = b"csrf-sec/v1 session-token mac key";
/// Subkey label for one-time tokens.
const LABEL_ONCE: &[u8] = b"csrf-sec/v1 one-time-token mac key";

/// Identifies a key in the ring. It is written into every token, so a token
/// says which key signed it.
///
/// Ids are public. Never reuse an id for a different key while tokens signed
/// under it can still be presented.
///
/// ```
/// use csrf_sec::KeyId;
///
/// let id = KeyId(3);
/// assert_eq!(id.0, 3);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct KeyId(pub u8);

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// What a key in the ring may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// Signs new tokens and verifies.
    Signing,
    /// Verifies only, with no end (a key staged on every node before it signs).
    Accepted,
    /// Verifies only, while `now < until` (unix seconds).
    Retired { until: u64 },
}

/// Which subkey a token kind uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Per-session token (format version 1).
    Session,
    /// One-time token (format version 2).
    Once,
}

/// One key in the ring: its id, role, and derived subkeys.
#[derive(Clone)]
pub(crate) struct Slot {
    pub(crate) id: KeyId,
    pub(crate) role: Role,
    session: Zeroizing<[u8; KEY_LEN]>,
    once: Zeroizing<[u8; KEY_LEN]>,
}

impl Slot {
    /// Derive the subkeys for `key` under `id`. The caller wipes `key`.
    pub(crate) fn derive(id: KeyId, role: Role, key: &[u8; KEY_LEN]) -> Result<Self, Error> {
        if is_weak(key) {
            return Err(Error::WeakKey(id));
        }
        Ok(Self {
            id,
            role,
            session: derive_subkey(key, LABEL_SESSION, id),
            once: derive_subkey(key, LABEL_ONCE, id),
        })
    }

    /// The subkey for `kind`.
    #[inline]
    pub(crate) fn subkey(&self, kind: Kind) -> &[u8; KEY_LEN] {
        match kind {
            Kind::Session => &self.session,
            Kind::Once => &self.once,
        }
    }

    /// Whether this slot verifies tokens at `now`.
    #[inline]
    pub(crate) fn verifies_at(&self, now: u64) -> bool {
        match self.role {
            Role::Signing | Role::Accepted => true,
            Role::Retired { until } => now < until,
        }
    }

    /// Whether `other` holds the same key material, compared in constant time.
    pub(crate) fn same_key(&self, other: &Self) -> bool {
        crypt_io::Tag::new(*self.session).ct_eq(other.session.as_slice())
    }
}

/// `true` when all 32 bytes are equal (an unset or zeroed buffer). Runs in
/// time independent of the key bytes.
fn is_weak(key: &[u8; KEY_LEN]) -> bool {
    let first = key[0];
    let diff = key.iter().fold(0u8, |acc, &b| acc | (b ^ first));
    diff == 0
}

/// `keyed BLAKE3(key, label | id)`.
fn derive_subkey(key: &[u8; KEY_LEN], label: &[u8], id: KeyId) -> Zeroizing<[u8; KEY_LEN]> {
    let mut input = [0u8; 64];
    let n = label.len();
    input[..n].copy_from_slice(label);
    input[n] = id.0;
    Zeroizing::new(mac::blake3_keyed(key, &input[..=n]))
}

/// The key ring: one signing key, then accepted and retired keys.
///
/// The signing slot is always at index 0, so issuing never searches.
#[derive(Clone)]
pub(crate) struct Ring {
    slots: Vec<Slot>,
}

impl Ring {
    /// Build a ring from slots. Exactly one slot must be `Signing`, ids must be
    /// unique, and at most `MAX_KEYS` slots are allowed.
    pub(crate) fn new(mut slots: Vec<Slot>) -> Result<Self, Error> {
        let signing = slots.iter().filter(|s| s.role == Role::Signing).count();
        if signing == 0 {
            return Err(Error::NoSigningKey);
        }
        if signing > 1 {
            return Err(Error::MultipleSigningKeys);
        }
        if slots.len() > MAX_KEYS {
            return Err(Error::TooManyKeys);
        }
        for (i, a) in slots.iter().enumerate() {
            if slots[..i].iter().any(|b| b.id == a.id) {
                return Err(Error::DuplicateKeyId(a.id));
            }
        }
        let pos = slots
            .iter()
            .position(|s| s.role == Role::Signing)
            .unwrap_or(0);
        slots.swap(0, pos);
        Ok(Self { slots })
    }

    /// The signing slot.
    #[inline]
    pub(crate) fn signing(&self) -> &Slot {
        // `Ring::new` guarantees a signing slot at index 0.
        &self.slots[0]
    }

    /// The slot for `id` if it verifies at `now`.
    #[inline]
    pub(crate) fn verifier(&self, id: u8, now: u64) -> Option<&Slot> {
        self.slots
            .iter()
            .find(|s| s.id.0 == id)
            .filter(|s| s.verifies_at(now))
    }

    /// Whether `id` is in the ring and verifies at `now`.
    pub(crate) fn accepts(&self, id: KeyId, now: u64) -> bool {
        self.verifier(id.0, now).is_some()
    }

    /// All slots, signing first.
    #[cfg(test)]
    pub(crate) fn slots(&self) -> &[Slot] {
        &self.slots
    }

    /// A new ring that signs with `new` and keeps the current signing key as
    /// retired until `retire_at`. Retired keys already past their time at
    /// `now` are dropped. If `new` has the id of an accepted key with the same
    /// key material, that key is promoted; any other id clash is an error.
    pub(crate) fn rotated(&self, new: Slot, now: u64, retire_at: u64) -> Result<Self, Error> {
        let mut slots: Vec<Slot> = Vec::with_capacity(self.slots.len() + 1);
        for slot in &self.slots {
            if !slot.verifies_at(now) {
                continue; // expired retired key: dropped, and its id is free again
            }
            if slot.id == new.id {
                if slot.role == Role::Accepted && slot.same_key(&new) {
                    continue; // promoted below
                }
                return Err(Error::DuplicateKeyId(new.id));
            }
            let mut kept = slot.clone();
            if kept.role == Role::Signing {
                kept.role = Role::Retired { until: retire_at };
            }
            slots.push(kept);
        }
        let mut new = new;
        new.role = Role::Signing;
        slots.insert(0, new);
        Self::new(slots)
    }
}

impl fmt::Debug for Ring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        for slot in &self.slots {
            list.entry(&(slot.id, slot.role));
        }
        list.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{Kind, MAX_KEYS, Ring, Role, Slot, is_weak};
    use crate::{Error, KeyId};

    fn key(b: u8) -> [u8; 32] {
        let mut k = [b; 32];
        k[31] = b.wrapping_add(1);
        k
    }

    #[test]
    fn test_is_weak_all_equal_bytes_detected() {
        assert!(is_weak(&[0u8; 32]));
        assert!(is_weak(&[0xff; 32]));
        assert!(is_weak(&[7; 32]));
        assert!(!is_weak(&key(0)));
        let mut k = [0u8; 32];
        k[0] = 1;
        assert!(!is_weak(&k));
    }

    #[test]
    fn test_slot_derive_weak_key_rejects() {
        assert_eq!(
            Slot::derive(KeyId(4), Role::Signing, &[0u8; 32]).err(),
            Some(Error::WeakKey(KeyId(4)))
        );
    }

    #[test]
    fn test_slot_subkeys_differ_by_kind_and_id() {
        let a = Slot::derive(KeyId(1), Role::Signing, &key(9)).unwrap();
        let b = Slot::derive(KeyId(2), Role::Signing, &key(9)).unwrap();
        assert_ne!(a.subkey(Kind::Session), a.subkey(Kind::Once));
        assert_ne!(a.subkey(Kind::Session), b.subkey(Kind::Session));
        assert_ne!(
            a.subkey(Kind::Session),
            &key(9),
            "the application key is never used directly"
        );
    }

    #[test]
    fn test_slot_subkey_is_deterministic() {
        let a = Slot::derive(KeyId(1), Role::Signing, &key(5)).unwrap();
        let b = Slot::derive(KeyId(1), Role::Accepted, &key(5)).unwrap();
        assert!(a.same_key(&b));
        assert_eq!(a.subkey(Kind::Session), b.subkey(Kind::Session));
    }

    #[test]
    fn test_ring_new_requires_exactly_one_signing_key() {
        let acc = Slot::derive(KeyId(1), Role::Accepted, &key(1)).unwrap();
        assert_eq!(
            Ring::new(vec![acc.clone()]).err(),
            Some(Error::NoSigningKey)
        );
        let s1 = Slot::derive(KeyId(2), Role::Signing, &key(2)).unwrap();
        let s2 = Slot::derive(KeyId(3), Role::Signing, &key(3)).unwrap();
        assert_eq!(
            Ring::new(vec![s1, s2]).err(),
            Some(Error::MultipleSigningKeys)
        );
    }

    #[test]
    fn test_ring_new_duplicate_id_rejects() {
        let s = Slot::derive(KeyId(2), Role::Signing, &key(2)).unwrap();
        let a = Slot::derive(KeyId(2), Role::Accepted, &key(3)).unwrap();
        assert_eq!(
            Ring::new(vec![s, a]).err(),
            Some(Error::DuplicateKeyId(KeyId(2)))
        );
    }

    #[test]
    fn test_ring_new_too_many_keys_rejects() {
        let mut slots = vec![Slot::derive(KeyId(0), Role::Signing, &key(0)).unwrap()];
        for i in 1..=MAX_KEYS as u8 {
            slots.push(Slot::derive(KeyId(i), Role::Accepted, &key(i)).unwrap());
        }
        assert_eq!(Ring::new(slots.clone()).err(), Some(Error::TooManyKeys));
        slots.pop();
        assert!(Ring::new(slots).is_ok());
    }

    #[test]
    fn test_ring_signing_slot_is_first() {
        let a = Slot::derive(KeyId(1), Role::Accepted, &key(1)).unwrap();
        let s = Slot::derive(KeyId(2), Role::Signing, &key(2)).unwrap();
        let ring = Ring::new(vec![a, s]).unwrap();
        assert_eq!(ring.signing().id, KeyId(2));
    }

    #[test]
    fn test_ring_retired_key_verifies_until_time() {
        let s = Slot::derive(KeyId(1), Role::Signing, &key(1)).unwrap();
        let r = Slot::derive(KeyId(2), Role::Retired { until: 100 }, &key(2)).unwrap();
        let ring = Ring::new(vec![s, r]).unwrap();
        assert!(ring.verifier(2, 99).is_some());
        assert!(ring.verifier(2, 100).is_none());
        assert!(ring.verifier(3, 0).is_none());
        assert!(ring.accepts(KeyId(1), u64::MAX));
    }

    #[test]
    fn test_ring_rotated_retires_old_and_prunes_expired() {
        let s = Slot::derive(KeyId(1), Role::Signing, &key(1)).unwrap();
        let old = Slot::derive(KeyId(2), Role::Retired { until: 50 }, &key(2)).unwrap();
        let ring = Ring::new(vec![s, old]).unwrap();
        let new = Slot::derive(KeyId(3), Role::Accepted, &key(3)).unwrap();
        let next = ring.rotated(new, 60, 1000).unwrap();
        assert_eq!(next.signing().id, KeyId(3));
        assert_eq!(
            next.verifier(1, 999).map(|s| s.role),
            Some(Role::Retired { until: 1000 })
        );
        assert!(
            next.verifier(2, 0).is_none(),
            "expired retired key is dropped"
        );
        assert_eq!(next.slots().len(), 2);
    }

    #[test]
    fn test_ring_rotated_promotes_matching_accepted_key() {
        let s = Slot::derive(KeyId(1), Role::Signing, &key(1)).unwrap();
        let staged = Slot::derive(KeyId(2), Role::Accepted, &key(2)).unwrap();
        let ring = Ring::new(vec![s, staged]).unwrap();
        let promote = Slot::derive(KeyId(2), Role::Signing, &key(2)).unwrap();
        let next = ring.rotated(promote, 0, 10).unwrap();
        assert_eq!(next.signing().id, KeyId(2));
        assert_eq!(next.slots().len(), 2);
    }

    #[test]
    fn test_ring_rotated_clashing_id_rejects() {
        let s = Slot::derive(KeyId(1), Role::Signing, &key(1)).unwrap();
        let staged = Slot::derive(KeyId(2), Role::Accepted, &key(2)).unwrap();
        let ring = Ring::new(vec![s, staged]).unwrap();
        let other = Slot::derive(KeyId(2), Role::Signing, &key(7)).unwrap();
        assert_eq!(
            ring.rotated(other, 0, 10).err(),
            Some(Error::DuplicateKeyId(KeyId(2)))
        );
        let same_as_signing = Slot::derive(KeyId(1), Role::Signing, &key(1)).unwrap();
        assert_eq!(
            ring.rotated(same_as_signing, 0, 10).err(),
            Some(Error::DuplicateKeyId(KeyId(1)))
        );
    }

    #[test]
    fn test_ring_rotated_expired_retired_id_can_be_reused() {
        let s = Slot::derive(KeyId(1), Role::Signing, &key(1)).unwrap();
        let old = Slot::derive(KeyId(2), Role::Retired { until: 50 }, &key(2)).unwrap();
        let ring = Ring::new(vec![s, old]).unwrap();
        let reuse = Slot::derive(KeyId(2), Role::Signing, &key(9)).unwrap();
        assert_eq!(
            ring.rotated(reuse.clone(), 49, 100).err(),
            Some(Error::DuplicateKeyId(KeyId(2))),
            "still verifying at 49"
        );
        let next = ring.rotated(reuse, 50, 100).unwrap();
        assert_eq!(next.signing().id, KeyId(2));
    }

    #[test]
    fn test_ring_debug_shows_ids_not_keys() {
        let s = Slot::derive(KeyId(1), Role::Signing, &key(1)).unwrap();
        let text = format!("{:?}", Ring::new(vec![s]).unwrap());
        assert!(text.contains("KeyId(1)"));
        assert!(text.contains("Signing"));
        assert!(text.len() < 40, "{text}");
    }
}
