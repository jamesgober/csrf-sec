//! Known-answer vectors: fixed key, key id, session, scope, time, and pad
//! bytes give exactly this token text, for both layouts.
//!
//! The format is fixed until 1.0 freezes it for the 1.x line; a change that
//! alters any of these strings is a format change. `tests/tokens.rs` and
//! `tests/once.rs` rebuild the format from its description in `docs/API.md`;
//! these strings pin the result, so the crate and that description cannot
//! drift together unnoticed. `docs/TEST_VECTORS.md` lists the same vectors
//! for other implementations.

use csrf_sec::{Binding, Csrf, Error, KeyId, NonceStore, NonceUse, PadSource, StoreError};

/// Pad bytes 0, 1, 2, ... (wrapping), continuing across calls.
struct CountingPads(u8);

impl PadSource for CountingPads {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        for b in out {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

/// A store that has never seen any nonce.
struct Fresh;

impl NonceStore for Fresh {
    fn consume(&self, _: &NonceUse<'_>) -> Result<bool, StoreError> {
        Ok(true)
    }
}

/// Key bytes 0x00, 0x01, ..., 0x1f.
const KEY: [u8; 32] = {
    let mut k = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        k[i] = i as u8;
        i += 1;
    }
    k
};

const T: u64 = 1_792_540_800; // 2026-10-21T00:00:00Z
const EPOCH: u64 = 1_577_836_800; // 2020-01-01T00:00:00Z
const LONG_SESSION: [u8; 300] = [b's'; 300];
const LONG_SCOPE: [u8; 200] = [b'p'; 200];

struct Vector {
    name: &'static str,
    key_id: u8,
    session: &'static [u8],
    scope: &'static [u8],
    issued_at: u64,
    once: bool,
    text: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        name: "session token, no scope",
        key_id: 0,
        session: b"session-1",
        scope: b"",
        issued_at: T,
        once: false,
        text: "AAECAwQFBgcICQoLDA0ODxAREhMUFQEBghzICcvIOkah9oYQIY-vW0wS77s",
    },
    Vector {
        name: "session token, scoped",
        key_id: 0,
        session: b"session-1",
        scope: b"POST /pay",
        issued_at: T,
        once: false,
        text: "AAECAwQFBgcICQoLDA0ODxAREhMUFQEBghzICQM0quXG3nig2Xkp-NswIXA",
    },
    Vector {
        name: "session token, key id 7, 43-character session id",
        key_id: 7,
        session: b"Q2xhc3NpY2FsIDQzLWNoYXJhY3RlciBzZXNzaW9uIGl",
        scope: b"POST /account/email",
        issued_at: T,
        once: false,
        text: "AAECAwQFBgcICQoLDA0ODxAREhMUFQEGghzICfn6ZD6fclsw30XkxvFLrf4",
    },
    Vector {
        name: "session token, long inputs (streamed MAC)",
        key_id: 255,
        session: &LONG_SESSION,
        scope: &LONG_SCOPE,
        issued_at: T,
        once: false,
        text: "AAECAwQFBgcICQoLDA0ODxAREhMUFQH-ghzICRNr7xvmCxjMogEJsbMWk6Q",
    },
    Vector {
        name: "session token, first second of the epoch",
        key_id: 0,
        session: b"session-1",
        scope: b"",
        issued_at: EPOCH,
        once: false,
        text: "AAECAwQFBgcICQoLDA0ODxAREhMUFQEBAgMEBfcRpXw8TFQNCqot3Orz7sk",
    },
    Vector {
        name: "session token, last representable second",
        key_id: 0,
        session: b"session-1",
        scope: b"",
        issued_at: EPOCH + u32::MAX as u64,
        once: false,
        text: "AAECAwQFBgcICQoLDA0ODxAREhMUFQEB_fz7-sGlCopL82Qp77lTqE6bqvU",
    },
    Vector {
        name: "one-time token, scoped",
        key_id: 0,
        session: b"session-1",
        scope: b"POST /pay",
        issued_at: T,
        once: true,
        text: "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDUSEZIM2BkWFhoaHh4aGhYWKiouLioqtAwWUz2ob7Iv7nQucaPUTA",
    },
    Vector {
        name: "one-time token, long inputs (streamed MAC)",
        key_id: 9,
        session: &LONG_SESSION,
        scope: &LONG_SCOPE,
        issued_at: T,
        once: true,
        text: "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDUSGJIM2BkWFhoaHh4aGhYWKiouLioq6KxTaiXqC1CIbNPjQ5CkKg",
    },
];

fn csrf(key_id: u8) -> Csrf {
    Csrf::builder().key(KeyId(key_id), KEY).build().unwrap()
}

#[test]
fn vectors_issue_exactly_this_text() {
    let mut mismatches = Vec::new();
    for v in VECTORS {
        let c = csrf(v.key_id);
        let base = Binding::new(v.session).scope(v.scope);
        let binding = if v.once { base.once(&Fresh) } else { base };
        let token = c
            .issue_at(&binding, v.issued_at, &mut CountingPads(0))
            .unwrap();
        if token.as_str() != v.text {
            mismatches.push(format!("{}: {}", v.name, token.as_str()));
        }
        assert!(
            c.verify_at(&binding, token.as_bytes(), v.issued_at).is_ok(),
            "{}",
            v.name
        );
    }
    assert!(mismatches.is_empty(), "\n{}", mismatches.join("\n"));
}

#[test]
fn vectors_verify_from_text_alone() {
    for v in VECTORS {
        let c = csrf(v.key_id);
        let base = Binding::new(v.session).scope(v.scope);
        let binding = if v.once { base.once(&Fresh) } else { base };
        assert!(
            c.verify_at(&binding, v.text.as_bytes(), v.issued_at)
                .is_ok(),
            "{}",
            v.name
        );
    }
}

#[test]
fn fingerprint_vector() {
    let fp = csrf(0).key_fingerprint(KeyId(0)).unwrap().to_string();
    assert_eq!(fp, "756b8253b16ff08a");
}
