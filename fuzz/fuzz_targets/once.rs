//! One-time tokens against `MemoryStore`, driven by an arbitrary sequence of
//! operations: a token passes at most once, a used token never passes again,
//! and the store agrees with a simple model.

#![no_main]

use std::collections::HashSet;

use csrf_sec::{Binding, Csrf, Error, MemoryStore, PadSource, Reason, Token};
use libfuzzer_sys::fuzz_target;

const NOW: u64 = 1_792_540_800;

struct Pads(u64);

impl PadSource for Pads {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        for b in out {
            self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *b = (self.0 >> 56) as u8;
        }
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let csrf = Csrf::new(*b"fuzz target key, thirty-two byte").unwrap();
    let store = MemoryStore::starting_at(64, NOW - 60); // small: exercise the full-shard path
    let binding = Binding::new("fuzz-session").once(&store);
    let mut pads = Pads(data.len() as u64);
    let mut issued: Vec<Token> = Vec::new();
    let mut used: HashSet<usize> = HashSet::new();

    for &op in data {
        match op % 3 {
            // Issue a new token.
            0 if issued.len() < 256 => issued.push(csrf.issue_at(&binding, NOW, &mut pads).unwrap()),
            // Verify a token chosen by the input.
            1 | 2 if !issued.is_empty() => {
                let i = usize::from(op / 3) % issued.len();
                match csrf.verify_at(&binding, issued[i].as_bytes(), NOW) {
                    Ok(_) => assert!(used.insert(i), "token {i} passed twice"),
                    Err(r) => match r.reason() {
                        Reason::AlreadyUsed => assert!(used.contains(&i), "token {i} refused as used"),
                        Reason::StoreUnavailable => {} // full store: fail closed
                        Reason::TooManyUses => {}      // session quota: fail closed
                        other => panic!("unexpected reason {other:?}"),
                    },
                }
            }
            _ => {}
        }
    }
    assert!(store.len() <= used.len());
});
