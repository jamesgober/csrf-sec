//! Arbitrary bytes as the session, scope, previous session, and token: verify
//! never panics, and nothing the fuzzer makes is ever accepted. A pass would
//! be a forged token.

#![no_main]

use csrf_sec::{Binding, Csrf};
use libfuzzer_sys::fuzz_target;

const NOW: u64 = 1_792_540_800;

fuzz_target!(|data: &[u8]| {
    let csrf = Csrf::new(*b"fuzz target key, thirty-two byte").unwrap();
    // Split the input into four parts by the first three bytes.
    if data.len() < 3 {
        return;
    }
    let (lens, rest) = data.split_at(3);
    let a = usize::from(lens[0]).min(rest.len());
    let (session, rest) = rest.split_at(a);
    let b = usize::from(lens[1]).min(rest.len());
    let (scope, rest) = rest.split_at(b);
    let c = usize::from(lens[2]).min(rest.len());
    let (previous, token) = rest.split_at(c);

    let binding = Binding::new(session).scope(scope).previous_session(previous);
    let verdict = csrf.verify_at(&binding, token, NOW);
    assert!(verdict.is_err(), "a fuzzer-made token verified: {verdict:?}");
});
