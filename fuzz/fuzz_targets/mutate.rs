//! Real tokens, mutated by the fuzzer. A mutated token may verify only if it
//! still carries the same raw token under a different mask (masking is public,
//! so remasking is not a forgery); any other change must be refused.

#![no_main]

use csrf_sec::{Binding, Csrf, Error, PadSource};
use libfuzzer_sys::fuzz_target;

const NOW: u64 = 1_792_540_800;
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

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

/// Reference decoder: `None` for anything that is not plain base64url.
fn decode(text: &[u8]) -> Option<Vec<u8>> {
    let (mut bits, mut n, mut out) = (0u32, 0, Vec::new());
    for &c in text {
        bits = (bits << 6) | ALPHABET.iter().position(|&a| a == c)? as u32;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    Some(out)
}

/// The raw token under a mask: body XOR pad.
fn unmask(masked: &[u8]) -> Vec<u8> {
    let (pad, body) = masked.split_at(masked.len() / 2);
    body.iter().zip(pad).map(|(b, p)| b ^ p).collect()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }
    let csrf = Csrf::new(*b"fuzz target key, thirty-two byte").unwrap();
    let seed = u64::from_le_bytes(data[..8].try_into().unwrap());
    let binding = Binding::new("fuzz-session").scope("POST /fuzz");
    let token = csrf.issue_at(&binding, NOW, &mut Pads(seed)).unwrap();
    let original = unmask(&decode(token.as_bytes()).unwrap());

    // Apply the rest of the input as (position, xor) pairs over the text.
    let mut text = token.as_bytes().to_vec();
    for pair in data[8..].chunks_exact(2) {
        let pos = usize::from(pair[0]) % text.len();
        text[pos] ^= pair[1];
    }
    if csrf.verify_at(&binding, &text, NOW).is_ok() {
        let raw = decode(&text).map(|m| unmask(&m));
        assert_eq!(raw.as_deref(), Some(original.as_slice()), "a changed token verified");
    }
});
