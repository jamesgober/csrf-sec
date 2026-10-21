//! Statistical constant-time checks (the dudect method).
//!
//! Each check times one operation on two classes of input that differ only in
//! secret-dependent ways, interleaved at random, and compares the two timing
//! distributions with Welch's t-test after cropping the slowest samples (which
//! are mostly interrupts and cache misses from the rest of the machine). A
//! leak shows up as a large |t|; dudect treats |t| above 4.5 as a sign of a
//! leak and above 10 as definite.
//!
//! These are `#[ignore]`d because they take seconds and need a quiet machine.
//! Run them in release mode:
//!
//! ```text
//! cargo test --release --test timing -- --ignored --nocapture
//! CSRF_TIMING_SAMPLES=2000000 CSRF_TIMING_T=4.5 cargo test --release --test timing -- --ignored
//! ```
//!
//! CI runs them as a smoke test with fewer samples and the threshold of 10.

use std::{hint::black_box, time::Instant};

use csrf_sec::{Binding, Csrf, Error, PadSource, Reason};

const NOW: u64 = 1_792_540_800;
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

struct Pads(u64);

impl PadSource for Pads {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        for b in out {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *b = (self.0 >> 56) as u8;
        }
        Ok(())
    }
}

fn samples() -> usize {
    std::env::var("CSRF_TIMING_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000)
}

fn threshold() -> f64 {
    std::env::var("CSRF_TIMING_T")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10.0)
}

fn decode(text: &[u8]) -> Vec<u8> {
    let (mut bits, mut n, mut out) = (0u32, 0, Vec::new());
    for &c in text {
        bits = (bits << 6) | ALPHABET.iter().position(|&a| a == c).unwrap() as u32;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    out
}

fn encode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in bytes.chunks(3) {
        let x = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let v = (u32::from(x[0]) << 16) | (u32::from(x[1]) << 8) | u32::from(x[2]);
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((v >> (18 - 6 * i)) & 63) as usize]);
        }
    }
    out
}

/// Welch's t statistic of two samples, after dropping each sample's slowest
/// 10 percent.
fn welch_t(mut a: Vec<f64>, mut b: Vec<f64>) -> f64 {
    let crop = |v: &mut Vec<f64>| {
        v.sort_by(f64::total_cmp);
        v.truncate(v.len() * 9 / 10);
    };
    crop(&mut a);
    crop(&mut b);
    let stats = |v: &[f64]| {
        let n = v.len() as f64;
        let mean = v.iter().sum::<f64>() / n;
        let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
        (mean, var, n)
    };
    let (ma, va, na) = stats(&a);
    let (mb, vb, nb) = stats(&b);
    (ma - mb) / (va / na + vb / nb).sqrt()
}

/// A 64-byte-aligned buffer, so both classes' inputs sit at the same offset
/// within a cache line. Otherwise their heap addresses differ, and loads that
/// straddle a cache line for one class but not the other show up as a timing
/// difference that has nothing to do with the data.
#[repr(align(64))]
struct Aligned([u8; 128]);

/// Time `run` on inputs of class 0 and class 1, interleaved at random. Each
/// sample times a batch of calls, so the clock's resolution does not dominate.
fn measure(inputs: [&[u8]; 2], run: impl Fn(&[u8])) -> f64 {
    const BATCH: usize = 8;
    let place = |input: &[u8]| {
        let mut buf = Box::new(Aligned([0u8; 128]));
        buf.0[..input.len()].copy_from_slice(input);
        (buf, input.len())
    };
    let placed = [place(inputs[0]), place(inputs[1])];
    let inputs = [&placed[0].0.0[..placed[0].1], &placed[1].0.0[..placed[1].1]];
    let n = samples();
    let mut times: [Vec<f64>; 2] = [Vec::with_capacity(n), Vec::with_capacity(n)];
    let mut rng = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..1_000 {
        run(inputs[0]);
        run(inputs[1]);
    }
    for _ in 0..2 * n {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let class = (rng & 1) as usize;
        let input = inputs[class];
        let start = Instant::now();
        for _ in 0..BATCH {
            run(black_box(input));
        }
        times[class].push(start.elapsed().as_nanos() as f64);
    }
    let [a, b] = times;
    welch_t(a, b)
}

/// The tag comparison: a forged tag wrong in its first byte against one
/// wrong only in its last byte. A comparison that stops at the first
/// difference would be faster for the first class.
#[test]
#[ignore = "statistical timing test; run with --release --ignored"]
fn timing_tag_comparison_does_not_depend_on_where_tags_differ() {
    let c = Csrf::new(*b"timing test key, thirty-two byte").unwrap();
    let b = Binding::new("victim-session");
    let real = c.issue_at(&b, NOW, &mut Pads(1)).unwrap();
    let bytes = decode(real.as_bytes());
    let forge = |tag_byte: usize| {
        let mut f = bytes.clone();
        f[22 + 6 + tag_byte] ^= 0x80; // body = raw XOR pad; the raw tag starts at 6
        encode(&f)
    };
    let (first, last) = (forge(0), forge(15));
    assert_eq!(
        c.verify_at(&b, &first, NOW).unwrap_err().reason(),
        Reason::BadMac
    );
    assert_eq!(
        c.verify_at(&b, &last, NOW).unwrap_err().reason(),
        Reason::BadMac
    );
    let t = measure([&first, &last], |token| {
        let _ = black_box(c.verify_at(&b, token, NOW));
    });
    println!("tag comparison: t = {t:.2}");
    assert!(
        t.abs() < threshold(),
        "tag comparison timing depends on the data: t = {t:.2}"
    );
}

/// The codec: the same verify path (a forged MAC) on token text made of
/// characters from different parts of the alphabet. A table or a branch per
/// character class would show here.
#[test]
#[ignore = "statistical timing test; run with --release --ignored"]
fn timing_decoding_does_not_depend_on_the_characters() {
    let c = Csrf::new(*b"timing test key, thirty-two byte").unwrap();
    let b = Binding::new("victim-session");
    let mut uppers = vec![b'A'; 59];
    let mut mixed: Vec<u8> = (0..59).map(|i| ALPHABET[(i * 37 + 11) % 64]).collect();
    // Same version and key id bytes are not needed: both fail at the same
    // stage only if they decode; make both canonical and of version 1, key 0
    // by fixing their first raw bytes through the pad.
    for t in [&mut uppers, &mut mixed] {
        t[58] = b'A';
        let mut raw = decode(t);
        raw[22] = raw[0] ^ 1; // version 1
        raw[23] = raw[1]; // key id 0
        *t = encode(&raw);
    }
    assert_eq!(
        c.verify_at(&b, &uppers, NOW).unwrap_err().reason(),
        Reason::BadMac
    );
    assert_eq!(
        c.verify_at(&b, &mixed, NOW).unwrap_err().reason(),
        Reason::BadMac
    );
    let t = measure([&uppers, &mixed], |token| {
        let _ = black_box(c.verify_at(&b, token, NOW));
    });
    println!("decoding: t = {t:.2}");
    assert!(
        t.abs() < threshold(),
        "decoding timing depends on the characters: t = {t:.2}"
    );
}

/// Sanity check of the method itself: two classes of genuinely different
/// cost must be told apart, or the checks above would prove nothing.
#[test]
#[ignore = "statistical timing test; run with --release --ignored"]
fn timing_method_detects_a_real_difference() {
    let c = Csrf::new(*b"timing test key, thirty-two byte").unwrap();
    let b = Binding::new("victim-session");
    let token = c.issue_at(&b, NOW, &mut Pads(2)).unwrap();
    let short = b"short".to_vec();
    // A malformed length is refused in a few nanoseconds; a full verify takes
    // about a hundred.
    let t = measure([token.as_bytes(), &short], |input| {
        let _ = black_box(c.verify_at(&b, input, NOW));
    });
    println!("control: t = {t:.2}");
    assert!(
        t.abs() > 100.0,
        "the method failed to detect a real difference: t = {t:.2}"
    );
}
