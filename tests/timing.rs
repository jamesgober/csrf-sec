//! Statistical constant-time checks (the dudect method).
//!
//! Each check times one operation on two classes of input that differ only in
//! secret-dependent ways, interleaved at random, and compares the two timing
//! distributions with Welch's t-test after cropping the slowest samples (which
//! are mostly interrupts and cache misses from the rest of the machine). A
//! leak shows up as a large |t|; dudect treats |t| above 4.5 as a sign of a
//! leak and above 10 as definite.
//!
//! A real leak is consistent and its |t| grows with the number of samples;
//! noise from a busy machine comes and goes. So a reading over the threshold
//! is measured again with twice the samples, up to three attempts, and the
//! check fails only if every attempt is over.
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

/// Welch's t statistic of two samples after dropping each sample's slowest
/// 10 percent, and the difference of their cropped means.
fn welch_t(mut a: Vec<f64>, mut b: Vec<f64>) -> (f64, f64) {
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
    ((ma - mb) / (va / na + vb / nb).sqrt(), ma - mb)
}

/// One buffer, aligned to a cache line, that every sample of both classes is
/// copied into before it is timed. Inputs at different addresses can differ
/// in cache-line straddles and 4 KiB aliasing with the stack, which shows up
/// as a timing difference that has nothing to do with the data; from one
/// address, only the data differs.
#[repr(align(64))]
struct Aligned([u8; 128]);

/// Calls timed together in one sample, so the clock's resolution does not
/// dominate.
const BATCH: usize = 8;

/// Time `run` on inputs of class 0 and class 1, interleaved at random, `n`
/// samples per class. Returns Welch's t and the mean difference per call in
/// nanoseconds.
fn measure(inputs: [&[u8]; 2], n: usize, seed: u64, run: &impl Fn(&[u8])) -> (f64, f64) {
    assert_eq!(
        inputs[0].len(),
        inputs[1].len(),
        "classes must have equal length"
    );
    let len = inputs[0].len();
    let mut buf = Box::new(Aligned([0u8; 128]));
    let mut times: [Vec<f64>; 2] = [Vec::with_capacity(n + n / 8), Vec::with_capacity(n + n / 8)];
    let mut rng = seed | 1;
    for i in 0..2_000 {
        buf.0[..len].copy_from_slice(inputs[i & 1]);
        run(&buf.0[..len]);
    }
    for _ in 0..2 * n {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let class = ((rng >> 32) & 1) as usize;
        buf.0[..len].copy_from_slice(inputs[class]);
        let input = black_box(&buf.0[..len]);
        let start = Instant::now();
        for _ in 0..BATCH {
            run(black_box(input));
        }
        times[class].push(start.elapsed().as_nanos() as f64);
    }
    let [a, b] = times;
    let (t, diff) = welch_t(a, b);
    (t, diff / BATCH as f64)
}

/// Pass when one attempt reads |t| under the threshold; each further attempt
/// doubles the samples. Fails only if all three attempts are over.
fn check(name: &str, inputs: [&[u8]; 2], run: impl Fn(&[u8])) {
    let limit = threshold();
    let mut readings = Vec::new();
    for attempt in 0..3u32 {
        let n = samples() << attempt;
        let (t, diff) = measure(inputs, n, 0x9e37_79b9_7f4a_7c15 ^ u64::from(attempt), &run);
        println!(
            "{name}: t = {t:.2}, mean difference {diff:+.3} ns per call, {n} samples per class"
        );
        readings.push((t, diff));
        if t.abs() < limit {
            return;
        }
    }
    panic!("{name}: timing depends on the data in every attempt: {readings:?}");
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
    check("tag comparison", [&first, &last], |token| {
        let _ = black_box(c.verify_at(&b, token, NOW));
    });
}

/// The codec: the same raw token under two masks, one that turns most of the
/// text into `A` and one that spreads it over the whole alphabet. Everything
/// after unmasking is identical (both verify), so only the decoder's input
/// differs. A table, or a branch per character class, would show here.
#[test]
#[ignore = "statistical timing test; run with --release --ignored"]
fn timing_decoding_does_not_depend_on_the_characters() {
    let c = Csrf::new(*b"timing test key, thirty-two byte").unwrap();
    let b = Binding::new("victim-session");
    let token = c.issue_at(&b, NOW, &mut Pads(3)).unwrap();
    let masked = decode(token.as_bytes());
    let (pad, body) = masked.split_at(22);
    let raw: Vec<u8> = body.iter().zip(pad).map(|(x, p)| x ^ p).collect();
    let remask = |pad: &[u8]| {
        let mut m = pad.to_vec();
        m.extend(raw.iter().zip(pad).map(|(r, p)| r ^ p));
        encode(&m)
    };
    let zeros = remask(&[0u8; 22]);
    let spread: Vec<u8> = (0..22u8).map(|i| i.wrapping_mul(97) ^ 0xa5).collect();
    let spread = remask(&spread);
    assert!(zeros.starts_with(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    assert!(c.verify_at(&b, &zeros, NOW).is_ok());
    assert!(c.verify_at(&b, &spread, NOW).is_ok());
    check("decoding", [&zeros, &spread], |text| {
        let _ = black_box(c.verify_at(&b, text, NOW));
    });
}

/// Sanity check of the method itself: two classes of genuinely different
/// cost must be told apart, or the checks above would prove nothing.
#[test]
#[ignore = "statistical timing test; run with --release --ignored"]
fn timing_method_detects_a_real_difference() {
    let c = Csrf::new(*b"timing test key, thirty-two byte").unwrap();
    let b = Binding::new("victim-session");
    let token = c.issue_at(&b, NOW, &mut Pads(2)).unwrap();
    // Same length, but one is not base64url (refused after the constant-time
    // decode) and one runs the MAC: a real difference of about 75 ns.
    let garbage = vec![b'*'; token.len()];
    let (t, diff) = measure(
        [token.as_bytes(), &garbage],
        samples(),
        7,
        &|input: &[u8]| {
            let _ = black_box(c.verify_at(&b, input, NOW));
        },
    );
    println!("control: t = {t:.2}, mean difference {diff:+.3} ns per call");
    assert!(
        t.abs() > 100.0,
        "the method failed to detect a real difference: t = {t:.2}"
    );
}
