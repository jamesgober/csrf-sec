//! csrf-sec against the `csrf` crate (0.5.0), the standalone Rust CSRF
//! primitive the framework middlewares are built on.
//!
//! Each side does the work a server does per request:
//!
//! - **issue**: make what goes to the browser, encoded as text. csrf-sec: one
//!   masked token. `csrf`: a token and a cookie (a double-submit pair), both
//!   base64 encoded.
//! - **verify**: check what came back. csrf-sec: decode, unmask, MAC, window.
//!   `csrf`: decode both, check both MACs (or decrypt both), compare, expiry.
//!
//! Run from this directory: `cargo bench`.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use csrf::{
    AesGcmCsrfProtection, ChaCha20Poly1305CsrfProtection, CsrfProtection, HmacCsrfProtection,
};
use csrf_sec::{Binding, Csrf};
use data_encoding::BASE64;

const KEY: [u8; 32] = *b"comparison benchmark key, 32 b!!";
const SESSION: &str = "Q2xhc3NpY2FsIDQzLWNoYXJhY3RlciBzZXNzaW9uIGlk";

fn issue(c: &mut Criterion) {
    let mut group = c.benchmark_group("issue");
    let sec = Csrf::new(KEY).unwrap();
    group.bench_function("csrf-sec", |b| b.iter(|| sec.issue(black_box(SESSION)).unwrap()));

    fn pair<P: CsrfProtection>(p: &P) -> (String, String) {
        let (token, cookie) = p.generate_token_pair(None, 12 * 3600).unwrap();
        (token.b64_string(), cookie.b64_string())
    }
    let hmac = HmacCsrfProtection::from_key(KEY);
    group.bench_function("csrf 0.5 HMAC", |b| b.iter(|| pair(black_box(&hmac))));
    let aes = AesGcmCsrfProtection::from_key(KEY);
    group.bench_function("csrf 0.5 AES-GCM", |b| b.iter(|| pair(black_box(&aes))));
    let chacha = ChaCha20Poly1305CsrfProtection::from_key(KEY);
    group.bench_function("csrf 0.5 ChaCha20-Poly1305", |b| b.iter(|| pair(black_box(&chacha))));
    group.finish();
}

fn verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");
    let sec = Csrf::new(KEY).unwrap();
    let token = sec.issue(SESSION).unwrap();
    let binding = Binding::new(SESSION);
    group.bench_function("csrf-sec", |b| {
        b.iter(|| sec.verify_with(black_box(&binding), black_box(token.as_str())).unwrap())
    });

    fn check<P: CsrfProtection>(p: &P, token: &str, cookie: &str) {
        let token = BASE64.decode(token.as_bytes()).unwrap();
        let cookie = BASE64.decode(cookie.as_bytes()).unwrap();
        let token = p.parse_token(&token).unwrap();
        let cookie = p.parse_cookie(&cookie).unwrap();
        p.verify_token_pair(&token, &cookie).unwrap();
    }
    fn bench<P: CsrfProtection>(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>, name: &str, p: &P) {
        let (token, cookie) = p.generate_token_pair(None, 12 * 3600).unwrap();
        let (token, cookie) = (token.b64_string(), cookie.b64_string());
        group.bench_function(name, |b| b.iter(|| check(black_box(p), black_box(&token), black_box(&cookie))));
    }
    bench(&mut group, "csrf 0.5 HMAC", &HmacCsrfProtection::from_key(KEY));
    bench(&mut group, "csrf 0.5 AES-GCM", &AesGcmCsrfProtection::from_key(KEY));
    bench(&mut group, "csrf 0.5 ChaCha20-Poly1305", &ChaCha20Poly1305CsrfProtection::from_key(KEY));
    group.finish();
}

fn reject_forgery(c: &mut Criterion) {
    let mut group = c.benchmark_group("reject forged token");
    let sec = Csrf::new(KEY).unwrap();
    let mut forged = sec.issue(SESSION).unwrap().as_str().as_bytes().to_vec();
    forged[40] ^= 1;
    let binding = Binding::new(SESSION);
    group.bench_function("csrf-sec", |b| {
        b.iter(|| sec.verify_with(black_box(&binding), black_box(&forged)).unwrap_err())
    });

    let hmac = HmacCsrfProtection::from_key(KEY);
    let (token, cookie) = hmac.generate_token_pair(None, 12 * 3600).unwrap();
    let mut token = token.value().to_vec();
    token[40] ^= 1;
    let (token, cookie) = (BASE64.encode(&token), cookie.b64_string());
    group.bench_function("csrf 0.5 HMAC", |b| {
        b.iter(|| {
            let t = BASE64.decode(black_box(token.as_bytes())).unwrap();
            let k = BASE64.decode(black_box(cookie.as_bytes())).unwrap();
            let parsed = hmac.parse_token(&t).and_then(|t| hmac.parse_cookie(&k).map(|k| (t, k)));
            parsed.and_then(|(t, k)| hmac.verify_token_pair(&t, &k)).unwrap_err()
        })
    });
    group.finish();
}

criterion_group!(benches, issue, verify, reject_forgery);
criterion_main!(benches);
