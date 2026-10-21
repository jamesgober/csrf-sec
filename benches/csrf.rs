//! Hot-path benchmarks: issue, verify, check, the request policy, and
//! one-time tokens. Run with `cargo bench --bench csrf`.

use std::{hint::black_box, sync::Mutex, time::Duration};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use csrf_sec::{
    Binding, Csrf, Error, KeyId, MemoryStore, NonceStore, NonceUse, OsPads, PadSource,
    RequestFacts, StoreError,
};

const NOW: u64 = 1_792_540_800;
const SESSION: &str = "Q2xhc3NpY2FsIDQzLWNoYXJhY3RlciBzZXNzaW9uIGlk"; // 44 chars

/// Deterministic pads, so issue benchmarks measure the token work and not the
/// OS generator (`OsPads` is benchmarked separately).
struct FixedPads(u64);

impl PadSource for FixedPads {
    #[inline]
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

/// A store that never allocates, so one-time benchmarks measure csrf-sec.
struct ArrayStore(Mutex<[Option<[u8; 16]>; 4]>);

impl NonceStore for ArrayStore {
    fn consume(&self, u: &NonceUse<'_>) -> Result<bool, StoreError> {
        let mut slots = self.0.lock().map_err(|_| StoreError::Unavailable)?;
        if slots.iter().any(|s| s.as_ref() == Some(&u.nonce)) {
            return Ok(false);
        }
        slots.rotate_right(1);
        slots[0] = Some(u.nonce);
        Ok(true)
    }
}

fn csrf() -> Csrf {
    Csrf::builder()
        .key(KeyId(1), *b"benchmark key, thirty-two bytes!")
        .allow_origin("https://partner.example")
        .build()
        .unwrap()
}

fn tokens(c: &mut Criterion) {
    let csrf = csrf();
    let binding = Binding::new(SESSION);
    let token = csrf.issue_at(&binding, NOW, &mut FixedPads(1)).unwrap();
    let mut group = c.benchmark_group("session_token");
    group.throughput(Throughput::Elements(1));

    group.bench_function("issue_at", |b| {
        let mut pads = FixedPads(7);
        b.iter(|| csrf.issue_at(black_box(&binding), black_box(NOW), &mut pads))
    });
    group.bench_function("issue (system clock, OsPads)", |b| {
        b.iter(|| csrf.issue(black_box(SESSION)))
    });
    group.bench_function("verify_at", |b| {
        b.iter(|| {
            csrf.verify_at(
                black_box(&binding),
                black_box(token.as_bytes()),
                black_box(NOW),
            )
        })
    });
    group.bench_function("verify (system clock)", |b| {
        let fresh = csrf.issue(SESSION).unwrap();
        b.iter(|| csrf.verify(black_box(SESSION), black_box(&fresh)))
    });
    group.bench_function("issue_at + verify_at", |b| {
        let mut pads = FixedPads(9);
        b.iter(|| {
            let t = csrf.issue_at(&binding, NOW, &mut pads).unwrap();
            csrf.verify_at(&binding, black_box(t.as_bytes()), NOW)
        })
    });
    group.finish();
}

fn rejections(c: &mut Criterion) {
    let csrf = csrf();
    let binding = Binding::new(SESSION);
    let token = csrf.issue_at(&binding, NOW, &mut FixedPads(1)).unwrap();
    let other = Binding::new("another-session");
    let scoped = Binding::new(SESSION)
        .scope("POST /pay")
        .previous_session("old-session");
    let mut group = c.benchmark_group("rejection");

    group.bench_function("missing", |b| {
        b.iter(|| csrf.verify_at(&binding, black_box(b""), NOW))
    });
    group.bench_function("malformed length", |b| {
        b.iter(|| csrf.verify_at(&binding, black_box(b"short"), NOW))
    });
    group.bench_function("malformed text", |b| {
        b.iter(|| csrf.verify_at(&binding, black_box(&[b'*'; 59]), NOW))
    });
    group.bench_function("bad mac (other session)", |b| {
        b.iter(|| csrf.verify_at(&other, black_box(token.as_bytes()), NOW))
    });
    group.bench_function("bad mac, scope and previous session tried", |b| {
        b.iter(|| csrf.verify_at(&scoped, black_box(token.as_bytes()), NOW))
    });
    group.bench_function("expired", |b| {
        b.iter(|| csrf.verify_at(&binding, black_box(token.as_bytes()), NOW + 86_400))
    });
    group.finish();
}

fn session_lengths(c: &mut Criterion) {
    let csrf = csrf();
    let mut group = c.benchmark_group("verify_at by session length");
    for len in [16usize, 43, 56, 64, 128, 1024] {
        let session = vec![b'a'; len];
        let binding = Binding::new(&session);
        let token = csrf.issue_at(&binding, NOW, &mut FixedPads(3)).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, _| {
            b.iter(|| csrf.verify_at(&binding, black_box(token.as_bytes()), NOW))
        });
    }
    group.finish();
}

fn policy(c: &mut Criterion) {
    let csrf = csrf();
    let binding = Binding::new(SESSION);
    let token = csrf.issue_at(&binding, NOW, &mut FixedPads(1)).unwrap();
    let same = RequestFacts::new("POST").fetch_site("same-origin");
    let origin = RequestFacts::new("POST")
        .origin("https://Example.com:443")
        .own_origin("https://example.com");
    let referer = RequestFacts::new("POST")
        .referer("https://example.com/account/settings?tab=email")
        .own_origin("https://example.com");
    let cross = RequestFacts::new("POST")
        .fetch_site("cross-site")
        .origin("https://evil.example")
        .own_origin("https://example.com");
    let mut group = c.benchmark_group("policy");

    group.bench_function("fetch metadata", |b| {
        b.iter(|| csrf.policy(black_box(&same)))
    });
    group.bench_function("origin match", |b| {
        b.iter(|| csrf.policy(black_box(&origin)))
    });
    group.bench_function("referer match", |b| {
        b.iter(|| csrf.policy(black_box(&referer)))
    });
    group.bench_function("cross-site refused", |b| {
        b.iter(|| csrf.policy(black_box(&cross)))
    });
    group.bench_function("facts from raw headers", |b| {
        b.iter(|| {
            RequestFacts::new(black_box("POST"))
                .fetch_site(black_box("same-origin"))
                .origin(black_box("https://example.com"))
                .own_origin(black_box("https://example.com"))
        })
    });
    group.bench_function("check_at strict (policy + token)", |b| {
        b.iter(|| {
            csrf.check_at(
                black_box(&origin),
                &binding,
                black_box(token.as_bytes()),
                NOW,
            )
        })
    });
    group.bench_function("check_at cross-site refused", |b| {
        b.iter(|| {
            csrf.check_at(
                black_box(&cross),
                &binding,
                black_box(token.as_bytes()),
                NOW,
            )
        })
    });
    group.finish();
}

fn one_time(c: &mut Criterion) {
    let csrf = csrf();
    let array = ArrayStore(Mutex::new([None; 4]));
    let memory = MemoryStore::starting_at(1 << 20, NOW - 60);
    let mut group = c.benchmark_group("one_time_token");

    let binding = Binding::new(SESSION).once(&array);
    group.bench_function("issue_at", |b| {
        let mut pads = FixedPads(5);
        b.iter(|| csrf.issue_at(black_box(&binding), NOW, &mut pads))
    });
    group.bench_function("issue_at + verify_at (array store)", |b| {
        let mut pads = FixedPads(11);
        b.iter(|| {
            let t = csrf.issue_at(&binding, NOW, &mut pads).unwrap();
            csrf.verify_at(&binding, black_box(t.as_bytes()), NOW)
        })
    });
    // Steady state: one use a second, records that last a minute, so the
    // session stays under its quota and expired records are dropped as it
    // reaches it. Every verify must pass.
    let short = Csrf::builder()
        .key(KeyId(1), *b"benchmark key, thirty-two bytes!")
        .once_lifetime(Duration::from_secs(50))
        .skew(Duration::from_secs(10))
        .build()
        .unwrap();
    // Criterion runs this closure more than once: the clock must not step
    // back, and nonces must not repeat.
    let binding = Binding::new(SESSION).once(&memory);
    let mut now = NOW;
    let mut pads = FixedPads(13);
    group.bench_function("issue_at + verify_at (MemoryStore)", |b| {
        b.iter(|| {
            now += 1;
            let t = short.issue_at(&binding, now, &mut pads).unwrap();
            short
                .verify_at(&binding, black_box(t.as_bytes()), now)
                .unwrap()
        });
    });
    group.finish();
}

fn randomness(c: &mut Criterion) {
    let mut group = c.benchmark_group("pads");
    group.bench_function("OsPads 22 bytes", |b| {
        let mut pad = [0u8; 22];
        b.iter(|| OsPads.fill(black_box(&mut pad)))
    });
    group.finish();
}

fn setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("setup");
    group.bench_function("Csrf::new", |b| {
        b.iter(|| Csrf::new(black_box(*b"benchmark key, thirty-two bytes!")))
    });
    group.finish();
}

criterion_group!(
    benches,
    tokens,
    rejections,
    session_lengths,
    policy,
    one_time,
    randomness,
    setup
);
criterion_main!(benches);
