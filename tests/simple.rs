//! The Tier 1 surface: a key, a request's facts from its headers in one call,
//! and the plain names for randomness.

#![cfg(feature = "std")]

use std::collections::HashMap;

use csrf_sec::{Csrf, OriginCheck, OsRandom, RandomSource, Reason, RequestFacts};
use proptest::prelude::*;

const OWN: &str = "https://example.com";

fn csrf() -> Csrf {
    Csrf::new(*b"tier 1 tests, a 32 byte key!!!!!").unwrap()
}

/// Facts the long way, from the same headers, for comparison.
fn by_hand<'a>(method: &'a str, headers: &'a HashMap<&'a str, &'a str>) -> RequestFacts<'a> {
    let mut f = RequestFacts::new(method).own_origin(OWN);
    if let Some(v) = headers.get("sec-fetch-site") {
        f = f.fetch_site(*v);
    }
    if let Some(v) = headers.get("origin") {
        f = f.origin(*v);
    }
    if let Some(v) = headers.get("referer") {
        f = f.referer(*v);
    }
    f
}

#[test]
fn test_from_headers_is_one_line_and_checks_a_request() {
    let csrf = csrf();
    let token = csrf.issue("session-1").unwrap();
    let headers = HashMap::from([("sec-fetch-site", "same-origin"), ("origin", OWN)]);
    let facts = RequestFacts::from_headers("POST", OWN, |name| headers.get(name));
    assert!(csrf.check(&facts, "session-1", &token).is_ok());

    let attack = HashMap::from([
        ("sec-fetch-site", "cross-site"),
        ("origin", "https://evil.example"),
    ]);
    let facts = RequestFacts::from_headers("POST", OWN, |name| attack.get(name));
    assert_eq!(
        csrf.check(&facts, "session-1", &token)
            .unwrap_err()
            .reason(),
        Reason::CrossSite
    );
}

#[test]
fn test_from_headers_reads_the_referer() {
    // An older browser: no Fetch Metadata, no Origin, only a Referer.
    let csrf = csrf();
    let ours = HashMap::from([("referer", "https://example.com/form")]);
    let facts = RequestFacts::from_headers("POST", OWN, |name| ours.get(name));
    assert_eq!(csrf.policy(&facts).unwrap(), OriginCheck::Referer);

    let theirs = HashMap::from([("referer", "https://evil.example/page")]);
    let facts = RequestFacts::from_headers("POST", OWN, |name| theirs.get(name));
    assert_eq!(
        csrf.policy(&facts).unwrap_err().reason(),
        Reason::OriginMismatch
    );
}

#[test]
fn test_from_headers_asks_for_lowercase_names() {
    let mut asked = Vec::new();
    let _ = RequestFacts::from_headers("POST", OWN, |name: &str| {
        asked.push(name.to_owned());
        None::<&str>
    });
    asked.sort();
    assert_eq!(asked, ["origin", "referer", "sec-fetch-site"]);
}

#[test]
fn test_from_headers_with_nothing_sent_judges_nothing() {
    let csrf = csrf();
    let facts = RequestFacts::from_headers("POST", OWN, |_| None::<&[u8]>);
    assert_eq!(csrf.policy(&facts).unwrap(), OriginCheck::NoFacts);
    // A safe method passes the policy whatever the headers say.
    let attack = HashMap::from([("sec-fetch-site", "cross-site")]);
    let facts = RequestFacts::from_headers("GET", OWN, |name| attack.get(name));
    assert!(csrf.policy(&facts).is_ok());
}

#[test]
fn test_generate_key_gives_a_usable_new_key_each_time() {
    let a = Csrf::generate_key().unwrap();
    let b = Csrf::generate_key().unwrap();
    assert_ne!(a, b);
    let csrf = Csrf::new(a).unwrap();
    let token = csrf.issue("session-1").unwrap();
    assert!(csrf.verify("session-1", &token).is_ok());
    assert!(Csrf::new(b).unwrap().verify("session-1", &token).is_err());
}

#[test]
fn test_os_random_fills_with_unpredictable_bytes() {
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    OsRandom.fill(&mut a).unwrap();
    OsRandom.fill(&mut b).unwrap();
    assert_ne!(a, b);
    assert_ne!(a, [0u8; 32]);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// `from_headers` decides exactly as the facts built by hand from the
    /// same headers, for any method and header values.
    #[test]
    fn prop_from_headers_equals_the_builder(
        method in prop_oneof![Just("POST".to_owned()), Just("GET".to_owned()), Just("PUT".to_owned()), "[A-Za-z]{0,8}"],
        site in prop_oneof![Just(None), Just(Some("same-origin".to_owned())), Just(Some("same-site".to_owned())), Just(Some("cross-site".to_owned())), Just(Some("none".to_owned())), proptest::option::of("[ -~]{0,16}")],
        origin in prop_oneof![Just(None), Just(Some(OWN.to_owned())), Just(Some("https://evil.example".to_owned())), Just(Some("null".to_owned())), proptest::option::of("[ -~]{0,40}")],
        referer in prop_oneof![Just(None), Just(Some("https://example.com/a".to_owned())), Just(Some("https://evil.example/b".to_owned())), proptest::option::of("[ -~]{0,60}")],
    ) {
        let mut headers = HashMap::new();
        if let Some(v) = &site { headers.insert("sec-fetch-site", v.as_str()); }
        if let Some(v) = &origin { headers.insert("origin", v.as_str()); }
        if let Some(v) = &referer { headers.insert("referer", v.as_str()); }
        let csrf = csrf();
        let token = csrf.issue("s").unwrap();
        let quick = RequestFacts::from_headers(method.as_str(), OWN, |name| headers.get(name));
        let long = by_hand(&method, &headers);
        let a = csrf.check(&quick, "s", &token).map(|v| v.origin_check()).map_err(|e| e.reason());
        let b = csrf.check(&long, "s", &token).map(|v| v.origin_check()).map_err(|e| e.reason());
        prop_assert_eq!(a, b);
    }
}
