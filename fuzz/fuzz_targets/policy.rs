//! Arbitrary request facts and allowlists: the policy never panics, safe
//! methods always pass, and a request the browser calls cross-site passes
//! only on an allowlisted origin. `RequestFacts::from_headers` decides
//! exactly as the setters do.

#![no_main]

use csrf_sec::{Csrf, KeyId, MethodClass, OriginCheck, RequestFacts};
use libfuzzer_sys::fuzz_target;

/// What the browser declared in `Sec-Fetch-Site`, parsed here independently
/// of the crate: the four defined values, surrounding spaces and tabs (byte
/// 9) ignored; anything else declares nothing.
fn declared(site: &[u8]) -> Option<&[u8]> {
    let mut v = site;
    while let [b' ' | 9, rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | 9] = v {
        v = rest;
    }
    matches!(v, b"same-origin" | b"same-site" | b"cross-site" | b"none").then_some(v)
}

fuzz_target!(|data: &[u8]| {
    // Six fields separated by 0xff: method, Sec-Fetch-Site, Origin, Referer,
    // own origin, allowlist entry.
    let mut parts = data.split(|&b| b == 0xff);
    let mut next = || parts.next().unwrap_or(&[]);
    let (method, site, origin, referer, own, allow) = (next(), next(), next(), next(), next(), next());

    let mut builder = Csrf::builder().own_origin("https://example.com").key(KeyId(0), *b"fuzz target key, thirty-two byte");
    let allow_text = std::str::from_utf8(allow).ok();
    if let Some(entry) = allow_text.filter(|s| !s.is_empty()) {
        builder = builder.allow_origin(entry);
    }
    let Ok(csrf) = builder.build() else {
        return; // an invalid allowlist entry is refused at build time
    };

    let facts = RequestFacts::new(method)
        .fetch_site(site)
        .origin(origin)
        .referer(referer)
        .own_origin(own);
    let decision = csrf.policy(&facts);

    let quick = RequestFacts::from_headers(method, |name| match name {
        "sec-fetch-site" => Some(site),
        "origin" => Some(origin),
        "referer" => Some(referer),
        _ => None,
    })
    .own_origin(own);
    assert_eq!(csrf.policy(&quick), decision, "from_headers differs from the setters");

    if MethodClass::classify(method) == MethodClass::Safe {
        assert_eq!(decision, Ok(OriginCheck::SafeMethod));
        return;
    }
    let declared = declared(site);
    if declared == Some(&b"cross-site"[..]) && decision.is_ok() {
        // Only an allowlisted Origin can pass a cross-site request.
        let entry = allow_text.unwrap_or("");
        assert!(!entry.is_empty() && !origin.is_empty(), "cross-site passed without an allowlist");
    }
    if declared.is_none() && origin == b"null" {
        assert!(decision.is_err(), "Origin: null passed");
    }
});
