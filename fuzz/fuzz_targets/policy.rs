//! Arbitrary request facts and allowlists: the policy never panics, safe
//! methods always pass, and a request the browser calls cross-site passes
//! only on an allowlisted origin.

#![no_main]

use csrf_sec::{Csrf, KeyId, MethodClass, OriginCheck, RequestFacts};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Six fields separated by 0xff: method, Sec-Fetch-Site, Origin, Referer,
    // own origin, allowlist entry.
    let mut parts = data.split(|&b| b == 0xff);
    let mut next = || parts.next().unwrap_or(&[]);
    let (method, site, origin, referer, own, allow) = (next(), next(), next(), next(), next(), next());

    let mut builder = Csrf::builder().key(KeyId(0), *b"fuzz target key, thirty-two byte");
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

    if MethodClass::classify(method) == MethodClass::Safe {
        assert_eq!(decision, Ok(OriginCheck::SafeMethod));
        return;
    }
    let declared = csrf_sec::FetchSite::parse(site);
    if matches!(declared, Some(csrf_sec::FetchSite::CrossSite)) && decision.is_ok() {
        // Only an allowlisted Origin can pass a cross-site request.
        let entry = allow_text.unwrap_or("");
        assert!(!entry.is_empty() && !origin.is_empty(), "cross-site passed without an allowlist");
    }
    if declared.is_none() && origin == b"null" {
        assert!(decision.is_err(), "Origin: null passed");
    }
});
