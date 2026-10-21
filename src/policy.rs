//! Layer 1: the request origin policy.
//!
//! Browsers send `Sec-Fetch-Site` and `Origin` on unsafe requests, and script
//! on an attacker's page cannot set either (they are forbidden request
//! headers). The adapter hands their raw values over in [`RequestFacts`];
//! nothing here parses HTTP.
//!
//! ```text
//! safe method                                   -> pass (no token needed)
//! Sec-Fetch-Site: same-origin | none            -> pass
//! Sec-Fetch-Site: same-site                     -> pass if allow_same_site or Origin allowed; else CrossSite
//! Sec-Fetch-Site: cross-site                    -> pass if Origin allowed; else CrossSite
//! no Fetch Metadata, Origin present             -> allowed: pass; "null" or other: OriginMismatch
//! no Fetch Metadata, no Origin, Referer present -> origin allowed: pass; else OriginMismatch
//! nothing at all                                -> no facts: the token decides
//! ```

use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use crate::verdict::{OriginCheck, Reason, Rejected};

/// Longest `Origin` or `Referer` value examined. Longer values never match,
/// which bounds the work per request.
const MAX_HEADER: usize = 4096;

/// Whether a request method may change state.
///
/// Classification is case-sensitive (methods are, in HTTP): exactly `GET`,
/// `HEAD`, and `OPTIONS` are safe. Everything else is unsafe, including `get`,
/// `TRACE`, and methods nobody has heard of. A handler that changes state must
/// be reachable only through an unsafe method; csrf-sec cannot see your routes,
/// so that is your router's contract.
///
/// ```
/// use csrf_sec::MethodClass;
///
/// assert_eq!(MethodClass::classify(b"GET"), MethodClass::Safe);
/// assert_eq!(MethodClass::classify(b"POST"), MethodClass::Unsafe);
/// assert_eq!(MethodClass::classify(b"get"), MethodClass::Unsafe);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MethodClass {
    /// `GET`, `HEAD`, `OPTIONS`: must not change state; no check needed.
    Safe,
    /// Every other method: checked.
    Unsafe,
}

impl MethodClass {
    /// Classify a method name exactly as it appeared on the request line.
    #[must_use]
    pub const fn classify(method: &[u8]) -> Self {
        match method {
            b"GET" | b"HEAD" | b"OPTIONS" => Self::Safe,
            _ => Self::Unsafe,
        }
    }
}

/// The value of the `Sec-Fetch-Site` request header.
///
/// ```
/// use csrf_sec::FetchSite;
///
/// assert_eq!(FetchSite::parse(b"cross-site"), Some(FetchSite::CrossSite));
/// assert_eq!(FetchSite::parse(b"same-origin "), Some(FetchSite::SameOrigin));
/// assert_eq!(FetchSite::parse(b"Same-Origin"), None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FetchSite {
    /// The request came from a page of the same origin.
    SameOrigin,
    /// The request came from another origin of the same site (a sibling
    /// subdomain).
    SameSite,
    /// The request came from another site.
    CrossSite,
    /// The user started it (typed URL, bookmark): no page was involved.
    None,
}

impl FetchSite {
    /// Parse a header value. Surrounding spaces and tabs are ignored; the
    /// value itself must match exactly. Anything else is `None` (and is then
    /// treated as if the header were absent, never as same-origin).
    #[must_use]
    pub fn parse(value: &[u8]) -> Option<Self> {
        match trim(value) {
            b"same-origin" => Some(Self::SameOrigin),
            b"same-site" => Some(Self::SameSite),
            b"cross-site" => Some(Self::CrossSite),
            b"none" => Some(Self::None),
            _ => None,
        }
    }
}

/// Strip HTTP optional whitespace (spaces and tabs) from both ends.
fn trim(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }
    v
}

/// The facts about a request that layer 1 decides on.
///
/// Fill in what the request carried; leave out what it did not. Values are
/// raw header bytes. An empty value counts as absent.
///
/// ```
/// use csrf_sec::RequestFacts;
///
/// let facts = RequestFacts::new("POST")
///     .fetch_site("same-origin")
///     .origin("https://example.com")
///     .own_origin("https://example.com");
/// # let _ = facts;
/// ```
#[derive(Clone, Copy)]
pub struct RequestFacts<'a> {
    method: MethodClass,
    fetch_site: Option<FetchSite>,
    origin: Option<&'a [u8]>,
    referer: Option<&'a [u8]>,
    own_origin: Option<&'a [u8]>,
}

impl<'a> RequestFacts<'a> {
    /// Facts for a request with this method (classified with
    /// [`MethodClass::classify`]).
    #[must_use]
    pub fn new<M: AsRef<[u8]> + ?Sized>(method: &M) -> Self {
        Self::with_class(MethodClass::classify(method.as_ref()))
    }

    /// Facts for a request whose method the adapter already classified.
    #[must_use]
    pub const fn with_class(method: MethodClass) -> Self {
        Self {
            method,
            fetch_site: None,
            origin: None,
            referer: None,
            own_origin: None,
        }
    }

    /// The `Sec-Fetch-Site` header value.
    #[must_use]
    pub fn fetch_site<V: AsRef<[u8]> + ?Sized>(mut self, value: &V) -> Self {
        self.fetch_site = FetchSite::parse(value.as_ref());
        self
    }

    /// The `Origin` header value.
    #[must_use]
    pub fn origin<V: AsRef<[u8]> + ?Sized>(mut self, value: &'a V) -> Self {
        self.origin = non_empty(value.as_ref());
        self
    }

    /// The `Referer` header value (a full URL; only its origin is used).
    #[must_use]
    pub fn referer<V: AsRef<[u8]> + ?Sized>(mut self, value: &'a V) -> Self {
        self.referer = non_empty(value.as_ref());
        self
    }

    /// This site's own origin, such as `https://example.com`: the scheme, host,
    /// and port the request was addressed to. Requests from it are allowed in
    /// addition to [`Builder::allow_origin`](crate::Builder::allow_origin).
    #[must_use]
    pub fn own_origin<V: AsRef<[u8]> + ?Sized>(mut self, value: &'a V) -> Self {
        self.own_origin = non_empty(value.as_ref());
        self
    }

    /// The method class.
    #[must_use]
    pub const fn method(&self) -> MethodClass {
        self.method
    }
}

impl fmt::Debug for RequestFacts<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn text(v: Option<&[u8]>) -> Option<&str> {
            v.map(|b| core::str::from_utf8(b).unwrap_or("<non-utf8>"))
        }
        f.debug_struct("RequestFacts")
            .field("method", &self.method)
            .field("fetch_site", &self.fetch_site)
            .field("origin", &text(self.origin))
            .field("referer", &self.referer.is_some())
            .field("own_origin", &text(self.own_origin))
            .finish()
    }
}

fn non_empty(v: &[u8]) -> Option<&[u8]> {
    if v.is_empty() { None } else { Some(v) }
}

/// How layer 1 and layer 2 combine for an unsafe request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Mode {
    /// The policy must not refuse **and** the token must verify. The default,
    /// and the right mode for browsers.
    #[default]
    Strict,
    /// Only the token is checked. For clients that send no browser headers.
    TokenOnly,
    /// Only the policy is checked, and `Sec-Fetch-Site` must be present. For
    /// endpoints called only from modern browsers, with no forms. Never the
    /// default.
    PolicyOnly,
}

/// A parsed origin: scheme and host as given, and the effective port.
#[derive(Clone, Copy)]
struct OriginRef<'v> {
    scheme: &'v [u8],
    host: &'v [u8],
    port: Option<u16>,
}

impl OriginRef<'_> {
    fn eq(&self, other: &OriginRef<'_>) -> bool {
        self.port == other.port
            && self.scheme.eq_ignore_ascii_case(other.scheme)
            && self.host.eq_ignore_ascii_case(other.host)
    }
}

/// The default port of the schemes browsers send in `Origin`.
fn default_port(scheme: &[u8]) -> Option<u16> {
    if scheme.eq_ignore_ascii_case(b"https") || scheme.eq_ignore_ascii_case(b"wss") {
        Some(443)
    } else if scheme.eq_ignore_ascii_case(b"http") || scheme.eq_ignore_ascii_case(b"ws") {
        Some(80)
    } else {
        None
    }
}

/// Parse a serialized origin (`scheme://host[:port]`). Anything else,
/// including `null`, a path, user information, or non-ASCII bytes, is `None`.
fn parse_origin(v: &[u8]) -> Option<OriginRef<'_>> {
    if v.len() > MAX_HEADER {
        return None;
    }
    let sep = v.windows(3).position(|w| w == b"://")?;
    let (scheme, authority) = (&v[..sep], &v[sep + 3..]);
    let (first, rest) = scheme.split_first()?;
    if !first.is_ascii_alphabetic()
        || !rest
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
    {
        return None;
    }
    let (host, explicit) = split_host_port(authority)?;
    let port = match explicit {
        Some(p) => Some(p),
        None => default_port(scheme),
    };
    Some(OriginRef { scheme, host, port })
}

/// Split an authority with no user information into host and explicit port.
fn split_host_port(authority: &[u8]) -> Option<(&[u8], Option<u16>)> {
    let (host, port) = if authority.first() == Some(&b'[') {
        let close = authority.iter().position(|&c| c == b']')?;
        let inner = &authority[1..close];
        if inner.is_empty()
            || !inner
                .iter()
                .all(|&c| c.is_ascii_hexdigit() || c == b':' || c == b'.')
        {
            return None;
        }
        match &authority[close + 1..] {
            [] => (&authority[..=close], None),
            [b':', digits @ ..] => (&authority[..=close], Some(digits)),
            _ => return None,
        }
    } else {
        match authority.iter().rposition(|&c| c == b':') {
            Some(i) => (&authority[..i], Some(&authority[i + 1..])),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    if host.first() != Some(&b'[')
        && !host
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_'))
    {
        return None;
    }
    let port = match port {
        None => None,
        Some(digits) => Some(parse_port(digits)?),
    };
    Some((host, port))
}

/// A port of 1 to 5 ASCII digits, value 1 to 65535.
fn parse_port(digits: &[u8]) -> Option<u16> {
    if digits.is_empty() || digits.len() > 5 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let value = digits
        .iter()
        .fold(0u32, |acc, &d| acc * 10 + u32::from(d - b'0'));
    u16::try_from(value).ok().filter(|&p| p != 0)
}

/// The origin of a `Referer` URL: `scheme://authority` up to the first `/`,
/// `?`, or `#`. A URL with user information never yields an origin.
fn referer_origin(v: &[u8]) -> Option<OriginRef<'_>> {
    if v.len() > MAX_HEADER {
        return None;
    }
    let sep = v.windows(3).position(|w| w == b"://")?;
    let after = &v[sep + 3..];
    let end = after
        .iter()
        .position(|&c| matches!(c, b'/' | b'?' | b'#'))
        .unwrap_or(after.len());
    let authority = &after[..end];
    if authority.contains(&b'@') {
        return None;
    }
    parse_origin(&v[..sep + 3 + end])
}

/// An allowed origin, stored normalized: lowercase scheme and host, effective
/// port.
#[derive(Clone)]
struct Allowed {
    scheme: Box<[u8]>,
    host: Box<[u8]>,
    port: Option<u16>,
}

impl Allowed {
    fn as_ref(&self) -> OriginRef<'_> {
        OriginRef {
            scheme: &self.scheme,
            host: &self.host,
            port: self.port,
        }
    }
}

/// The configured policy: allowed origins and the sibling-subdomain rule.
#[derive(Clone, Default)]
pub(crate) struct Policy {
    allowed: Vec<Allowed>,
    allow_same_site: bool,
}

impl Policy {
    /// Add an allowed origin. Returns `false` when `origin` is not a
    /// serialized origin (or is `null`).
    pub(crate) fn allow(&mut self, origin: &str) -> bool {
        let Some(o) = parse_origin(origin.as_bytes()) else {
            return false;
        };
        let allowed = Allowed {
            scheme: o.scheme.to_ascii_lowercase().into_boxed_slice(),
            host: o.host.to_ascii_lowercase().into_boxed_slice(),
            port: o.port,
        };
        if !self
            .allowed
            .iter()
            .any(|a| a.as_ref().eq(&allowed.as_ref()))
        {
            self.allowed.push(allowed);
        }
        true
    }

    pub(crate) fn set_allow_same_site(&mut self, allow: bool) {
        self.allow_same_site = allow;
    }

    /// Whether `origin` matches this site or an allowed origin. `None` when
    /// there is nothing to compare against (no own origin, no allowlist).
    fn allows(&self, origin: Option<OriginRef<'_>>, own: Option<&[u8]>) -> Option<bool> {
        let own = own.and_then(parse_origin);
        if own.is_none() && self.allowed.is_empty() {
            return None;
        }
        let Some(origin) = origin else {
            return Some(false);
        };
        Some(
            own.is_some_and(|o| o.eq(&origin))
                || self.allowed.iter().any(|a| a.as_ref().eq(&origin)),
        )
    }

    /// The layer-1 decision. `Ok(OriginCheck::NoFacts)` means the request
    /// carried nothing to decide on, so the token decides.
    pub(crate) fn decide(&self, facts: &RequestFacts<'_>) -> Result<OriginCheck, Rejected> {
        if facts.method == MethodClass::Safe {
            return Ok(OriginCheck::SafeMethod);
        }
        let origin = facts.origin.map(parse_origin);
        let origin_allowed = || match origin {
            Some(parsed) => self.allows(parsed, facts.own_origin) == Some(true),
            None => false,
        };
        match facts.fetch_site {
            Some(FetchSite::SameOrigin | FetchSite::None) => Ok(OriginCheck::FetchMetadata),
            Some(FetchSite::SameSite) if self.allow_same_site => Ok(OriginCheck::FetchMetadata),
            Some(FetchSite::SameSite | FetchSite::CrossSite) => {
                if origin_allowed() {
                    Ok(OriginCheck::Origin)
                } else {
                    Err(Rejected::new(Reason::CrossSite))
                }
            }
            None => {
                if let Some(parsed) = origin {
                    match self.allows(parsed, facts.own_origin) {
                        Some(true) => Ok(OriginCheck::Origin),
                        Some(false) => Err(Rejected::new(Reason::OriginMismatch)),
                        // Nothing configured to compare with; "null" and
                        // unparseable values are still refused.
                        None if parsed.is_none() => Err(Rejected::new(Reason::OriginMismatch)),
                        None => Ok(OriginCheck::NoFacts),
                    }
                } else if let Some(referer) = facts.referer {
                    match self.allows(referer_origin(referer), facts.own_origin) {
                        Some(true) => Ok(OriginCheck::Referer),
                        Some(false) => Err(Rejected::new(Reason::OriginMismatch)),
                        None => Ok(OriginCheck::NoFacts),
                    }
                } else {
                    Ok(OriginCheck::NoFacts)
                }
            }
        }
    }

    /// `PolicyOnly`: the decision, and Fetch Metadata must have been sent.
    pub(crate) fn decide_strict_metadata(
        &self,
        facts: &RequestFacts<'_>,
    ) -> Result<OriginCheck, Rejected> {
        if facts.method == MethodClass::Safe {
            return Ok(OriginCheck::SafeMethod);
        }
        if facts.fetch_site.is_none() {
            return Err(Rejected::new(Reason::Unverifiable));
        }
        self.decide(facts)
    }
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        for a in &self.allowed {
            let scheme = core::str::from_utf8(&a.scheme).unwrap_or("?");
            let host = core::str::from_utf8(&a.host).unwrap_or("?");
            match a.port {
                Some(p) => list.entry(&format_args!("{scheme}://{host}:{p}")),
                None => list.entry(&format_args!("{scheme}://{host}")),
            };
        }
        list.finish()?;
        write!(f, " allow_same_site={}", self.allow_same_site)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FetchSite, MethodClass, OriginRef, Policy, RequestFacts, parse_origin, parse_port,
        referer_origin, trim,
    };
    use crate::{OriginCheck, Reason};

    fn eq(a: &str, b: &str) -> bool {
        match (parse_origin(a.as_bytes()), parse_origin(b.as_bytes())) {
            (Some(x), Some(y)) => x.eq(&y),
            _ => false,
        }
    }

    #[test]
    fn test_method_classify_exact_and_case_sensitive() {
        for safe in ["GET", "HEAD", "OPTIONS"] {
            assert_eq!(
                MethodClass::classify(safe.as_bytes()),
                MethodClass::Safe,
                "{safe}"
            );
        }
        for unsafe_ in [
            "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT", "get", "Get", "GET ", " GET", "",
            "PROPFIND", "GETX",
        ] {
            assert_eq!(
                MethodClass::classify(unsafe_.as_bytes()),
                MethodClass::Unsafe,
                "{unsafe_:?}"
            );
        }
    }

    #[test]
    fn test_fetch_site_parse_exact_values_only() {
        assert_eq!(
            FetchSite::parse(b"same-origin"),
            Some(FetchSite::SameOrigin)
        );
        assert_eq!(FetchSite::parse(b"same-site"), Some(FetchSite::SameSite));
        assert_eq!(FetchSite::parse(b"cross-site"), Some(FetchSite::CrossSite));
        assert_eq!(FetchSite::parse(b"none"), Some(FetchSite::None));
        assert_eq!(FetchSite::parse(b"\t none \t"), Some(FetchSite::None));
        for bad in [
            "",
            "SAME-ORIGIN",
            "same-origin,cross-site",
            "same_origin",
            "same-origin\0",
            "unknown",
        ] {
            assert_eq!(FetchSite::parse(bad.as_bytes()), None, "{bad:?}");
        }
    }

    #[test]
    fn test_trim_only_spaces_and_tabs() {
        assert_eq!(trim(b"  a b\t"), b"a b");
        assert_eq!(trim(b"\r\na"), b"\r\na");
        assert_eq!(trim(b"   "), b"");
    }

    #[test]
    fn test_parse_origin_valid_forms() {
        assert!(parse_origin(b"https://example.com").is_some());
        assert!(parse_origin(b"http://localhost:8080").is_some());
        assert!(parse_origin(b"https://[::1]:8443").is_some());
        assert!(parse_origin(b"https://[2001:db8::1]").is_some());
        assert!(parse_origin(b"chrome-extension://abcdef").is_some());
        assert!(parse_origin(b"https://xn--bcher-kva.example").is_some());
    }

    #[test]
    fn test_parse_origin_rejects_non_origins() {
        for bad in [
            "null",
            "",
            "example.com",
            "https://",
            "https://example.com/",
            "https://example.com/path",
            "https://user@example.com",
            "https://example.com:",
            "https://example.com:0",
            "https://example.com:65536",
            "https://example.com:+443",
            "https://example.com:44 3",
            "https://exa mple.com",
            "https://example.com?",
            "https://example.com#",
            "https://ex\u{e4}mple.com",
            "1https://example.com",
            "ht tp://example.com",
            "https://[::1",
            "https://[]",
            "https://[::1]x",
            "https://[zz::1]",
            "://example.com",
            "https:/example.com",
            "https://example.com\\evil.com",
        ] {
            assert!(parse_origin(bad.as_bytes()).is_none(), "{bad:?}");
        }
        let long = format!("https://{}.com", "a".repeat(5000));
        assert!(parse_origin(long.as_bytes()).is_none());
    }

    #[test]
    fn test_origin_eq_normalizes_case_and_default_ports() {
        assert!(eq("https://example.com", "HTTPS://EXAMPLE.COM"));
        assert!(eq("https://example.com", "https://example.com:443"));
        assert!(eq("http://example.com:80", "http://example.com"));
        assert!(!eq("https://example.com", "http://example.com"));
        assert!(!eq("https://example.com", "https://example.com:8443"));
        assert!(!eq("https://example.com", "https://example.com."));
        assert!(!eq("https://example.com", "https://sub.example.com"));
        assert!(!eq("https://example.com", "https://example.com.evil.com"));
        assert!(!eq("https://a.example", "https://b.example"));
    }

    #[test]
    fn test_parse_port_bounds() {
        assert_eq!(parse_port(b"1"), Some(1));
        assert_eq!(parse_port(b"65535"), Some(65535));
        assert_eq!(parse_port(b"00443"), Some(443));
        assert_eq!(parse_port(b"65536"), None);
        assert_eq!(parse_port(b"0"), None);
        assert_eq!(parse_port(b"123456"), None);
        assert_eq!(parse_port(b""), None);
        assert_eq!(parse_port(b"-1"), None);
    }

    #[test]
    fn test_referer_origin_extraction() {
        fn o(s: &str) -> Option<OriginRef<'_>> {
            referer_origin(s.as_bytes())
        }
        let is = |a: Option<OriginRef<'_>>, b: &str| {
            a.is_some_and(|a| a.eq(&parse_origin(b.as_bytes()).unwrap()))
        };
        assert!(is(
            o("https://example.com/form?x=1#y"),
            "https://example.com"
        ));
        assert!(is(o("https://example.com"), "https://example.com"));
        assert!(is(o("https://example.com?q"), "https://example.com"));
        assert!(is(o("https://example.com:443/"), "https://example.com"));
        assert!(o("https://user@example.com/").is_none());
        assert!(o("https://example.com@evil.com/").is_none());
        assert!(o("not a url").is_none());
        assert!(o("/relative/path").is_none());
        assert!(!is(
            o("https://example.com.evil.com/"),
            "https://example.com"
        ));
    }

    fn policy(origins: &[&str], same_site: bool) -> Policy {
        let mut p = Policy::default();
        for o in origins {
            assert!(p.allow(o));
        }
        p.set_allow_same_site(same_site);
        p
    }

    fn post<'a>() -> RequestFacts<'a> {
        RequestFacts::new("POST").own_origin("https://example.com")
    }

    #[test]
    fn test_policy_allow_rejects_invalid_and_dedups() {
        let mut p = Policy::default();
        assert!(!p.allow("null"));
        assert!(!p.allow("https://example.com/"));
        assert!(p.allow("https://example.com"));
        assert!(p.allow("HTTPS://example.com:443"));
        assert_eq!(p.allowed.len(), 1);
    }

    #[test]
    fn test_policy_safe_method_passes_without_facts() {
        let p = Policy::default();
        let facts = RequestFacts::new("GET")
            .fetch_site("cross-site")
            .origin("https://evil.com");
        assert_eq!(p.decide(&facts), Ok(OriginCheck::SafeMethod));
        assert_eq!(
            p.decide_strict_metadata(&facts),
            Ok(OriginCheck::SafeMethod)
        );
    }

    #[test]
    fn test_policy_fetch_metadata_branches() {
        let p = policy(&[], false);
        let check = |site: &str| p.decide(&post().fetch_site(site));
        assert_eq!(check("same-origin"), Ok(OriginCheck::FetchMetadata));
        assert_eq!(check("none"), Ok(OriginCheck::FetchMetadata));
        assert_eq!(check("same-site").unwrap_err().reason(), Reason::CrossSite);
        assert_eq!(check("cross-site").unwrap_err().reason(), Reason::CrossSite);
    }

    #[test]
    fn test_policy_same_site_allowed_when_configured() {
        let p = policy(&[], true);
        assert_eq!(
            p.decide(&post().fetch_site("same-site")),
            Ok(OriginCheck::FetchMetadata)
        );
        assert_eq!(
            p.decide(&post().fetch_site("cross-site"))
                .unwrap_err()
                .reason(),
            Reason::CrossSite
        );
    }

    #[test]
    fn test_policy_cross_site_allowlisted_origin_passes() {
        let p = policy(&["https://partner.example"], false);
        let f = post()
            .fetch_site("cross-site")
            .origin("https://partner.example");
        assert_eq!(p.decide(&f), Ok(OriginCheck::Origin));
        let f = post()
            .fetch_site("same-site")
            .origin("https://partner.example");
        assert_eq!(p.decide(&f), Ok(OriginCheck::Origin));
        let f = post()
            .fetch_site("cross-site")
            .origin("https://evil.example");
        assert_eq!(p.decide(&f).unwrap_err().reason(), Reason::CrossSite);
        let f = post().fetch_site("cross-site");
        assert_eq!(p.decide(&f).unwrap_err().reason(), Reason::CrossSite);
    }

    #[test]
    fn test_policy_origin_fallback_without_fetch_metadata() {
        let p = policy(&["https://partner.example"], false);
        assert_eq!(
            p.decide(&post().origin("https://example.com")),
            Ok(OriginCheck::Origin)
        );
        assert_eq!(
            p.decide(&post().origin("https://EXAMPLE.com:443")),
            Ok(OriginCheck::Origin)
        );
        assert_eq!(
            p.decide(&post().origin("https://partner.example")),
            Ok(OriginCheck::Origin)
        );
        for bad in [
            "null",
            "https://evil.com",
            "https://example.com.evil.com",
            "garbage",
            "https://example.com/",
        ] {
            assert_eq!(
                p.decide(&post().origin(bad)).unwrap_err().reason(),
                Reason::OriginMismatch,
                "{bad}"
            );
        }
    }

    #[test]
    fn test_policy_unknown_fetch_site_treated_as_absent() {
        let p = policy(&[], false);
        let f = post()
            .fetch_site("same-origin-ish")
            .origin("https://evil.com");
        assert_eq!(p.decide(&f).unwrap_err().reason(), Reason::OriginMismatch);
        let f = post().fetch_site("SAME-ORIGIN");
        assert_eq!(p.decide(&f), Ok(OriginCheck::NoFacts));
    }

    #[test]
    fn test_policy_referer_fallback() {
        let p = policy(&[], false);
        assert_eq!(
            p.decide(&post().referer("https://example.com/account")),
            Ok(OriginCheck::Referer)
        );
        for bad in [
            "https://evil.com/x",
            "https://example.com@evil.com/",
            "nonsense",
        ] {
            assert_eq!(
                p.decide(&post().referer(bad)).unwrap_err().reason(),
                Reason::OriginMismatch,
                "{bad}"
            );
        }
        // Origin takes precedence over Referer.
        let f = post()
            .origin("https://evil.com")
            .referer("https://example.com/");
        assert_eq!(p.decide(&f).unwrap_err().reason(), Reason::OriginMismatch);
    }

    #[test]
    fn test_policy_no_facts_leaves_it_to_the_token() {
        let p = policy(&[], false);
        assert_eq!(p.decide(&post()), Ok(OriginCheck::NoFacts));
        assert_eq!(
            p.decide(&RequestFacts::new("DELETE")),
            Ok(OriginCheck::NoFacts)
        );
    }

    #[test]
    fn test_policy_nothing_to_compare_defers_except_null() {
        let p = Policy::default();
        let f = RequestFacts::new("POST").origin("https://example.com");
        assert_eq!(p.decide(&f), Ok(OriginCheck::NoFacts));
        let f = RequestFacts::new("POST").origin("null");
        assert_eq!(p.decide(&f).unwrap_err().reason(), Reason::OriginMismatch);
        let f = RequestFacts::new("POST").referer("https://example.com/");
        assert_eq!(p.decide(&f), Ok(OriginCheck::NoFacts));
    }

    #[test]
    fn test_policy_empty_values_count_as_absent() {
        let p = policy(&[], false);
        let f = post().fetch_site("").origin("").referer("");
        assert_eq!(p.decide(&f), Ok(OriginCheck::NoFacts));
    }

    #[test]
    fn test_policy_only_requires_fetch_metadata() {
        let p = policy(&[], false);
        assert_eq!(
            p.decide_strict_metadata(&post().origin("https://example.com"))
                .unwrap_err()
                .reason(),
            Reason::Unverifiable
        );
        assert_eq!(
            p.decide_strict_metadata(&post().fetch_site("same-origin")),
            Ok(OriginCheck::FetchMetadata)
        );
        assert_eq!(
            p.decide_strict_metadata(&post().fetch_site("cross-site"))
                .unwrap_err()
                .reason(),
            Reason::CrossSite
        );
    }

    #[test]
    fn test_request_facts_debug_hides_referer() {
        let f = post().referer("https://example.com/reset?token=secret");
        let text = format!("{f:?}");
        assert!(!text.contains("secret"));
    }

    #[test]
    fn test_policy_debug_lists_origins() {
        let p = policy(&["https://a.example", "http://b.example:8080"], true);
        let text = format!("{p:?}");
        assert!(text.contains("https://a.example:443"));
        assert!(text.contains("http://b.example:8080"));
        assert!(text.contains("allow_same_site=true"));
    }
}
