//! Tokens: the raw layout, the MAC input, masking, and the issue and verify
//! core.
//!
//! ```text
//! raw session token (22 bytes):  version=1 | key id | issued at (u32 LE) | tag (16)
//! raw one-time token (38 bytes): version=2 | key id | issued at | nonce (16) | tag (16)
//! issued at:                     seconds since 2020-01-01T00:00:00Z
//! MAC input:                     version | key id | issued at | [nonce] | varint(len session)
//!                                | varint(len scope) | session | scope
//! tag:                           first 16 bytes of keyed BLAKE3(subkey, MAC input)
//! masked:                        pad (len raw) | raw XOR pad  pad: fresh CSPRNG bytes
//! text:                          base64url, no padding        59 or 102 characters
//! ```

use core::{fmt, ops::Deref};

use crypt_io::{Tag, mac};

use crate::{
    b64,
    binding::Binding,
    error::Error,
    key::{Kind, Ring, Role, Slot},
    once::{NONCE_LEN, ONCE_TOKEN_LEN},
    pad::PadSource,
    verdict::{Reason, Rejected, Verdict, Verified},
};

/// Length of a session token's text, in characters.
pub const TOKEN_LEN: usize = 59;

/// Unix time of the token epoch, 2020-01-01T00:00:00Z.
pub(crate) const EPOCH: u64 = 1_577_836_800;

/// Length of the MAC tag carried in a token.
const TAG_LEN: usize = 16;

/// Largest raw token any format uses; sizes the stack buffers.
const MAX_RAW: usize = 38;

/// Largest token text any format uses; sizes `Token`'s inline buffer.
const MAX_TEXT: usize = 102;

/// MAC inputs up to this length are hashed in one call from a stack buffer;
/// longer ones are streamed.
const INLINE_MAC: usize = 128;

/// The byte layout of one token format.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Layout {
    /// Format version, the first raw byte.
    version: u8,
    /// Raw length: header plus tag.
    raw: usize,
    /// Text length after masking and encoding.
    text: usize,
    /// Which subkey signs it.
    kind: Kind,
}

impl Layout {
    /// Header length: everything before the tag.
    #[inline]
    const fn header(&self) -> usize {
        self.raw - TAG_LEN
    }
}

/// Per-session tokens (format version 1).
pub(crate) const SESSION: Layout = Layout {
    version: 1,
    raw: 22,
    text: TOKEN_LEN,
    kind: Kind::Session,
};

/// One-time tokens (format version 2): a nonce follows the issued-at field.
pub(crate) const ONCE: Layout = Layout {
    version: 2,
    raw: 22 + NONCE_LEN,
    text: ONCE_TOKEN_LEN,
    kind: Kind::Once,
};

/// A masked token, ready to put in a form field or a request header.
///
/// Its text is base64url (`A-Z a-z 0-9 - _`), safe in HTML attributes,
/// headers, URLs, and cookies without escaping. It derefs to `&str` and
/// displays as its text. Every issue returns different text for the same
/// session; all of it verifies.
///
/// `Token` has no `PartialEq`, so it cannot be compared in variable time by
/// accident, and its `Debug` output never shows the value.
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use csrf_sec::{Csrf, FIELD_NAME, TOKEN_LEN};
///
/// let csrf = Csrf::new(*b"an example key, 32 bytes long!!!")?;
/// let token = csrf.issue("session-1")?;
/// assert_eq!(token.len(), TOKEN_LEN);
///
/// let field = format!(r#"<input type="hidden" name="{FIELD_NAME}" value="{token}">"#);
/// assert!(field.contains(token.as_str()));
/// assert_eq!(format!("{token:?}"), "Token(59 chars)");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Token {
    len: u8,
    buf: [u8; MAX_TEXT],
}

impl Token {
    /// The token text.
    #[must_use]
    #[inline]
    pub fn as_str(&self) -> &str {
        // Always ASCII: every byte comes from the base64url alphabet.
        core::str::from_utf8(self.as_bytes()).unwrap_or_default()
    }

    /// The token text as bytes.
    #[must_use]
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..usize::from(self.len)]
    }

    /// Length of the text in characters: [`TOKEN_LEN`] for session tokens,
    /// [`ONCE_TOKEN_LEN`](crate::ONCE_TOKEN_LEN) for one-time tokens.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Always `false`: an issued token is never empty.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Deref for Token {
    type Target = str;

    #[inline]
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for Token {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for Token {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Token {
    /// Tokens are bearer values for a session, so `Debug` shows only the length.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Token({} chars)", self.len)
    }
}

#[cfg(feature = "alloc")]
impl From<Token> for alloc::string::String {
    fn from(token: Token) -> Self {
        alloc::string::String::from(token.as_str())
    }
}

/// The token's validity window, in whole seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Window {
    pub(crate) lifetime: u32,
    pub(crate) skew: u32,
}

impl Window {
    /// Expired when `now > issued + lifetime`; not yet valid when
    /// `issued > now + skew`.
    #[inline]
    fn check(self, issued_at: u32, now: u64) -> Result<(), Rejected> {
        let issued = EPOCH + u64::from(issued_at);
        if issued > now.saturating_add(u64::from(self.skew)) {
            return Err(Rejected::new(Reason::NotYetValid));
        }
        if now > issued + u64::from(self.lifetime) {
            return Err(Rejected::new(Reason::Expired));
        }
        Ok(())
    }
}

/// `now` as seconds since the token epoch, or `Error::Clock` when it cannot be
/// represented (before 2020 or after early 2156).
#[inline]
pub(crate) fn issued_at(now: u64) -> Result<u32, Error> {
    now.checked_sub(EPOCH)
        .and_then(|d| u32::try_from(d).ok())
        .ok_or(Error::Clock)
}

/// Write `n` as an LEB128 varint; returns the number of bytes written (1-10).
#[inline]
fn put_varint(out: &mut [u8], mut n: u64) -> usize {
    let mut i = 0;
    while n >= 0x80 {
        out[i] = (n as u8) | 0x80;
        n >>= 7;
        i += 1;
    }
    out[i] = n as u8;
    i + 1
}

/// Overwrite `bytes` with zeros in a way the optimizer keeps.
#[inline]
fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    core::hint::black_box(bytes);
}

/// The 16-byte tag over `header | varint(len session) | varint(len scope) |
/// session | scope`.
fn compute_tag(subkey: &[u8; 32], header: &[u8], session: &[u8], scope: &[u8]) -> [u8; TAG_LEN] {
    let mut buf = [0u8; INLINE_MAC];
    let mut n = header.len();
    buf[..n].copy_from_slice(header);
    n += put_varint(&mut buf[n..], session.len() as u64);
    n += put_varint(&mut buf[n..], scope.len() as u64);
    let total = n + session.len() + scope.len();
    let full = if total <= INLINE_MAC {
        let mid = n + session.len();
        buf[n..mid].copy_from_slice(session);
        buf[mid..total].copy_from_slice(scope);
        let full = mac::blake3_keyed(subkey, &buf[..total]);
        // The session id may be the session secret itself: do not leave a copy.
        wipe(&mut buf[..total]);
        full
    } else {
        let mut stream = mac::Blake3Mac::new(subkey);
        stream.update(&buf[..n]).update(session).update(scope);
        stream.finalize()
    };
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    tag
}

/// Whether `received` is the tag for this input, compared in constant time.
#[inline]
fn tag_matches(
    subkey: &[u8; 32],
    header: &[u8],
    session: &[u8],
    scope: &[u8],
    received: &[u8],
) -> bool {
    Tag::new(compute_tag(subkey, header, session, scope)).ct_eq(received)
}

/// Build, sign, mask, and encode a token of `layout`.
///
/// `extra` is written into the header after the issued-at field (the nonce of
/// a one-time token; empty otherwise).
pub(crate) fn issue<P: PadSource + ?Sized>(
    layout: Layout,
    slot: &Slot,
    binding: &Binding<'_>,
    issued_at: u32,
    extra: &[u8],
    pads: &mut P,
) -> Result<Token, Error> {
    let raw_len = layout.raw;
    let header_len = layout.header();
    debug_assert_eq!(6 + extra.len(), header_len);

    let mut raw = [0u8; MAX_RAW];
    raw[0] = layout.version;
    raw[1] = slot.id.0;
    raw[2..6].copy_from_slice(&issued_at.to_le_bytes());
    raw[6..header_len].copy_from_slice(extra);
    let tag = compute_tag(
        slot.subkey(layout.kind),
        &raw[..header_len],
        binding.session,
        binding.scope,
    );
    raw[header_len..raw_len].copy_from_slice(&tag);

    let mut masked = [0u8; 2 * MAX_RAW];
    let masked = &mut masked[..2 * raw_len];
    let (pad, body) = masked.split_at_mut(raw_len);
    pads.fill(pad)?;
    for ((m, r), p) in body.iter_mut().zip(&raw[..raw_len]).zip(pad.iter()) {
        *m = r ^ p;
    }

    let mut token = Token {
        len: layout.text as u8,
        buf: [0u8; MAX_TEXT],
    };
    b64::encode(masked, &mut token.buf[..layout.text]);
    Ok(token)
}

/// A token that decoded, unmasked, and passed its MAC.
pub(crate) struct Opened<'r> {
    pub(crate) slot: &'r Slot,
    raw: [u8; MAX_RAW],
}

impl Opened<'_> {
    /// The nonce of a one-time token.
    pub(crate) fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&self.raw[6..6 + NONCE_LEN]);
        nonce
    }

    /// The pass this token earns.
    pub(crate) fn verified(&self) -> Verified {
        Verified::token(self.slot.id, matches!(self.slot.role, Role::Retired { .. }))
    }
}

/// Decode, unmask, and check a token of `layout` against `binding`, in the
/// order of PLAN section 7.1: length, decode, unmask, version, key id, MAC,
/// validity window. Returns the opened token on success.
pub(crate) fn open<'r>(
    layout: Layout,
    ring: &'r Ring,
    window: Window,
    binding: &Binding<'_>,
    token: &[u8],
    now: u64,
) -> Result<Opened<'r>, Rejected> {
    if token.is_empty() {
        return Err(Rejected::new(Reason::Missing));
    }
    if binding.session.is_empty() {
        return Err(Rejected::new(Reason::Unverifiable));
    }
    if token.len() != layout.text {
        return Err(Rejected::new(Reason::Malformed));
    }
    let raw_len = layout.raw;
    let mut masked = [0u8; 2 * MAX_RAW];
    let masked = &mut masked[..2 * raw_len];
    if !b64::decode(token, masked) {
        return Err(Rejected::new(Reason::Malformed));
    }
    let (pad, body) = masked.split_at(raw_len);
    let mut raw = [0u8; MAX_RAW];
    for ((r, m), p) in raw.iter_mut().zip(body).zip(pad) {
        *r = m ^ p;
    }
    if raw[0] != layout.version {
        return Err(Rejected::new(Reason::Malformed));
    }
    let slot = ring
        .verifier(raw[1], now)
        .ok_or(Rejected::new(Reason::UnknownKey))?;

    let header_len = layout.header();
    let header = &raw[..header_len];
    let received = &raw[header_len..raw_len];
    let subkey = slot.subkey(layout.kind);
    if !tag_matches(subkey, header, binding.session, binding.scope, received) {
        return Err(Rejected::new(diagnose(subkey, header, binding, received)));
    }

    let issued_at = u32::from_le_bytes([raw[2], raw[3], raw[4], raw[5]]);
    window.check(issued_at, now)?;
    Ok(Opened { slot, raw })
}

/// Name a MAC failure accurately. Only runs on the failure path, and adds at
/// most two MAC computations, so verify work stays bounded.
fn diagnose(subkey: &[u8; 32], header: &[u8], binding: &Binding<'_>, received: &[u8]) -> Reason {
    if !binding.scope.is_empty() && tag_matches(subkey, header, binding.session, &[], received) {
        return Reason::WrongScope;
    }
    if let Some(previous) = binding.previous {
        if tag_matches(subkey, header, previous, binding.scope, received) {
            return Reason::StaleSession;
        }
    }
    Reason::BadMac
}

/// Verify a session token.
#[inline]
pub(crate) fn verify_session(
    ring: &Ring,
    window: Window,
    binding: &Binding<'_>,
    token: &[u8],
    now: u64,
) -> Verdict {
    open(SESSION, ring, window, binding, token, now).map(|opened| opened.verified())
}

#[cfg(test)]
mod tests {
    use super::{EPOCH, INLINE_MAC, Window, compute_tag, issued_at, put_varint};
    use crate::{Error, Reason};

    #[test]
    fn test_put_varint_known_encodings() {
        let cases: [(u64, &[u8]); 6] = [
            (0, &[0]),
            (1, &[1]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (300, &[0xac, 0x02]),
            (
                u64::MAX,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
            ),
        ];
        for (n, expected) in cases {
            let mut buf = [0u8; 10];
            let len = put_varint(&mut buf, n);
            assert_eq!(&buf[..len], expected, "{n}");
        }
    }

    #[test]
    fn test_issued_at_range_boundaries() {
        assert_eq!(issued_at(EPOCH), Ok(0));
        assert_eq!(issued_at(EPOCH + 10), Ok(10));
        assert_eq!(issued_at(EPOCH - 1), Err(Error::Clock));
        assert_eq!(issued_at(EPOCH + u64::from(u32::MAX)), Ok(u32::MAX));
        assert_eq!(
            issued_at(EPOCH + u64::from(u32::MAX) + 1),
            Err(Error::Clock)
        );
        assert_eq!(issued_at(0), Err(Error::Clock));
        assert_eq!(issued_at(u64::MAX), Err(Error::Clock));
    }

    #[test]
    fn test_window_boundaries_inclusive_of_valid_side() {
        let w = Window {
            lifetime: 100,
            skew: 10,
        };
        let iat = 1_000u32;
        let issued = EPOCH + 1_000;
        assert!(w.check(iat, issued).is_ok());
        assert!(w.check(iat, issued + 100).is_ok());
        assert_eq!(
            w.check(iat, issued + 101).unwrap_err().reason(),
            Reason::Expired
        );
        assert!(w.check(iat, issued - 10).is_ok());
        assert_eq!(
            w.check(iat, issued - 11).unwrap_err().reason(),
            Reason::NotYetValid
        );
        assert_eq!(w.check(iat, 0).unwrap_err().reason(), Reason::NotYetValid);
        assert_eq!(w.check(0, u64::MAX).unwrap_err().reason(), Reason::Expired);
        assert!(w.check(u32::MAX, u64::MAX).is_err());
    }

    #[test]
    fn test_compute_tag_is_canonical_across_boundaries() {
        let key = [7u8; 32];
        let h = [1u8, 0, 0, 0, 0, 0];
        // Moving bytes between session and scope must change the tag.
        assert_ne!(
            compute_tag(&key, &h, b"ab", b"c"),
            compute_tag(&key, &h, b"a", b"bc")
        );
        assert_ne!(
            compute_tag(&key, &h, b"abc", b""),
            compute_tag(&key, &h, b"", b"abc")
        );
        assert_ne!(
            compute_tag(&key, &h, b"a", b""),
            compute_tag(&key, &[1, 0, 0, 0, 0, 1], b"a", b"")
        );
    }

    #[test]
    fn test_compute_tag_inline_and_streamed_paths_agree_with_one_shot() {
        let key = [3u8; 32];
        let h = [1u8, 9, 1, 2, 3, 4];
        for len in [
            0usize,
            1,
            50,
            INLINE_MAC - 8,
            INLINE_MAC - 7,
            INLINE_MAC,
            300,
            5000,
        ] {
            let session: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let scope = b"POST /x";
            let got = compute_tag(&key, &h, &session, scope);
            // Reference: build the whole MAC input and hash it in one call.
            let mut input = h.to_vec();
            let mut v = [0u8; 10];
            let n = put_varint(&mut v, session.len() as u64);
            input.extend_from_slice(&v[..n]);
            let n = put_varint(&mut v, scope.len() as u64);
            input.extend_from_slice(&v[..n]);
            input.extend_from_slice(&session);
            input.extend_from_slice(scope);
            let full = crypt_io::mac::blake3_keyed(&key, &input);
            assert_eq!(got, full[..16], "session length {len}");
        }
    }
}
