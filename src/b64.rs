//! base64url (RFC 4648 section 5) without padding, in constant time.
//!
//! Tokens are bearer values for a session, so the codec must not leak them
//! through the cache: no lookup table is indexed by token bytes and no branch
//! depends on them. Each character is mapped with a few arithmetic masks
//! instead (the same approach as constant-time base64 implementations in
//! audited cryptographic libraries).
//!
//! Decoding accepts canonical text only: the unused low bits of the last
//! character must be zero. Otherwise two different strings would decode to the
//! same token, and changing a character could leave a token valid.

/// Text length of `n` bytes encoded without padding.
pub(crate) const fn encoded_len(n: usize) -> usize {
    (n * 4).div_ceil(3)
}

/// Map a 6-bit value (`0..=63`) to its base64url character.
#[inline(always)]
const fn enc6(v: u8) -> u8 {
    let v = v as i16;
    let mut diff: i16 = b'A' as i16;
    // v >= 26: 'a'..='z'
    diff += ((25 - v) >> 8) & 6;
    // v >= 52: '0'..='9'
    diff -= ((51 - v) >> 8) & 75;
    // v == 62: '-'
    diff -= ((61 - v) >> 8) & 13;
    // v == 63: '_'
    diff += ((62 - v) >> 8) & 49;
    (v + diff) as u8
}

/// Map a base64url character to its 6-bit value, or `-1` when it is not in
/// the alphabet.
#[inline(always)]
const fn dec6(c: u8) -> i16 {
    let c = c as i16;
    let mut ret: i16 = -1;
    // Each line adds `value + 1` when `c` is inside the range and 0 otherwise.
    ret += (((0x40 - c) & (c - 0x5b)) >> 8) & (c - 64); // 'A'..='Z'
    ret += (((0x60 - c) & (c - 0x7b)) >> 8) & (c - 70); // 'a'..='z'
    ret += (((0x2f - c) & (c - 0x3a)) >> 8) & (c + 5); // '0'..='9'
    ret += (((0x2c - c) & (c - 0x2e)) >> 8) & 63; // '-'
    ret += (((0x5e - c) & (c - 0x60)) >> 8) & 64; // '_'
    ret
}

/// Encode `src` into `dst`. `dst.len()` must be `encoded_len(src.len())`.
pub(crate) fn encode(src: &[u8], dst: &mut [u8]) {
    debug_assert_eq!(dst.len(), encoded_len(src.len()));
    let mut src_chunks = src.chunks_exact(3);
    let mut dst_chunks = dst.chunks_exact_mut(4);
    for (s, d) in (&mut src_chunks).zip(&mut dst_chunks) {
        let (b0, b1, b2) = (s[0], s[1], s[2]);
        d[0] = enc6(b0 >> 2);
        d[1] = enc6(((b0 << 4) | (b1 >> 4)) & 0x3f);
        d[2] = enc6(((b1 << 2) | (b2 >> 6)) & 0x3f);
        d[3] = enc6(b2 & 0x3f);
    }
    let rest = src_chunks.remainder();
    let out = dst_chunks.into_remainder();
    match (rest, out) {
        ([b0], [d0, d1]) => {
            *d0 = enc6(b0 >> 2);
            *d1 = enc6((b0 << 4) & 0x3f);
        }
        ([b0, b1], [d0, d1, d2]) => {
            *d0 = enc6(b0 >> 2);
            *d1 = enc6(((b0 << 4) | (b1 >> 4)) & 0x3f);
            *d2 = enc6((b1 << 2) & 0x3f);
        }
        _ => {}
    }
}

/// Decode `src` into `dst`, returning `false` when `src` is not canonical
/// base64url of exactly `dst.len()` bytes. The work does not depend on the
/// content of `src`; only the final answer does.
#[must_use]
pub(crate) fn decode(src: &[u8], dst: &mut [u8]) -> bool {
    if src.len() != encoded_len(dst.len()) {
        return false;
    }
    // Negative as soon as any character is invalid or the tail is not canonical.
    let mut err: i16 = 0;
    let mut src_chunks = src.chunks_exact(4);
    let mut dst_chunks = dst.chunks_exact_mut(3);
    for (s, d) in (&mut src_chunks).zip(&mut dst_chunks) {
        let (c0, c1, c2, c3) = (dec6(s[0]), dec6(s[1]), dec6(s[2]), dec6(s[3]));
        err |= c0 | c1 | c2 | c3;
        d[0] = ((c0 << 2) | (c1 >> 4)) as u8;
        d[1] = ((c1 << 4) | (c2 >> 2)) as u8;
        d[2] = ((c2 << 6) | c3) as u8;
    }
    let rest = src_chunks.remainder();
    let out = dst_chunks.into_remainder();
    match (rest, out) {
        ([s0, s1], [d0]) => {
            let (c0, c1) = (dec6(*s0), dec6(*s1));
            err |= c0 | c1;
            // The low four bits of the last character carry no data.
            err |= -(c1 & 0x0f);
            *d0 = ((c0 << 2) | (c1 >> 4)) as u8;
        }
        ([s0, s1, s2], [d0, d1]) => {
            let (c0, c1, c2) = (dec6(*s0), dec6(*s1), dec6(*s2));
            err |= c0 | c1 | c2;
            // The low two bits of the last character carry no data.
            err |= -(c2 & 0x03);
            *d0 = ((c0 << 2) | (c1 >> 4)) as u8;
            *d1 = ((c1 << 4) | (c2 >> 2)) as u8;
        }
        ([], []) => {}
        // A remainder of one character cannot encode a byte.
        _ => return false,
    }
    err >= 0
}

#[cfg(test)]
mod tests {
    use super::{dec6, decode, enc6, encode, encoded_len};

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    #[test]
    fn test_enc6_every_value_matches_alphabet() {
        for v in 0u8..64 {
            assert_eq!(enc6(v), ALPHABET[v as usize], "value {v}");
        }
    }

    #[test]
    fn test_dec6_every_byte_matches_alphabet_or_rejects() {
        for c in 0u8..=255 {
            let expected = ALPHABET
                .iter()
                .position(|&a| a == c)
                .map_or(-1, |p| p as i16);
            assert_eq!(dec6(c), expected, "byte {c:#04x}");
        }
    }

    #[test]
    fn test_encoded_len_token_sizes_match_format() {
        assert_eq!(encoded_len(44), 59);
        assert_eq!(encoded_len(76), 102);
        assert_eq!(encoded_len(0), 0);
        assert_eq!(encoded_len(1), 2);
        assert_eq!(encoded_len(2), 3);
        assert_eq!(encoded_len(3), 4);
    }

    /// Reference encoder (table driven, variable time) used only as an oracle.
    fn reference(src: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in src.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            let chars = chunk.len() + 1;
            for i in 0..chars {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize]);
            }
        }
        out
    }

    #[test]
    fn test_encode_matches_reference_for_every_length_up_to_80() {
        let data: Vec<u8> = (0..80u32)
            .map(|i| (i.wrapping_mul(97) ^ 0x5a) as u8)
            .collect();
        for len in 0..=80 {
            let src = &data[..len];
            let mut dst = vec![0u8; encoded_len(len)];
            encode(src, &mut dst);
            assert_eq!(dst, reference(src), "length {len}");
        }
    }

    #[test]
    fn test_decode_round_trips_every_length_up_to_80() {
        let data: Vec<u8> = (0..80u32)
            .map(|i| (i.wrapping_mul(31) ^ 0xa5) as u8)
            .collect();
        for len in 0..=80 {
            let src = &data[..len];
            let mut text = vec![0u8; encoded_len(len)];
            encode(src, &mut text);
            let mut back = vec![0u8; len];
            assert!(decode(&text, &mut back), "length {len}");
            assert_eq!(back, src);
        }
    }

    #[test]
    fn test_decode_all_byte_values_round_trip() {
        let src: Vec<u8> = (0..=255u8).collect();
        let mut text = vec![0u8; encoded_len(src.len())];
        encode(&src, &mut text);
        let mut back = vec![0u8; src.len()];
        assert!(decode(&text, &mut back));
        assert_eq!(back, src);
    }

    #[test]
    fn test_decode_wrong_length_rejects() {
        let mut dst = [0u8; 44];
        assert!(!decode(&[b'A'; 58], &mut dst));
        assert!(!decode(&[b'A'; 60], &mut dst));
        assert!(!decode(&[], &mut dst));
    }

    #[test]
    fn test_decode_invalid_character_anywhere_rejects() {
        let mut text = [0u8; 59];
        encode(&[0x11; 44], &mut text);
        for i in 0..text.len() {
            for bad in [b'=', b'+', b'/', b' ', 0u8, 0x7f, 0x80, 0xff, b'.', b'~'] {
                let mut t = text;
                t[i] = bad;
                let mut dst = [0u8; 44];
                assert!(!decode(&t, &mut dst), "position {i} byte {bad:#04x}");
            }
        }
    }

    #[test]
    fn test_decode_non_canonical_tail_rejects() {
        // 44 bytes -> 59 chars: the last char carries 4 data bits and 2 zero bits.
        let mut text = [0u8; 59];
        encode(&[0u8; 44], &mut text);
        assert_eq!(text[58], b'A');
        let mut dst = [0u8; 44];
        assert!(decode(&text, &mut dst));
        for alt in *b"BCD" {
            let mut t = text;
            t[58] = alt; // sets one or both of the unused low bits
            assert!(!decode(&t, &mut dst), "{}", alt as char);
        }
        // 76 bytes -> 102 chars: the last char carries 2 data bits and 4 zero bits.
        let mut text = [0u8; 102];
        encode(&[0u8; 76], &mut text);
        let mut dst = [0u8; 76];
        assert!(decode(&text, &mut dst));
        for v in 1u8..16 {
            let mut t = text;
            t[101] = ALPHABET[v as usize];
            assert!(!decode(&t, &mut dst), "value {v}");
        }
    }

    #[test]
    fn test_decode_one_char_remainder_rejects() {
        let mut dst = [0u8; 0];
        assert!(decode(&[], &mut dst));
        // Length mismatch is caught before the remainder match.
        let mut dst = [0u8; 1];
        assert!(!decode(b"A", &mut dst));
    }
}
