//! base64url (RFC 4648 section 5) without padding, in constant time.
//!
//! Tokens are bearer values for a session, so the codec must not leak them
//! through the cache: no lookup table is indexed by token bytes and no branch
//! depends on them. Characters are mapped with arithmetic masks instead.
//!
//! Full blocks (6 bytes, 8 characters) are handled eight lanes at a time in a
//! `u64` (SWAR): every lane computes its range tests and offsets in parallel,
//! and no lane can carry into its neighbour, because every intermediate value
//! of a lane stays within 0 to 255. The tail uses the one-character versions,
//! which are also the reference the block code is tested against.
//!
//! Decoding accepts canonical text only: the unused low bits of the last
//! character must be zero. Otherwise two different strings would decode to the
//! same token, and changing a character could leave a token valid.

/// Text length of `n` bytes encoded without padding.
pub(crate) const fn encoded_len(n: usize) -> usize {
    (n * 4).div_ceil(3)
}

/// `0x0101..01`: one in every byte lane.
const ONES: u64 = 0x0101_0101_0101_0101;
/// `0x8080..80`: the high bit of every byte lane.
const HIGH: u64 = 0x8080_8080_8080_8080;

/// Every lane set to `b`.
#[inline(always)]
const fn lanes(b: u8) -> u64 {
    ONES * b as u64
}

/// Per lane, 1 where the lane is `>= k`, else 0. Every lane must be below
/// 0x80 and `k` at most 0x80, so no lane borrows from its neighbour.
#[inline(always)]
const fn ge(x: u64, k: u8) -> u64 {
    (((x | HIGH) - lanes(k)) & HIGH) >> 7
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

/// First byte of a decoded group from two 6-bit values (garbage when either
/// is invalid; the caller's error flag decides). The parts never overlap.
#[inline(always)]
const fn byte0(c0: i16, c1: i16) -> u8 {
    ((c0 << 2) | (c1 >> 4)) as u8
}

/// Second byte of a decoded group. The parts never overlap.
#[inline(always)]
const fn byte1(c1: i16, c2: i16) -> u8 {
    ((c1 << 4) | (c2 >> 2)) as u8
}

/// Third byte of a decoded group. The parts never overlap.
#[inline(always)]
const fn byte2(c2: i16, c3: i16) -> u8 {
    ((c2 << 6) | c3) as u8
}

/// Encode one block: 6 bytes to 8 characters.
#[inline(always)]
fn enc_block(s: &[u8], d: &mut [u8]) {
    let n0 = (u64::from(s[0]) << 16) | (u64::from(s[1]) << 8) | u64::from(s[2]);
    let n1 = (u64::from(s[3]) << 16) | (u64::from(s[4]) << 8) | u64::from(s[5]);
    // Two 24-bit groups in 32-bit lanes.
    let x = n0 | (n1 << 32);
    // Each group to two 12-bit halves in 16-bit lanes, high half first.
    let t = ((x >> 12) & 0x0000_0fff_0000_0fff) | ((x & 0x0000_0fff_0000_0fff) << 16);
    // Each half to two 6-bit values in byte lanes, high value first.
    let v = ((t >> 6) & 0x003f_003f_003f_003f) | ((t & 0x003f_003f_003f_003f) << 8);
    // The same offsets as `enc6`, per lane. Lanes hold 0..=63; every partial
    // sum stays within 45..=134, so nothing carries between lanes.
    let c = v + lanes(b'A') + ge(v, 26) * 6 - ge(v, 52) * 75 - ge(v, 62) * 13 + ge(v, 63) * 49;
    d.copy_from_slice(&c.to_le_bytes());
}

/// Decode one block: 8 characters to 6 bytes. Returns a mask that is nonzero
/// when any character is not in the alphabet.
#[inline(always)]
fn dec_block(s: &[u8], d: &mut [u8]) -> u64 {
    let mut chars = [0u8; 8];
    chars.copy_from_slice(s);
    let x = u64::from_le_bytes(chars);
    // Any non-ASCII byte is invalid; masking it keeps the lane tests exact.
    let bad_high = x & HIGH;
    let x = x & !HIGH;
    let digit = ge(x, b'0') - ge(x, b'9' + 1);
    let upper = ge(x, b'A') - ge(x, b'Z' + 1);
    let lower = ge(x, b'a') - ge(x, b'z' + 1);
    let dash = ge(x, b'-') - ge(x, b'-' + 1);
    let under = ge(x, b'_') - ge(x, b'_' + 1);
    let valid = digit + upper + lower + dash + under;
    // Exactly one class applies to a valid lane, so each lane moves once and
    // stays within 0..=127.
    let v = x + digit * 4 + dash * 17 - upper * 65 - lower * 71 - under * 32;
    // Byte lanes of 6 bits to 16-bit lanes of 12, then to 32-bit lanes of 24.
    let t = ((v & 0x00ff_00ff_00ff_00ff) << 6) | ((v >> 8) & 0x00ff_00ff_00ff_00ff);
    let u = ((t & 0x0000_ffff_0000_ffff) << 12) | ((t >> 16) & 0x0000_ffff_0000_ffff);
    let (n0, n1) = (u as u32, (u >> 32) as u32);
    d[0] = (n0 >> 16) as u8;
    d[1] = (n0 >> 8) as u8;
    d[2] = n0 as u8;
    d[3] = (n1 >> 16) as u8;
    d[4] = (n1 >> 8) as u8;
    d[5] = n1 as u8;
    bad_high | (valid ^ ONES)
}

/// Encode `src` into `dst`. `dst.len()` must be `encoded_len(src.len())`.
pub(crate) fn encode(src: &[u8], dst: &mut [u8]) {
    debug_assert_eq!(dst.len(), encoded_len(src.len()));
    let mut src_blocks = src.chunks_exact(6);
    let mut dst_blocks = dst.chunks_exact_mut(8);
    for (s, d) in (&mut src_blocks).zip(&mut dst_blocks) {
        enc_block(s, d);
    }
    let mut src_chunks = src_blocks.remainder().chunks_exact(3);
    let mut dst_chunks = dst_blocks.into_remainder().chunks_exact_mut(4);
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
    let mut bad: u64 = 0;
    let mut src_blocks = src.chunks_exact(8);
    let mut dst_blocks = dst.chunks_exact_mut(6);
    for (s, d) in (&mut src_blocks).zip(&mut dst_blocks) {
        bad |= dec_block(s, d);
    }
    // Negative as soon as any tail character is invalid or the tail is not
    // canonical.
    let mut err: i16 = 0;
    let mut src_chunks = src_blocks.remainder().chunks_exact(4);
    let mut dst_chunks = dst_blocks.into_remainder().chunks_exact_mut(3);
    for (s, d) in (&mut src_chunks).zip(&mut dst_chunks) {
        let (c0, c1, c2, c3) = (dec6(s[0]), dec6(s[1]), dec6(s[2]), dec6(s[3]));
        // One flag per character: flags must accumulate, never cancel.
        err |= c0;
        err |= c1;
        err |= c2;
        err |= c3;
        d[0] = byte0(c0, c1);
        d[1] = byte1(c1, c2);
        d[2] = byte2(c2, c3);
    }
    let rest = src_chunks.remainder();
    let out = dst_chunks.into_remainder();
    match (rest, out) {
        ([s0, s1], [d0]) => {
            let (c0, c1) = (dec6(*s0), dec6(*s1));
            err |= c0;
            err |= c1;
            // The low four bits of the last character carry no data.
            err |= -(c1 & 0x0f);
            *d0 = byte0(c0, c1);
        }
        ([s0, s1, s2], [d0, d1]) => {
            let (c0, c1, c2) = (dec6(*s0), dec6(*s1), dec6(*s2));
            err |= c0;
            err |= c1;
            err |= c2;
            // The low two bits of the last character carry no data.
            err |= -(c2 & 0x03);
            *d0 = byte0(c0, c1);
            *d1 = byte1(c1, c2);
        }
        ([], []) => {}
        // A remainder of one character cannot encode a byte.
        _ => return false,
    }
    (bad == 0) & (err >= 0)
}

#[cfg(test)]
mod tests {
    use super::{dec_block, dec6, decode, enc_block, enc6, encode, encoded_len};

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// Pack eight 6-bit values into 6 bytes, big-endian per 3-byte group.
    fn pack(values: &[u8]) -> [u8; 6] {
        let group = |v: &[u8]| {
            (u32::from(v[0]) << 18)
                | (u32::from(v[1]) << 12)
                | (u32::from(v[2]) << 6)
                | u32::from(v[3])
        };
        let (n0, n1) = (group(&values[..4]), group(&values[4..]));
        [
            (n0 >> 16) as u8,
            (n0 >> 8) as u8,
            n0 as u8,
            (n1 >> 16) as u8,
            (n1 >> 8) as u8,
            n1 as u8,
        ]
    }

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
    fn test_dec_block_every_byte_in_every_lane_matches_scalar() {
        for lane in 0..8 {
            for c in 0u8..=255 {
                let mut text = *b"AZaz09-_";
                text[lane] = c;
                let mut got = [0u8; 6];
                let bad = dec_block(&text, &mut got);
                let scalar: Vec<i16> = text.iter().map(|&b| dec6(b)).collect();
                let valid = scalar.iter().all(|&v| v >= 0);
                assert_eq!(bad == 0, valid, "lane {lane} byte {c:#04x}");
                if valid {
                    let values: Vec<u8> = scalar.iter().map(|&v| v as u8).collect();
                    assert_eq!(got, pack(&values), "lane {lane} byte {c:#04x}");
                }
            }
        }
    }

    #[test]
    fn test_enc_block_every_value_in_every_lane_matches_scalar() {
        for lane in 0..8 {
            for v in 0u8..64 {
                for fill in [0u8, 17, 63] {
                    let mut values = [fill; 8];
                    values[lane] = v;
                    let mut got = [0u8; 8];
                    enc_block(&pack(&values), &mut got);
                    let want: Vec<u8> = values.iter().map(|&x| enc6(x)).collect();
                    assert_eq!(got.to_vec(), want, "lane {lane} value {v} fill {fill}");
                }
            }
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

    /// xorshift64*, for reproducible random inputs.
    fn random_bytes(seed: &mut u64, n: usize) -> Vec<u8> {
        (0..n)
            .map(|_| {
                *seed ^= *seed >> 12;
                *seed ^= *seed << 25;
                *seed ^= *seed >> 27;
                (seed.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
            })
            .collect()
    }

    #[test]
    fn test_encode_matches_reference_for_every_length_up_to_100() {
        let mut seed = 0x9e37_79b9_7f4a_7c15;
        for len in 0..=100 {
            for _ in 0..20 {
                let src = random_bytes(&mut seed, len);
                let mut dst = vec![0u8; encoded_len(len)];
                encode(&src, &mut dst);
                assert_eq!(dst, reference(&src), "length {len}");
            }
        }
    }

    #[test]
    fn test_decode_round_trips_every_length_up_to_100() {
        let mut seed = 7;
        for len in 0..=100 {
            for _ in 0..20 {
                let src = random_bytes(&mut seed, len);
                let mut text = vec![0u8; encoded_len(len)];
                encode(&src, &mut text);
                let mut back = vec![0u8; len];
                assert!(decode(&text, &mut back), "length {len}");
                assert_eq!(back, src);
            }
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
    fn test_decode_every_invalid_byte_at_every_position_rejects() {
        for len in [44usize, 76] {
            let mut text = vec![0u8; encoded_len(len)];
            encode(&vec![0x11; len], &mut text);
            for i in 0..text.len() {
                for bad in 0u8..=255 {
                    if dec6(bad) >= 0 {
                        continue;
                    }
                    let mut t = text.clone();
                    t[i] = bad;
                    let mut dst = vec![0u8; len];
                    assert!(
                        !decode(&t, &mut dst),
                        "length {len} position {i} byte {bad:#04x}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_decode_two_invalid_characters_anywhere_reject() {
        // Error flags must accumulate, not cancel: two invalid characters in
        // one group (found by mutation testing: `|` swapped for `^` in the
        // tail accumulator let a pair of -1 flags cancel out).
        for len in [44usize, 76] {
            let mut text = vec![0u8; encoded_len(len)];
            encode(&vec![0x5a; len], &mut text);
            for i in 0..text.len() {
                for j in i + 1..text.len() {
                    for (a, b) in [(b'=', b'='), (0x80, 0xff), (b'+', b'/'), (0, b'.')] {
                        let mut t = text.clone();
                        t[i] = a;
                        t[j] = b;
                        let mut dst = vec![0u8; len];
                        assert!(!decode(&t, &mut dst), "length {len} positions {i},{j}");
                    }
                }
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
