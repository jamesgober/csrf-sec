"""An independent implementation of the csrf-sec token format.

Rebuilds every vector in tests/vectors.rs (and docs/TEST_VECTORS.md) from the
format description in docs/API.md, with a BLAKE3 written from its
specification instead of the crate's dependencies, and exits non-zero on any
difference. CI runs it: `python3 dev/reference/vectors.py`.

Single-chunk BLAKE3 only (inputs up to 1024 bytes), which covers every vector.
"""
import base64
import struct

IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
CHUNK_START, CHUNK_END, ROOT, KEYED_HASH = 1, 2, 8, 16
M32 = 0xFFFFFFFF


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def g(s, a, b, c, d, x, y):
    s[a] = (s[a] + s[b] + x) & M32
    s[d] = rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M32
    s[b] = rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + y) & M32
    s[d] = rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M32
    s[b] = rotr(s[b] ^ s[c], 7)


def compress(cv, block, block_len, counter, flags):
    m = list(struct.unpack('<16I', block))
    s = cv[:] + IV[:4] + [counter & M32, (counter >> 32) & M32, block_len, flags]
    for r in range(7):
        g(s, 0, 4, 8, 12, m[0], m[1]); g(s, 1, 5, 9, 13, m[2], m[3])
        g(s, 2, 6, 10, 14, m[4], m[5]); g(s, 3, 7, 11, 15, m[6], m[7])
        g(s, 0, 5, 10, 15, m[8], m[9]); g(s, 1, 6, 11, 12, m[10], m[11])
        g(s, 2, 7, 8, 13, m[12], m[13]); g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[PERM[i]] for i in range(16)]
    return [s[i] ^ s[i + 8] for i in range(8)]


def blake3(data, key=None):
    assert len(data) <= 1024
    cv = list(struct.unpack('<8I', key)) if key else IV[:]
    base = KEYED_HASH if key else 0
    blocks = [data[i:i + 64] for i in range(0, len(data), 64)] or [b'']
    for i, blk in enumerate(blocks):
        flags = base
        if i == 0:
            flags |= CHUNK_START
        if i == len(blocks) - 1:
            flags |= CHUNK_END | ROOT
        cv = compress(cv, blk.ljust(64, b'\0'), len(blk), 0, flags)
    return struct.pack('<8I', *cv)


assert blake3(b'').hex() == 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262', 'empty-input vector'

KEY = bytes(range(32))
EPOCH = 1_577_836_800
LABEL = {1: b'csrf-sec/v1 session-token mac key', 2: b'csrf-sec/v1 one-time-token mac key'}


def varint(n):
    out = b''
    while n >= 0x80:
        out += bytes([(n & 0x7F) | 0x80])
        n >>= 7
    return out + bytes([n])


def token(version, kid, session, scope, issued_at, pads):
    """pads: the PadSource byte stream (bytes 0, 1, 2, ...)."""
    subkey = blake3(LABEL[version] + bytes([kid]), KEY)
    nonce = b''
    if version == 2:
        nonce, pads = pads[:16], pads[16:]
    header = bytes([version, kid]) + struct.pack('<I', issued_at - EPOCH) + nonce
    mac_input = header + varint(len(session)) + varint(len(scope)) + session + scope
    tag = blake3(mac_input, subkey)[:16]
    raw = header + tag
    pad = pads[:len(raw)]
    masked = pad + bytes(a ^ b for a, b in zip(raw, pad))
    return base64.urlsafe_b64encode(masked).rstrip(b'=').decode()


counting = bytes(i % 256 for i in range(512))
T = 1_792_540_800
S43 = b'Q2xhc3NpY2FsIDQzLWNoYXJhY3RlciBzZXNzaW9uIGl'
VECTORS = [
    ('session token, no scope', token(1, 0, b'session-1', b'', T, counting),
     'AAECAwQFBgcICQoLDA0ODxAREhMUFQEBghzICcvIOkah9oYQIY-vW0wS77s'),
    ('session token, scoped', token(1, 0, b'session-1', b'POST /pay', T, counting),
     'AAECAwQFBgcICQoLDA0ODxAREhMUFQEBghzICQM0quXG3nig2Xkp-NswIXA'),
    ('session token, key id 7, 43-character session id', token(1, 7, S43, b'POST /account/email', T, counting),
     'AAECAwQFBgcICQoLDA0ODxAREhMUFQEGghzICfn6ZD6fclsw30XkxvFLrf4'),
    ('session token, long inputs (streamed MAC)', token(1, 255, b's' * 300, b'p' * 200, T, counting),
     'AAECAwQFBgcICQoLDA0ODxAREhMUFQH-ghzICRNr7xvmCxjMogEJsbMWk6Q'),
    ('session token, first second of the epoch', token(1, 0, b'session-1', b'', EPOCH, counting),
     'AAECAwQFBgcICQoLDA0ODxAREhMUFQEBAgMEBfcRpXw8TFQNCqot3Orz7sk'),
    ('session token, last representable second', token(1, 0, b'session-1', b'', EPOCH + 0xFFFFFFFF, counting),
     'AAECAwQFBgcICQoLDA0ODxAREhMUFQEB_fz7-sGlCopL82Qp77lTqE6bqvU'),
    ('one-time token, scoped', token(2, 0, b'session-1', b'POST /pay', T, counting),
     'EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDUSEZIM2BkWFhoaHh4aGhYWKiouLioqtAwWUz2ob7Iv7nQucaPUTA'),
    ('one-time token, long inputs (streamed MAC)', token(2, 9, b's' * 300, b'p' * 200, T, counting),
     'EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDUSGJIM2BkWFhoaHh4aGhYWKiouLioq6KxTaiXqC1CIbNPjQ5CkKg'),
    ('key fingerprint, key id 0', blake3(b'csrf-sec/v1 key fingerprint', blake3(LABEL[1] + bytes([0]), KEY))[:8].hex(),
     '756b8253b16ff08a'),
]

failed = 0
for name, got, want in VECTORS:
    status = 'ok' if got == want else 'MISMATCH'
    failed += got != want
    print(f'{status:8} {name}')
    if got != want:
        print(f'         got  {got}')
        print(f'         want {want}')
raise SystemExit(1 if failed else 0)
