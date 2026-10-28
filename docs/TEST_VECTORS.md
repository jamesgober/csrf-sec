# Token test vectors

Fixed inputs and the exact token text csrf-sec issues for them, for both token layouts. The format is described in [`API.md`](./API.md#token-format); these vectors pin it. Every vector here is checked twice in CI: by the crate (`tests/vectors.rs`) and by an independent implementation of the format, with a BLAKE3 written from its specification, in Python (`dev/reference/vectors.py`). An implementation of the format in another language should reproduce every line.

## Common inputs

| Input | Value |
|---|---|
| application key | the 32 bytes `00 01 02 ... 1f` |
| pad source | bytes `00 01 02 ...`, continuing across calls, starting at `00` for each token |
| `T` | `1792540800` (2026-10-21T00:00:00Z) |
| epoch | `1577836800` (2020-01-01T00:00:00Z); the token carries `issued at - epoch` |
| long session | 300 bytes of `s` |
| long scope | 200 bytes of `p` |

A one-time token draws its 16-byte nonce from the pad source first, so its nonce is `00 ... 0f` and its pad starts at `10`.

## Vectors

| # | Layout | Key id | Session | Scope | Issued at | Token |
|---|---|---|---|---|---|---|
| 1 | session (v1) | 0 | `session-1` | (none) | `T` | `AAECAwQFBgcICQoLDA0ODxAREhMUFQEBghzICcvIOkah9oYQIY-vW0wS77s` |
| 2 | session (v1) | 0 | `session-1` | `POST /pay` | `T` | `AAECAwQFBgcICQoLDA0ODxAREhMUFQEBghzICQM0quXG3nig2Xkp-NswIXA` |
| 3 | session (v1) | 7 | `Q2xhc3NpY2FsIDQzLWNoYXJhY3RlciBzZXNzaW9uIGl` | `POST /account/email` | `T` | `AAECAwQFBgcICQoLDA0ODxAREhMUFQEGghzICfn6ZD6fclsw30XkxvFLrf4` |
| 4 | session (v1) | 255 | long session | long scope | `T` | `AAECAwQFBgcICQoLDA0ODxAREhMUFQH-ghzICRNr7xvmCxjMogEJsbMWk6Q` |
| 5 | session (v1) | 0 | `session-1` | (none) | epoch | `AAECAwQFBgcICQoLDA0ODxAREhMUFQEBAgMEBfcRpXw8TFQNCqot3Orz7sk` |
| 6 | session (v1) | 0 | `session-1` | (none) | epoch + 4294967295 | `AAECAwQFBgcICQoLDA0ODxAREhMUFQEB_fz7-sGlCopL82Qp77lTqE6bqvU` |
| 7 | one-time (v2) | 0 | `session-1` | `POST /pay` | `T` | `EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDUSEZIM2BkWFhoaHh4aGhYWKiouLioqtAwWUz2ob7Iv7nQucaPUTA` |
| 8 | one-time (v2) | 9 | long session | long scope | `T` | `EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDUSGJIM2BkWFhoaHh4aGhYWKiouLioq6KxTaiXqC1CIbNPjQ5CkKg` |

Vectors 4 and 8 take the MAC input past one 64-byte BLAKE3 block (the streamed path in the crate); 5 and 6 are the first and last representable issue times.

## Key fingerprint

`KeyFingerprint` for key id 0 under the key above: `756b8253b16ff08a` (the first 8 bytes of keyed BLAKE3 over `csrf-sec/v1 key fingerprint`, under the session-token subkey).
