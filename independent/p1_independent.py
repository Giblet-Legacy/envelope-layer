"""
p1_independent.py — Independent reimplementation of P1 Envelope (SPEC §8.4)

Function:
    A second, separate implementation of every P1 primitive, written
    from SPEC.md v1.1.0 without importing or referring to envelope.py.
    It exists so P1 is accepted by cross-implementation agreement, not
    by self-verification (SPEC §7).

    Independence is deliberate at every layer where it is affordable:
      - Canonicalisation is a hand-written serialiser, NOT json.dumps.
      - SHA-256 is hand-rolled from FIPS 180-4, NOT hashlib.sha256.
        Round constants are derived from primes, not typed in.
      - Ed25519 is hand-rolled from RFC 8032 §5.1 / §6, NOT the
        cryptography package. (Its internal SHA-512 uses hashlib —
        SHA-512 is not a P1 primitive.)
      - base58btc and did:key are written from SPEC §9 / §9a.

    This module works on raw bytes only (32-byte seeds, 32-byte public
    keys). It never touches key objects from the cryptography package.

    Rule: this file must never import envelope.

Functions in this file:
    1.  canonicalise       — canonical JSON string (hand-written serialiser)
    2.  canonical_bytes    — canonical ASCII bytes
    3.  sha256_digest      — hand-rolled SHA-256, raw 32 bytes
    4.  sha256_hex         — hand-rolled SHA-256, 64-char lowercase hex
    5.  ed25519_public_key — 32-byte seed → 32-byte public key
    6.  ed25519_sign       — 32-byte seed + message → 64-byte signature
    7.  ed25519_verify     — public key + message + signature → bool
    8.  base58btc_encode   — bytes → base58btc string (SPEC §9a)
    9.  base58btc_decode   — base58btc string → bytes (SPEC §9a)
    10. did_key_encode     — 32-byte public key → did:key string
    11. did_key_decode     — did:key string → 32-byte public key

Internal helpers:
    12. _escape_string     — JSON string escaping, ensure_ascii form
    13. _primes            — first n primes (SHA-256 constant derivation)
    14. _iroot             — integer k-th root (SHA-256 constant derivation)
    15. _sha256_compress   — one SHA-256 block compression
    16. _ed_* group        — Ed25519 field / point arithmetic (RFC 8032)

Layer:    P1 — Envelope (independent verification, not consumed)
Spec:     SPEC.md v1.1.0
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import hashlib  # SHA-512 only, inside Ed25519. Never used for SHA-256.
import math


# ---------------------------------------------------------------------------
# 12. _escape_string
#     Escape a str exactly as SPEC §1 requires (json.dumps ensure_ascii
#     form): '"' and '\\' backslash-escaped; \b \f \n \r \t short forms;
#     other code points < 0x20 and everything >= 0x7F as \uXXXX
#     (lowercase hex); code points above U+FFFF as a surrogate pair.
# ---------------------------------------------------------------------------
_SHORT_ESCAPES = {
    '"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f",
    "\n": "\\n", "\r": "\\r", "\t": "\\t",
}


def _escape_string(s):
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if ch in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[ch])
        elif 0x20 <= cp < 0x7F:
            out.append(ch)
        elif cp <= 0xFFFF:
            out.append("\\u%04x" % cp)
        else:
            v = cp - 0x10000
            out.append("\\u%04x\\u%04x" % (0xD800 | (v >> 10), 0xDC00 | (v & 0x3FF)))
    out.append('"')
    return "".join(out)


# ---------------------------------------------------------------------------
# 1. canonicalise
#    Hand-written serialiser for SPEC §1. Keys sorted by code point, no
#    whitespace, ASCII-only. Floats use Python's shortest round-trip
#    repr (SPEC §1: "Python's default float repr"). NaN and ±Infinity
#    are rejected with ValueError: they are not JSON, and SPEC v1.1.0
#    does not define a canonical form for them (see NOTES.md D4).
# ---------------------------------------------------------------------------
def canonicalise(obj):
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int):
        return int.__repr__(obj)
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise ValueError(f"non-finite float has no canonical form: {obj!r}")
        return float.__repr__(obj)
    if isinstance(obj, str):
        return _escape_string(obj)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(canonicalise(v) for v in obj) + "]"
    if isinstance(obj, dict):
        for k in obj:
            if not isinstance(k, str):
                raise TypeError(f"object keys must be str, got {type(k).__name__}")
        return "{" + ",".join(
            _escape_string(k) + ":" + canonicalise(obj[k]) for k in sorted(obj)
        ) + "}"
    raise TypeError(f"not JSON-serialisable: {type(obj).__name__}")


# ---------------------------------------------------------------------------
# 2. canonical_bytes
#    canonicalise(obj) as bytes. Output is pure ASCII by construction.
# ---------------------------------------------------------------------------
def canonical_bytes(obj):
    return canonicalise(obj).encode("ascii")


# ---------------------------------------------------------------------------
# 13. _primes
#     First n primes by trial division. Used to derive SHA-256 constants.
# ---------------------------------------------------------------------------
def _primes(n):
    found = []
    c = 2
    while len(found) < n:
        if all(c % p for p in found if p * p <= c):
            found.append(c)
        c += 1
    return found


# ---------------------------------------------------------------------------
# 14. _iroot
#     Floor of the k-th root of non-negative integer n (binary search).
# ---------------------------------------------------------------------------
def _iroot(n, k):
    lo, hi = 0, 1 << (n.bit_length() // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo


# FIPS 180-4 §4.2.2 / §5.3.3: first 32 bits of the fractional parts of the
# cube roots (K) and square roots (H0) of the first 64 / 8 primes.
_K = [_iroot(p << 96, 3) & 0xFFFFFFFF for p in _primes(64)]
_H0 = [_iroot(p << 64, 2) & 0xFFFFFFFF for p in _primes(8)]
_M32 = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _M32


# ---------------------------------------------------------------------------
# 15. _sha256_compress
#     Process one 64-byte block into the 8-word state (FIPS 180-4 §6.2.2).
# ---------------------------------------------------------------------------
def _sha256_compress(state, block):
    w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    for t in range(16, 64):
        s0 = _rotr(w[t - 15], 7) ^ _rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
        s1 = _rotr(w[t - 2], 17) ^ _rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & _M32)
    a, b, c, d, e, f, g, h = state
    for t in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + _K[t] + w[t]) & _M32
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & _M32
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & _M32, c, b, a, (t1 + t2) & _M32
    return [(x + y) & _M32 for x, y in zip(state, (a, b, c, d, e, f, g, h))]


# ---------------------------------------------------------------------------
# 3. sha256_digest
#    Hand-rolled SHA-256 over bytes. Raw 32-byte digest.
# ---------------------------------------------------------------------------
def sha256_digest(data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("sha256 input must be bytes-like")
    data = bytes(data)
    bitlen = len(data) * 8
    padded = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + bitlen.to_bytes(8, "big")
    state = list(_H0)
    for i in range(0, len(padded), 64):
        state = _sha256_compress(state, padded[i:i + 64])
    return b"".join(x.to_bytes(4, "big") for x in state)


# ---------------------------------------------------------------------------
# 4. sha256_hex
#    Hand-rolled SHA-256, 64-char lowercase hex.
# ---------------------------------------------------------------------------
def sha256_hex(data):
    return sha256_digest(data).hex()


# ---------------------------------------------------------------------------
# 16. _ed_* group — Ed25519 arithmetic, RFC 8032 §5.1 and §6.
#     Extended homogeneous coordinates (X, Y, Z, T), x = X/Z, y = Y/Z,
#     x*y = T/Z.
# ---------------------------------------------------------------------------
_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _ed_sha512_modq(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little") % _Q


def _ed_add(P1, P2):
    A = (P1[1] - P1[0]) * (P2[1] - P2[0]) % _P
    B = (P1[1] + P1[0]) * (P2[1] + P2[0]) % _P
    C = 2 * P1[3] * P2[3] * _D % _P
    D = 2 * P1[2] * P2[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _ed_mul(s, P):
    R = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            R = _ed_add(R, P)
        P = _ed_add(P, P)
        s >>= 1
    return R


def _ed_equal(P1, P2):
    return ((P1[0] * P2[2] - P2[0] * P1[2]) % _P == 0
            and (P1[1] * P2[2] - P2[1] * P1[2]) % _P == 0)


def _ed_recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _ed_compress(P):
    zinv = pow(P[2], _P - 2, _P)
    x, y = P[0] * zinv % _P, P[1] * zinv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _ed_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


_G_Y = 4 * pow(5, _P - 2, _P) % _P
_G_X = _ed_recover_x(_G_Y, 0)
_G = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def _ed_expand(seed):
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


# ---------------------------------------------------------------------------
# 5. ed25519_public_key
#    32-byte private seed → 32-byte compressed public key (RFC 8032 §5.1.5).
# ---------------------------------------------------------------------------
def ed25519_public_key(seed):
    a, _ = _ed_expand(seed)
    return _ed_compress(_ed_mul(a, _G))


# ---------------------------------------------------------------------------
# 6. ed25519_sign
#    Pure Ed25519 (RFC 8032 §5.1.6) over arbitrary bytes. No pre-hash.
#    Deterministic: same seed + message → same 64 bytes.
# ---------------------------------------------------------------------------
def ed25519_sign(seed, msg):
    a, prefix = _ed_expand(seed)
    A = _ed_compress(_ed_mul(a, _G))
    r = _ed_sha512_modq(prefix + msg)
    Rs = _ed_compress(_ed_mul(r, _G))
    k = _ed_sha512_modq(Rs + A + msg)
    s = (r + k * a) % _Q
    return Rs + s.to_bytes(32, "little")


# ---------------------------------------------------------------------------
# 7. ed25519_verify
#    RFC 8032 §5.1.7 verification. Malformed input → False, never raises
#    (SPEC §3 failure posture).
# ---------------------------------------------------------------------------
def ed25519_verify(public, msg, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _ed_decompress(public)
    R = _ed_decompress(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    k = _ed_sha512_modq(signature[:32] + public + msg)
    return _ed_equal(_ed_mul(s, _G), _ed_add(R, _ed_mul(k, A)))


_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


# ---------------------------------------------------------------------------
# 8. base58btc_encode
#    SPEC §9a encode, including leading-zero-byte → '1' handling.
# ---------------------------------------------------------------------------
def base58btc_encode(data):
    z = len(data) - len(bytes(data).lstrip(b"\x00"))
    n = int.from_bytes(data[z:], "big")
    body = []
    while n > 0:
        n, digit = divmod(n, 58)
        body.append(_ALPHABET[digit])
    return "1" * z + "".join(reversed(body))


# ---------------------------------------------------------------------------
# 9. base58btc_decode
#    SPEC §9a decode. ValueError on any character outside the alphabet.
# ---------------------------------------------------------------------------
def base58btc_decode(s):
    z = len(s) - len(s.lstrip("1"))
    n = 0
    for c in s[z:]:
        idx = _ALPHABET.find(c)
        if idx < 0:
            raise ValueError(f"invalid base58btc character: {c!r}")
        n = n * 58 + idx
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * z + body


# ---------------------------------------------------------------------------
# 10. did_key_encode
#     32 raw public-key bytes → did:key:z6Mk... (SPEC §4.7, §9).
# ---------------------------------------------------------------------------
def did_key_encode(public):
    if not isinstance(public, (bytes, bytearray)):
        raise TypeError("public key must be 32 raw bytes")
    if len(public) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(public)}")
    return "did:key:z" + base58btc_encode(b"\xed\x01" + bytes(public))


# ---------------------------------------------------------------------------
# 11. did_key_decode
#     did:key string → 32 raw public-key bytes. Every malformation raises
#     ValueError (SPEC §4.8).
# ---------------------------------------------------------------------------
def did_key_decode(did):
    prefix = "did:key:z"
    if not isinstance(did, str) or not did.startswith("did:key:"):
        raise ValueError("not a did:key")
    if not did.startswith(prefix):
        raise ValueError("multibase prefix is not 'z'")
    raw = base58btc_decode(did[len(prefix):])
    if raw[:2] != b"\xed\x01":
        raise ValueError("multicodec is not ed25519-pub (0xed 0x01)")
    if len(raw) != 34:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw) - 2}")
    return raw[2:]
