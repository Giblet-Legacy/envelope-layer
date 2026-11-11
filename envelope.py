"""
envelope.py — P1 Envelope primitive layer

Function:
    Provides the byte-level cryptographic primitives on which every
    higher layer of the Forge Stack depends: canonical JSON
    serialisation, SHA-256 hashing, Ed25519 signing/verification,
    and did:key encoding/decoding for Ed25519 public keys.

    P1 does not decide what gets hashed or signed — that decision
    belongs to the calling layer. The capsule-signing rule (raw
    canonical bytes, "signature": null, no pre-hash) is P2's
    responsibility. The ledger-signing rule (hash the canonical
    unsigned entry, sign the raw 32-byte digest) is P4's. P1
    exposes primitives that make both expressible without knowing
    either.

    P1 does not touch the filesystem, network, environment, clock,
    or key storage. did:key is self-resolving: the key IS the
    identifier, and P1 performs no lookup. P1 is pure function:
    input in, output out.

Public API:
    1. canonicalise    — canonical JSON string from Python object
    2. canonical_bytes — canonical UTF-8 bytes from Python object
    3. sha256_hex      — SHA-256 hex digest of bytes
    4. sha256_digest   — SHA-256 raw 32-byte digest of bytes
    5. sign_bytes      — Ed25519 signature over arbitrary bytes
    6. verify_bytes    — verify Ed25519 signature over arbitrary bytes
    7. did_key_encode  — Ed25519 public key → did:key string
    8. did_key_decode  — did:key string → Ed25519 public key

Internal helpers (not exported):
    9.  _base58btc_encode — raw bytes → base58btc string
    10. _base58btc_decode — base58btc string → raw bytes

Layer:    P1 — Envelope
Depends:  (nothing — base primitive)
Consumed: P2 Sign, P3 Freeze, P4 Ledger, P5 Genesis, P6 Canon Verify,
          P7 Record
Version:  1.0.0 (on freeze; 0.0.0-dev until then)
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import json
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ALPHABET_INDEX = {c: i for i, c in enumerate(_ALPHABET)}
_ED25519_MULTICODEC = b"\xed\x01"


# ---------------------------------------------------------------------------
# 1. canonicalise
#    Returns the canonical JSON string for obj: keys sorted, no
#    whitespace, ASCII-only output. This exact form is the byte-level
#    contract for the whole stack. Not RFC 8785 / JCS.
# ---------------------------------------------------------------------------
def canonicalise(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


# ---------------------------------------------------------------------------
# 2. canonical_bytes
#    canonicalise(obj) encoded to UTF-8. Because ensure_ascii=True
#    guarantees ASCII, output is pure ASCII bytes (every byte < 0x80).
# ---------------------------------------------------------------------------
def canonical_bytes(obj):
    return canonicalise(obj).encode("utf-8")


# ---------------------------------------------------------------------------
# 3. sha256_hex
#    Lowercase hex SHA-256 digest of data. 64 characters. Pure function.
# ---------------------------------------------------------------------------
def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# 4. sha256_digest
#    Raw 32-byte SHA-256 digest of data. Used where the digest itself
#    is signed (P4 ledger rule).
# ---------------------------------------------------------------------------
def sha256_digest(data):
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# 5. sign_bytes
#    Ed25519 signature over arbitrary bytes. No pre-hash — the caller
#    decides what data means (canonical capsule bytes, or raw digest).
# ---------------------------------------------------------------------------
def sign_bytes(data, private_key):
    return private_key.sign(data)


# ---------------------------------------------------------------------------
# 6. verify_bytes
#    Returns True if signature is valid for data under public_key,
#    False otherwise. Malformed input is False, not an exception.
# ---------------------------------------------------------------------------
def verify_bytes(data, signature, public_key):
    try:
        public_key.verify(signature, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# 7. did_key_encode
#    Ed25519 public key → did:key:z6Mk... string.
#    Multicodec 0xed 0x01 + raw 32-byte key → base58btc → 'z' → did:key:
# ---------------------------------------------------------------------------
def did_key_encode(public_key):
    if isinstance(public_key, (bytes, bytearray)):
        raw = bytes(public_key)
    else:
        raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    if len(raw) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    multikey = _ED25519_MULTICODEC + raw
    return "did:key:z" + _base58btc_encode(multikey)


# ---------------------------------------------------------------------------
# 8. did_key_decode
#    did:key:z6Mk... string → Ed25519 public key object.
#    Raises ValueError on any malformed input — a malformed did:key is
#    a policy error, not a verification result.
# ---------------------------------------------------------------------------
def did_key_decode(did):
    if not isinstance(did, str) or not did.startswith("did:key:"):
        raise ValueError(f"not a did:key: {did!r}")
    rest = did[len("did:key:"):]
    if not rest.startswith("z"):
        raise ValueError(f"not base58btc multibase (expected 'z'): {rest[:1]!r}")
    multikey = _base58btc_decode(rest[1:])
    if not multikey.startswith(_ED25519_MULTICODEC):
        raise ValueError("not Ed25519 multicodec (expected 0xed 0x01)")
    raw = multikey[2:]
    if len(raw) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


# ---------------------------------------------------------------------------
# 9. _base58btc_encode
#    Raw bytes → base58btc string. Bitcoin alphabet, leading-zero-byte
#    handling per spec §9a.
# ---------------------------------------------------------------------------
def _base58btc_encode(data):
    z = 0
    for b in data:
        if b == 0:
            z += 1
        else:
            break
    n = int.from_bytes(data[z:], "big") if data[z:] else 0
    body = ""
    while n > 0:
        n, digit = divmod(n, 58)
        body = _ALPHABET[digit] + body
    return ("1" * z) + body


# ---------------------------------------------------------------------------
# 10. _base58btc_decode
#     base58btc string → raw bytes. Raises ValueError on invalid
#     character. Leading '1's become leading 0x00 bytes.
# ---------------------------------------------------------------------------
def _base58btc_decode(s):
    z = 0
    for c in s:
        if c == "1":
            z += 1
        else:
            break
    n = 0
    for c in s[z:]:
        if c not in _ALPHABET_INDEX:
            raise ValueError(f"invalid base58btc character: {c!r}")
        n = n * 58 + _ALPHABET_INDEX[c]
    body_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    return (b"\x00" * z) + body_bytes
