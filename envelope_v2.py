"""
envelope_v2.py — P1 Envelope v2, strict layer over the frozen v1 primitive

Function:
    The layer new code imports instead of envelope.py. It adds input
    checks that SPEC.md v1.1.0 required but envelope.py v1.0.0 did not
    enforce, and rejects non-finite floats (SPEC_V2.md §2). It never
    reimplements a primitive: every byte it returns comes from
    envelope.py, so every artefact signed through v1 verifies through
    v2 (SPEC_V2.md §1, §3).

    envelope.py is not edited (Immutable Rule). This file is the
    "add a layer" half of that rule.

Public API (same names and numbering as P1 v1.0.0):
    1. canonicalise    — v1 canonical string; ValueError on NaN/±Infinity
    2. canonical_bytes — v2 canonicalise, UTF-8 (pure ASCII) bytes
    3. sha256_hex      — re-exported from v1 unchanged
    4. sha256_digest   — re-exported from v1 unchanged
    5. sign_bytes      — TypeError checks, then v1
    6. verify_bytes    — TypeError checks, then v1
    7. did_key_encode  — TypeError check, then v1
    8. did_key_decode  — re-exported from v1 unchanged

Internal helpers (not exported):
    9.  _reject_constant — json.loads hook that fires on NaN/±Infinity
    10. _require_bytes   — TypeError unless bytes-like

Layer:    P1 — Envelope, v2 (strict)
Depends:  envelope.py (P1 v1.0.0)
Consumed: P2 Sign onward
Spec:     SPEC_V2.md 2.0.0 (over SPEC.md v1.1.0)
Version:  2.0.0
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import envelope as _v1

sha256_hex = _v1.sha256_hex
sha256_digest = _v1.sha256_digest
did_key_decode = _v1.did_key_decode

_BYTES_LIKE = (bytes, bytearray, memoryview)


# ---------------------------------------------------------------------------
# 9. _reject_constant
#    json.loads calls parse_constant only for the bare tokens NaN,
#    Infinity and -Infinity — never for strings that contain that text.
# ---------------------------------------------------------------------------
def _reject_constant(token):
    raise ValueError(f"non-finite float has no canonical form: {token}")


# ---------------------------------------------------------------------------
# 10. _require_bytes
#     TypeError unless value is bytes, bytearray or memoryview.
# ---------------------------------------------------------------------------
def _require_bytes(name, value):
    if not isinstance(value, _BYTES_LIKE):
        raise TypeError(f"{name} must be bytes-like, got {type(value).__name__}")


# ---------------------------------------------------------------------------
# 1. canonicalise
#    v1's canonical string, returned untouched, after confirming it
#    contains no non-finite constant (SPEC_V2.md §2.1, §3).
# ---------------------------------------------------------------------------
def canonicalise(obj):
    text = _v1.canonicalise(obj)
    json.loads(text, parse_constant=_reject_constant)
    return text


# ---------------------------------------------------------------------------
# 2. canonical_bytes
#    v2 canonicalise encoded to UTF-8. Pure ASCII by construction.
# ---------------------------------------------------------------------------
def canonical_bytes(obj):
    return canonicalise(obj).encode("utf-8")


# ---------------------------------------------------------------------------
# 5. sign_bytes
#    TypeError unless data is bytes-like and private_key is an Ed25519
#    private key (SPEC_V2.md §2.3). Signature bytes come from v1.
# ---------------------------------------------------------------------------
def sign_bytes(data, private_key):
    _require_bytes("data", data)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError(f"private_key must be Ed25519PrivateKey, got {type(private_key).__name__}")
    return _v1.sign_bytes(data, private_key)


# ---------------------------------------------------------------------------
# 6. verify_bytes
#    TypeError on wrong input types (SPEC_V2.md §2.2, resolves D1/D2).
#    Every other failure is a False result from v1, as before.
# ---------------------------------------------------------------------------
def verify_bytes(data, signature, public_key):
    _require_bytes("data", data)
    _require_bytes("signature", signature)
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError(f"public_key must be Ed25519PublicKey, got {type(public_key).__name__}")
    return _v1.verify_bytes(data, signature, public_key)


# ---------------------------------------------------------------------------
# 7. did_key_encode
#    TypeError unless public_key is an Ed25519 public key, bytes or
#    bytearray (SPEC_V2.md §2.4, resolves D3). Length check stays in v1.
# ---------------------------------------------------------------------------
def did_key_encode(public_key):
    if not isinstance(public_key, (Ed25519PublicKey, bytes, bytearray)):
        raise TypeError(f"public_key must be Ed25519PublicKey or bytes, got {type(public_key).__name__}")
    return _v1.did_key_encode(public_key)
