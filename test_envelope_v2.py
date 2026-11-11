"""
test_envelope_v2.py — P1 Envelope v2 (strict layer) test suite

Function:
    Executable expression of SPEC_V2.md §5. Written before
    envelope_v2.py. Proves two things: (1) v2 is byte-identical to the
    frozen v1 primitive for every in-contract input, so old artefacts
    still verify; (2) v2 raises where SPEC requires and v1 did not
    (NOTES.md Q1, D1–D4).

Functions in this file (pytest-collected):
    1.  test_public_api                   — eight names, all callable
    2.  test_canonical_identity_with_v1   — same bytes as v1
    3.  test_non_finite_rejected          — NaN / ±Infinity at any depth
    4.  test_non_finite_strings_accepted  — "NaN" as text is fine
    5.  test_old_signatures_verify        — v1 ⇄ v2 signatures
    6.  test_verify_type_errors           — D1, D2 resolved
    7.  test_verify_false_results         — bad sig / tamper still False
    8.  test_sign_identity_and_errors     — same sig as v1; TypeErrors
    9.  test_did_key_encode               — identity with v1; D3 resolved
    10. test_did_key_decode_unchanged     — same as v1, results and errors
    11. test_sha256_reexported            — same objects as v1

Layer:    P1 — Envelope, v2 (strict)
Spec:     SPEC_V2.md 2.0.0 (over SPEC.md v1.1.0)
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import envelope
import envelope_v2

CORPUS = [
    {}, [], "", 0, -0.0, 1, 1.0, 1.5, 1e308, 5e-324, 2 ** 64, True, False, None,
    {"b": 2, "a": 1}, {"a": {"b": [1, 2]}}, {"signature": None, "seq": 0},
    "quote\" back\\ ctrl\n\x00 é \U0001F600", {"é": [1.25, None]},
]

NAN, INF = float("nan"), float("inf")


# ---------------------------------------------------------------------------
# 1. test_public_api
# ---------------------------------------------------------------------------
def test_public_api():
    for name in ["canonicalise", "canonical_bytes", "sha256_hex", "sha256_digest",
                 "sign_bytes", "verify_bytes", "did_key_encode", "did_key_decode"]:
        assert callable(getattr(envelope_v2, name))


# ---------------------------------------------------------------------------
# 2. test_canonical_identity_with_v1
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("obj", CORPUS, ids=lambda o: repr(o)[:30])
def test_canonical_identity_with_v1(obj):
    assert envelope_v2.canonicalise(obj) == envelope.canonicalise(obj)
    assert envelope_v2.canonical_bytes(obj) == envelope.canonical_bytes(obj)


# ---------------------------------------------------------------------------
# 3. test_non_finite_rejected
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("obj", [NAN, INF, -INF, [1, NAN], {"a": {"b": [INF]}}, {"x": -INF}])
def test_non_finite_rejected(obj):
    with pytest.raises(ValueError):
        envelope_v2.canonicalise(obj)
    with pytest.raises(ValueError):
        envelope_v2.canonical_bytes(obj)


# ---------------------------------------------------------------------------
# 4. test_non_finite_strings_accepted
# ---------------------------------------------------------------------------
def test_non_finite_strings_accepted():
    obj = {"NaN": "NaN", "v": ["Infinity", "-Infinity"]}
    assert envelope_v2.canonicalise(obj) == envelope.canonicalise(obj)


# ---------------------------------------------------------------------------
# 5. test_old_signatures_verify
# ---------------------------------------------------------------------------
def test_old_signatures_verify():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    capsule = envelope.canonical_bytes({"capsule": 1, "signature": None})
    digest = envelope.sha256_digest(capsule)
    for data in [capsule, digest, b""]:
        assert envelope_v2.verify_bytes(data, envelope.sign_bytes(data, sk), pk) is True
        assert envelope.verify_bytes(data, envelope_v2.sign_bytes(data, sk), pk) is True


# ---------------------------------------------------------------------------
# 6. test_verify_type_errors
# ---------------------------------------------------------------------------
def test_verify_type_errors():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sig = envelope.sign_bytes(b"x", sk)
    with pytest.raises(TypeError):
        envelope_v2.verify_bytes("x", sig, pk)              # D1
    with pytest.raises(TypeError):
        envelope_v2.verify_bytes(b"x", sig.hex(), pk)
    with pytest.raises(TypeError):
        envelope_v2.verify_bytes(b"x", sig, None)           # D2
    with pytest.raises(TypeError):
        envelope_v2.verify_bytes(b"x", sig, sk)             # private, not public
    assert envelope_v2.verify_bytes(bytearray(b"x"), memoryview(sig), pk) is True


# ---------------------------------------------------------------------------
# 7. test_verify_false_results
# ---------------------------------------------------------------------------
def test_verify_false_results():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sig = envelope_v2.sign_bytes(b"original", sk)
    assert envelope_v2.verify_bytes(b"tampered", sig, pk) is False
    assert envelope_v2.verify_bytes(b"original", b"short", pk) is False
    other = Ed25519PrivateKey.generate().public_key()
    assert envelope_v2.verify_bytes(b"original", sig, other) is False


# ---------------------------------------------------------------------------
# 8. test_sign_identity_and_errors
# ---------------------------------------------------------------------------
def test_sign_identity_and_errors():
    sk = Ed25519PrivateKey.generate()
    assert envelope_v2.sign_bytes(b"data", sk) == envelope.sign_bytes(b"data", sk)
    with pytest.raises(TypeError):
        envelope_v2.sign_bytes("data", sk)
    with pytest.raises(TypeError):
        envelope_v2.sign_bytes(b"data", ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(TypeError):
        envelope_v2.sign_bytes(b"data", sk.public_key())


# ---------------------------------------------------------------------------
# 9. test_did_key_encode
# ---------------------------------------------------------------------------
def test_did_key_encode():
    pk = Ed25519PrivateKey.generate().public_key()
    raw = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert envelope_v2.did_key_encode(pk) == envelope.did_key_encode(pk)
    assert envelope_v2.did_key_encode(raw) == envelope.did_key_encode(raw)
    assert envelope_v2.did_key_encode(bytearray(raw)) == envelope.did_key_encode(raw)
    with pytest.raises(TypeError):
        envelope_v2.did_key_encode("abc")                   # D3
    with pytest.raises(TypeError):
        envelope_v2.did_key_encode(None)
    with pytest.raises(ValueError):
        envelope_v2.did_key_encode(raw[:31])


# ---------------------------------------------------------------------------
# 10. test_did_key_decode_unchanged
# ---------------------------------------------------------------------------
def test_did_key_decode_unchanged():
    did = "did:key:z6MkgGoK1f2rh84pkWmFL3ew1CmMidaPxVFSvxsbUyxkKLZE"
    assert envelope.did_key_encode(envelope_v2.did_key_decode(did)) == did
    for bad in ["did:web:example.com", "did:key:f6Mkabc", "did:key:z0OIl"]:
        with pytest.raises(ValueError):
            envelope_v2.did_key_decode(bad)


# ---------------------------------------------------------------------------
# 11. test_sha256_reexported
# ---------------------------------------------------------------------------
def test_sha256_reexported():
    assert envelope_v2.sha256_hex is envelope.sha256_hex
    assert envelope_v2.sha256_digest is envelope.sha256_digest
    assert envelope_v2.did_key_decode is envelope.did_key_decode
