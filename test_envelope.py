"""
test_envelope.py — P1 Envelope test suite

Function:
    Executable expression of SPEC.md §8. Written before envelope.py
    per build discipline. Each test matches a numbered requirement
    in SPEC.md. All tests must pass before P1 is signed off.

Functions in this file (test functions, pytest-collected):
    §8.1 canonicalise   — roundtrip, sort, no-whitespace, ascii, nested,
                          numbers, literals
    §8.2 sha256         — known vectors, length, consistency
    §8.3 ed25519        — roundtrip, wrong data/key, length, determinism, malformed
    §8.3b did:key       — roundtrip, prefix, format, known vector, wrong
                          prefix/multibase/key type/length, invalid char

    Cross-implementation agreement (SPEC §8.4) lives in
    independent/test_cross.py, not here.

Layer:    P1 — Envelope
Spec:     SPEC.md v1.1.0
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import json
import re
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import envelope


# ---------------------------------------------------------------------------
# §8.1 Canonicalisation
# ---------------------------------------------------------------------------
def test_canonicalise_roundtrip():
    for obj in [{"a": 1}, [1, 2, 3], "hello", 42, True, None, {"nested": {"deep": [1, 2]}}]:
        assert json.loads(envelope.canonicalise(obj)) == obj

def test_canonicalise_key_sorting():
    assert envelope.canonicalise({"b": 2, "a": 1}) == envelope.canonicalise({"a": 1, "b": 2})

def test_canonicalise_no_whitespace():
    assert envelope.canonicalise({"a": 1}) == '{"a":1}'

def test_canonicalise_ascii_only():
    assert all(ord(c) < 128 for c in envelope.canonicalise({"key": "é"}))

def test_canonicalise_unicode_escape():
    assert envelope.canonicalise({"a": "é"}) == '{"a":"\\u00e9"}'

def test_canonicalise_empty():
    assert envelope.canonicalise({}) == "{}"
    assert envelope.canonicalise([]) == "[]"

def test_canonicalise_nested():
    assert envelope.canonicalise({"a": {"b": [1, 2]}}) == '{"a":{"b":[1,2]}}'

def test_canonicalise_numbers():
    assert envelope.canonicalise(1) == "1"
    assert envelope.canonicalise(1.0) == "1.0"
    assert envelope.canonicalise(1.5) == "1.5"

def test_canonicalise_literals():
    assert envelope.canonicalise(None) == "null"
    assert envelope.canonicalise(True) == "true"
    assert envelope.canonicalise(False) == "false"

def test_canonical_bytes_is_utf8():
    assert envelope.canonical_bytes({"a": 1}) == b'{"a":1}'


# ---------------------------------------------------------------------------
# §8.2 SHA-256
# ---------------------------------------------------------------------------
def test_sha256_known_empty():
    assert envelope.sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def test_sha256_known_abc():
    assert envelope.sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

def test_sha256_digest_length():
    assert len(envelope.sha256_digest(b"anything")) == 32

def test_sha256_consistency():
    for data in [b"", b"abc", b"x" * 1000]:
        assert envelope.sha256_digest(data).hex() == envelope.sha256_hex(data)


# ---------------------------------------------------------------------------
# §8.3 Ed25519
# ---------------------------------------------------------------------------
def test_ed25519_roundtrip():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    for data in [b"", b"x", b"x" * 1024, envelope.canonical_bytes({"a": 1})]:
        assert envelope.verify_bytes(data, envelope.sign_bytes(data, sk), pk) is True

def test_ed25519_wrong_data():
    sk = Ed25519PrivateKey.generate()
    sig = envelope.sign_bytes(b"original", sk)
    assert envelope.verify_bytes(b"tampered", sig, sk.public_key()) is False

def test_ed25519_wrong_key():
    sk1 = Ed25519PrivateKey.generate()
    sk2 = Ed25519PrivateKey.generate()
    sig = envelope.sign_bytes(b"data", sk1)
    assert envelope.verify_bytes(b"data", sig, sk2.public_key()) is False

def test_ed25519_signature_length():
    assert len(envelope.sign_bytes(b"data", Ed25519PrivateKey.generate())) == 64

def test_ed25519_determinism():
    sk = Ed25519PrivateKey.generate()
    assert envelope.sign_bytes(b"data", sk) == envelope.sign_bytes(b"data", sk)

def test_ed25519_malformed_signature():
    sk = Ed25519PrivateKey.generate()
    # Must return False, not raise
    assert envelope.verify_bytes(b"data", b"short", sk.public_key()) is False


# ---------------------------------------------------------------------------
# §8.3b did:key
# ---------------------------------------------------------------------------
def test_did_key_roundtrip():
    for _ in range(3):
        sk = Ed25519PrivateKey.generate()
        did = envelope.did_key_encode(sk.public_key())
        decoded_pk = envelope.did_key_decode(did)
        assert envelope.did_key_encode(decoded_pk) == did

def test_did_key_prefix():
    sk = Ed25519PrivateKey.generate()
    did = envelope.did_key_encode(sk.public_key())
    assert did.startswith("did:key:z6Mk")

def test_did_key_format():
    sk = Ed25519PrivateKey.generate()
    did = envelope.did_key_encode(sk.public_key())
    assert re.match(r"^did:key:z[1-9A-HJ-NP-Za-km-z]+$", did)

def test_did_key_known_vector():
    did = "did:key:z6MkgGoK1f2rh84pkWmFL3ew1CmMidaPxVFSvxsbUyxkKLZE"
    pk = envelope.did_key_decode(did)
    assert envelope.did_key_encode(pk) == did

def test_did_key_wrong_prefix():
    with pytest.raises(ValueError):
        envelope.did_key_decode("did:web:example.com")

def test_did_key_wrong_multibase():
    with pytest.raises(ValueError):
        envelope.did_key_decode("did:key:f6Mkabc")

def test_did_key_wrong_key_type():
    # secp256k1 did:key (multicodec 0xe7 0x01) — valid base58btc, wrong curve
    with pytest.raises(ValueError):
        envelope.did_key_decode("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")

def test_did_key_invalid_char():
    # 0, O, I, l are not in base58btc
    with pytest.raises(ValueError):
        envelope.did_key_decode("did:key:z0OIl")

def test_did_key_wrong_length():
    # 0xed01 + 1 byte = 3 bytes; after multicodec strip, 1 byte, not 32
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(bytes.fromhex("ed0141"), "big")
    body = ""
    while n > 0:
        n, d = divmod(n, 58)
        body = alphabet[d] + body
    with pytest.raises(ValueError):
        envelope.did_key_decode("did:key:z" + body)
