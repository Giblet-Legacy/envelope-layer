"""
test_cross.py — Cross-implementation agreement tests (SPEC §7, §8.4)

Function:
    Runs envelope.py (P1 v1.0.0) and independent/p1_independent.py
    against the same inputs and requires byte-identical results for
    canonical JSON, SHA-256 hex and digest, Ed25519 public keys and
    signatures, and did:key strings. Signatures made by either side
    must verify on the other. This is the acceptance test SPEC §7
    names: agreement between two implementations, not self-checks.

    Also pins the known v1 divergences recorded in NOTES.md (D1–D4).
    envelope.py is frozen, so these pins hold forever; the divergences
    are resolved in envelope_v2.py, which test 15 checks against the
    independent implementation.

    Inputs are fixed vectors plus seeded pseudo-random corpora (seed
    fixed, so runs are reproducible on both devices).

Functions in this file (pytest-collected):
    1.  test_sha256_constants_derived      — derived K/H0 spot-check
    2.  test_sha256_known_vectors          — independent SHA-256 vs FIPS vectors
    3.  test_sha256_agreement              — lengths 0..300 incl. block edges
    4.  test_canonical_fixed_corpus        — hand-picked edge cases
    5.  test_canonical_random_corpus       — 500 random nested values
    6.  test_ed25519_rfc8032_vector        — RFC 8032 §7.1 TEST 1
    7.  test_ed25519_agreement             — keys and signatures identical
    8.  test_ed25519_cross_verify          — each side verifies the other
    9.  test_ed25519_independent_rejects   — tamper / malformed → False
    10. test_did_key_known_vector          — SPEC §9 anchor
    11. test_did_key_agreement             — encode/decode identical
    12. test_did_key_independent_errors    — SPEC §4.8 failure modes
    13. test_base58_leading_zeros          — SPEC §9a leading-zero rule
    14. test_divergence_pins               — NOTES.md D1–D4 v1 behaviour (frozen)
    15. test_v2_agreement                  — envelope_v2 vs independent, incl. NaN

Helpers:
    16. _random_value                      — seeded random JSON value

Layer:    P1 — Envelope (independent verification)
Spec:     SPEC.md v1.1.0
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import os
import random
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

import envelope  # noqa: E402  (P1 v1.0.0, under test)
import envelope_v2  # noqa: E402  (P1 v2.0.0 strict layer, under test)
import p1_independent as ind  # noqa: E402  (independent, never imports envelope)


SEED = 20261111


def _raw_pub(pk):
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


# ---------------------------------------------------------------------------
# 16. _random_value
#     Seeded random JSON value: nested dicts/lists, unicode (incl. astral
#     plane and control chars), ints of all sizes, finite floats.
# ---------------------------------------------------------------------------
def _random_value(rng, depth=0):
    kind = rng.randrange(8 if depth < 3 else 6)
    if kind == 0:
        return None
    if kind == 1:
        return rng.random() < 0.5
    if kind == 2:
        return rng.choice([0, -1, 1, 2 ** 53, -(2 ** 63), 10 ** 30, rng.randrange(-10 ** 6, 10 ** 6)])
    if kind == 3:
        return rng.choice([0.0, -0.0, 0.1, 1.0, 1.5, 1e16, 1e-7, 123456.789, 1e308, 5e-324,
                           rng.uniform(-1e6, 1e6)])
    if kind in (4, 5):
        pool = "abc \"\\/\b\f\n\r\t\x00\x1f\x7fé 中\U0001F600\U0010FFFF"
        return "".join(rng.choice(pool) for _ in range(rng.randrange(8)))
    if kind == 6:
        return [_random_value(rng, depth + 1) for _ in range(rng.randrange(4))]
    keys = ("".join(rng.choice("aAbBé_\U0001F600") for _ in range(rng.randrange(1, 4)))
            for _ in range(rng.randrange(4)))
    return {k: _random_value(rng, depth + 1) for k in keys}


# ---------------------------------------------------------------------------
# 1. test_sha256_constants_derived
# ---------------------------------------------------------------------------
def test_sha256_constants_derived():
    assert ind._K[0] == 0x428A2F98 and ind._K[63] == 0xC67178F2
    assert ind._H0[0] == 0x6A09E667 and ind._H0[7] == 0x5BE0CD19


# ---------------------------------------------------------------------------
# 2. test_sha256_known_vectors
# ---------------------------------------------------------------------------
def test_sha256_known_vectors():
    assert ind.sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert ind.sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert ind.sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") == \
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"


# ---------------------------------------------------------------------------
# 3. test_sha256_agreement
# ---------------------------------------------------------------------------
def test_sha256_agreement():
    rng = random.Random(SEED)
    for n in list(range(0, 130)) + [255, 256, 300]:
        data = bytes(rng.randrange(256) for _ in range(n))
        assert ind.sha256_hex(data) == envelope.sha256_hex(data)
        assert ind.sha256_digest(data) == envelope.sha256_digest(data)


# ---------------------------------------------------------------------------
# 4. test_canonical_fixed_corpus
# ---------------------------------------------------------------------------
FIXED_CORPUS = [
    {}, [], "", 0, -0.0, 1, 1.0, 1.5, 0.1, 1e16, 1e-7, 1e308, 5e-324, 2 ** 64,
    True, False, None,
    {"b": 2, "a": 1}, {"a": {"b": [1, 2]}},
    {"signature": None, "z": [None, True, False]},
    "quote\" backslash\\ slash/ ctrl\b\f\n\r\t\x00\x1f del\x7f",
    "é   中 \U0001F600 \U0010FFFF",
    {"é": 1, "e": 2, "E": 3, "\U0001F600": 4, "￿": 5},
    [[[[[]]]]], {"": ""},
]


@pytest.mark.parametrize("obj", FIXED_CORPUS, ids=lambda o: repr(o)[:40])
def test_canonical_fixed_corpus(obj):
    assert ind.canonicalise(obj) == envelope.canonicalise(obj)
    assert ind.canonical_bytes(obj) == envelope.canonical_bytes(obj)


# ---------------------------------------------------------------------------
# 5. test_canonical_random_corpus
# ---------------------------------------------------------------------------
def test_canonical_random_corpus():
    rng = random.Random(SEED)
    for _ in range(500):
        obj = _random_value(rng)
        assert ind.canonicalise(obj) == envelope.canonicalise(obj), repr(obj)


# ---------------------------------------------------------------------------
# 6. test_ed25519_rfc8032_vector
#    RFC 8032 §7.1 TEST 1 (empty message).
# ---------------------------------------------------------------------------
def test_ed25519_rfc8032_vector():
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert ind.ed25519_public_key(seed) == pub
    assert ind.ed25519_sign(seed, b"") == sig
    assert ind.ed25519_verify(pub, b"", sig) is True
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    assert envelope.sign_bytes(b"", sk) == sig


# ---------------------------------------------------------------------------
# 7. test_ed25519_agreement
# ---------------------------------------------------------------------------
def test_ed25519_agreement():
    rng = random.Random(SEED)
    for i in range(8):
        seed = bytes(rng.randrange(256) for _ in range(32))
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        assert ind.ed25519_public_key(seed) == _raw_pub(sk.public_key())
        for msg in [b"", b"x", envelope.canonical_bytes({"i": i, "signature": None}),
                    envelope.sha256_digest(bytes([i]))]:
            assert ind.ed25519_sign(seed, msg) == envelope.sign_bytes(msg, sk)


# ---------------------------------------------------------------------------
# 8. test_ed25519_cross_verify
# ---------------------------------------------------------------------------
def test_ed25519_cross_verify():
    rng = random.Random(SEED + 1)
    seed = bytes(rng.randrange(256) for _ in range(32))
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = ind.ed25519_public_key(seed)
    msg = envelope.canonical_bytes({"capsule": "x", "signature": None})
    assert envelope.verify_bytes(msg, ind.ed25519_sign(seed, msg), sk.public_key()) is True
    assert ind.ed25519_verify(pub, msg, envelope.sign_bytes(msg, sk)) is True


# ---------------------------------------------------------------------------
# 9. test_ed25519_independent_rejects
# ---------------------------------------------------------------------------
def test_ed25519_independent_rejects():
    seed = bytes(range(32))
    pub = ind.ed25519_public_key(seed)
    sig = ind.ed25519_sign(seed, b"original")
    assert ind.ed25519_verify(pub, b"tampered", sig) is False
    assert ind.ed25519_verify(pub, b"original", b"short") is False
    assert ind.ed25519_verify(b"\x00" * 31, b"original", sig) is False
    other = ind.ed25519_public_key(bytes(32))
    assert ind.ed25519_verify(other, b"original", sig) is False


# ---------------------------------------------------------------------------
# 10. test_did_key_known_vector
# ---------------------------------------------------------------------------
def test_did_key_known_vector():
    did = "did:key:z6MkgGoK1f2rh84pkWmFL3ew1CmMidaPxVFSvxsbUyxkKLZE"
    raw = ind.did_key_decode(did)
    assert len(raw) == 32
    assert ind.did_key_encode(raw) == did
    assert raw == _raw_pub(envelope.did_key_decode(did))


# ---------------------------------------------------------------------------
# 11. test_did_key_agreement
# ---------------------------------------------------------------------------
def test_did_key_agreement():
    rng = random.Random(SEED + 2)
    keys = [bytes(32), b"\xff" * 32] + [bytes(rng.randrange(256) for _ in range(32)) for _ in range(20)]
    for raw in keys:
        did = ind.did_key_encode(raw)
        assert did == envelope.did_key_encode(raw)
        assert did.startswith("did:key:z6Mk")
        assert ind.did_key_decode(did) == raw
        assert _raw_pub(envelope.did_key_decode(did)) == raw


# ---------------------------------------------------------------------------
# 12. test_did_key_independent_errors
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad", [
    "did:web:example.com",
    "did:key:f6Mkabc",
    "did:key:z0OIl",
    "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",  # secp256k1
    "did:key:z" + ind.base58btc_encode(bytes.fromhex("ed0141")),   # 1-byte key
    "did:key:z" + ind.base58btc_encode(b"\xed\x01" + bytes(33)),  # 33-byte key
    "did:key:z",
])
def test_did_key_independent_errors(bad):
    with pytest.raises(ValueError):
        ind.did_key_decode(bad)
    with pytest.raises(ValueError):
        envelope.did_key_decode(bad)


# ---------------------------------------------------------------------------
# 13. test_base58_leading_zeros
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("data", [b"", b"\x00", b"\x00\x00", b"\x00\x01", b"\x00\x00\xff", b"\x01\x00"])
def test_base58_leading_zeros(data):
    s = ind.base58btc_encode(data)
    assert s == envelope._base58btc_encode(data)
    assert ind.base58btc_decode(s) == data
    assert envelope._base58btc_decode(s) == data


# ---------------------------------------------------------------------------
# 14. test_divergence_pins
#     Pins envelope.py v1.0.0's behaviour where it diverges from SPEC
#     v1.1.0 (NOTES.md D1–D4). Not endorsements: v1 is frozen, so these
#     hold forever. Resolved in envelope_v2.py (see test 15).
# ---------------------------------------------------------------------------
def test_divergence_pins():
    sk = Ed25519PrivateKey.generate()
    sig = envelope.sign_bytes(b"x", sk)
    # D1: str data → False (SPEC §4.6 says TypeError)
    assert envelope.verify_bytes("x", sig, sk.public_key()) is False
    # D2: non-key public_key → AttributeError (SPEC §4.6 says TypeError)
    with pytest.raises(AttributeError):
        envelope.verify_bytes(b"x", sig, None)
    # D3: non-key, non-bytes input → AttributeError (SPEC §4.7 says TypeError)
    with pytest.raises(AttributeError):
        envelope.did_key_encode("abc")
    # D4: non-finite floats emit non-JSON tokens; independent rejects
    assert envelope.canonicalise(float("nan")) == "NaN"
    assert envelope.canonicalise(float("inf")) == "Infinity"
    with pytest.raises(ValueError):
        ind.canonicalise(float("nan"))


# ---------------------------------------------------------------------------
# 15. test_v2_agreement
#     envelope_v2 matches the independent implementation on the whole
#     canonical corpus, and both reject non-finite floats (resolves D4).
# ---------------------------------------------------------------------------
def test_v2_agreement():
    rng = random.Random(SEED)
    corpus = FIXED_CORPUS + [_random_value(rng) for _ in range(500)]
    for obj in corpus:
        assert envelope_v2.canonical_bytes(obj) == ind.canonical_bytes(obj), repr(obj)
    for bad in [float("nan"), float("inf"), float("-inf"), {"a": [float("nan")]}]:
        with pytest.raises(ValueError):
            envelope_v2.canonicalise(bad)
        with pytest.raises(ValueError):
            ind.canonicalise(bad)
    seed = bytes(range(32))
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    msg = envelope_v2.canonical_bytes({"signature": None, "v": 2})
    assert envelope_v2.sign_bytes(msg, sk) == ind.ed25519_sign(seed, msg)
    assert envelope_v2.did_key_encode(sk.public_key()) == ind.did_key_encode(ind.ed25519_public_key(seed))
