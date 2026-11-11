"""
verify_spec.py — Minimal base58btc spec check (SPEC §9a conformance anchor)

Function:
    The original freeze-time check for P1 v1.0.0. Decodes the SPEC §9
    known did:key vector with a base58btc decoder written without
    importing envelope.py, confirms the 0xed 0x01 multicodec prefix
    and 34-byte length, and re-encodes to prove round-trip.

    Scope is deliberately narrow: base58btc only, one vector, no
    leading-zero handling (the vector has none). Kept as freeze-time
    evidence. The full SPEC §8.4 independent implementation —
    canonicalisation, SHA-256, Ed25519 and did:key — lives in
    independent/ and is run by independent/test_cross.py.

Functions in this file:
    1. b58encode — bytes → base58btc (no leading-zero handling)
    2. b58decode — base58btc → bytes (no leading-zero handling)

Layer:    P1 — Envelope (verification, not consumed)
Spec:     SPEC.md v1.1.0
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


# ---------------------------------------------------------------------------
# 1. b58encode
#    Big-endian integer → base58btc digits. Leading zero bytes are not
#    handled; the SPEC §9 vector starts with 0xed, so none occur.
# ---------------------------------------------------------------------------
def b58encode(data):
    n = int.from_bytes(data, "big")
    res = ""
    while n > 0:
        n, digit = divmod(n, 58)
        res = ALPHABET[digit] + res
    return res


# ---------------------------------------------------------------------------
# 2. b58decode
#    base58btc digits → minimum-length big-endian bytes. Raises
#    ValueError (via str.index) on a character outside the alphabet.
# ---------------------------------------------------------------------------
def b58decode(s):
    n = 0
    for char in s:
        n = n * 58 + ALPHABET.index(char)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


# The known vector from SPEC §9 (multibase 'z' already stripped).
target = "6MkgGoK1f2rh84pkWmFL3ew1CmMidaPxVFSvxsbUyxkKLZE"

decoded_bytes = b58decode(target)
assert decoded_bytes.startswith(b"\xed\x01"), "Multicodec prefix mismatch"
assert len(decoded_bytes) == 34, "Length mismatch"

re_encoded = b58encode(decoded_bytes)
assert re_encoded == target, f"Roundtrip failed: {re_encoded} != {target}"

print(f"OK: Independent base58btc verification passed for did:key:z{target}")
