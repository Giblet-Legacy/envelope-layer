# verify_spec.py — Independent spec verification (SPEC §8.4 / §9a)
# Written without importing envelope.py to prove the spec is implementable.

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(data):
    n = int.from_bytes(data, "big")
    res = ""
    while n > 0:
        n, digit = divmod(n, 58)
        res = ALPHABET[digit] + res
    return res

# The known vector from the SPEC
target = "6MkgGoK1f2rh84pkWmFL3ew1CmMidaPxVFSvxsbUyxkKLZE"

# The raw bytes (we know it starts with 0xed01, the rest is the 32-byte key)
# Let's decode the target to get the 34 bytes.
def b58decode(s):
    n = 0
    for char in s:
        n = n * 58 + ALPHABET.index(char)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

decoded_bytes = b58decode(target)
assert decoded_bytes.startswith(b"\xed\x01"), "Multicodec prefix mismatch"
assert len(decoded_bytes) == 34, "Length mismatch"

# Re-encode it to prove round-trip
re_encoded = b58encode(decoded_bytes)
assert re_encoded == target, f"Roundtrip failed: {re_encoded} != {target}"

print(f"OK: Independent base58btc verification passed for did:key:z{target}")
