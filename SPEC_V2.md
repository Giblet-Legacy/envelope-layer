# SPEC V2 — envelope-layer (P1 Envelope, strict layer)

SPEC_V2.md — specification for envelope_v2.py, the layer above P1 v1.0.0.

Function:
    Specifies envelope_v2.py, a thin strict layer over the frozen P1
    v1.0.0 primitive (envelope.py). It closes the gap Q1 and the
    divergences D1–D3 recorded in NOTES.md, without editing
    envelope.py (Immutable Rule).

    SPEC.md v1.1.0 remains authoritative for everything this document
    does not change. Where this document is silent, SPEC.md v1.1.0
    applies unchanged.

Layer:     P1 — Envelope, v2 (strict)
Depends:   envelope.py (P1 v1.0.0)
Consumed:  P2 Sign onward — new code imports envelope_v2, not envelope
Version:   SPEC V2 2.0.0
Licence:   MSL-1.0
Author:    James Gilbert (Giblets Forge)

---

## 1. Compatibility guarantee

For every input that P1 v1.0.0 accepts and that is inside the
SPEC.md v1.1.0 contract, envelope_v2 returns byte-identical output.
In particular:

- canonicalise / canonical_bytes produce the same bytes for every
  finite JSON value.
- sign_bytes produces the same 64 bytes for the same data and key.
- verify_bytes returns the same bool for every bytes-like data,
  bytes-like signature and Ed25519PublicKey.
- did_key_encode / did_key_decode produce the same strings and keys.

Therefore every artefact signed through v1 verifies through v2.

v2 differs from v1 only by **raising** on inputs that v1 accepted
outside the contract. That narrowing is why the major version is 2.

## 2. Changes from SPEC.md v1.1.0

### 2.1 Non-finite floats (resolves NOTES Q1 / D4)

canonicalise and canonical_bytes raise ValueError if obj contains
NaN, Infinity or -Infinity at any depth. These are not JSON and have
no canonical form. v1 emitted the tokens `NaN`, `Infinity`,
`-Infinity`.

Strings whose text is "NaN" or "Infinity" are ordinary JSON strings
and are unaffected.

### 2.2 verify_bytes type checks (resolves D1, D2)

verify_bytes(data, signature, public_key) raises TypeError when:

- data is not bytes-like (bytes, bytearray, memoryview), or
- signature is not bytes-like, or
- public_key is not an Ed25519PublicKey.

These checks run before verification. This is the behaviour SPEC.md
§4.6 already specified. All other failure modes are unchanged: a
wrong-length or invalid signature returns False.

### 2.3 sign_bytes type checks (SPEC.md §3, §4.5)

sign_bytes(data, private_key) raises TypeError when data is not
bytes-like or private_key is not an Ed25519PrivateKey. v1 happened to
raise for most of these. v2 makes the rule explicit and the exception
class certain.

### 2.4 did_key_encode type check (resolves D3)

did_key_encode(public_key) raises TypeError unless public_key is an
Ed25519PublicKey, bytes or bytearray. A 32-byte length check still
raises ValueError, as in SPEC.md §4.7.

### 2.5 Unchanged

sha256_hex, sha256_digest and did_key_decode already conform to
SPEC.md v1.1.0. v2 re-exports them from v1 unchanged.

## 3. Construction rule

envelope_v2 delegates to envelope.py for every byte it produces. It
never reimplements a primitive:

- canonicalise calls envelope.canonicalise, then rejects the result
  if it contains a non-finite constant (detected by parsing the
  output with json.loads and a parse_constant hook). The returned
  string is v1's string, untouched.
- sign_bytes, verify_bytes and did_key_encode type-check, then call
  their v1 counterparts.

This keeps the §1 compatibility guarantee true by construction rather
than by testing alone.

## 4. Public API

Same eight names as P1 v1.0.0, same numbering:

1. canonicalise    — v2: rejects non-finite floats
2. canonical_bytes — v2: built on v2 canonicalise
3. sha256_hex      — re-exported from v1
4. sha256_digest   — re-exported from v1
5. sign_bytes      — v2: type checks, then v1
6. verify_bytes    — v2: type checks, then v1
7. did_key_encode  — v2: type check, then v1
8. did_key_decode  — re-exported from v1

## 5. Test plan (test_envelope_v2.py)

- Byte identity with v1 on a corpus of finite JSON values.
- NaN, Infinity, -Infinity rejected at top level, inside lists and
  inside dict values. Strings "NaN" / "Infinity" accepted.
- Old signatures verify: v1-signed data verifies under v2, and the
  reverse.
- verify_bytes: str data, str signature, None key, private key in
  place of public key → TypeError. Short signature and tampered data
  → False.
- sign_bytes: str data, non-Ed25519 key → TypeError. Output identical
  to v1.
- did_key_encode: str, None → TypeError. 31 bytes → ValueError. Output
  identical to v1 for key objects and raw bytes.
- did_key_decode: same results and errors as v1.
- Public API: the eight names exist and are callable.

Cross-implementation (independent/test_cross.py): v2 and
independent/p1_independent.py agree on the full canonical corpus and
both reject non-finite floats.

## 6. Known Limitations

All SPEC.md v1.1.0 §6 limitations still apply, including numeric type
sensitivity (1 vs 1.0). v2 adds one cost: canonicalise parses its own
output once, which roughly doubles its runtime. P1 inputs are small
capsule and ledger records, so this is accepted.

---

## Document control

- **SPEC V2 2.0.0** — initial version, frozen at sign-off.
- Decided 2026-11-11. James answered Q1 ("reject") and delegated
  Q2/Q3 to the VS Code AI ("please decide and finish"). See NOTES.md.
- Changes require a new SPEC version and a new layer above
  envelope_v2.py. envelope_v2.py is never edited after freeze.
