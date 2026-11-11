# SPEC — envelope-layer (P1 Envelope)

SPEC.md — the complete layer specification for P1 Envelope.

Function:
    This document is the authoritative specification for primitive
    layer P1 of the Forge Stack. Implementation (envelope.py) is
    written to this spec. Tests (test_envelope.py) are written to
    this spec. Independent reimplementation for verification is
    written from this spec, without reference to the implementation.

    The spec wins over the implementation. If envelope.py and this
    document disagree, the implementation is wrong.

    SPEC v1.0.0 is frozen at sign-off. Changes require a new SPEC
    version. Per the Immutable Rule, a new SPEC version does not
    retroactively rewrite a signed-off implementation — it describes
    the next version of the layer, above the current one.

Layer:     P1 — Envelope
Depends:   (nothing — base primitive)
Consumed:  P2 Sign, P3 Freeze, P4 Ledger, P5 Genesis, P6 Canon Verify,
           P7 Record
Version:   SPEC 1.0.0
Licence:   MSL-1.0
Author:    James Gilbert (Giblets Forge)

---

## Top header — what P1 is

P1 is the byte-level cryptographic foundation of the Forge Stack.
It provides canonical JSON serialisation, SHA-256 hashing, Ed25519
signing/verification, and did:key encoding/decoding for Ed25519
public keys, and nothing else.

P1 does not decide what gets hashed or signed — that decision
belongs to the calling layer, and it differs between capsules and
ledger entries. P1 exposes primitives that make both rules
expressible without knowing either.

P1 does not touch the filesystem, network, environment, clock, or
key storage. did:key is self-resolving: the key IS the identifier,
and P1 performs no lookup. P1 is pure function: input in, output
out.

## Functions in this file (planned)

1. canonicalise    — canonical JSON string from Python object
2. canonical_bytes — canonical UTF-8 bytes from Python object
3. sha256_hex      — SHA-256 hex digest of bytes
4. sha256_digest   — SHA-256 raw 32-byte digest of bytes
5. sign_bytes      — Ed25519 signature over arbitrary bytes
6. verify_bytes    — verify Ed25519 signature over arbitrary bytes
7. did_key_encode  — Ed25519 public key → did:key string
8. did_key_decode  — did:key string → Ed25519 public key

---

## 1. Canonicalisation

Every JSON object in the Forge Stack is canonicalised to a specific
byte form before hashing or signing. The form is defined by exactly
this Python call:

    json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

Each parameter is load-bearing:

- sort_keys=True — object keys are emitted in Unicode code-point
  order. Two implementations receiving the same dict in different
  insertion orders must produce identical bytes.
- separators=(',', ':') — no whitespace between elements or pairs.
  Eliminates formatting ambiguity and reduces byte count.
- ensure_ascii=True — all non-ASCII characters are escaped as
  \uXXXX (surrogate pairs above U+FFFF). Output is pure ASCII
  regardless of locale, terminal, or filesystem encoding.

This is not RFC 8785 / JCS. Implementations must reproduce this
byte form exactly. JCS and this form diverge on edge cases (notably
non-ASCII handling and number formatting). Signature verification
depends on byte-level identity.

Canonicalisation is a pure function: same input → same output,
always. No locale, environment, timezone, or interpreter state may
affect it.

What canonicalisation does not do:

- Does not validate that obj is JSON-serialisable. Callers must
  pass dict/list/str/int/float/bool/None, or JSON-serialisable
  nested structures.
- Does not strip or add fields. If obj has "signature", it appears
  in output. Per the capsule rule, the caller (P2) must pass a
  copy with "signature": null.
- Does not sort list elements. Only object keys are sorted.
- Does not normalise numbers beyond Python's default float repr.
  1.0 and 1 produce different bytes ("1.0" vs "1"). Callers must
  pass canonical-typed input.

---

## 2. SHA-256

P1 provides SHA-256 as a pure primitive over arbitrary bytes. It
does not decide what bytes get hashed — that decision belongs to
the calling layer.

Two forms are exposed:

- sha256_hex(data) — 64-character lowercase hex digest. Used where
  human-readable or storage-friendly form is needed: capsule
  hash-pins, .jsonl chain prev/hash, document_sha256 in
  P3-frozen artefacts.
- sha256_digest(data) — raw 32-byte digest. Used where the digest
  bytes themselves are signed: P4's ledger entry signatures,
  which sign the raw digest rather than canonical entry bytes.

sha256_hex(data) is exactly hashlib.sha256(data).hexdigest().
sha256_digest(data) is exactly hashlib.sha256(data).digest().
No salt, no iteration count, no domain-separation prefix. Raw
SHA-256.

---

## 3. Ed25519 sign/verify

P1 provides Ed25519 signing and verification as pure primitives
over arbitrary bytes. It does not decide what bytes get signed —
that decision belongs to the calling layer, and it differs between
capsules and ledger entries.

Two signing rules coexist in the Forge Stack. Confusing them is a
hard failure.

Capsule rule (P2). Payload is the capsule dict with
"signature": null. Payload is canonicalised (Section 1). Ed25519
signature is over the raw UTF-8 canonical bytes. No pre-hash, no
digest intermediate. Ed25519's own internal hashing (SHA-512) is
inherent and not what "no pre-hash" refers to — "no pre-hash"
means we do not apply our own SHA-256 between canonicalisation and
signing.

Ledger rule (P4). Canonical unsigned entry (seq, prev, record,
signer — hash and signature excluded) is hashed with SHA-256, and
Ed25519 signature is over the raw 32-byte digest. The chain hash
field stores the hex form of the same digest.

P1 exposes both paths via sign_bytes(data, private_key), which
signs whatever bytes it receives. P2 calls it with canonical
capsule bytes. P4 calls it with the raw 32-byte digest. The
divergence lives in the calling layer, not in P1.

Why this split is intentional. If P1 absorbed the capsule rule as
default, P4 would have to work around it to sign digests. If P1
absorbed the ledger rule, P2 would have to work around it to sign
canonical bytes. By keeping P1 primitive, both rules are
expressible without P1 knowing either.

Failure posture:

- sign_bytes with a non-Ed25519 key must raise, not silently
  produce a wrong-length signature.
- verify_bytes with wrong-length signature must return False, not
  raise. Verification is a boolean operation; malformed input is a
  False result, not an exception.
- verify_bytes with malformed public key must return False.
- No function in P1 ever logs, prints, caches, or persists key
  material.

---

## 4. Function contracts

### 4.1 canonicalise(obj) -> str

Input: any Python object serialisable by json — dict, list, str,
int, float, bool, None, nested.

Output: str in exact canonical form defined in Section 1.

Invariants:
- Deterministic: canonicalise(x) == canonicalise(x).
- canonicalise(x) == canonicalise(y) iff x and y are equal as JSON
  values, modulo key insertion order.
- Pure ASCII output (ensure_ascii=True).
- No whitespace between tokens.

Failure modes: TypeError for non-serialisable values, ValueError
for circular references or float overflow. Not caught — caller
supplies valid input.

### 4.2 canonical_bytes(obj) -> bytes

Input: same as canonicalise.

Output: canonicalise(obj).encode('utf-8'). Because ensure_ascii=True
guarantees ASCII, UTF-8 encoding is pure ASCII bytes. Exists so
callers don't have to remember encoding — encoding is part of the
contract.

Invariants: every byte in 0x00–0x7F.

### 4.3 sha256_hex(data: bytes) -> str

Input: arbitrary bytes.

Output: 64-char lowercase hex string of
hashlib.sha256(data).hexdigest().

Invariants: length 64, matches [0-9a-f]{64}, pure function.

Failure modes: TypeError if data is not bytes-like. P1 does not
accept str; callers with a string must encode first (usually via
canonical_bytes).

### 4.4 sha256_digest(data: bytes) -> bytes

Input: arbitrary bytes.

Output: exactly 32 bytes of hashlib.sha256(data).digest().

Invariants: length 32.
sha256_digest(x).hex() == sha256_hex(x) for all x.

---

### 4.5 sign_bytes(data: bytes, private_key: Ed25519PrivateKey) -> bytes

Input:
- data — arbitrary bytes. Capsule path: canonical bytes with
  "signature": null. Ledger path: 32-byte SHA-256 digest.
- private_key — Ed25519 private key object. P1 accepts the key
  object; did:key string handling and passphrase-protected key
  loading belong to P2 and P7 respectively.

Output: exactly 64 bytes of Ed25519 signature over data.

Invariants: deterministic for same data and key (Ed25519 is
deterministic given same message and key). Output length 64. No
pre-hash — P1 does not apply SHA-256, SHA-512, or any other hash
to data before invoking Ed25519.

Failure modes: TypeError for wrong types, ValueError for invalid
Ed25519 key.

### 4.6 verify_bytes(data: bytes, signature: bytes, public_key: Ed25519PublicKey) -> bool

Input:
- data — arbitrary bytes, same bytes that were signed.
- signature — 64-byte Ed25519 signature.
- public_key — Ed25519 public key object.

Output: True if signature valid for data under public_key, else
False.

Invariants:
verify_bytes(data, sign_bytes(data, sk), pk) == True for any valid
keypair and any data. Deterministic.

Failure modes: wrong-length signature → False. Malformed public
key → False. Invalid signature value → False. TypeError only if
data/signature not bytes-like or public_key not an Ed25519 key
object.

The bool-return posture is deliberate: verification is a policy
question for the caller. P1 does not raise on invalid signatures;
it returns False and lets the caller decide.

### 4.7 did_key_encode(public_key) -> str

Input: Ed25519 public key object (32 raw bytes, or a wrapper
exposing them).

Output: str of the form did:key:z6Mk..., conforming to the
multibase + multicodec did:key spec for Ed25519:

1. Take the 32-byte Ed25519 public key.
2. Prefix with multicodec varint for ed25519-pub = 0xed 0x01
   (two bytes).
3. Base58btc-encode the resulting 34 bytes.
4. Prefix the encoded string with z (base58btc multibase prefix).
5. Prefix with did:key:.

Invariants:
- Output always starts with did:key:z6Mk for any valid Ed25519
  public key. The z6Mk prefix is the direct consequence of
  0xed 0x01 multicodec + base58btc; it is a fixed prefix, not a
  coincidence.
- Deterministic: same public key → same did:key string.
- Round-trip: did_key_decode(did_key_encode(pk)) == pk for all
  valid Ed25519 public keys.

Failure modes: TypeError if public_key is not an Ed25519 public key
object or raw 32 bytes. ValueError if the raw key is not exactly
32 bytes.

What P1 does not do here:
- Does not generate or store the keypair. Key generation remains
  outside P1.
- Does not resolve did:key over a network. did:key is
  self-resolving by construction — the key is the identifier. No
  lookup, no registry.

### 4.8 did_key_decode(did: str) -> Ed25519PublicKey

Input: str in the form did:key:z....

Output: Ed25519 public key object (32 raw bytes).

Process (inverse of 4.7):
1. Strip did:key: prefix.
2. Strip z multibase prefix.
3. Base58btc-decode to bytes.
4. Strip the 2-byte 0xed 0x01 multicodec prefix.
5. Remaining bytes must be exactly 32 — the raw Ed25519 public key.

Invariants: did_key_encode(did_key_decode(s)) == s for any
well-formed did:key:z6Mk... string with a valid Ed25519 key.

Failure modes: all return a raised exception, not False, because
a malformed did:key is a policy error, not a verification result:
- ValueError if did does not start with did:key:.
- ValueError if the multibase prefix is not z.
- ValueError if base58btc decoding fails.
- ValueError if the multicodec prefix is not 0xed 0x01 (i.e. not
  Ed25519).
- ValueError if the remaining key bytes are not exactly 32.

Why exceptions and not False: verify_bytes returning False is a
verification outcome — the caller asked "is this signature valid?"
and the answer was no. did_key_decode is not asking a question; it
is being handed a string and asked to produce a key. If the string
is malformed, the caller has a bug or is being fed malformed data.
Silent False/None would mask that. P1 raises.

---

## 5. Proposed file header for envelope.py

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

    Functions in this file:
        1. canonicalise    — canonical JSON string from Python object
        2. canonical_bytes — canonical UTF-8 bytes from Python object
        3. sha256_hex      — SHA-256 hex digest of bytes
        4. sha256_digest   — SHA-256 raw 32-byte digest of bytes
        5. sign_bytes      — Ed25519 signature over arbitrary bytes
        6. verify_bytes    — verify Ed25519 signature over arbitrary bytes
        7. did_key_encode  — Ed25519 public key → did:key string
        8. did_key_decode  — did:key string → Ed25519 public key

    Layer:    P1 — Envelope
    Depends:  (nothing — base primitive)
    Consumed: P2 Sign, P3 Freeze, P4 Ledger, P5 Genesis, P6 Canon Verify,
              P7 Record
    Version:  1.0.0 (on freeze; 0.0.0-dev until then)
    Licence:  MSL-1.0
    Author:   James Gilbert (Giblets Forge)
    """

Each of the eight functions below the header carries its own
numbered header (# 1. canonicalise, # 2. canonical_bytes, etc.),
matching the list above.

---

## 6. Known Limitations

- No key generation. P1 does not provide generate_keypair().
  Tests and setup scripts generate Ed25519 keys via the underlying
  crypto library. Key generation is a setup concern, not a
  byte-level primitive.

- did:key is Ed25519-only. did_key_encode / did_key_decode handle
  Ed25519 public keys exclusively, per the 0xed 0x01 multicodec.
  Other did:key key types (secp256k1, X25519, etc.) are not
  supported and will raise on decode. This matches the Forge
  Stack's single-curve choice.

- No passphrase handling. Passphrase-protected key loading is P7's
  responsibility. P1 accepts an already-unlocked key object.

- No .sig sidecar handling. Detached .sig sidecars for non-JSON
  artefacts are P2's. P1 provides sha256_hex and sign_bytes; P2
  combines them.

- No ledger entry assembly. P1 does not construct, hash, sign, or
  verify ledger entries. It provides primitives P4 needs. The
  ledger rule is P4's to implement and P6's to independently
  reimplement.

- No file I/O. P1 reads no files, writes no files, accesses no
  environment variables. Pure functions only — a deliberate
  constraint so verification is trivially auditable.

- No logging. Not even on failure. Callers decide what to record.

- No JCS. Canonicalisation is the specific json.dumps form defined
  in Section 1, not RFC 8785 / JCS. JCS-conformant implementations
  diverge on some inputs.

- Number type sensitivity. 1 and 1.0 produce different bytes.
  Callers must pass canonical-typed input. Accepted as a
  limitation; no numeric normalisation is applied.

---

## 7. What P1 v1 does not prove

- P1's own tests do not prove P1 is correct. Test-suite passing
  is necessary, not sufficient. Acceptance is independent
  reimplementation: separate code, written from this spec, must
  produce byte-identical canonical JSON, SHA-256 hex, SHA-256
  digest, must verify every signature P1 produces, and must
  produce identical did:key strings for identical Ed25519 public
  keys. Until independent implementation agrees, P1 is not frozen.

- P1 v1 does not prove the capsule-signing rule. Lives in P2.

- P1 v1 does not prove the ledger-signing rule. Lives in P4.

- P1 v1 does not prove chain integrity. Lives in P4, independently
  verified by P6.

- P1 v1 does not validate that its canonicalisation is the
  canonicalisation. Tests could pass against a wrong
  implementation if written against the same wrong form. Only
  cross-implementation testing closes this gap.

---

## 8. Test plan

Tests go in test_envelope.py, plain pytest style. Written after
this spec is signed off, before envelope.py is implemented.

### 8.1 Canonicalisation

- Round-trip: json.loads(canonicalise(x)) == x (JSON-normal
  equality).
- Key sorting: two dicts with same key-value pairs, different
  insertion order, canonicalise to identical bytes.
- No whitespace: canonicalise({"a": 1}) == '{"a":1}'.
- ASCII-only: all(ord(c) < 128 for c in canonicalise(x)) for
  non-ASCII inputs.
- Unicode escape: canonicalise({"a": "é"}) == '{"a":"\\u00e9"}'.
- Empty structures: canonicalise({}) == "{}", canonicalise([]) ==
  "[]".
- Nested: canonicalise({"a": {"b": [1, 2]}}) matches expected form.
- Numbers: 1 → 1, 1.0 → 1.0, 1.5 → 1.5.
- None / True / False render as null / true / false.

### 8.2 SHA-256

- Known-vector:
  sha256_hex(b"") ==
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".
- Known-vector:
  sha256_hex(b"abc") ==
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".
- Length: len(sha256_digest(b"anything")) == 32.
- Consistency: sha256_digest(x).hex() == sha256_hex(x).

### 8.3 Ed25519

- Round-trip: verify_bytes(data, sign_bytes(data, sk), pk) == True
  for multiple data sizes (empty, 1 byte, 1 KB, canonical JSON).
- Wrong data: verify_bytes(b"tampered",
  sign_bytes(b"original", sk), pk) == False.
- Wrong key: verify_bytes(data, sign_bytes(data, sk1), pk2) ==
  False.
- Length: len(sign_bytes(data, sk)) == 64.
- Determinism: sign_bytes(data, sk) == sign_bytes(data, sk).
- Malformed sig: verify_bytes(data, b"short", pk) == False, not
  exception.

### 8.3b did:key

- Round-trip: did_key_decode(did_key_encode(pk)) == pk for
  multiple generated Ed25519 public keys.
- Fixed prefix: did_key_encode(pk).startswith("did:key:z6Mk") for
  any valid Ed25519 pk.
- Format: did_key_encode(pk) matches
  ^did:key:z[1-9A-HJ-NP-Za-km-z]+$ (base58btc alphabet — no 0, O,
  I, l).
- Known-vector: the fixed did:key from the v1.2.1 doc —
  did:key:z6MkgGoK1f2rh84pkWmFL3ew1CmMidaPxVFSvxsbUyxkKLZE —
  decodes and re-encodes to itself.
- Wrong prefix: did_key_decode("did:web:example.com") raises
  ValueError.
- Wrong multibase: did_key_decode("did:key:f6Mk...") (base16
  multibase) raises ValueError.
- Wrong key type: a secp256k1 did:key string raises ValueError.
- Wrong length: base58btc string that decodes to fewer or more
  than 32+2 bytes raises ValueError.

### 8.4 Independent implementation

At least one independent implementation of canonicalisation,
SHA-256, Ed25519, and did:key encode/decode will be run against
the same test vectors and must produce identical results. Lives in
a separate directory or repo so it does not share code with
envelope.py. For v1, may be a second Python script written from
this spec without reference to envelope.py. Second-language
implementation strengthens proof; not required for v1 freeze.

### 8.5 Not covered by these tests

Key generation, passphrases, .sig sidecars, ledger assembly — all
out of scope. Network/filesystem/environment — P1 does none and
tests must not require them.

---

## 9. did:key encoding rule (reference)

For implementers and for the independent reimplementation to
check against:

    Ed25519 public key (32 raw bytes)
            |
            +-- prefix with multicodec varint 0xed 0x01 (2 bytes)
            |       total: 34 bytes
            |
            +-- base58btc encode
            |
            +-- prefix with multibase indicator 'z'
            |
            +-- prefix with 'did:key:'
                    |
                    +--> did:key:z6Mk...

Decode is the exact inverse, with each step validated and raising
ValueError on failure.

The z6Mk prefix is invariant for any Ed25519 did:key, and appears
in the v1.2.1 doc's example
did:key:z6MkgGoK1f2rh84pkWmFL3ew1CmMidaPxVFSvxsbUyxkKLZE — a
useful conformance anchor.

Base58btc alphabet:
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz —
Bitcoin alphabet, excludes 0, O, I, l. Implementation must not
confuse this with base58-flickr or other variants.

---

## Document control

- This spec is SPEC v1.0.0, frozen at sign-off.
- Implementation of envelope.py v1.0.0 must match this spec.
- Tests in test_envelope.py must match this spec.
- Independent implementation for verification must be written from
  this spec, without reference to envelope.py.
- Changes require a new SPEC version. SPEC v1.1.0 would describe
  changes above P1 v1.0.0, per the Immutable Rule.
