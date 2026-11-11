# envelope-layer — P1 Envelope

README.md — repository purpose and layer contract for P1 Envelope.

Function:
    This repository implements primitive layer P1 of the Forge Stack:
    canonical JSON, SHA-256, Ed25519 sign/verify, and did:key
    encoding/decoding for Ed25519 public keys. It is the bottom-most
    layer. Every layer above it depends on P1 and none depends below
    it. envelope.py is frozen at v1.0.0; envelope_v2.py is the strict
    layer above it, frozen at v2.0.0. New code imports envelope_v2.

Layer:    P1 — Envelope
Depends:  (nothing — this is the base primitive)
Consumed: P2 Sign, P3 Freeze, P4 Ledger, P5 Genesis, P6 Canon Verify,
          P7 Record, and — transitively — every layer above.
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
Status:   2.0.0 — envelope.py v1.0.0 and envelope_v2.py v2.0.0 both
          frozen. Neither is ever edited (Immutable Rule).
Spec:     SPEC.md v1.1.0 (v1), SPEC_V2.md 2.0.0 (v2)

## Which module to import

`import envelope_v2`. It returns exactly the same bytes as envelope.py
for every valid input, so v1-signed artefacts still verify, but it
raises on bad input instead of misbehaving:

- NaN / Infinity in canonicalise → ValueError (v1 emitted non-JSON)
- non-bytes data or signature, or a non-Ed25519 key → TypeError
  (v1 returned False or raised AttributeError)

## What this layer is responsible for

- Canonical JSON serialisation, byte-for-byte reproducible:
  `json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True)`
  (not RFC 8785 / JCS).
- SHA-256 over arbitrary bytes, as hex or raw 32-byte digest.
- Ed25519 signing and verification over arbitrary bytes, no pre-hash.
- did:key encode/decode for Ed25519 public keys (`did:key:z6Mk...`),
  using an internal, hand-rolled base58btc.

P1 does not decide *what* gets signed. It signs whatever bytes it is
given. The two signing rules live above it:

- Capsule rule (P2): sign the raw canonical bytes of the capsule with
  `"signature": null`.
- Ledger rule (P4): SHA-256 the canonical unsigned entry, sign the raw
  32-byte digest.

## What this layer is explicitly NOT responsible for

- The capsule-signing rule and detached `.sig` sidecars (P2).
- Ledger assembly, hash-chaining and digest signing (P4).
- Key generation, key storage, passphrases (setup / P7).
- File I/O, network, environment, clock, logging — none, ever.

## Files

| File | Purpose |
| --- | --- |
| `envelope_v2.py` | P1 v2.0.0 strict layer — import this. Frozen |
| `envelope.py` | P1 v1.0.0 primitive — frozen, never edited |
| `SPEC_V2.md` | Spec for envelope_v2 (changes over SPEC.md only) |
| `SPEC.md` | Authoritative spec (v1.1.0). The spec wins over the code |
| `test_envelope_v2.py` | SPEC_V2 §5 tests (34) |
| `test_envelope.py` | SPEC §8.1–§8.3b tests (29) |
| `independent/p1_independent.py` | SPEC §8.4 independent reimplementation — never imports envelope |
| `independent/test_cross.py` | Cross-implementation agreement tests (50) |
| `verify_spec.py` | Original freeze-time base58btc check |
| `NOTES.md` | Decisions, open questions, known divergences (D1–D4) |
| `CHANGELOG.md` | Good / Bad / Ugly, latest at top |
| `VERSION` | Layer version; advances only on freeze |
| `requirements.txt` | `cryptography` — the only runtime dependency |

## Verifying this repository

From the repository root (`python3` on Termux, `python` on Windows):

1. `python -m pytest -q test_envelope.py test_envelope_v2.py independent/`
   — expect 113 passed (29 + 34 + 50)
2. `python verify_spec.py` — expect `OK`

Independent reimplementation of P1 from the spec — not
self-verification — is the acceptance test (SPEC §7).

## Known divergences

envelope.py v1.0.0 disagrees with SPEC v1.1.0 on four edge cases
(wrong exception types and non-finite floats). None affects a valid
signature or did:key. See NOTES.md D1–D4. All four are resolved in
envelope_v2.py. They stay pinned against envelope.py by
`independent/test_cross.py::test_divergence_pins`, because v1 is
frozen and will never change.

## CHANGELOG

See CHANGELOG.md — Good / Bad / Ugly, latest at top.
