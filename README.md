# envelope-layer — P1 Envelope

README.md — repository purpose and layer contract for P1 Envelope.

Function:
    This repository implements primitive layer P1 of the Forge Stack:
    canonical JSON, SHA-256, Ed25519 sign/verify, and did:key
    encoding/decoding for Ed25519 public keys. It is the bottom-most
    layer. Every layer above it depends on P1 and none depends below
    it. It is frozen at v1.0.0.

Layer:    P1 — Envelope
Depends:  (nothing — this is the base primitive)
Consumed: P2 Sign, P3 Freeze, P4 Ledger, P5 Genesis, P6 Canon Verify,
          P7 Record, and — transitively — every layer above.
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
Status:   1.0.0 — frozen. envelope.py is never edited (Immutable Rule).
Spec:     SPEC.md v1.1.0

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
| `envelope.py` | P1 v1.0.0 implementation — frozen, never edited |
| `SPEC.md` | Authoritative spec (v1.1.0). The spec wins over the code |
| `test_envelope.py` | SPEC §8.1–§8.3b tests (29) |
| `independent/p1_independent.py` | SPEC §8.4 independent reimplementation — never imports envelope |
| `independent/test_cross.py` | Cross-implementation agreement tests (49) |
| `verify_spec.py` | Original freeze-time base58btc check |
| `NOTES.md` | Decisions, open questions, known divergences (D1–D4) |
| `CHANGELOG.md` | Good / Bad / Ugly, latest at top |
| `VERSION` | Layer version; advances only on freeze |
| `requirements.txt` | `cryptography` — the only runtime dependency |

## Verifying this repository

From the repository root (`python3` on Termux, `python` on Windows):

1. `python -m pytest -q test_envelope.py` — expect 29 passed
2. `python -m pytest -q independent/` — expect 49 passed
3. `python verify_spec.py` — expect `OK`

Independent reimplementation of P1 from the spec — not
self-verification — is the acceptance test (SPEC §7).

## Known divergences

envelope.py v1.0.0 disagrees with SPEC v1.1.0 on four edge cases
(wrong exception types and non-finite floats). None affects a valid
signature or did:key. See NOTES.md D1–D4. They are pinned by
`independent/test_cross.py::test_divergence_pins` and will be resolved,
if at all, by a new layer above P1 — never by editing envelope.py.

## CHANGELOG

See CHANGELOG.md — Good / Bad / Ugly, latest at top.
