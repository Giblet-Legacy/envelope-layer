# envelope-layer — P1 Envelope

README.md — repository purpose and layer contract for P1 Envelope.

Function:
    This repository implements primitive layer P1 of the Forge Stack:
    canonicalisation, SHA-256, and Ed25519 sign/verify. It is the
    bottom-most layer. Every layer above it depends on P1 and none
    depends below it. It is frozen at v1 before P2 begins.

Layer:    P1 — Envelope
Depends:  (nothing — this is the base primitive)
Consumed: P2 Sign, P3 Freeze, P4 Ledger, P5 Genesis, P6 Canon Verify,
          P7 Record, and — transitively — every layer above.
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
Status:   0.0.0-dev (in build, pre-freeze)

## What this layer is responsible for

- Canonical JSON serialisation, byte-for-byte reproducible:
  `json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True)`
- SHA-256 digesting of canonical bytes.
- Ed25519 signing over raw UTF-8 canonical bytes (no pre-hash), with the
  signature object's value set to null in the payload being signed.
- Ed25519 verification of the same.

## What this layer is explicitly NOT responsible for

- Ledger hash-chaining (P4).
- Signing over a SHA-256 digest for ledger entries — that is P4's rule,
  not P1's.
- Detached `.sig` sidecars for non-JSON artefacts (P2).
- Anything above P1.

## Functions in this file

(none — this is a Markdown document, not code)

See `envelope.py` (forthcoming) for the numbered function list of the layer
implementation, which will be added when the P1 section spec is written and
signed off.

## CHANGELOG

See CHANGELOG.md — Good / Bad / Ugly, latest at top.

## Verifying this repository

P1 is frozen at v1.0.0. To verify:

1. Run the test suite:
   `pytest -q test_envelope.py` (expect 27 passed)
2. Run the independent spec check:
   `python3 verify_spec.py` (expect OK)

Independent reimplementation of P1 from the spec — not self-verification —
is the acceptance test.
