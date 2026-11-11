# CHANGELOG — envelope-layer (P1 Envelope)

CHANGELOG.md — build history for P1 Envelope, latest entry at top.

Function:
    Records the Good / Bad / Ugly of every build step for this layer.
    Updated at every sign-off. Kept current without exception. Format
    never changes shape, even when a section is empty.

## [Unreleased]

### Good

- Laptop review (2026-11-11): 27/27 v1.0.0 tests and `verify_spec.py`
  pass on Windows / Python 3.13 / cryptography 49.0.0. All tracked
  files LF. Closes the v0.0.0-dev "Bad": the laptop has `dd47f52` and
  everything after it.
- SPEC §8.4 independent implementation added in `independent/`:
  hand-written canonicaliser, hand-rolled SHA-256 (FIPS 180-4,
  constants derived from primes) and Ed25519 (RFC 8032), base58btc and
  did:key from §9/§9a. Stdlib only; never imports envelope.
- `independent/test_cross.py`: 49 cross-implementation tests. Canonical
  bytes, SHA-256, public keys, signatures and did:key strings are
  byte-identical to envelope.py. Each side verifies the other's
  signatures. RFC 8032 §7.1 TEST 1 and FIPS vectors pass.
- Missing SPEC §8 tests added to `test_envelope.py`: §8.1 nested
  expected form, §8.3b secp256k1 wrong key type. 29/29 pass.
  `envelope.py` untouched.
- Header discipline: `verify_spec.py` (header + numbered functions) and
  `.gitignore` (header, plus `.pytest_cache/`).
- `requirements.txt` added (`cryptography`; laptop version recorded).
- README brought up to date: status 1.0.0, did:key, file map,
  verification steps. Removed the claim that P1 signs with
  `"signature": null` — that is P2's capsule rule (SPEC §3).
- SPEC errata E1 (header version label) and E2 (stale document-control
  sentence). No normative change.
- NOTES: divergences D1–D4 and open questions Q1–Q3 recorded.
- `CLAUDE.md` added and expanded for VS Code AI context.
- This CHANGELOG restructured so every entry has Good / Bad / Ugly.

### Bad

- envelope.py v1.0.0 diverges from SPEC v1.1.0 on four edge cases
  (NOTES D1–D4): str data to verify_bytes returns False instead of
  raising TypeError; two AttributeErrors where TypeError is specified;
  NaN / Infinity emitted as non-JSON tokens. Pinned, not fixed.
- No `v1.0.0` git tag exists yet (NOTES Q3).

### Ugly

- P1 was declared frozen before SPEC §7's own condition was met: the
  freeze-time independent check covered base58btc only. The full
  cross-implementation check now passes, but after the freeze rather
  than before it.

## [v1.0.0] — 2026-11-11

### Good

- `envelope.py` implemented to SPEC v1.1.0.
- 27/27 pytest tests pass.
- Independent base58btc verification passed (verify_spec.py).
- Layer frozen at v1.0.0.

### Bad

- (none recorded at the time — see [Unreleased] Ugly)

### Ugly

- (none)

## [v0.0.0-dev] — scaffold and spec

### Good

- Repository scaffolded: `Giblet-Legacy/envelope-layer` created for P1.
- Initial files in place: README.md, CHANGELOG.md, NOTES.md, VERSION,
  .gitattributes.
- LF-only policy enforced from first commit.
- Dual-device workflow declared (S24/Termux and laptop/VS Code).
- Repo naming convention established: `<primitive>-layer` for primitives,
  bare name for consumers.
- `envelope-layer` visibility: PUBLIC (org convention for primitives).
- SPEC.md written and agreed (SPEC v1.0.0).
- did:key moved into P1 (decision, spec revision 1).
- Numeric type sensitivity accepted as Known Limitation.
- SPEC v1.1.0: base58btc algorithm specified, internal helpers declared.
- Test suite written to SPEC v1.1.0 before implementation.

### Bad

- Laptop-side clone verification of the scaffold deferred — no PC access
  at setup time. Outstanding until the VS Code device pulls and confirms
  `dd47f52`. (Resolved 2026-11-11 — see [Unreleased].)

### Ugly

- (none)
