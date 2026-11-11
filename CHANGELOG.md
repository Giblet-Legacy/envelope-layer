# CHANGELOG — envelope-layer (P1 Envelope)

CHANGELOG.md — build history for P1 Envelope, latest entry at top.

Function:
    Records the Good / Bad / Ugly of every build step for this layer.
    Updated at every sign-off. Kept current without exception. Format
    never changes shape, even when a section is empty.

## [Unreleased]

### Good

- (none)

### Bad

- (none)

### Ugly

- (none)

## [v2.0.0] — 2026-11-11

### Good

- `envelope_v2.py`: strict layer above the frozen P1 v1.0.0, specified
  in `SPEC_V2.md` before any code. It delegates every byte to
  envelope.py, so every v1 artefact still verifies (tested both ways).
- Q1 resolved (James: "reject"): NaN / Infinity / -Infinity raise
  ValueError in v2 canonicalise. Resolves D4.
- Q2 resolved (option b, AI-decided on delegation): v2 raises TypeError
  for wrong input types in verify_bytes, sign_bytes and did_key_encode,
  as SPEC v1.1.0 §4.5–§4.7 already required. Resolves D1–D3.
- Q3 resolved (AI-decided on delegation): tag `v1.0.0` → `6c71b8d`,
  tag `v2.0.0` → this release.
- `test_envelope_v2.py`: 34 tests, written before envelope_v2.py and
  run red first. Cross-implementation suite now 50, including v2
  against the independent implementation.
- Laptop review: 27/27 v1.0.0 tests and `verify_spec.py` pass on
  Windows / Python 3.13 / cryptography 49.0.0. All tracked files LF.
  Closes the v0.0.0-dev "Bad": the laptop has `dd47f52` onward.
- SPEC §8.4 independent implementation added in `independent/`:
  hand-written canonicaliser, hand-rolled SHA-256 (FIPS 180-4,
  constants derived from primes) and Ed25519 (RFC 8032), base58btc and
  did:key from §9/§9a. Stdlib only; never imports envelope.
- Missing SPEC §8 tests added to `test_envelope.py`: §8.1 nested
  expected form, §8.3b secp256k1 wrong key type. 29/29 pass.
  `envelope.py` untouched.
- Header discipline: `verify_spec.py` (header + numbered functions) and
  `.gitignore` (header, plus `.pytest_cache/`).
- `requirements.txt` added (`cryptography`; laptop version recorded).
- README brought up to date. Removed the claim that P1 signs with
  `"signature": null` — that is P2's capsule rule (SPEC §3).
- SPEC errata E1 (header version label) and E2 (stale document-control
  sentence). No normative change.
- `CLAUDE.md` added and expanded for VS Code AI context.
- This CHANGELOG restructured so every entry has Good / Bad / Ugly.
- Totals: 113 tests pass (v1 29, v2 34, cross 50).

### Bad

- envelope.py v1.0.0 still has D1–D4. It is frozen, so they are pinned
  rather than fixed; any caller still importing envelope directly
  keeps them. New code must import envelope_v2.
- Q2 and Q3 were decided by the AI on James's delegation, not by
  James. Recorded as such in NOTES.md so they can be revisited.
- S24 (Termux) has not yet run the v2 or cross suites. Outstanding
  until the S24 pulls and confirms.

### Ugly

- P1 v1.0.0 was declared frozen before SPEC §7's own condition was
  met: the freeze-time independent check covered base58btc only. The
  full cross-implementation check passes, but after the freeze rather
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
