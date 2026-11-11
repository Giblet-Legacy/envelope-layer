# NOTES — envelope-layer (P1 Envelope)

NOTES.md — open questions, divergences and decisions for P1 Envelope.

Function:
    Records our open questions and any divergences, both between the
    v1.2.1 stack document and SPEC.md, and between envelope.py v1.0.0
    and SPEC.md v1.1.0. Clean slate at setup — this layer inherits
    nothing, so every question here is ours. Where the spec wins, the
    divergence is noted here; envelope.py is never edited (Immutable
    Rule), so a fix means a new layer above P1, after a SPEC version
    describes it.

## Open questions

- (none)

## Resolved questions

- **Q1 — Non-finite floats (see D4).** SPEC v1.1.0 says nothing about
  NaN / Infinity / -Infinity. envelope.py emits the non-JSON tokens
  `NaN`, `Infinity`, `-Infinity`; the independent implementation
  rejects them with ValueError. Proposed answer: a SPEC revision
  declares non-finite floats out of contract (ValueError), and the
  next layer above P1 calls `json.dumps(..., allow_nan=False)`. Adding
  this rejection changes no bytes for any valid JSON input, so every
  v1-signed artefact still verifies. Raised 2026-11-11. Owner: James.
  **Resolved 2026-11-11 — James: "reject".** SPEC_V2.md §2.1;
  envelope_v2.canonicalise raises ValueError. Implemented by
  delegating to v1 and rejecting non-finite tokens in its output
  (not by re-calling json.dumps), so the bytes are v1's by
  construction.
- **Q2 — Resolve D1–D3 or accept them?** Options: (a) record them as
  SPEC errata that relax the exception type to "raises" (no code
  change); (b) a strict-typing layer above P1 v1.0.0 that checks types
  before delegating. Recommendation: (a) for D2/D3 (wrong exception
  class only), and decide D1 explicitly, since it turns a caller bug
  into a silent False. Raised 2026-11-11. Owner: James.
  **Resolved 2026-11-11 — option (b), decided by the VS Code AI on
  James's delegation ("please decide and finish").** Reason: Q1
  already needed a layer above P1, so the strict checks cost nothing
  extra there, and (b) makes the code match what SPEC v1.1.0 already
  said instead of weakening the spec to match the code. SPEC_V2.md
  §2.2–§2.4.
- **Q3 — What does the `v1.0.0` git tag mean?** No tag exists yet. Tag
  the freeze commit `1cb2aa6`/`6c71b8d` as-is, or tag only after the
  §8.4 cross-implementation check (now in `independent/`) is signed
  off? Raised 2026-11-11. Owner: James.
  **Resolved 2026-11-11 — decided by the VS Code AI on James's
  delegation.** `v1.0.0` tags `6c71b8d`, the only commit that touches
  envelope.py (`1cb2aa6` is the freeze note and predates the code).
  The tag means "these are the frozen v1 bytes", not "fully verified";
  the CHANGELOG Ugly records that §8.4 passed after the freeze.
  `v2.0.0` tags the commit that freezes envelope_v2.py.

## Divergences from v1.2.1 specification

- (none)

## Divergences: envelope.py v1.0.0 vs SPEC v1.1.0

Found 2026-11-11 (laptop review). Pinned in
`independent/test_cross.py::test_divergence_pins`. None affects a
valid signature, digest or did:key — they are all failure-path or
out-of-contract inputs.

**All four are resolved in envelope_v2.py (SPEC_V2.md).** They remain
true of envelope.py forever, because v1 is frozen. New code imports
envelope_v2.

- **D1 — verify_bytes with str data returns False.** SPEC §4.6:
  "TypeError only if data/signature not bytes-like". The cryptography
  library raises TypeError, and verify_bytes catches TypeError and
  returns False. Effect: a caller passing a str instead of bytes gets
  "invalid signature" instead of a crash that exposes their bug.
- **D2 — verify_bytes with a non-key public_key raises
  AttributeError.** SPEC §4.6 says TypeError. Effect: wrong exception
  class; it still raises.
- **D3 — did_key_encode with a non-key, non-bytes argument raises
  AttributeError.** SPEC §4.7 says TypeError. Effect: wrong exception
  class; it still raises.
- **D4 — canonicalise emits NaN / Infinity / -Infinity.** SPEC §1 and
  §4.1 do not cover non-finite floats; Python's default
  `allow_nan=True` produces tokens that are not JSON. Another
  implementation may reject them or produce different bytes. See Q1.

Not a divergence, noted for completeness: did_key_decode accepts a
32-byte string that is not a valid curve point. The SPEC §4.8 failure
list does not require point validation, and any signature checked
against such a key returns False.

## Decisions

- did:key lives in P1, not P2. Decided at spec review, revision 1.
  Rationale: did:key is a byte-level identity primitive, colocated
  with the Ed25519 sign/verify primitives it depends on. P2 consumes
  it rather than implementing it. v1.2.1 listed P1 as
  "Canonicalisation, SHA-256, Ed25519 sign/verify" without
  mentioning did:key — moving it into P1 is an intentional
  interpretation, not a divergence. If a future layer needs
  did:key handling that does not belong in P1, this decision is
  the point to revisit.
- Numeric type sensitivity accepted as Known Limitation. 1 and 1.0
  produce different canonical bytes. No normalisation. Callers must
  pass canonical-typed input. Rejected at spec review, revision 1:
  adding numeric normalisation would diverge from plain
  json.dumps and complicate the canonicalisation rule for a case
  the stack can avoid by discipline.
- base58btc lives in P1 as internal helpers (_base58btc_encode and
  _base58btc_decode). Decided at spec review, revision 1.1.0.
  Rationale: base58btc is an encoding, not a cryptographic primitive.
  Keeping it private avoids widening P1's public API speculatively,
  while ensuring did:key is fully specified and independently
  implementable. If a future layer needs base58btc, it gets a new
  layer above P1 v1.0.0 (version assigned when specified), not a
  public API change to v1.0.0.
- SPEC.md header/metadata corrections are errata, not a new SPEC
  version. Decided 2026-11-11 by the VS Code AI on James's delegation
  ("please decide and finish"). An erratum may fix a wrong version
  label or a stale sentence, but never a normative rule; each one is
  listed under "Errata" in SPEC.md's document control. Anything
  normative needs a new SPEC version.
- The §8.4 independent implementation lives in `independent/`, is
  stdlib-only, and hand-rolls canonicalisation, SHA-256 and Ed25519
  instead of reusing json.dumps, hashlib.sha256 or cryptography.
  Decided 2026-11-11 by the VS Code AI on James's delegation.
  Rationale: two implementations that call the
  same library prove nothing about the library call (SPEC §7).
  `p1_independent.py` must never import envelope.
- envelope_v2.py is a layer, not a rewrite. Decided 2026-11-11 (Q1/Q2).
  It delegates every byte to envelope.py and only adds rejections.
  Re-exports sha256_hex, sha256_digest and did_key_decode unchanged.
  Major version 2 because it rejects inputs v1 accepted. New code
  imports envelope_v2. envelope.py stays importable for existing
  callers and for the divergence pins.
- Spec file per layer: SPEC.md describes envelope.py (v1.1.0, errata
  only); SPEC_V2.md describes envelope_v2.py. Decided 2026-11-11.
