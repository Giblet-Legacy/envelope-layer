# NOTES — envelope-layer (P1 Envelope)

NOTES.md — open questions, divergences and decisions for P1 Envelope.

Function:
    Records our open questions and any divergences between the v1.2.1
    specification and the implementation. Clean slate at setup — this
    layer inherits nothing, so every question here is ours. Divergences
    that the spec wins are noted; gaps the spec leaves open are raised
    here and answered before build continues.

## Open questions
- (none)

## Divergences from v1.2.1 specification
- (none)

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
  implementable. If a future layer needs base58btc, it gets a new P1
  layer above (v1.1.0), not a public API change to v1.0.0.
