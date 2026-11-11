# CHANGELOG — envelope-layer (P1 Envelope)

CHANGELOG.md — build history for P1 Envelope, latest entry at top.

Function:
    Records the Good / Bad / Ugly of every build step for this layer.
    Updated at every sign-off. Kept current without exception. Format
    never changes shape, even when a section is empty.

## [v1.0.0] — 2026-11-11

### Good
- `envelope.py` implemented to SPEC v1.1.0.
- 27/27 pytest tests pass.
- Independent base58btc verification passed (verify_spec.py).
- Layer frozen at v1.0.0.

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

### Bad
- Laptop-side clone verification of the scaffold deferred — no PC access
  at setup time. Outstanding until the VS Code device pulls and confirms
  `dd47f52`.

### Ugly
- (none)
