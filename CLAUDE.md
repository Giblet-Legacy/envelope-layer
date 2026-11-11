# Forge Stack Context — P1 Envelope

CLAUDE.md — Context briefing for AI assistants working in this repository.

Function:
    Instructs the AI assistant on the strict architectural rules of the
    Forge Stack. Do not hallucinate external frameworks. Reason strictly
    within these boundaries.

## The Immutable Rule
Never rewrite a primitive. Add a layer. 
If `envelope.py` needs a change, we do NOT edit it. We create a v2 layer above it. Old artefacts signed by v1 must still verify.

## Dual-Device Workflow
We build on an S24 (Termux) and a laptop (VS Code). State is confirmed, never assumed. Always use LF line endings. AI on VS Code is a co-worker, not the author. Commit messages must be clear. We use the Good/Bad/Ugly CHANGELOG format (latest at top).

## Header Discipline
Every file MUST have a top header paragraph explaining its function.
Every function MUST have a numbered header (e.g., `# 1. canonicalise`).

## P1 Architecture Specifics
- Standard library only. No external dependencies except `cryptography`.
- Canonicalisation is `json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=True)`. Not JCS.
- base58btc is internal and hand-rolled.
