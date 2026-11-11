# Forge Stack Context — P1 Envelope

CLAUDE.md — Context briefing for AI assistants working in this repository.

Function:
    Instructs the AI assistant on the strict architectural rules of the
    Forge Stack and the current state of this layer. Do not hallucinate
    external frameworks. Reason strictly within these boundaries.

## The Immutable Rule

Never rewrite a primitive. Add a layer.
If `envelope.py` needs a change, we do NOT edit it. We create a v2 layer above it. Old artefacts signed by v1 must still verify.

- `envelope.py` is frozen at v1.0.0. Do not edit it — not for typos, headers, or "obvious" fixes.
- A new layer is specified first (new SPEC version), then tested, then implemented. Never code-first.
- SPEC.md is frozen at v1.1.0. Only non-normative errata are allowed, each listed under "Errata" in its document control. Anything that changes a rule, contract or test vector is a new SPEC version.

## Dual-Device Workflow

We build on an S24 (Termux) and a laptop (VS Code). State is confirmed, never assumed. Always use LF line endings. AI on VS Code is a co-worker, not the author. Commit messages must be clear. We use the Good/Bad/Ugly CHANGELOG format (latest at top).

- "Co-worker, not author": the AI may propose decisions, but records them as "Proposed … pending James's sign-off", never as "Decided". Open questions go in NOTES.md with an owner.
- Confirm state by running things (tests, `git ls-files --eol`, `git status -sb`), not by reading claims in docs.
- Do not commit, tag or push unless asked.
- Laptop is Windows: use `python`, not `python3`. Termux uses `python3`.

## Header Discipline

Every file MUST have a top header paragraph explaining its function.
Every function MUST have a numbered header (e.g., `# 1. canonicalise`).

- Python files: docstring header with Function, a numbered function list, Layer, Spec, Licence, Author.
- Config files (`.gitignore`, `requirements.txt`, `VERSION`): `#` comment header.
- Test files: the § section headers mapping to SPEC §8 count as the structure. New test files use numbered headers.

## P1 Architecture Specifics

- Standard library only. No external dependencies except `cryptography`.
- Canonicalisation is `json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=True)`. Not JCS.
- base58btc is internal and hand-rolled.
- P1 signs whatever bytes it is given. The capsule rule (`"signature": null`, raw canonical bytes) is P2's. The ledger rule (sign the raw SHA-256 digest) is P4's. Do not push either into P1.
- P1 is pure: no file I/O, network, environment, clock, logging or key storage.

## Repository map

| Path | Role | Editable? |
| --- | --- | --- |
| `envelope.py` | P1 v1.0.0 implementation | **No** (frozen) |
| `SPEC.md` | Authoritative spec v1.1.0. Spec wins over code | Errata only |
| `test_envelope.py` | SPEC §8.1–§8.3b tests | Add tests for missing SPEC items only |
| `independent/p1_independent.py` | SPEC §8.4 independent reimplementation | Yes. Must **never** import envelope |
| `independent/test_cross.py` | Cross-implementation agreement + divergence pins | Yes |
| `verify_spec.py` | Freeze-time base58btc evidence | Headers only |
| `NOTES.md` | Decisions, open questions (Q), divergences (D) | Yes |
| `CHANGELOG.md` | Good / Bad / Ugly, latest at top, every block has all three | Yes |
| `VERSION` | Advances only on freeze | Only at a freeze |

## Verify before claiming anything works

From the repo root:

1. `python -m pytest -q test_envelope.py` → 29 passed
2. `python -m pytest -q independent/` → 49 passed
3. `python verify_spec.py` → `OK`
4. `git ls-files --eol` → every file `i/lf w/lf`

## Current state (2026-11-11)

- P1 v1.0.0 frozen. Cross-implementation agreement passes (added after the freeze; see CHANGELOG Ugly).
- Known divergences D1–D4 between envelope.py and SPEC are recorded in NOTES.md and pinned in `test_divergence_pins`. They are not bugs to patch in place. Any fix is a new layer.
- Open for James: Q1 (NaN/Infinity), Q2 (resolve D1–D3 how), Q3 (meaning of the `v1.0.0` tag; none exists yet).
