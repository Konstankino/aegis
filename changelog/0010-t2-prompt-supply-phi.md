# 0010 — T2: aegis-prompt (prompt supply) + PHI patterns

- **Date:** 2026-09-14
- **Status:** Implemented (green) — core slice; retrieval extensions + cross-tenant scan are follow-ups
- **Type:** Track T2 (new crate `aegis-prompt` + extend `aegis-redact`)
- **Roadmap:** Track T2 in [0003-reconciled-roadmap.md](0003-reconciled-roadmap.md)

## What & why

T2 closes the RAG-governance gaps. This delivers the headline **prompt supply** crate (the roadmap's
`aegis-prompt`, resolving the `aegis-supply` name collision — that stays artifact pinning) and extends
PHI detection with the labelled MRN/DOB patterns compliance cares about.

## New crate: `aegis-prompt`

Deterministic, pure (no model calls, no I/O), so fully testable.

- **`PromptRegistry`** / `Prompt` — system prompts / few-shot / schemas, **versioned by content hash**
  (`sha256:<hex>`), stored outside app code. `register` keeps version history (rollback/audit reach an
  exact `(id, version)`); `register` re-hashes so a caller cannot record a mismatched version;
  `validate` fails closed if any recorded version drifts from its content. A `Prompt` can carry a
  planted **canary** (leak tripwire the output/eval scanners check). Covers LLM07/LLM03.
- **`ContextWindow`** — assembles the final prompt from **clearly delimited sections** (`### SYSTEM` /
  `### CONTEXT` / `### USER`) so the model sees structure, not a flat string; `render(max_chars)`
  **trims the lowest-relevance chunks first, never the system prompt or user input**.
- **`ModelRouter`** — per-tenant **approved-model allowlist**; `route()` returns the model only if
  approved, else fails closed — an injected "switch to model X" cannot swap it. Empty router denies
  everything (safe by default). Covers LLM03/ASI04.

## Extended: `aegis-redact` (PHI)

- New `FindingKind::Mrn` and `FindingKind::Dob` with **labelled** detectors (`MRN …` + 6–10 digits;
  `DOB`/`D.O.B` + a date), placed before the bare-digit detectors so a labelled id is redacted whole
  under its own kind. Labelling gates DOB so ordinary dates in text are left alone.
- Free win: `aegis-eval`'s `PhiLeakEvaluator` reuses `aegis-redact`, so it now catches MRN/DOB too.

## Verification

- `cargo test -p aegis-prompt` green (8 tests: content-hash versioning + tamper detection, registry
  history + exact-version + re-hash + validate, delimited context window, lowest-relevance trim,
  per-tenant model allowlist + fail-closed route). `cargo test -p aegis-redact` green (13, incl. new
  MRN/DOB + plain-date negative). `cargo test --workspace` green (52 groups).
- **Coverage:** `aegis-prompt` 97.2% lines.
- `clippy --workspace --all-targets -D warnings` clean; `cargo fmt --all --check` clean. README +
  coverage matrix updated.

## Remaining T2 (follow-ups)

- **`aegis-retrieval` extensions**: a `RetrievalBackend` trait, an ingestion gate (scan documents at
  ingest, tag chunk tenant ownership), and `EmbeddingVersion` per chunk (flag stale on model change).
- **Cross-tenant entity scan** in output/eval (needs a per-tenant allowed-entity registry) — a natural
  new deterministic evaluator in `aegis-eval`.
- Wire the gate/handler to build prompts through `aegis-prompt` and emit a `Stage::Prompt` span.
