# 0008 — T3 finished: LLM-judge evaluators + CI gate binary

- **Date:** 2026-09-14
- **Status:** Implemented (green)
- **Type:** Track T3 (completes [0007](0007-t3-eval-harness.md))

## What & why

0007 shipped the deterministic eval core; this adds the semantic LLM-as-judge evaluators and the CI
regression gate, finishing T3's headline scope.

## Changes (all in `aegis-eval`)

- **`Judge` trait** — the host's model-call abstraction: `score(&JudgeRequest) -> Result<JudgeVerdict,
  JudgeError>`. Synchronous (so `Evaluator` stays sync and a CI gate can block on it) and `Send+Sync`.
  The crate stays pure: unit tests drive a scripted judge; CI wires a real one. A judge error makes
  the evaluator **fail closed** (score 0.0).
- **Three LLM-judge evaluators**, all implementing the existing `Evaluator` trait behind a shared
  `Arc<dyn Judge>`:
  - `FaithfulnessEvaluator` — is the response supported only by the retrieved chunks? (`LLM09`, thr 0.85)
  - `RetrievalRelevanceEvaluator` — are the chunks relevant to the question? (`LLM08`, thr 0.70; skips
    when nothing was retrieved)
  - `MedicalAccuracyEvaluator` — is the response medically equivalent to the golden answer? (`LLM09`,
    thr 0.90; **skips/passes** when the sample has no golden reference)
  Each has a `with_threshold` override and composes in the `ThresholdEngine` alongside the
  deterministic evaluators.
- **`deterministic_evaluators(forbidden)`** — the default fast suite for a CI gate (PHI leak + optional
  forbidden-term).
- **CI gate binary `aegis-eval`** (`src/main.rs`) — `aegis-eval <samples.json> [--forbid t1,t2] [--json]`.
  Reads `{"samples":[…]}` or a bare array of `EvalSample`, runs the deterministic suite, prints a human
  or `--json` report, and **exits 1 if any sample fails** (2 on usage/IO). Model-free by design — the
  right thing to block a PR; LLM judges run in a separate, sampled job.

## Design notes

- The gate is deterministic and network-free so it is reproducible and fast; the LLM-judge evaluators
  are library types used by a separate job that supplies a real `Judge`.
- Reasons never echo secret material — the forbidden-term check reports a count, not the term.

## Verification

- `cargo test -p aegis-eval` green (16 tests; judges via a scripted `Judge`, fail-closed on judge
  error, engine composition, metadata/thresholds, golden validation). `cargo test --workspace` green
  (50 groups).
- **Coverage:** `aegis-eval` lib **99.4%**. `main.rs` (CLI glue) is excluded from the bar, same as
  `aegis-cli`'s `main.rs`; it is exercised manually (clean → exit 0; PHI/canary → exit 1; `--json`).
- `clippy --workspace --all-targets -D warnings` clean; `cargo fmt --all --check` clean.

## Remaining eval follow-ups (beyond T3 headline)

- A production trace sampler + drift detector (rolling-window scores, alert on drop).
- Attach the model response to the gate's trace so `EvalSample::from_trace` runs on live traffic and
  the deterministic gate can score real responses, not just CI fixtures.
