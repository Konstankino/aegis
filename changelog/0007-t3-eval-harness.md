# 0007 — T3: aegis-eval harness (deterministic core + PhiLeakEvaluator)

- **Date:** 2026-09-14
- **Status:** Implemented (green) — deterministic core; LLM-judge evaluators are the next T3 step
- **Type:** Track T3 (new crate)
- **Roadmap:** Track T3 in [0003-reconciled-roadmap.md](0003-reconciled-roadmap.md); consumes the T0
  trace spine ([0004](0004-t0-trace-spine-core-additions.md))

## What & why

Detection catches known-bad patterns and governance bounds blast radius; neither tells you whether the
system is producing *correct, safe* output. T3 adds the evaluation harness that closes the loop and
produces the compliance evidence clients ask for. Per the roadmap, the **deterministic**
`PhiLeakEvaluator` ships first (fastest to build, first thing compliance asks for).

## New crate: `aegis-eval`

- `Evaluator` trait → `EvalResult { score 0..1, reasoning }`; `EvalSample` (tenant, question, response,
  retrieved chunks, expected answer) with `from_response` and **`from_trace`** (reads conventional
  `response`/`question`/`retrieved` attributes off an `aegis_trace::Trace` — the T0 → T3 link).
- **`PhiLeakEvaluator`** — zero-tolerance PHI/PII leak check reusing `aegis_redact::redact` (SSN, email,
  card, IBAN, JWT, private key, UA tax id, …); any finding → 0.0, clean → 1.0; risk `LLM02`.
- **`ForbiddenTermEvaluator`** — configurable "these strings must not appear" (e.g. planted canary →
  system-prompt leakage, `LLM07`); reports counts only, never echoes the (possibly secret) term.
- **`ThresholdEngine`** — runs many evaluators, applies per-evaluator thresholds (default or override),
  aggregates into a `Report` that **passes only if every evaluator passes** (safety isn't averaged
  away); `failures()`, `min_score()`.
- **`GoldenSet`** / `GoldenEntry` — the git-versioned "this must never break" corpus: `from_json`/
  `to_json`, `get`, `by_tag`, `validate` (unique ids, non-empty questions) for a CI gate.

## Design notes

- Model-free and fully deterministic, so it is testable and CI-safe. LLM-as-judge evaluators
  (faithfulness, retrieval relevance, medical accuracy) implement the **same `Evaluator` trait** behind
  a model and are the next T3 step; the harness is ready for them.
- Complements `aegis-redteam`: red-team proves Aegis *blocks bad*; eval proves it *doesn't block good*
  and stays accurate.

## Verification

- `cargo test -p aegis-eval` green (8 tests: PHI zero-tolerance, canary non-echo, score clamp,
  all-must-pass aggregation, threshold override, report serde with OWASP codes, `from_trace`, golden
  round-trip/validate/filter). `cargo test --workspace` green (49 groups).
- **Coverage:** `aegis-eval` 98.3% lines.
- `clippy --workspace --all-targets -D warnings` clean; `cargo fmt --all --check` clean.
- Additive: new crate; nothing else changed.

## Next T3 (follow-ups)

- LLM-judge evaluators (faithfulness / relevance / medical) behind the `Evaluator` trait (needs model
  access — pairs with T2 `aegis-prompt`).
- A CI gate binary that runs the golden set through a staging pipeline and fails on threshold drop;
  a production trace sampler + drift detector.
- Attach the model response to the gate's trace so `EvalSample::from_trace` runs on real traffic.
