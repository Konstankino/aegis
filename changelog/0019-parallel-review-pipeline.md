# 0019 — Second example pipeline: parallel-review (fan-out/fan-in)

- **Date:** 2026-09-15
- **Status:** Done
- **Type:** New example pipeline (data + code + ASL + tests)
- **Follows:** [0018-generic-multi-pipeline-platform.md](0018-generic-multi-pipeline-platform.md)

## What & why

A second example to exercise the generic platform with a **non-linear topology**: Agent A prepares the
text and dispatches it to **two peer writers, B and C, that improve it concurrently**; when both have
submitted, Agent D referees and publishes the best. This validates that a fan-out/fan-in pipeline needs
**no engine or module change** — the parallelism lives entirely in the pipeline's ASL.

## The pipeline — `pipelines/parallel-review/`

```
                    ┌─▶ Agent B ─submit.candidate─┐
   Agent A ─────────┤                             ├──▶ Agent D ─publish.final─▶ out
   dispatch         └─▶ Agent C ─submit.candidate─┘   referee
```

- `policies/` — tools.json (6 tools), broker.cedar (4 principals, default-deny), plus egress/meter/
  sandbox/grants/pins/honeypots.
- `pipeline.json` — manifest; B and C are peers (identical tool sets); a `branch` field notes which
  agents run inside the ASL `Parallel` state.
- `code/pipeline.py` — the transforms (grammar/improve/referee + terminal handoffs).
- `asl/pipeline.asl.json` — `Init → AgentA_Prepare → Improve (Parallel: AgentB_Improve ‖
  AgentC_Improve) → AgentD_Referee → Respond`. Every Task invokes the same `${agent_lambda_arn}` with a
  different `agent_id`. Fan-in collects the branch outputs (`ResultSelector: "$[*].text"`) into
  `candidates` for the referee.
- `README.md`.

## Why the engine is unchanged

The engine runs **one principal per invocation** and knows nothing about topology. A's terminal
handoff yields `{output: text}`; each of B and C (separate invocations, run in parallel by Step
Functions) yields its own `{output: text}`; the ASL collects both into `candidates`, and D consumes
`candidates` — a shape the engine's `seed_input` already handles. No change to `agent.py`,
`modules/aegis-pipeline`, or the stack.

## Tests

- `pipelines/parallel-review/code/test_pipeline.py` (11) — plugin transforms; a **consistency** suite
  that navigates the `Parallel` branches (every manifest tool in tools.json + implemented; principals
  match broker.cedar and the ASL; B/C are peers with identical tools; fan-in wiring); and an
  **end-to-end** suite that stages the bundle and runs A, B, C, D through the **real generic engine**
  (scripted model + in-process broker), proving the fan-out is served from data alone.
- `crates/aegis-broker/tests/parallel_review.rs` (6) — the least-privilege matrix (A/D lanes, B and C
  as identical-rights peers, unknown agent/tool denied, malformed args refused) and the `Parallel`
  ASL structure (two branches → agent-b/agent-c on one function, fan-in → referee).

## Deploy

Add an entry to `var.pipelines` in `stacks/editorial-pipeline` pointing at
`pipelines/parallel-review` (see `terraform.tfvars.example`). The generic `aegis-pipeline` module
stages the bundle and renders this pipeline's `Parallel` ASL exactly as it does the linear one.

## Verification

- `aegis --dir pipelines/parallel-review/policies validate` → all 8 artifacts ok (6 tools, 8 Cedar
  statements).
- `python3 -m unittest` green: parallel-review 11, editorial 7, engine 8.
- `cargo test -p aegis-broker --test parallel_review` → 6 passed; `cargo fmt --all --check` clean.
- `terraform validate` on `stacks/editorial-pipeline` = valid; the ASL is valid JSON and its only
  `templatefile` interpolation is `${agent_lambda_arn}` (identical mechanism to the editorial ASL).
