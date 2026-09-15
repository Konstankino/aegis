# 0016 — Editorial pipeline: deployable + test coverage

- **Date:** 2026-09-15
- **Status:** Done
- **Type:** Scenario deployment (Terraform/ASL) + tests
- **Follows:** [0015-editorial-pipeline-scenario.md](0015-editorial-pipeline-scenario.md)

## What & why

0015 shipped the policy set + authorization test. The user asked to make the scenario **deployable**
and ensure **proper test coverage** — and asked how it works given no new Lambda functions appear.

## The model (why there are no new Lambdas)

Agents A/B/C are **principals (Cedar identities), not compute.** A deployment has one agent Lambda +
one inline-plane extension (same as any project). Step Functions invokes that **one** function per
stage with a different `agent_id`; the broker applies the per-agent Cedar policy keyed on the
principal. Same binary + same policy files + different `agent_id` ⇒ different least-privilege
permissions.

## Deployable orchestration

- **`deploy/terraform/asl/editorial_pipeline.asl.json`** — a linear `AgentA_Grammar → AgentB_Enrich →
  AgentC_Referee → Respond` state machine (+ `Failed`). Every Task invokes the same
  `${agent_lambda_arn}` with `agent_id` = `agent-a` / `agent-b` / `agent-c` and passes the running text
  along.
- **`modules/aegis-agent`** — added a **`pipeline` topology**: `topology = "pipeline"` selects the new
  ASL (reusing the agent Lambda; no supervisor). `variables.tf` validation and `main.tf` ASL selector
  updated.
- Deploys as an ordinary `aegis-agent` project pointing `policy_dir` at
  `policies/scenarios/editorial-pipeline` — the policy files upload/bake like any project and the
  extension applies them per `agent_id`. See the doc's "How it deploys" section.

## Test coverage

`crates/aegis-broker/tests/editorial_pipeline.rs` (now **6 tests**):

- **Authorization matrix** (5) — each agent may call only its lane; A can't skip the chain; unknown
  agent/tool denied; malformed args refused; the happy chain flows.
- **Orchestration** (new) — `asl_orchestration_is_a_linear_a_b_c_chain_over_one_lambda`: parses the
  deployable ASL, asserts the three stages run **in order**, each invokes the **same** agent Lambda
  with a distinct `agent_id`, the agent_ids match the `broker.cedar` principals, and the terminal
  shape is correct. This ties the deployment to the least-privilege policy.

## Verification

`cargo test --workspace` green (55 groups); all four ASL files parse as valid JSON; `clippy -D
warnings` clean; `cargo fmt --all --check` clean. Terraform not installed here — the `pipeline`
topology + ASL follow the existing single/multi conventions; run `terraform validate` before apply.
