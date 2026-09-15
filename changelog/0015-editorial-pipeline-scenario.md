# 0015 — Scenario: the editorial pipeline (A → B → C)

- **Date:** 2026-09-15
- **Status:** Done (policy set + acceptance test + docs)
- **Type:** Scenario / policy authoring

## What & why

The user asked for a multi-agent pipeline of three sub-agents — Agent A (grammar → hand to B), Agent B
(enrichment: add interesting facts → hand to C), Agent C (referee: choose the version to publish) —
with **all policies and permissions for tool use properly created**. The heart of the request is
least-privilege authorization for a multi-agentic chain.

## The policy set

`policies/scenarios/editorial-pipeline/` — a complete, validated 8-artifact set:

- **`tools.json`** — six tools: `grammar.correct`, `enrich.add_facts`, `referee.select`, and the
  handoffs `send.to_agent_b` / `send.to_agent_c` / `publish.final`, each with a strict arg schema and
  Rule-of-Two classification (the handoffs + enrich carry an external effect).
- **`broker.cedar`** — **default-deny** least-privilege: each agent may invoke only its own transform
  plus the single handoff it is allowed. The chain order is enforced by *which handoff tool each agent
  holds* — A→B→C — so an agent cannot skip the chain, loop back, or reach another lane.
- **`egress-allowlist.toml`** — default-deny; only Agent B's internal facts service reachable.
- **`meter.toml`** — a small per-turn budget with loop/fan-out breakers.
- **`sandbox.toml`** (locked-down; no code execution), **`grants.toml`** (none needed),
  **`pins.json`** / **`honeypots.json`** (empty defaults).

## Proof (CI-gated)

`crates/aegis-broker/tests/editorial_pipeline.rs` (5 tests) `include_str!`s the scenario's `tools.json`
+ `broker.cedar` and asserts:

- each agent may call **only** its own lane (allowed on the diagonal, denied off it);
- A cannot skip the chain (`send.to_agent_c` / `publish.final` denied for A);
- an unknown agent or tool is denied (default-deny + fail-closed);
- a malformed argument is refused by the schema;
- the happy chain A→B→C flows end to end.

Also verified live via `aegis --dir … validate` (exit 0) and `aegis … test mediate` per agent.

## Docs

`docs/scenarios/editorial-pipeline.md` — the flow diagram, the least-privilege matrix table, how the
chain is enforced, the defense-in-depth controls, and the **inter-agent identity + signed-mesh** setup
(AgentCards in an attested registry, intent-bound narrow-only delegation A→B→C, peer messages treated
as untrusted). Includes runnable commands and the orchestration note (a Step Functions A→B→C chain via
the `stacks/multi-agent` scaffold pointed at this `policy_dir`).

## Verification

`cargo test --workspace` green (55 groups, incl. the 5 new scenario tests); `clippy -D warnings` clean;
`cargo fmt --all --check` clean. The scenario dir is isolated under `policies/scenarios/` — it does not
affect the default policy set the extension loads/bakes.
