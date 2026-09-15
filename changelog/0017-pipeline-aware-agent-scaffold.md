# 0017 — Pipeline-aware agent scaffold (+ terraform validate)

- **Date:** 2026-09-15
- **Status:** Done
- **Type:** Lambda scaffold code + Python tests; terraform validation
- **Follows:** [0016-editorial-pipeline-deployable.md](0016-editorial-pipeline-deployable.md)

## What & why

0015/0016 built the editorial pipeline's **enforcement plane** (policy set, Cedar matrix, ASL
orchestration, broker acceptance test) but left the **agent business logic** as the generic
healthcare scaffold. Reviewing "where is the LLM logic for the pipeline?" surfaced three concrete
mismatches that meant A/B/C could not actually run end-to-end on the shared Lambda:

1. `agent.py` read the principal from the **environment** (`AEGIS_AGENT_ID`), but the ASL passes a
   different `agent_id` per stage in the **event payload** — so all three stages would have mediated
   under one identity.
2. The model's tool registry (`TOOL_SPECS` / `TOOL_NAME_MAP`) listed the healthcare demo tools, not
   the editorial tools — the model would never see `grammar.correct` / `enrich.add_facts` /
   `referee.select` / the handoffs.
3. The handler returned `{"answer": …}`, but the ASL `ResultSelector` expects `$.Payload.output`
   (A/C) and `$.Payload.candidates` (B).

## The change — [deploy/terraform/agent-src/agent/agent.py](../deploy/terraform/agent-src/agent/agent.py)

Kept the generic (healthcare) path 100% backward-compatible; added a **per-principal profile** layer:

- **`agent_id` from the event.** `agent_id = event.get("agent_id") or DEFAULT_AGENT_ID`; threaded
  through `mediate(agent_id, …)`, `run_tool(…, agent_id, …)`, `run_code(…, agent_id, …)` (was a
  module global). Env is now only a fallback.
- **Tool profiles keyed by principal.** `EDITORIAL_PROFILES["agent-a"|"agent-b"|"agent-c"]` each
  expose ONLY that principal's transform + its single handoff, with matching Converse `inputSchema`
  from the scenario `tools.json`. `profile_for(agent_id)` falls back to `DEFAULT_PROFILE` (the
  healthcare tool set + `{"answer"}` return) for any non-pipeline id. The model's tool view now
  mirrors the Cedar least-privilege matrix (the broker remains authoritative).
- **Terminal handoff = stage output.** Each profile names a `terminal` tool (`send.to_agent_b` /
  `send.to_agent_c` / `publish.final`); when the broker allows it, its args become the stage result
  in the exact shape the ASL consumes — `{"output": text}` for A/C, `{"candidates": [...]}` for B —
  and the turn ends.
- **Referee input.** The handler now also accepts a `candidates` event (Agent C receives candidate
  versions, not a single `input` text).
- **Packaging:** `modules/aegis-agent/main.tf` `archive_file.agent` gains
  `excludes = ["test_agent.py", "__pycache__"]` so the test/bytecode never ship in the Lambda zip.

## Tests — [deploy/terraform/agent-src/agent/test_agent.py](../deploy/terraform/agent-src/agent/test_agent.py)

Stdlib `unittest`, **no AWS/network**: `boto3` stubbed in `sys.modules` before import, the gate
replaced with an in-process broker that enforces the editorial matrix and records calls, Bedrock
replaced with a scripted model that picks its move from the tools it is shown. 8 tests, all green:

- `agent_id` is sourced from the event, not the env (overrides the `AEGIS_AGENT_ID` default).
- A → `{"output": corrected}`; B → `{"candidates": […]}`; C (from `candidates`) → `{"output": chosen}`.
- Full A→B→C chain wired the way the ASL wires it (A.output → B.input, B.candidates → C.candidates).
- Profile isolation: agent-a's model is shown ONLY `grammar_correct` + `send_to_agent_b`.
- The broker (not the profile) is authoritative: a confused model emitting `publish_final` as
  agent-a is denied and re-plans; no terminal payload leaks.
- Unknown principal → generic profile → `{"answer": …}` (backward compatible).

Run: `cd deploy/terraform/agent-src/agent && python3 -m unittest test_agent`.

## Verification

- `python3 -m unittest test_agent` → 8 passed; `py_compile` clean on all five scaffolds.
- `terraform validate` clean on the demo root, `modules/rag`, `modules/phoenix`,
  `stacks/single-agent`, `stacks/multi-agent` (run with `TF_DATA_DIR` on local disk — the SMB mount
  made provider schema-load time out; providers come from the plugin cache). `terraform fmt` clean on
  all touched files.
- Rust unchanged and still green (broker acceptance test in
  `crates/aegis-broker/tests/editorial_pipeline.rs` still gates the policy matrix + ASL topology).

## Note

The transform bodies in `run_tool` (grammar/enrich/referee) remain **stubs** — in production the
model does the transform and these are the governed side effects (e.g. `enrich.add_facts` calls the
egress-allowlisted facts service). What is now real: principal-sourced identity, per-agent tool
profiles, and the ASL I/O contract, all under test.
