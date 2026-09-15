# 0018 — Generic multi-pipeline platform (engine, layout, Terraform) + demo removal

- **Date:** 2026-09-15
- **Status:** Done
- **Type:** Architecture refactor (Python engine + repo layout + Terraform) + deletions
- **Follows:** [0017-pipeline-aware-agent-scaffold.md](0017-pipeline-aware-agent-scaffold.md)

## What & why

The repo was "a Phase-0 demo + one hard-coded editorial scenario." The user asked to turn it into a
**generic multi-pipeline platform**: each pipeline self-contained in its own directory (policies +
Python), each deployable as a Terraform module, with **no hard-coded tool-spec data structures in
Python**, and with the demo handlers and related files removed.

Locked decisions (from the user):
- Pipelines live at top-level **`pipelines/<name>/`**; migrate editorial there.
- **One generic reusable module** (`modules/aegis-pipeline`) instantiated per pipeline.
- Demo removal goes as far as **dropping the single/multi stacks** — pipelines are the only topology.
- The engine keeps **platform tools only** (web.fetch / code.run / log.write); healthcare demo stubs
  (db.read_patient / email.send) are removed.

## New layout — a pipeline is one directory

```
pipelines/editorial/
  policies/            tools.json, broker.cedar, egress-allowlist.toml, meter.toml, pins.json,
                       sandbox.toml, grants.toml, honeypots.json   (moved from policies/scenarios/…)
  pipeline.json        manifest: per stage -> agent_id, state, system prompt, tools (+descriptions),
                       terminal handoff {tool, output_key, arg_key}
  code/pipeline.py     the ONLY pipeline-specific Python: run_tool(fq, args, agent_id, thread_id)
  code/test_pipeline.py
  asl/pipeline.asl.json   (moved from deploy/terraform/asl/editorial_pipeline.asl.json)
  README.md
```

## Generic engine — no hard-coded specs

[`agent-src/agent/agent.py`](../deploy/terraform/agent-src/agent/agent.py) is now data-driven and
pipeline-agnostic. At start-up it loads a **bundle** from its own dir:

- `tools.json` → tool **schemas**; the Converse `toolConfig` is *built* from these (dotted↔underscore
  names generated). **There are no `TOOL_SPECS`/`TOOL_NAME_MAP`/`EDITORIAL_PROFILES` literals left.**
- `pipeline.json` → per-principal profiles (system prompt, which tools, terminal handoff). Absent ⇒ a
  generic single-agent profile (all tools, returns `{"answer"}`).
- `pipeline.py` → the pipeline's `run_tool`; the engine tries it first, then its platform tools.

`profile_for(agent_id)` keys off the manifest; an unknown principal in pipeline mode gets a locked
(no-tools) profile. `reload_bundle()` is the test seam. Platform tools kept: `web.fetch` (egress
gate), `code.run` (isolated runner), `log.write` (redaction gate). Removed: db.read_patient,
email.send.

## Generic Terraform — one reusable module per pipeline

- **`modules/aegis-pipeline`** (from the old `aegis-agent`, simplified to pipeline-only): removed the
  `topology` var, the multi supervisor (function, log group, IAM role/policy/attachment), the
  `worker_roles` var, and the single/multi ASL selection. The agent zip is now assembled from a
  **bundle file-map** — `agent.py` + the pipeline's `tools.json` + `pipeline.json` + `code/pipeline.py`
  — so the engine has its data at runtime. ASL is always the pipeline's own
  `${asl_dir}/pipeline.asl.json`. New vars: `pipeline_dir`, `pipeline_name`. The S3 policy upload now
  also ships `sandbox.toml` + `grants.toml`.
- **`stacks/editorial-pipeline`** (new): composes `aegis-shared` + one `aegis-pipeline` per entry in
  `var.pipelines` (defaults to the editorial pipeline). Adding a pipeline = a new directory + one map
  entry; no module or shared-code change. Optional `rag`/`phoenix` modules wired as before.

## Removed (demo + superseded) — backed up to the session scratchpad first

- `deploy/terraform/handler/` (demo handler), `deploy/terraform/approver/` (demo dup),
  `deploy/terraform/examples/` (demo script).
- The entire flat-root **Phase-0 demo** Terraform (19 `*.tf`: main, lambda, iam, s3, kms, dynamodb,
  ledger, sqs, sfn, vpc, otel, approver, jit, rag, phoenix, build, versions, variables, outputs),
  `terraform.tfvars.example`, `AGENT-STACKS.md`; `README.md` replaced with a pipeline-oriented one.
- `modules/aegis-agent` (replaced by `aegis-pipeline`), `stacks/single-agent`, `stacks/multi-agent`,
  `agent-src/supervisor/`, and the whole `deploy/terraform/asl/` dir (single/multi/orchestration/demo
  ASL; editorial's ASL moved into its pipeline dir).

## Tests

- `deploy/terraform/agent-src/agent/test_agent.py` (8) — rewritten to drive the engine against a
  **synthetic** fixture bundle via `reload_bundle()`: specs derived from tools.json, agent_id from the
  event, terminal output shapes, profile isolation, plugin `run_tool`, locked unknown principal,
  default profile without a manifest. Proves the engine carries no baked-in pipeline.
- `pipelines/editorial/code/test_pipeline.py` (7) — the editorial plugin transforms + a **consistency**
  suite: every manifest tool exists in tools.json, is implemented by pipeline.py, and every principal
  matches broker.cedar and the ASL (order + one shared function).

## Verification

- `python3 -m unittest` green: engine 8, editorial 7; `py_compile` clean.
- `cargo test --workspace` green (RC=0); the broker acceptance test
  (`crates/aegis-broker/tests/editorial_pipeline.rs`, include paths repointed to `pipelines/editorial/`)
  still gates the matrix + ASL.
- `terraform fmt` clean; `terraform validate` on `stacks/editorial-pipeline` = **valid** (the fallback
  default instantiates `aegis-pipeline` against the real editorial files, so the bundle file-map is
  exercised). Run with `TF_DATA_DIR` on local disk to avoid SMB provider-load timeouts.

## Note / follow-ups

- The transform bodies in `pipeline.py` remain SCAFFOLD stubs (the model does the real work; these are
  the governed side effects).
- `docs/scripts/gen_agent_stacks_pdf.py` and `gen_codeexec_pdf.py` describe the removed demo/stacks and
  are now stale — left in place (doc generators, not handlers); prune in a docs pass.
