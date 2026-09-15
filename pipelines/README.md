# Pipelines

An Aegis **pipeline** is a linear chain of agents — each a Cedar **principal**, not a separate Lambda —
that run over the one generic agent engine. Everything specific to a pipeline lives in its own
directory here; the engine, the Terraform module, and the stack are all generic and never change when
you add one.

```
pipelines/<name>/
  policies/            # the Aegis policy set the broker enforces
    tools.json         #   tool schemas (the single source of truth for tool shapes)
    broker.cedar       #   per-principal least-privilege authorization
    egress-allowlist.toml  meter.toml  pins.json  sandbox.toml  grants.toml  honeypots.json
  pipeline.json        # manifest: per stage -> agent_id, state, system prompt, tools, terminal handoff
  code/
    pipeline.py        # the ONLY pipeline-specific Python: run_tool(fq, args, agent_id, thread_id)
    test_pipeline.py   # plugin + manifest/policy/ASL consistency tests
  asl/
    pipeline.asl.json  # the Step Functions state machine (one Task per stage, same ${agent_lambda_arn})
```

## How the pieces fit

- **`tools.json`** defines each tool's JSON schema. The engine builds the model's Bedrock Converse
  `toolConfig` from it — there are **no tool specs hard-coded in Python.**
- **`pipeline.json`** says, per stage: the `agent_id` (Cedar principal), the `state` name in the ASL,
  the `system` prompt, which `tools` that principal may see (a subset of `tools.json`, with optional
  descriptions), and the `terminal` handoff whose args become the stage's output
  (`{tool, output_key, arg_key}` → `{output: …}` or `{candidates: […]}`).
- **`code/pipeline.py`** implements the pipeline's own tools: `run_tool(fq, args, agent_id, thread_id)`
  returns a dict for a tool it owns, or `None` to fall through to the engine's platform tools
  (`web.fetch`, `code.run`, `log.write`).
- **`asl/pipeline.asl.json`** invokes the **same** agent function once per stage with a different
  `agent_id`. The broker applies each principal's policy from `broker.cedar` on every tool call.

The engine is authoritative-agnostic: the profile in `pipeline.json` is only what the *model* is
shown; the **broker** independently enforces `broker.cedar`, so an off-lane call is denied even if the
model is confused.

## Add a pipeline

1. `cp -R pipelines/editorial pipelines/<name>` and edit the four inputs above.
2. Add an entry to `var.pipelines` in
   [`deploy/terraform/stacks/editorial-pipeline`](../deploy/terraform/stacks/editorial-pipeline):
   `<name> = { pipeline_dir = "../../../../pipelines/<name>" }`.
3. `terraform apply`. No engine, module, or shared-code change is needed.

## Test a pipeline (no AWS)

```bash
cd pipelines/<name>/code && python3 -m unittest test_pipeline    # plugin + consistency
cd deploy/terraform/agent-src/agent && python3 -m unittest test_agent   # the generic engine
cargo test -p aegis-broker --test editorial_pipeline             # the broker acceptance gate
```

## Pipelines

- **[editorial](editorial/README.md)** — a linear three-agent A→B→C chain: grammar correction → fact
  enrichment → referee that publishes the chosen version.
- **[parallel-review](parallel-review/README.md)** — a fan-out/fan-in chain A→(B∥C)→D: an intake
  agent dispatches to two peer writers that improve the text **concurrently** (a Step Functions
  `Parallel` state), then a referee picks the best. Shows that parallelism lives in the ASL — the
  engine is unchanged.
