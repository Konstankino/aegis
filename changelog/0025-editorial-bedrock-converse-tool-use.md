# 0025 — Runnable Bedrock Converse tool-use driver for the editorial pipeline

- **Date:** 2026-09-17
- **Status:** Done
- **Type:** Reference implementation + tests
- **Follows:** [0024-future-improvements-catalogue.md](0024-future-improvements-catalogue.md)

## What & why

The editorial pipeline's Converse tool-use loop only existed inside the deployed Lambda engine
(`agent-src/agent/agent.py`), which needs the running inline-plane gate. There was no way to *run* and
watch the Amazon Bedrock **Converse API tool use** for editorial locally. This adds a self-contained,
runnable reference (+ tests) that drives A → B → C in one process.

## New — [pipelines/editorial/run_local.py](../pipelines/editorial/run_local.py)

Reads the SAME source of truth as production and needs nothing generated:
- `policies/tools.json` → the Bedrock Converse `toolConfig` (schemas; dotted↔underscore names);
- `policies/broker.cedar` → parsed into an allow-map, so **mediation reflects the real policy**
  (order mirrors the broker: unknown tool → schema → policy-deny);
- `pipeline.json` → per-stage system prompt + which tools the model sees + the terminal handoff;
- `code/pipeline.py` → the tool implementations (`run_tool`).

Per stage it runs the loop `converse → toolUse → mediate → run_tool → toolResult`, ending at the
**terminal** handoff whose args become the stage output (`{output}` for A/C, `{candidates}` for B),
which threads into the next stage exactly as the Step Functions ASL does. Two clients:
- **`LiveConverse`** — the real `bedrock-runtime.converse()` (boto3 imported lazily; `--live`);
- **`MockConverse`** — a scripted, offline stand-in (default) that does a believable tiny transform, so
  the demo and tests run with no AWS.

```bash
python3 pipelines/editorial/run_local.py "he go to the stor yesterday"          # offline mock
python3 pipelines/editorial/run_local.py --live --region us-east-1 --model … "…" # real Bedrock
```

It prints the mediated tool calls (allow/deny with reason), the per-stage outputs, and the final text.
It is a top-level driver (not under `code/`), so the `aegis-pipeline` bundle never ships it in the
Lambda zip.

## Tests — [pipelines/editorial/test_run_local.py](../pipelines/editorial/test_run_local.py) (5, no AWS)

- `toolConfig` is built from `tools.json` (converse names + schema + terminal from the manifest);
- the allow-map is parsed from `broker.cedar` (exact per-agent sets);
- `mediate` allow / policy-deny / unknown-tool / schema-violation;
- the full A→B→C flow over the mock (six allowed calls in order; B → `{candidates}`; C publishes the
  enriched candidate);
- **deny path:** a rogue "model" for agent-a proposing `publish_final` is DENIED, then the legit
  `send_to_agent_b` is allowed and the stage still completes.

## Docs

`pipelines/editorial/README.md` gains a "Run the Bedrock Converse tool-use loop locally" section.

## Verification

`python3 -m unittest` green: `test_run_local` (5), `test_pipeline` (7); `py_compile` clean. Rust /
Terraform untouched.

## Note

`MockConverse` does a naïve transform (capitalise + period; append a fun-fact) — it demonstrates the
*mechanics* of tool use, not real editing. With `--live` the model does the real grammar/enrichment/
referee work; the tool bodies remain the governed side effects. See E2 in
[future-improvements.md](../docs/future-improvements.md).
