# Editorial pipeline (A → B → C)

A three-agent chain that improves a piece of text, governed end-to-end by Aegis so each sub-agent has
**exactly** the permissions it needs and nothing more.

```
   text ──▶  Agent A  ──send.to_agent_b──▶  Agent B  ──send.to_agent_c──▶  Agent C  ──publish.final──▶ out
            (grammar)                     (enrichment)                    (referee)
         correct grammar              add interesting, sound facts     choose the best version
```

- **Agent A — grammar.** Corrects the grammar, hands the corrected text to B.
- **Agent B — enrichment.** Adds interesting, accurate facts, hands **both** versions to C as candidates.
- **Agent C — referee.** Chooses the best candidate and publishes the final.

The three agents are Cedar **principals** on one shared agent Lambda — there are no per-agent
functions. Step Functions ([`asl/pipeline.asl.json`](asl/pipeline.asl.json)) invokes that one function
per stage with a different `agent_id`; the broker applies each principal's policy from
[`policies/broker.cedar`](policies/broker.cedar).

## The files

| File | Role |
|---|---|
| [`policies/tools.json`](policies/tools.json) | Tool schemas (source of truth); the engine builds the model's tool list from these. |
| [`policies/broker.cedar`](policies/broker.cedar) | Default-deny per-principal authorization (the enforced matrix). |
| [`pipeline.json`](pipeline.json) | Manifest: each stage's principal, prompt, visible tools, and terminal handoff. |
| [`code/pipeline.py`](code/pipeline.py) | The pipeline's tool implementations (`run_tool`). |
| [`asl/pipeline.asl.json`](asl/pipeline.asl.json) | Linear A→B→C state machine over one `${agent_lambda_arn}`. |
| other `policies/*` | egress allowlist, meter budget, sandbox, grants (none needed), honeypots, pins. |

## The least-privilege matrix

`broker.cedar` is default-deny; each agent may invoke only what it is explicitly permitted:

| Tool | Agent A | Agent B | Agent C |
|---|:---:|:---:|:---:|
| `grammar.correct` | ✅ | — | — |
| `send.to_agent_b` (terminal) | ✅ | — | — |
| `enrich.add_facts` | — | ✅ | — |
| `send.to_agent_c` (terminal) | — | ✅ | — |
| `referee.select` | — | — | ✅ |
| `publish.final` (terminal) | — | — | ✅ |

The order A → B → C is enforced by **which handoff each agent holds**, not by a prompt: A holds only
`send.to_agent_b`, B only `send.to_agent_c`, C only `publish.final`. A confused Agent A that emits
`publish.final` is denied by the broker deterministically, before any effect.

## Run the Bedrock Converse tool-use loop locally

[`run_local.py`](run_local.py) is a self-contained reference that drives the **Amazon Bedrock Converse
API tool-use** loop for A → B → C in one process. It reads the SAME source of truth as production —
`policies/tools.json` (→ the Converse `toolConfig`), `policies/broker.cedar` (→ least-privilege
mediation), `pipeline.json` (per-stage prompt + tools + terminal), and `code/pipeline.py` (the tool
implementations) — and prints the mediated tool calls, the per-stage outputs, and the final text.

```bash
# Offline: a scripted mock model — no AWS, deterministic (what the tests use).
python3 pipelines/editorial/run_local.py "he go to the stor yesterday"

# Live: the real Bedrock Converse API (needs AWS creds + model access).
python3 pipelines/editorial/run_local.py --live --region us-east-1 \
        --model anthropic.claude-sonnet-4-5-20250929-v1:0 "he go to the stor yesterday"
```

Each stage runs the loop `converse → toolUse → mediate → run_tool → toolResult`, ending at its
*terminal* handoff whose args become the stage output (`{output}` for A/C, `{candidates}` for B), which
threads into the next stage exactly as the Step Functions ASL does. By default mediation is in-process
(broker.cedar parsed locally).

### Through the REAL Aegis gate (`--gate`)

Instead of the in-process check, `--gate` routes every `/mediate` and `/output/scan` to the actual
inline-plane gate — the same endpoints the deployed engine calls. Start the gate locally over this
pipeline's policies (dev mode; no Lambda, no AWS), then point the driver at it:

```bash
# 1) Serve the gate over the editorial policy set (leave running).
CARGO_TARGET_DIR=$HOME/.aegis-target \
AEGIS_GATE_ADDR=127.0.0.1:8785 \
AEGIS_POLICY_DIR="$PWD/pipelines/editorial/policies" \
cargo run -p aegis-extension

# 2) In another shell — drive A→B→C through the gate (add --live for real Bedrock).
python3 pipelines/editorial/run_local.py --gate 127.0.0.1:8785 "he go to the stor yesterday"
```

All A/B/C stages share one `thread_id` (so the gate accumulates Rule-of-Two taint across the chain, as
in production), and each tool call is authorised as its own principal from the real `broker.cedar`.

## Run / test (no AWS)

```bash
# Validate the policy set with the CLI.
aegis --dir pipelines/editorial/policies validate

# The pipeline's own tests: plugin transforms + manifest/policy/ASL consistency.
cd pipelines/editorial/code && python3 -m unittest test_pipeline

# The local Bedrock Converse tool-use driver (mock model, no AWS).
cd pipelines/editorial && python3 -m unittest test_run_local

# The generic engine + the broker acceptance gate.
cd deploy/terraform/agent-src/agent && python3 -m unittest test_agent
cargo test -p aegis-broker --test editorial_pipeline
```

## Deploy

The [`stacks/editorial-pipeline`](../../deploy/terraform/stacks/editorial-pipeline) stack deploys this
pipeline by default:

```bash
cd deploy/terraform/stacks/editorial-pipeline && terraform init && terraform apply
```

If you make `publish.final` high-consequence, add a `RequestApproval` / `Resume` pair to
`asl/pipeline.asl.json` so the referee's publish pauses for a human via `waitForTaskToken`.
