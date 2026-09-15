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

## Run / test (no AWS)

```bash
# Validate the policy set with the CLI.
aegis --dir pipelines/editorial/policies validate

# The pipeline's own tests: plugin transforms + manifest/policy/ASL consistency.
cd pipelines/editorial/code && python3 -m unittest test_pipeline

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
