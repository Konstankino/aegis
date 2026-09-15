# Parallel-review pipeline (A → B ∥ C → D)

A fan-out/fan-in chain that improves a piece of text with **two writers working concurrently** and a
referee that picks the winner — governed end-to-end by Aegis so each agent has exactly the permissions
it needs.

```
                       ┌──▶  Agent B  ──submit.candidate──┐
   text ──▶ Agent A ───┤     (writer)                     ├──▶  Agent D  ──publish.final──▶ out
           (dispatch)  └──▶  Agent C  ──submit.candidate──┘     (referee)
                             (writer)
```

- **Agent A — intake.** Lightly corrects grammar, then `dispatch.to_workers` hands the text to the pool.
- **Agents B and C — writers (peers).** Each independently produces a better version and calls
  `submit.candidate`. They run **at the same time** and have **identical permissions**.
- **Agent D — referee.** Once both candidates are in, chooses the best and `publish.final`.

## The parallelism is in the ASL, not the engine

The generic engine ([`agent.py`](../../deploy/terraform/agent-src/agent/agent.py)) is unchanged — it
runs **one principal per invocation**. The fan-out/fan-in lives entirely in
[`asl/pipeline.asl.json`](asl/pipeline.asl.json): a Step Functions **`Parallel`** state runs
`AgentB_Improve` and `AgentC_Improve` as two branches, each invoking the **same** `${agent_lambda_arn}`
with a different `agent_id`. The branch outputs are collected (`ResultSelector: "$[*].text"`) into
`candidates` and handed to the referee. Same one agent Lambda; four Cedar principals.

## The least-privilege matrix

[`policies/broker.cedar`](policies/broker.cedar) is default-deny:

| Tool | Agent A | Agent B | Agent C | Agent D |
|---|:---:|:---:|:---:|:---:|
| `grammar.correct` | ✅ | — | — | — |
| `dispatch.to_workers` (terminal) | ✅ | — | — | — |
| `improve.text` | — | ✅ | ✅ | — |
| `submit.candidate` (terminal) | — | ✅ | ✅ | — |
| `referee.select` | — | — | — | ✅ |
| `publish.final` (terminal) | — | — | — | ✅ |

Agents B and C are **peers** — identical rights, isolated from each other and from the referee's
`publish.final`. A confused writer that emits `publish.final` is denied by the broker deterministically.

## Files

| File | Role |
|---|---|
| [`policies/`](policies) | tools.json (schemas), broker.cedar (authorization), egress/meter/sandbox/grants/pins/honeypots |
| [`pipeline.json`](pipeline.json) | manifest: per stage → principal, prompt, tools, terminal handoff (+ `branch`) |
| [`code/pipeline.py`](code/pipeline.py) | the pipeline's tool implementations |
| [`asl/pipeline.asl.json`](asl/pipeline.asl.json) | the `Parallel` fan-out/fan-in state machine |

## Run / test (no AWS)

```bash
aegis --dir pipelines/parallel-review/policies validate
cd pipelines/parallel-review/code && python3 -m unittest test_pipeline   # plugin + consistency + engine E2E
cargo test -p aegis-broker --test parallel_review                        # the broker acceptance gate
```

## Deploy

Add it alongside editorial in the stack's `var.pipelines`:

```hcl
pipelines = {
  editorial      = { pipeline_dir = "../../../../pipelines/editorial" }
  parallel_review = { pipeline_dir = "../../../../pipelines/parallel-review" }
}
```

Then `terraform apply` in [`stacks/editorial-pipeline`](../../deploy/terraform/stacks/editorial-pipeline).
No engine, module, or shared-code change is needed.
