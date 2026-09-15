# Aegis — deploying pipelines to AWS (Terraform)

Aegis deploys **agentic pipelines**: a linear chain of Cedar principals (`agent-a → agent-b → …`)
running over **one** agent Lambda, with every tool call mediated by the Aegis inline-plane extension
and human approval paused/resumed by Step Functions. Each pipeline is self-contained under
[`pipelines/<name>/`](../../pipelines) — its policies, its `pipeline.json` manifest, its
`code/pipeline.py` tool implementations, and its `asl/pipeline.asl.json` state machine. The generic
engine ([`agent-src/agent/agent.py`](agent-src/agent/agent.py)) builds the model's tool registry from
the pipeline's `tools.json`; **nothing pipeline-specific is baked into the engine, the module, or the
stack.**

## Layout

```
deploy/terraform/
  build.sh                     # cross-compiles the aegis-extension layer (cargo-lambda)
  agent-src/                   # the shared Lambda sources
    agent/agent.py             #   the generic turn engine (+ its unit tests)
    start/ approver/ runner/   #   API front door, auto-approver, isolated code runner (ASI05)
  modules/
    aegis-shared/              # L0-L2: extension layer, KMS CMK, policy bucket, optional VPC (once)
    aegis-pipeline/            # L3: per-pipeline agent + Step Functions + tables + API (reusable)
    rag/  phoenix/             # optional, separately layered (see docs/infrastructure-layers.md)
  stacks/
    editorial-pipeline/        # composes shared + one aegis-pipeline module per pipeline
```

## Deploy

```bash
cd stacks/editorial-pipeline
cp terraform.tfvars.example terraform.tfvars   # optional; defaults deploy the editorial pipeline
terraform init
terraform apply
```

By default the stack deploys the **editorial** pipeline (`pipelines/editorial`). Requires the AWS CLI
credentials, an `arm64`/`x86_64` toolchain for `cargo-lambda`, and (for egress containment or the
RAG/Phoenix modules) `enable_vpc = true`.

## Add another pipeline

1. Create `pipelines/<name>/` with `policies/`, `pipeline.json`, `code/pipeline.py`, and
   `asl/pipeline.asl.json` (copy `pipelines/editorial/` as a template).
2. Add an entry to `var.pipelines` in the stack pointing `pipeline_dir` at it:

   ```hcl
   pipelines = {
     editorial   = { pipeline_dir = "../../../../pipelines/editorial" }
     my_pipeline = { pipeline_dir = "../../../../pipelines/my-pipeline" }
   }
   ```

No module or shared-code change is needed — that is the point of the generic `aegis-pipeline` module.

## Validate

```bash
cd stacks/editorial-pipeline
terraform init -backend=false
terraform validate
```

On a slow (e.g. SMB-mounted) working copy, point Terraform's data dir at local disk so provider
schema loading does not time out: `TF_DATA_DIR=/tmp/tfd terraform init -backend=false && TF_DATA_DIR=/tmp/tfd terraform validate`.
