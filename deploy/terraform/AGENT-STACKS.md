# Aegis agent scaffolds (single & multi-agent, multi-project)

Two ready-to-copy stacks for building agent Lambdas that talk to an LLM, mediate every tool call
through the Aegis inline plane, and pause for human approval via Step Functions. Both scale to
many projects: **shared infra is built once**, and **each project gets its own isolated stack**.

```
deploy/terraform/
  agent-src/                 shared Lambda source (packaged per project)
    agent/agent.py           the turn engine — single agent, and the worker in multi
    supervisor/supervisor.py multi: decomposes a request into worker sub-tasks
    start/start.py           API front door: POST /chat, GET /status
    approver/approver.py     demo auto-approver (resumes waitForTaskToken)
  asl/
    single_agent.asl.json    loop: turn → (approval pause) → loop → respond
    multi_agent.asl.json     supervisor → Map fan-out → per-worker loop → aggregate
  modules/
    aegis-shared/            built once per stack: extension layer + KMS CMK + policy bucket
    aegis-agent/             per project: Lambdas + SFN + DynamoDB + SQS + API + IAM
  stacks/
    single-agent/            ← scaffold 1: one agent per project
    multi-agent/             ← scaffold 2: supervisor + worker fan-out per project
```

## How it works (both scaffolds)

- **Step Functions** is the durable outer loop and owns the human-approval pause
  (`waitForTaskToken`). It invokes your agent Lambda for one *turn* at a time.
- **The agent Lambda** (`agent.py`) runs the LLM (Amazon Bedrock **Converse**) + tool loop
  in-process until it either returns a **final answer** (`status: done`) or hits a tool the broker
  sends to a human (`status: needs_approval`). Every proposed tool call goes through the
  **Aegis gate** on loopback (`/meter/preflight`, `/mediate`, `/decide`) — so a fooled model
  reaches nothing important, budgets are enforced, and the tamper-evident ledger records it.
- **Conversation state** is checkpointed in a **KMS-encrypted DynamoDB** table keyed by
  `thread_id`, so it survives the pause. The **Aegis gate state** — per-thread Rule-of-Two taint +
  meter budget and per-agent quarantine — is persisted to the **same table** (distinct sort keys
  `aegis#cap`/`aegis#meter`/`aegis#quarantine`, written by the extension's `dynamodb` feature) and
  rehydrated on a cold resume, so the trifecta/budget/quarantine are **not reset** when a
  `waitForTaskToken` approval resumes on a fresh execution environment; a store outage fails closed.
- **The tamper-evident audit ledger** is persisted to a per-project **S3 Object Lock** bucket
  (`AEGIS_LEDGER_BUCKET`); the agent/worker role gets `PutObject` only (append-only, write-once).
- **The API** is asynchronous (a turn may pause): `POST /chat` starts an execution and returns its
  arn; `GET /status?executionArn=…` returns `RUNNING` / `SUCCEEDED` + the answer.

**Multi-agent** adds a `supervisor` Lambda that decomposes the request into sub-tasks; Step
Functions fans out (`Map`) to a worker per sub-task (the same `agent.py`), each independently
gated and approvable. Coordination rides on the Step Functions state (the trust boundary).

## Multi-project isolation

`modules/aegis-shared` creates the shared **extension layer** (built once with `s3,otel,dynamodb`), the
**KMS CMK**, and the **policy S3 bucket**. Each project instantiated from `modules/aegis-agent`
gets its **own** Lambdas, state machine, DynamoDB table, SQS queue, API, IAM roles, and
**S3 Object Lock audit-ledger bucket** scoped to its resources; its **policies** are uploaded to the
shared bucket under `s3://…/<project>/…` and
the extension fetches them at cold start. Add a project by adding a key to the `projects` map — no
code changes.

## Deploy

Prereqs: Terraform ≥ 1.5, AWS credentials, and `cargo-lambda` (the shared module cross-compiles the
extension). Enable the Bedrock model in your account/region first.

> **Policies are blank starters.** The committed `policies/*` files are safe default-deny starters,
> so a stack deployed as-is has an agent that can't do anything. Point each project's `policy_dir`
> at its own populated files, or start from the reference set:
> `for f in policies/*.example.*; do cp "$f" "${f/.example/}"; done` (see `policies/README.md`).

```bash
cd deploy/terraform/stacks/single-agent      # or stacks/multi-agent
cp terraform.tfvars.example terraform.tfvars # add your projects
terraform init
terraform apply
terraform output projects                    # per-project api_base_url
```

Talk to a project:
```bash
API=$(terraform output -json projects | jq -r '."care-assistant".api_base_url')
EXEC=$(curl -s -XPOST "$API/chat" -d '{"message":"read patient abc-123 and summarize"}' | jq -r .executionArn)
curl -s "$API/status?executionArn=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$EXEC")" | jq
```

With `auto_approve = true`, a `human_approve` decision resumes automatically (demo). Set it false
to approve by hand (`aws stepfunctions send-task-success --task-token <token> …`; the token lands
in the project's approval SQS queue), or wire a real approval UI into `approver.py`.

## What you fill in

- **Tool implementations** in `agent.py::run_tool` (they're stubs) and the matching `TOOL_SPECS` /
  your project's `policies/tools.json` (+ `broker.cedar`, `egress-allowlist.toml`, `meter.toml`,
  `pins.json`, `honeypots.json`).
- **Auth** in front of the API (a JWT/IAM authorizer) — the scaffold API is unauthenticated.

## Egress containment (VPC) and observability (OTel)

Both are stack toggles (off by default):

- **`enable_vpc = true`** — the shared module creates a **no-default-route VPC** (two private
  subnets, no IGW/NAT) and the endpoints the agents actually need: **S3 + DynamoDB gateway
  endpoints** (policy fetch + checkpointer) and a **Bedrock interface endpoint** (the LLM call).
  Containment is the route table; a fooled model can't reach the internet. Agent/worker/supervisor
  Lambdas are placed in these subnets automatically. (CloudWatch Logs need no endpoint — Lambda
  delivers them out-of-band.)
- **`otel_collector_layer_arn = "arn:aws:lambda:…:aws-otel-collector-…"`** — attaches the ADOT
  collector layer to each agent, points the extension at it
  (`OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317`), and grants X-Ray + CloudWatch-metrics
  IAM. When combined with `enable_vpc`, the shared VPC also gets **X-Ray + CloudWatch interface
  endpoints** so the collector can export without internet.

## Code execution (isolated runner + honeypot canary, ASI05/ASI08)

Agent-generated code is **never run in the agent Lambda**. When the model calls the `code_run`
tool, `agent.py::run_code` (1) runs the deterministic **`/sandbox/validate`** gate on the loopback
plane, then (2) — only on `allow` — invokes a **separate, locked-down runner Lambda**
(`agent-src/runner/runner.py`). AWS Lambda is itself a Firecracker microVM, so that microVM
boundary is the "container"; isolation comes from **separation**, not a nested container:

- **Its own minimal role** — CloudWatch Logs only. No Bedrock, S3, DynamoDB, KMS, or ledger.
- **No network** — placed in the no-default-route VPC behind a **deny-all-egress** security group
  (`modules/aegis-shared` → `runner_security_group_ids`). Real network isolation needs
  `enable_vpc = true`; without a VPC a Lambda has internet egress by default.
- **`/tmp` only** — the ephemeral working dir, wiped before/after each run; the child runs under
  `python -I -B` with per-process rlimits (CPU / address-space / file-size / `NPROC=0`), a stripped
  env, and a wall-clock timeout.

Toggle with `enable_code_runner` (default `true`); size with `runner_timeout_seconds` /
`runner_memory_mb`. `code.run` is registered in the example `policies/tools.json` so the broker
does not refuse it as an unknown tool.

**Honeypot canary (ASI08).** Each project gets a unique decoy token (`random_id.canary` →
`AEGIS_CANARY`). The runner plants it as a decoy `~/.aws/credentials` in the working dir; the same
value is injected into the agent extension, which watches for it at two chokepoints:

- **`/sandbox/validate`** — a command touching a planted decoy (`.aws/credentials`, the
  `169.254.169.254` metadata IP, `/etc/shadow`, …, from `policies/honeypots.json`) is a **tripwire**,
  not a routine deny: an immutable `EntryKind::Tripwire` ledger entry **+ agent quarantine**.
- **`/mediate`** — the canary token appearing in later tool-call args (or an outbound URL, via the
  egress allowlist) is proof of exfiltration → the same tripwire + quarantine.

A quarantined agent's next `/mediate` is refused deterministically (killswitch); reintegration needs
fresh attestation **+** a human.

**Per-project honeypots.** Each project ships its own `policies/honeypots.json`; it is uploaded to
`s3://<bucket>/<project>/honeypots.json` and the extension fetches it per-project at cold start
(`load_honeypots_configured`), falling back to the layer-baked `/opt/policies/honeypots.json` (from
`build.sh`) if the S3 object is missing. The committed `policies/honeypots.json` is an **empty
starter** (`{"decoys": [], "canaries": []}`) — inert, so a fresh deploy has zero false positives
until you deliberately opt in. The curated default set lives beside it in
**`policies/honeypots.example.json`**; enable it by copying it in and trimming to taste:

```bash
cp policies/honeypots.example.json policies/honeypots.json   # or into <project>/policies/
```

Two kinds of canary coexist: **static** ones listed in the file (committed tripwire tokens, e.g.
`aegis-static-canary-…`) and the **runtime** per-project `AEGIS_CANARY` (unique `random_id`), merged
on top at startup. Decoys are case-insensitive substring matches on the command/target path (e.g.
`169.254.169.254`, `.aws/credentials`, `.ssh/authorized_keys`, `.kube/config`, `/proc/self/environ`),
so keep them high-signal — strings legitimate code never touches — to stay false-positive-free.

**Try it locally** (no AWS needed) with the dev gate:

```bash
# the committed policy files are blank starters — activate the example set first:
for f in policies/*.example.*; do cp "$f" "${f/.example/}"; done
# terminal 1 — run the inline-plane gate against the repo policies + a demo canary
AEGIS_GATE_ADDR=127.0.0.1:8080 AEGIS_POLICY_DIR="$PWD/policies" \
  AEGIS_CANARY=CANARY-demo-123 cargo run -p aegis-extension
# terminal 2
deploy/terraform/examples/code-exec-demo.sh
```

The demo shows: a benign snippet → `allow`; a snippet reading the decoy `.aws/credentials` →
`403 tripwire` + quarantine; and the now-quarantined agent's next `/mediate` refused. (The canary
step trips on `AEGIS_CANARY` alone; the decoy step needs a populated `honeypots.json`.)

> These stacks are new scaffolding and have not been `terraform apply`-ed from here (no
> terraform/aws/cargo-lambda in the authoring environment). Run `terraform init && terraform
> validate` and a first apply in a throwaway account/region to shake out any environment-specific
> details. The Lambda handlers and ASL are syntax-validated.
