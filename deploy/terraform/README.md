# Aegis Phase-0 — AWS deployment (Terraform)

Deploys the Phase-0 inline plane to AWS and demonstrates it end to end:

- **`aegis-extension` as a Lambda layer** (an external extension, built with the
  `s3,otel,dynamodb` features — see `build.sh`). It boots at cold start, **fetches the policy
  artifacts from a versioned S3 bucket** (§2.4), and serves the inline-plane gate (`/mediate`,
  `/encode`, `/decide`, `/healthz`) on loopback. The same artifacts are also baked into the layer at
  `/opt/policies` as a fallback. The `dynamodb` feature persists per-thread taint/meter + per-agent
  quarantine to the checkpoint table so they survive a cold-start resume across a human-approval
  pause (fail-closed on a store outage).
- **A versioned, encrypted S3 bucket** that is the source of truth for `tools.json`,
  `broker.cedar`, and `egress-allowlist.toml`. Edit a policy, `terraform apply`, and the next
  cold start picks up the new version — no rebuild of the extension needed.
- **A Python agent Lambda** that plays the agent loop: it runs a scripted sequence of
  model-proposed tool calls through the gate and returns the decisions — allow, human-approve,
  and deny — including the lethal-trifecta catch.
- **A Step Functions state machine** (Architecture A, §1.3): the durable orchestrator. It fans
  out over the proposed tool calls (Map), mediates each through the agent Lambda, and **pauses
  on `.waitForTaskToken` for human approval** whenever the broker returns `human_approve` — the
  concrete home for `Decision::HumanApprove`. The ASL in `asl/agent_orchestration.asl.json` is a
  documented starting-point tree covering every core state type (Pass, Task, Choice, Map,
  Parallel, Wait, Succeed, Fail) plus Retry, Catch, fan-out, and the task-token pause.
- **A customer-managed KMS CMK** encrypting everything at rest: the S3 policy bucket, the
  DynamoDB checkpoint table, the SQS approval queue, all CloudWatch log groups, the Step
  Functions state, and the Lambda environment variables (§1.4, §2.4).
- **A KMS-encrypted DynamoDB checkpointer table** (composite PK/SK) — the LangGraph checkpointer
  from Architecture A. The Aegis gate reuses it (distinct sort keys
  `aegis#cap`/`aegis#meter`/`aegis#quarantine`) to durably hold per-thread taint/meter + quarantine;
  the existing `GetItem`/`PutItem` grants cover it, so no extra IAM.
- **An SQS approval queue + optional auto-approver Lambda** that resumes the task-token pause so
  the demo completes end to end (set `auto_approve = false` to approve manually).
- **(default on) A no-default-route VPC**: a private subnet with no IGW/NAT and a closed-egress
  security group, so egress containment (§2.4) is architectural, not just code. An **S3 gateway
  endpoint** lets the extension reach the policy bucket without any internet route. The function
  still runs and returns normally.

```
  Step Functions (Architecture A, CMK-encrypted)
     │  Map (fan-out over proposed tool calls)
     ▼
  ┌ agent Lambda (python) ┐   loopback   ┌ aegis-extension (layer) ┐
  │ handler.py: mediate 1 │ ───────────► │ /mediate  (broker)       │
  └───────────┬───────────┘  127.0.0.1   └─────────────────────────┘
              ▼ decision
     allow → execute   deny → record   human_approve → .waitForTaskToken
                                             │  token → SQS (CMK)
                                             ▼
                                   approver Lambda → SendTaskSuccess → resume
     (agent Lambda in a private, no-default-route subnet; checkpointer in DynamoDB, CMK)
```

## Prerequisites

- **Terraform** ≥ 1.5 and **AWS credentials** (`aws configure` / env vars) for the target account.
- **Rust** toolchain and **[cargo-lambda](https://www.cargo-lambda.info/)** (which uses Zig) to
  cross-compile the extension — Terraform runs it for you via `build.sh`:
  ```bash
  cargo install cargo-lambda        # one time (installs/uses Zig)
  ```
- The `aws` CLI (optional, for manual invokes).

> Building on an SMB-mounted workspace is slow. If this repo is on such a mount, export a
> local `CARGO_TARGET_DIR` before `terraform apply` — `build.sh` honors it:
> `export CARGO_TARGET_DIR=/tmp/aegis-target`

## Deploy

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars   # optional; edit to taste
terraform init
terraform apply
```

`architecture` must match what cargo-lambda builds (default `arm64`, i.e. Graviton). With
`run_demo = true`, apply finishes by invoking the function and printing the trace:

```bash
terraform output demo_trace
```

You will see, among other steps:

- `web.fetch` (untrusted) → **allow**, then `db.read_patient` on the **same thread** →
  **human_approve** with `is_trifecta: true` — the trifecta caught across two calls.
- the identical `db.read_patient` on a **fresh thread** → **allow** (single leg).
- `care-assistant` → `admin.rotate_keys` → **deny** (Cedar least privilege); the `system`
  agent → **human_approve** (allowed but irreversible).
- schema-invalid args, unknown tool, and untrusted-args-reaching-sensitive → **deny**.
- `/encode` turning `<script>` and `$(rm -rf /)` inert, rejecting `../../etc/passwd`.
- `/decide` stripping `leak=PHI_SECRET` from an allowlisted host and denying an unlisted one.

Invoke again anytime:

```bash
terraform output -raw invoke_command | bash
# or watch the extension + handler logs:
aws logs tail "$(terraform output -raw log_group)" --follow
```

## Run the Step Functions orchestration

Start an execution that fans out over the example tool calls (`asl/example-input.json`):

```bash
cd deploy/terraform
aws stepfunctions start-execution \
  --state-machine-arn "$(terraform output -raw state_machine_arn)" \
  --input file://asl/example-input.json
```

Watch it in the console (Graph view) or:

```bash
aws stepfunctions describe-execution --execution-arn <execution-arn-from-start>
```

What happens: the **Map** state mediates each proposed tool call through the agent Lambda. The
`t-trifecta` thread's second call returns `human_approve`, so that branch enters
**`.waitForTaskToken`** and the task token is written to the SQS approval queue. With
`auto_approve = true` the approver Lambda calls `SendTaskSuccess` and the branch resumes; the
clean-thread read is allowed, and the `admin.rotate_keys` call is denied by Cedar. The
execution then runs the **Parallel** post-processing branches, a **Wait**, and **Succeeds**.

### Approving manually

Set `auto_approve = false` to act as the human. The task token is delivered to the approval
queue; read it and resume:

```bash
QURL=$(aws sqs get-queue-url --queue-name "$(terraform output -raw project_name 2>/dev/null || echo aegis-demo)-approval" --query QueueUrl --output text)
MSG=$(aws sqs receive-message --queue-url "$QURL" --query 'Messages[0].Body' --output text)
TOKEN=$(echo "$MSG" | python3 -c 'import sys,json; print(json.load(sys.stdin)["taskToken"])')
aws stepfunctions send-task-success --task-token "$TOKEN" --task-output '{"approved":true}'
```

## Phase 1 (budget, evidence, hygiene)

The extension serves the Phase-1 gates too (`/sanitize`, `/meter/preflight`, `/meter/record`,
`/memory/gate`, `/ledger/verify`), and the meter circuit breaker + audit ledger are wired into
`/mediate`. Deploy adds:

- **`meter.toml`** — budget limits baked into the layer at `/opt/policies` and uploaded to the S3
  policy bucket (edit + `apply` to retune token/cost caps and circuit-breaker thresholds).
- **`ledger.tf`** — a KMS-encrypted **S3 Object Lock** bucket (`ledger_bucket` output) as the
  write-once immutable audit sink. The agent role gets `PutObject` only (no delete/overwrite);
  the tamper-evident hash chain the ledger produces is verifiable via `GET /ledger/verify`. The
  demo uses GOVERNANCE retention (1 day) so `terraform destroy` works — switch to COMPLIANCE
  mode with a real retention period in production.

The extension **persists each ledger entry** to the Object Lock bucket (built with the `s3`
feature; best-effort `PutObject` keyed `thread_id/<seq>-<hash>.json`), so the tamper-evident
chain is durable and write-once. `GET /ledger/verify` checks the in-process chain.

## Phase 2 (data-plane guards)

The extension serves the Phase-2 gates: `POST /redact` (PII/secret redaction of text/traces),
`POST /retrieval/authorize` (authorize a retrieval query in-scope), and `POST /supply/verify`
(digest-pin check). Deploy adds **`pins.json`** — the supply-chain pinset — baked into the layer
at `/opt/policies` and uploaded to the S3 policy bucket. Absent/empty pinset fails closed.

## KMS

A single customer-managed CMK (`alias/<project>-cmk`, rotation enabled) encrypts the S3 policy
bucket, the DynamoDB checkpoint table, the SQS queues, every CloudWatch log group, the Step
Functions state, and the agent Lambda's environment variables. Roles get least-privilege
`kms:Decrypt`/`GenerateDataKey`/`DescribeKey` on that key; the key policy additionally grants
the CloudWatch Logs service principal (which cannot be granted via IAM). See `kms.tf`.

## OpenTelemetry

The extension is built with the `otel` feature (see `build.sh`) so it can export OTLP traces +
metrics. By default no collector is attached, so it emits **structured logs only** (to
CloudWatch via the KMS-encrypted log group) with no errors. To turn on full tracing/metrics,
set `otel_collector_layer_arn` to an ADOT collector layer ARN for your region + architecture:
Terraform then attaches the layer, sets `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317`, and
grants the role least-privilege X-Ray + CloudWatch-metrics permissions (`otel.tf`). Traces land
in X-Ray and the `aegis.broker.decisions` metric in CloudWatch. See `Observability` in the
top-level README for the signal details.

## Teardown

```bash
terraform destroy
```

(With `enable_vpc = true`, destroy can take a few minutes while the Lambda ENIs are released.)

## Notes

- The extension binary must match the function architecture; both are driven by
  `var.architecture`.
- **Policy source of truth is S3.** The extension reads `s3://<bucket>/policies/*` at cold
  start (env `AEGIS_POLICY_S3_BUCKET` / `AEGIS_POLICY_S3_PREFIX`), using the function's
  execution-role credentials and — in VPC mode — the S3 gateway endpoint. If the bucket env is
  unset (or the extension is built without the `s3` feature) it falls back to the layer's
  `/opt/policies`. To update a policy: edit the file under `../../policies/`, `terraform apply`
  (uploads a new S3 version), and the next cold start loads it. Iterating on `broker.cedar`
  needs no extension rebuild.
- To force existing warm environments to pick up a new policy version immediately, publish a
  trivial function change (or briefly lower reserved concurrency) so Lambda cycles the sandbox.
- `Decision::HumanApprove` is where you integrate a Step Functions `waitForTaskToken` pause;
  this demo simply reports it.
- The gate is bound to `127.0.0.1` only — it is co-located with the function, never public.
