# 0029 — Editorial: S3 file-drop ingestion via EventBridge + JIT short-lived read

- **Date:** 2026-09-21
- **Status:** Done
- **Type:** Feature (pipeline + engine + Terraform), test-first
- **Follows:** [0028-ci-node20-deprecation-checkout-v5.md](0028-ci-node20-deprecation-checkout-v5.md)

## What & why

A second entry point for the editorial pipeline: **drop a `*.txt` into an S3 bucket → the pipeline
runs on that file's text.** The file is fetched by a dedicated principal using a **short-lived,
object-scoped credential** minted by the existing JIT broker — never a standing role — and every layer
is least-privilege. The pre-existing HTTP `POST /chat` path is unchanged.

The JIT machinery already existed (`aegis-jit`, `aegis-extension/src/jit.rs`, `/credentials/issue`,
the `grants.toml` artifact + `aegis jit` CLI); the gaps were the trigger, the read tool, the identity
step, and the Terraform to provision it. This change fills exactly those, gated so pipelines without a
source bucket are untouched.

## Change

**Flow:** `*.txt` drop → EventBridge rule (`<prefix>*.txt`) → Step Functions `StartExecution`
(input = `{source_bucket, source_key}`) → ASL `Choice` routes to a new **`agent-ingest`** stage → the
engine's `source.read` tool calls loopback `/identity/self` (sign) then `/credentials/issue` (exchange)
→ a ≤5-min, object-scoped STS session → `GetObject` → the text hands off into `A → B → C`.

- **Policies/manifest** (`pipelines/editorial/`): new `source.read` tool (`reads_sensitive`, leg B);
  `broker.cedar` permits it for **`agent-ingest` only**, and that principal for nothing else; `grants.toml`
  gains one STS grant `editorial-source-read` (audience `editorial-source`, scope `s3.read`, 300s,
  `s3:GetObject` on `{resource}`); `pipeline.json` prepends the ingest stage; the ASL adds `Route`
  (Choice) + `Ingest` (Task) + `SeedText`, leaving A/B/C byte-identical and `StartAt: "Init"`.
- **Engine** (`agent-src/agent/agent.py`): a `source.read` platform tool (`read_source`) that mints the
  short-lived credential and reads the object, fail-closed; a general terminal option **`"from": "result"`**
  so the fetched document is the stage output **verbatim** (never rewritten by the model); a `seed_input`
  branch for the S3 coordinates.
- **Extension** (`crates/aegis-extension/src/gate.rs`): a minimal loopback **`POST /identity/self`** that
  mints the agent's short-lived signed identity credential in Rust (canonical signing), so the Python
  engine never holds a private key. Its trust boundary is loopback isolation (verify checks only
  self-consistency), so it grants nothing on its own — the grant catalog + Rule-of-Two still gate every
  exchange.
- **Terraform** (`modules/aegis-pipeline/`, gated on new `var.source_bucket`): `jit.tf` (per-grant role
  assumable **only** by the agent role + `ExternalId`, scoped to `s3:GetObject` under the prefix; the
  agent role gains **only** `sts:AssumeRole` on it; `grants.toml` rendered with the real ARNs at deploy,
  or emptied to default-deny when off); `eventbridge.tf` (rule on `<prefix>*.txt`, StartExecution target
  with input transformer, an EventBridge role limited to `states:StartExecution`); `AEGIS_JIT_EXTERNAL_ID`
  on the agent Lambda; stack `pipelines` map + module wiring. `source_bucket=""` ⇒ **zero** new resources.

## Test-first

Regression tests were written and watched fail **before** the implementation (repo rule):
- `crates/aegis-broker/tests/editorial_pipeline.rs`: `agent-ingest` may call only `source.read`; no other
  principal may; the ASL routes S3 drops through `Ingest`.
- `crates/aegis-extension/src/gate.rs`: `/identity/self` issues a credential the JIT gate accepts through
  the full decision path; TTL is clamped to the 5-min ceiling and bound to the request facts.
- `agent-src/agent/test_agent.py`: `source.read` mints → reads (asserts the minted session is used, not a
  standing role); fail-closed on missing args, identity failure, credential deny, and S3 error; the
  `"from": "result"` terminal; the S3 seed. `pipelines/editorial/code/test_pipeline.py`: ingest
  stage/Route consistency + platform-tool recognition. `pipelines/editorial/test_run_local.py`: offline
  file seed.

## Coverage

New engine code (`read_source`, the `from: "result"` terminal, the S3 seed, the `source.read` arm) is at
**100% statement coverage** (measured with `coverage.py`); the new `/identity/self` path is exercised by
two dedicated gate tests (default-TTL, clamp, the seed loop, both deserialize shapes). The remaining
`agent.py` gaps are pre-existing platform tools deliberately left untouched.

## Verification

- `cargo test --workspace` (57 groups green), `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo fmt --all --check` — all clean (SMB: `CARGO_TARGET_DIR=$HOME/.aegis-target`).
- `python3 -m unittest` green in `agent-src/agent`, `pipelines/editorial/code`, `pipelines/editorial`.
- `aegis --dir pipelines/editorial/policies validate` → exit 0 (7 tools, 7 cedar statements, 1 grant).
- `terraform validate` (module + `stacks/editorial-pipeline`, `-backend=false`, `TF_DATA_DIR=/tmp/...`) →
  Success. With `source_bucket=""` no EventBridge/JIT resources are planned.
- Doc regenerated: `docs/aegis-editorial-pipeline-uk.pdf` gains a section on the S3/EventBridge + JIT flow.
