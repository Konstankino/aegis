# 0030 — Editorial is S3-ingestion-only; HTTP /chat entry made optional

- **Date:** 2026-09-21
- **Status:** Done
- **Type:** Refactor (scope reduction), test-first
- **Follows:** [0029-editorial-s3-eventbridge-jit-ingest.md](0029-editorial-s3-eventbridge-jit-ingest.md)

## What & why

The editorial pipeline's **only** use case is S3 file ingestion, so its alternative entry — the
synchronous HTTP `POST /chat` / `GET /status` front door — is removed from the editorial deployment.
The `aegis-pipeline` module stays generic (parallel-review keeps HTTP), so the HTTP entry is now
**optional behind a variable** rather than deleted.

## Change

- **Editorial ASL** (`pipelines/editorial/asl/pipeline.asl.json`): now S3-ingestion-only. `StartAt` is
  the `Ingest` stage; the HTTP seed states (`Init`, `Route` Choice, `SeedText`) are gone. A run is
  started only by the EventBridge `*.txt` trigger, whose input `{source_bucket, source_key}` flows
  straight into `agent-ingest → A → B → C`.
- **Module** (`modules/aegis-pipeline/`): new `var.enable_http_entry` (bool, default **true**). It gates
  the whole HTTP front door — `apigw.tf` (API Gateway, routes, stage, integration, permission), the
  `start` Lambda + its log group, and the `start` IAM role/policy — plus the `api_base_url` output
  (null when off). Nothing else changes; `start.py` stays in the module for pipelines that keep HTTP.
- **Stack** (`stacks/editorial-pipeline/`): the `pipelines` map gains `enable_http_entry`
  (`optional(bool, true)`); the built-in editorial entry sets it **false** (S3-only). Other pipelines
  (e.g. parallel-review added to `var.pipelines`) default to `true` and are unaffected.
- **Docs**: PDF §16 reframed from "two inputs" to "single, event-driven entry".

## Test-first

Updated the ASL assertions **before** changing the state machine:
- `crates/aegis-broker/tests/editorial_pipeline.rs`: `asl_entry_is_s3_ingestion_only` asserts
  `StartAt == "Ingest"`, the ingest Task hands off to `AgentA_Grammar`, and there are **no** leftover
  `Init`/`Route`/`SeedText` states; the linear-chain test now expects `StartAt == "Ingest"`.
- `pipelines/editorial/code/test_pipeline.py`: the ingest test asserts `StartAt == "Ingest"` and that
  `Route`/`SeedText` are absent.

## Verification

- `cargo test -p aegis-broker --test editorial_pipeline` (8) and `cargo test --workspace` green;
  `clippy -D warnings`, `fmt --all --check` clean.
- `python3 -m unittest` green in `pipelines/editorial/code`, `agent-src/agent`, `pipelines/editorial`.
- `terraform validate` (module + stack) Success; with `enable_http_entry=false` no API Gateway / start
  Lambda / start role is planned.
- PDF regenerated.
