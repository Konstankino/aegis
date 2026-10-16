# 0031 — Editorial S3 ingest: TOCTOU version pin (versionId/etag)

- **Date:** 2026-09-21
- **Status:** Done
- **Type:** Security fix (TOCTOU), test-first
- **Follows:** [0030-editorial-s3-only-http-entry-optional.md](0030-editorial-s3-only-http-entry-optional.md)

## What & why

**TOCTOU:** between the S3 `Object Created` event (time of check) and when `agent-ingest` actually
reads the object (time of use), the object at that key can be overwritten — so the pipeline could
process a *different* file than the one that triggered the run (worse under retries, throttling, or a
cold-start/HITL pause that widens the window). Fix: carry the object's **versionId** (and **etag**)
from the event as **authoritative** state, and pin the read to that exact object.

## Change

- **EventBridge** (`modules/aegis-pipeline/eventbridge.tf`): the input transformer now also extracts
  `object.version-id` and `object.etag` → execution input `{source_bucket, source_key,
  source_version_id, source_etag}`. (Also fixed the placeholders to be quoted so a missing version-id
  on an unversioned bucket renders as `""` instead of breaking the JSON.)
- **ASL** (`pipelines/editorial/asl/pipeline.asl.json`): the `Ingest` Task passes `source_version_id`
  and `source_etag` in its Payload.
- **Engine** (`agent-src/agent/agent.py`):
  - `read_source` pins the read — `GetObject(VersionId=…)` when a version is present (exact version),
    else a conditional `GetObject(IfMatch=etag)` that fails closed (412) if the object changed.
  - **Authoritative injection:** the handler overwrites the `source.read` tool args with the event's
    `bucket/key/version_id/etag` **before mediation**, so the read cannot be redirected or un-pinned by
    a tampered/stale model call. Because the event carries this on every (re)invocation, a **cold-start
    or retry re-applies the pin**, and the value is persisted into `pending`, so a **HITL resume** reads
    the same version.
- **Policy** (`tools.json`, `grants.toml`, `jit.tf`): `source.read` schema gains optional `version_id`
  / `etag`; the grant's session policy and the per-grant IAM role add `s3:GetObjectVersion` (required to
  read a specific version).

## Test-first

- `agent-src/agent/test_agent.py`: `read_source` pins `VersionId` (preferred), falls back to `IfMatch`
  on etag, and reads the current object when neither is given; a handler test proves the **event source
  overrides a tampered model call** (mediation and `GetObject` both see the event's authoritative
  bucket/key/version, never the attacker's). All written and watched fail before the fix.
- `crates/aegis-broker/tests/editorial_pipeline.rs`: the version/etag pin passes schema mediation.

## Coverage

New TOCTOU engine code: **100% statement coverage** (`coverage.py`).

## Verification

- `cargo test --workspace` (56 groups), `clippy -D warnings`, `fmt --all --check` clean.
- `python3 -m unittest` green (engine 22, editorial, run_local, parallel-review).
- `aegis --dir pipelines/editorial/policies validate` exit 0; `terraform validate` Success.
- PDF §16 updated with the TOCTOU/version-pin explanation.
