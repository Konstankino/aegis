# 0004 — T0: aegis-trace spine + non-breaking aegis-core additions

- **Date:** 2026-09-14
- **Status:** Implemented (green)
- **Type:** Foundation (new crate + non-breaking core additions)
- **Roadmap:** Track T0 in [0003-reconciled-roadmap.md](0003-reconciled-roadmap.md)

## What & why

T0 is the one true foundation gap the reconciled roadmap identified: a typed observability spine and
a shared decision/OWASP/tenant vocabulary that the evaluation harness, drift detection, per-tenant
dashboards, and the gateway all depend on. Built additively so the existing 18-crate tree and the
Lambda extension compile unchanged.

## aegis-core additions (non-breaking)

- `TenantId` — an operator-assigned **slug** newtype (validated `[a-z0-9._-]`, 1–64 chars),
  `Default = "default"` so single-tenant deployments behave exactly as before; serde validates on
  deserialize (fails closed). **Design note:** chose a slug over the roadmap's literal "UUID" for
  tenant ids — they appear in config paths, ACLs and audit and must be human-meaningful; `TraceId`/
  `SpanId` remain UUIDs.
- `PolicyDecision::{Allow, Deny(reason), Escalate(reason)}` — the plane-wide outcome vocabulary, with
  `deny`/`escalate` constructors and `is_allow`/`is_deny`/`is_escalate`/`reason`/`label`. It does
  **not** replace the rich per-domain enums; they map into it.
- `Owasp` — typed `LLM01..LLM10` / `ASI01..ASI10` with `code()`, `title()`, `Display`, and `ALL`
  (for generating the coverage matrix). serde renames to the codes.
- New error variant `AegisError::InvalidId`.

## New crate: aegis-trace

- `TraceId`/`SpanId` — UUID v4 newtypes (`new`/`nil`/`as_uuid`/`from_uuid`/`Display`).
- `Stage` (Ingress·BrokerCheck·Retrieval·Prompt·LlmCall·OutputScan·Egress·CredentialIssue·Other),
  `Span` (uniform record: stage + name + timing + `PolicyDecision` + `Vec<Owasp>` + open `attributes`
  bag + error, with builders), `Trace` (spans + tenant + request attributes; `outcome()` =
  most-severe decision, `risks()` = distinct OWASP ids).
  - **Design note:** `Span` is a uniform stage-tagged record with an attribute bag, not the roadmap's
    per-stage enum — so one collector stores every stage and the eval harness reads any span
    generically (the OpenTelemetry model). Documented in the crate.
- `trait TraceCollector` (pluggable sink) + `InMemoryCollector` (test/local; clonable, inspectable).
- `SpanEmitter` — **non-blocking**: a bounded `sync_channel` + background drain thread; `emit` uses
  `try_send` and drops (bumping a counter) rather than stalling the request path. `flush()` for
  deterministic tests/shutdown; `CollectorHandle::join()`. OTel/Postgres collectors are later tracks.
- No I/O and no internal clock — timestamps are caller-supplied, so traces are deterministic; a
  `now_ms()` helper is offered for hosts.

## From adapters (make the vocabulary usable, non-breaking)

`impl From<_> for aegis_core::PolicyDecision` added in each decision-producing crate:
`broker::Decision` (HumanApprove→Escalate), `egress::EgressDecision`, `sandbox::ExecDecision`,
`identity::AuthDecision`, `jit::JitDecision` (Grant→Allow, HumanApprove→Escalate). Each with a test.

## Verification

- `cargo test --workspace` green (added aegis-trace + core t0 tests + 5 adapter tests); broker
  acceptance still green.
- **Coverage:** `aegis-core` 95.9% lines, `aegis-trace` 99.1% lines (`cargo llvm-cov`, clean build).
- `clippy --workspace --all-targets -D warnings` clean; `cargo fmt --all --check` clean.
- Non-breaking: no existing crate or the extension changed behavior; only additive types + trait impls.
- Workspace `Cargo.toml`: new member `crates/aegis-trace`, new pinned dep `uuid` (v4 + serde).

## Next (T0 wiring, optional follow-up)

Wire the extension gate to emit typed `Span`s into a `SpanEmitter` (currently it emits OTel spans);
then T1 (thread `TenantId` through `Session`/gate/config) and T3 (`aegis-eval`, `PhiLeakEvaluator`
first) can begin.
