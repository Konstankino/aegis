# 0005 — Wire the extension gate to emit typed spans

- **Date:** 2026-09-14
- **Status:** Implemented (green)
- **Type:** T0 wiring (extension)
- **Follows:** [0004-t0-trace-spine-core-additions.md](0004-t0-trace-spine-core-additions.md)

## What & why

T0 shipped the `aegis-trace` spine but nothing produced spans yet. This wires the loopback gate to
emit typed `Span`s into a `SpanEmitter`, so the plane's decisions become structured traces (the input
the eval harness, drift detection, and dashboards consume) instead of only ad-hoc logs.

## Change

- **`crates/aegis-extension/src/trace_sink.rs`** (new): `TracingCollector` implements
  `aegis_trace::TraceCollector` by forwarding each span to `tracing` on the `aegis.trace` target —
  so spans flow into the extension's existing structured-log / OTLP pipeline with no new transport.
  Fields are non-sensitive (decision labels/reasons are fixed strings; attributes are ids/counts).
- **`gate.rs`**:
  - `GateState` gains a `SpanEmitter`. `router()` spawns the non-blocking drain
    (`SpanEmitter::spawn(TracingCollector, 4096)`) and detaches it for the process life; a new
    `router_with_emitter()` lets tests inject an `InMemoryCollector`.
  - Helpers: `trace_id_for(thread_id)` (UUID v5 → a stable `TraceId`, so all spans for a thread group
    into one trace across handlers and cold restarts), `policy_from(verdict, reason)`, `emit_span`.
  - `/mediate` emits a `Stage::BrokerCheck` span (decision via `PolicyDecision`, risk `LLM06`, attrs
    tool/trifecta/steps). `/credentials/issue` emits a `Stage::CredentialIssue` span (decision via
    `From<JitDecision>`, risk `ASI03`, attr grant). Tenant is `TenantId::default()` until T1.
- **`main.rs`**: `mod trace_sink;`.
- **Deps**: `aegis-trace` + `uuid` added to the extension; the workspace `uuid` gains the `v5`
  feature (deterministic name-based ids).

## Design notes

- Emission is **best-effort and never on the hot path**: a full 4096-span buffer drops (and counts)
  rather than blocking the request — the property `aegis-trace` guarantees.
- The trace id is derived from the thread id, not random, so the many gate calls of one agent turn
  correlate without the Python handler passing a trace id.
- The pre-decision rejections in `/credentials/issue` (unknown grant, quarantine, store-unavailable)
  don't emit yet — a small follow-up; the decisioned paths all do.

## Verification

- `cargo test -p aegis-extension` green (39 tests, incl. 2 new: `mediate_emits_a_typed_broker_span`,
  `mediate_span_carries_the_deny_decision`); `cargo test --workspace` green.
- `clippy --workspace --all-targets -D warnings` clean; also clean with `-p aegis-extension
  --features jit`. `cargo fmt --all --check` clean.
- Non-breaking: existing gate behavior/responses unchanged; spans are additive.
