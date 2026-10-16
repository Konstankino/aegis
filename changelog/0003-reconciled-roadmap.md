# 0003 — Reconciled roadmap (proposed plan × shipped codebase)

- **Date:** 2026-09-14
- **Status:** Delivered (planning artifact)
- **Type:** Roadmap / planning
- **Artifact:** external 22-week build-plan artifact (shared by the user)

## What & why

The user shared an external 22-week build-plan artifact (a multi-tenant / healthcare-RAG conception of
Aegis, "Konstankino Associates retained IP") and asked to "build phase 1." That roadmap's Phase 1
(`aegis-core` + `aegis-meter` around `Trace`/`Span`/`TenantId`/`PolicyDecision`, Postgres
`TraceCollector`) **conflicts** with the shipped crates (`Provenance`/`Capability`/`Consequence`;
`Limits`/`Meter`/`Verdict`), which 18 other crates + the Lambda extension depend on. Building it
literally would either rewrite the foundation (breaking) or fork a parallel core (confusing).

The user then asked to **stop and prepare a new roadmap combining the established codebase/patterns
with the proposed roadmap's new data structures and design decisions.** This changelog records that
synthesis; the deliverable is the published artifact above.

## Key finding

~70% (est.) of the proposed roadmap already exists in the repo, often in a stronger deterministic
form. The genuinely-new work is: a typed **Trace/Span observability spine**, a **TenantId** dimension,
a unified **PolicyDecision** vocabulary, and **two new product crates** (`aegis-eval`,
`aegis-gateway`) — plus `aegis-trace` and `aegis-prompt`.

## The merged plan (six tracks, re-sequenced)

- **T0 — Trace spine + shared vocabulary** *(new `aegis-trace`; extend `aegis-core`, `aegis-extension`)*:
  `Trace`/`Span`(enum per stage)/`TraceId`/`SpanId`/`TenantId`, `trait TraceCollector` + `SpanEmitter`,
  `PolicyDecision::{Allow,Deny,Escalate}` via `From` adapters, `enum Owasp`. The one true foundation gap.
- **T1 — Multi-tenancy** *(extend broker/meter/killswitch/cli)*: `Session.tenant_id`, per-tenant Cedar
  ACLs + `Limits`, `Target::{Tenant,Global}` kill-switch scope, per-tenant `PolicyDir`.
- **T2 — RAG governance gaps** *(new `aegis-prompt`; extend redact/retrieval)*: `PromptRegistry`,
  `ContextWindow` builder, `ModelRoute`; PHI patterns (`Mrn`/`Dob`) + cross-tenant scan; `RetrievalBackend`
  trait, ingestion gate, `EmbeddingVersion`.
- **T3 — Evaluation harness** *(new `aegis-eval`)*: `trait Evaluator`→`EvalScore`, `PhiLeakEvaluator`
  (deterministic, first), faithfulness/relevance/medical judges, `GoldenSet`, sampler, `ThresholdEngine`,
  drift. Depends on T0; joins `aegis-redteam` in CI.
- **T4 — Edge** *(new `aegis-gateway`)*: MCP JSON-RPC adapter, REST API, `ApiKey`+`TenantId` auth,
  gateway rate-limit over `Meter`. Peer host to `aegis-extension`.
- **T5 — Hardening & evidence** *(extend redteam/docs)*: expanded attack corpus, chaos tests for
  breaker/kill-switch, generated OWASP matrix, per-tenant dashboard over OTel + Postgres traces.

## Design decisions reconciled

- **"Rule of Two"** — two meanings kept and composed: the code's capability trifecta (A/B/C) gates
  auto-approval; the plan's "two independent signals" gates destructive execution.
- **Trace/Span** live in a **new `aegis-trace` crate**, not `aegis-core` (keeps core light, no 18-crate rebuild).
- **PolicyDecision** is a common vocabulary via `From` adapters — the rich per-domain enums stay.
- **`aegis-supply` name collision** — the plan's *prompt* supply becomes `aegis-prompt`; the shipped
  `aegis-supply` (artifact pinning) is unchanged.
- **TenantId** is phased in (default tenant = today's behavior); **Postgres** is one optional
  `TraceCollector`, not a hard dependency (InMemory + existing OTel first).

## Start-here (if time is short)

1. T0 trace spine + `PolicyDecision`/`TenantId`. 2. `PhiLeakEvaluator` (compliance evidence, reuses
redact). 3. Multi-tenancy in broker/meter/killswitch.

## Next step

Awaiting the user's go-ahead on **T0** (build the `aegis-trace` crate + core additions) — no code
written yet; this entry and the artifact are planning only.
