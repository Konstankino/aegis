# 0013 — Document remaining infrastructure

- **Date:** 2026-09-14
- **Status:** Done (documentation)
- **Type:** Docs

## What & why

With T0–T5 built (see 0004–0012), the user asked what infrastructure components remain. All Rust
control cores are complete and tested; what's left is deployment/storage/integration glue, not new
controls. Captured it as [`docs/remaining-infrastructure.md`](../docs/remaining-infrastructure.md).

> **Update (same day):** added a sixth component — the **RAG engine** (vector DB + embeddings +
> `RetrievalBackend` adapter) — after the user noted it was only implied by the `RetrievalBackend`
> seam, never a standalone infra line item. Aegis governs the RAG engine but does not ship it.

## The remaining components

1. **Gateway HTTP host (T4)** — an axum shell mounting `aegis-gateway::Gateway::admit` + the MCP/REST
   endpoints, dispatching `tools/call` through the live pipeline; plus a durable key store and deploy.
2. **Trace persistence + dashboard (T5)** — a `PostgresCollector` for `aegis_trace::TraceCollector`,
   storage (RDS/Tempo), and a per-tenant Langfuse/Grafana dashboard + alerting. OTLP export already
   exists.
3. **Real `Judge` + production eval sampler (Eval)** — a Claude-backed `aegis_eval::Judge`, a sampled
   drift/eval job, and CI wiring of the `aegis-eval` gate binary.
4. **Per-tenant policy delivery + key/secret mgmt** — per-tenant S3 policy prefixes (mirroring the
   CLI's `tenants/<id>/`), API-key rotation, and KMS-backed `aegis-identity` signing (deferred
   hardening).
5. **Prompt-stage handler wiring (T2)** — the agent handler assembling prompts through `aegis-prompt`
   and emitting a `Stage::Prompt` span.
6. **RAG engine (external)** — a vector DB (pgvector, can share §2's Postgres) + embedding/ingestion
   pipeline (running docs through `aegis_retrieval::ingest`) + a `RetrievalBackend` adapter. Aegis
   provides the guard + the seam; the engine itself is deployment infra.

Each is documented with what already exists vs. what to build. None introduce new deterministic
controls.
