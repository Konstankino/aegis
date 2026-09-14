# 0012 — T1 + T2 + Eval follow-ups

- **Date:** 2026-09-14
- **Status:** Implemented (green)
- **Type:** Follow-ups across broker / cli / retrieval / eval / extension
- **Roadmap:** closes the remaining items in T1, T2, and the eval polish from
  [0003-reconciled-roadmap.md](0003-reconciled-roadmap.md)

## T1 — per-tenant Cedar ACLs + CLI per-tenant dirs

- **Broker:** `PolicyPrincipal` gains a `tenant` field, exposed to Cedar as **`context.tenant`**, so a
  policy can scope per-tenant ACLs (`permit(...) when { context.tenant == "acme" }`). `mediate` passes
  `session.tenant`. Non-breaking: policies that don't reference `context.tenant` are unaffected.
- **CLI:** `PolicyDir::for_tenant(root, tenant)` nests artifacts under `<root>/tenants/<tenant>/` (slug
  validated; `.`/`..` rejected — no traversal), wired to a global `--tenant` flag. `aegis --tenant acme
  init` scaffolds a tenant's own policy set; `--tenant ..` is refused.

## T2 — retrieval extensions + cross-tenant scan

- **`aegis-retrieval`:** `RetrievalBackend` trait (abstracts the vector store; receives the
  already-authorized query) + `search_guarded` (authorize → search → guard/surface, no unauthorized
  path); the **ingestion gate** `ingest()` → `IngestDecision` (normalizes, **rejects embedded-
  instruction payloads at ingest**, tags owner namespace + embedding version, LLM04); `EmbeddingVersion`
  + `stale_embeddings()` to flag chunks needing re-embedding (LLM08).
- **`aegis-eval`:** `CrossTenantEvaluator` + `TenantEntities` — flags a response naming an entity owned
  by a **different** tenant (cross-tenant disclosure, LLM02), reporting a count and never echoing the
  entity.

## Eval polish

- **`aegis-eval`:** `DriftMonitor` — a rolling-window score monitor that reports **drift** only once the
  window is full and the mean falls more than `tolerance` below a baseline (no cold-start false alarm).
- **Extension:** a new **`POST /output/scan`** gate endpoint runs the deterministic output evaluators
  (PHI leak + a canary/system-prompt-leak check built from the gate's honeypot canaries) over a model
  response, **emits a typed `Stage::OutputScan` span** (risk LLM02, tenant, min-score), and blocks the
  response (422) if it fails. This is eval on live traffic; the LLM-judge evaluators stay a sampled job.
  The extension now depends on `aegis-eval`.

## Verification

- `cargo test --workspace` green (54 groups; new tests in broker/cli/retrieval/eval/extension).
- **Coverage:** broker `policy.rs` 97.7%, `aegis-eval` lib 98.3%, `aegis-retrieval` 98.7% (all ≥95%).
- `clippy --workspace --all-targets -D warnings` clean (also `-p aegis-extension --features jit`);
  `cargo fmt --all --check` clean.

## What now remains (non-code / infra)

- The T4 axum HTTP host mounting `aegis-gateway` to the live pipeline (MCP endpoint + REST).
- The T5 per-tenant observability dashboard (Grafana/Langfuse over OTel + Postgres traces) and the
  Postgres `TraceCollector` — both infrastructure, not Rust code.
- Wiring the handler to build prompts through `aegis-prompt` + emit a `Stage::Prompt` span (needs the
  Python agent handler, which assembles prompts today).
