# 0011 — T4: aegis-gateway (edge gateway core)

- **Date:** 2026-09-14
- **Status:** Implemented (green) — deterministic core; the axum/HTTP host is a documented follow-up
- **Type:** Track T4 (new crate `aegis-gateway`)
- **Roadmap:** Track T4 in [0003-reconciled-roadmap.md](0003-reconciled-roadmap.md)

## What & why

T4 exposes the plane to external hosts (MCP clients, REST callers) — a peer host to the Lambda
extension. The guiding principle: **the security is in the pipeline, not the interface**, so the
gateway is transport. This crate is its deterministic, network-free core (fully testable); the axum
HTTP shell + pipeline dispatch is a thin outer host.

## New crate: `aegis-gateway`

- **`KeyStore` / `KeyRecord`** — API keys stored as **SHA-256 hashes** (never the secret), each mapped
  to a `TenantId` + scopes. `register` hashes on the way in; `authenticate` hashes a presented key and
  returns the record unless disabled (fail closed); `disable` revokes without deleting. Serializes
  hashes only.
- **`RateLimiter`** — a per-key fixed-window **requests/second** limiter with a **caller-supplied
  clock** (deterministic, testable). Returns `Allow` or `Limited { retry_after_ms }`. Layers *over*
  the pipeline meter's tokens/day: the gateway caps request rate, the meter caps token spend.
- **`McpAdapter`** — an **MCP JSON-RPC 2.0** protocol adapter advertising Aegis capabilities as MCP
  tools. `dispatch` handles `initialize` / `tools/list` purely and routes a valid `tools/call` back to
  the host as `McpOutcome::Call` (the adapter never runs a control); `tool_result`/`tool_error` wrap
  the host's result. Proper JSON-RPC error codes (`-32700/-32600/-32601/-32602`).
- **`Gateway`** — the front door: `admit(key, now_ms)` authenticates **then** rate-limits (an
  unauthorized request never consumes rate budget) and returns the tenant/scopes to attach downstream.

## Verification

- `cargo test -p aegis-gateway` green (9 tests: auth hashing + disabled/wrong-key deny, JSON round-trip,
  rate limiter cap→limit→reset + per-key isolation, `admit` ordering, MCP initialize/list/call/unknown/
  bad-version/parse-error, result/error wrappers). `cargo test --workspace` green (54 groups).
- **Coverage:** `aegis-gateway` 96.3% lines.
- `clippy --workspace --all-targets -D warnings` clean (boxed the large JSON-RPC error per
  `result_large_err`); `cargo fmt --all --check` clean. README + coverage matrix updated.

## Remaining T4 (follow-up)

- The **axum HTTP host**: mount `Gateway::admit` as middleware, expose the MCP endpoint (parse →
  `dispatch` → on `Call`, run through the extension gate / broker → wrap with `tool_result`), plus a
  versioned REST surface. This is thin transport glue that ties the gateway to the live pipeline;
  kept out of the pure crate so the security logic stays deterministic and testable.
