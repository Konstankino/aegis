# 0006 — T1: multi-tenancy (runtime enforcement slice)

- **Date:** 2026-09-14
- **Status:** Implemented (green) — core slice; two follow-ups noted
- **Type:** Track T1 (broker + meter + killswitch + gate)
- **Roadmap:** Track T1 in [0003-reconciled-roadmap.md](0003-reconciled-roadmap.md); builds on T0
  ([0004](0004-t0-trace-spine-core-additions.md), [0005](0005-gate-emits-typed-spans.md))

## What & why

T1 threads the tenant dimension through the running plane — the "retained IP, multi-client" model.
Every piece is additive and default-preserving: absent a tenant, requests use `TenantId::default()`
and behave exactly as before.

## Changes

- **`aegis-broker`** — `Session` gains `tenant: TenantId` (default in `new`; `with_tenant` builder).
- **`aegis-killswitch`** — `Target::Tenant(id)` and `Target::Global` scopes; `restore(target)` to lift
  a revocation; and `blocks(tenant, agent, tool) -> Option<&'static str>`, which composes the checks in
  order: global stop → tenant → agent (revoked/quarantined) → tool. Reasons match the gate's existing
  strings so behaviour is unchanged for single-tenant callers.
- **`aegis-extension` gate**:
  - `GateConfig.tenant_limits: HashMap<TenantId, Limits>` + `limits_for(tenant)` — **per-tenant meter
    budgets** (a tenant without an override uses the default `limits`).
  - `MediateRequest`/`IssueRequest` gain an optional `tenant`. `tenant_of()` resolves it: absent/empty
    ⇒ default; **malformed ⇒ fail closed (deny)**, never a silent cross-tenant fallback.
  - The tenant is threaded into `ensure_thread_loaded` (seeds the `Session` tenant + the tenant's meter
    limits), the killswitch check (`blocks`), the emitted `Span` (real tenant, not the T0 placeholder)
    and its `tenant` attribute, and the `/mediate` response (`"tenant"`).

## Verification

- `cargo test --workspace` green. New tests: killswitch tenant/global block + restore + serde;
  gate `tenant_killswitch_blocks_only_that_tenant`, `global_killswitch_blocks_every_tenant`,
  `malformed_tenant_is_denied`, `per_tenant_meter_budget_applies`; span carries the tenant.
- **Coverage:** `aegis-killswitch` 99.4%, `aegis-broker` lib 97.7%.
- `clippy --workspace --all-targets -D warnings` clean (also `-p aegis-extension --features jit`);
  `cargo fmt --all --check` clean.
- Non-breaking: existing responses/behaviour unchanged; the operator can now
  `POST /killswitch/revoke {"kind":"tenant","id":"acme"}` or `{"kind":"global"}`.

## Remaining T1 (follow-ups, separable)

1. **Per-tenant Cedar principals / ACLs** — `Session.tenant` is now carried, but the broker's Cedar
   policy doesn't yet use it as a principal attribute. This is the meatier remaining piece (Cedar
   schema + policy + `PolicyPrincipal`).
2. **Per-tenant `PolicyDir` in the CLI** — author tools/cedar/grants keyed by tenant; the gate loads a
   single policy set today.
