# 0009 — T5: hardening & evidence (coverage matrix + kill-switch attacks)

- **Date:** 2026-09-14
- **Status:** Implemented (green) — code slice; observability dashboard is a documented follow-up
- **Type:** Track T5 (extend `aegis-redteam` + docs)
- **Roadmap:** Track T5 in [0003-reconciled-roadmap.md](0003-reconciled-roadmap.md)

## What & why

T5 is "hardening & evidence — runs alongside every track." This delivers the two code-shaped pieces:
the **generated OWASP compliance matrix** (with a guarantee it can never miss a risk) and **new
hardening attacks** exercising the T1 tenant/global kill-switch scopes.

## Changes (all in `aegis-redteam`)

- **`coverage` module** — the compliance matrix, generated from typed crate metadata + the
  `aegis_core::Owasp` enum:
  - `CoverageRow { risk, crates, how, tier }`, `Tier { Contain/Reduce/Process }` with glyphs, one row
    per OWASP risk (`LLM01..10`, `ASI01..10`), each naming the covering crate(s) and how.
  - `coverage()` (typed) and `matrix_markdown()` (the rendered evidence doc).
  - **Test `coverage_matrix_covers_every_owasp_risk`** — the compliance guarantee: every
    `Owasp::ALL` risk has a covering crate and a non-empty "how", exactly one row per risk, and the
    rendered Markdown names every code. The matrix can never silently drop a risk.
- **Two new hardening attacks** (both `ASI08`, driving `aegis-killswitch` directly):
  - `tenant-killswitch-isolation` — revoke one tenant, confirm it is halted and a neighbor is not
    (T1 cross-tenant isolation).
  - `global-killswitch-halt` — the global stop refuses every tenant, then lifts cleanly.
  The default suite is now **25 attacks, all contained**; the existing
  `default_suite_all_attacks_are_contained` test covers the new ones.
- **Binary `--coverage`** — `aegis-redteam --coverage` prints the generated matrix (regenerate the
  evidence doc in CI).
- **`docs/owasp-coverage-matrix.md`** — the generated artifact (20 risk rows), committed as the
  compliance evidence a client hands their team. (Complements the hand-authored, crate-indexed
  `crate-coverage-matrix.md`; this one is risk-indexed and generated.)

## Verification

- `cargo test -p aegis-redteam` green (8 tests incl. coverage completeness + the two kill-switch
  attacks). `cargo run -p aegis-redteam` → GATE PASS, 25/25 contained. `--coverage` emits 20 rows.
- `cargo test --workspace` green (50 groups). **Coverage:** `aegis-redteam` 94.8% lines — the
  uncovered lines are the by-design `breached(...)` arms that only execute on a real regression.
- `clippy --workspace --all-targets -D warnings` clean; `cargo fmt --all --check` clean.

## Remaining T5 (follow-up)

- **Per-tenant observability dashboard** over OTel + Postgres traces (Langfuse/Grafana). Infra, not
  Rust code: the trace spine (T0) already exports via OTel; this is the deployment artifact — pairs
  with the Postgres `TraceCollector` (a T0 follow-up).
- Deeper attack corpus (multi-turn, delegation-chain bombs) can keep growing as new surfaces land.
