# 0027 — parallel-review through the real gate (concurrent B∥C, 4 principals)

- **Date:** 2026-09-17
- **Status:** Done
- **Type:** Reference driver + tests
- **Follows:** [0026-run-local-gate-and-shared-thread-principal-fix.md](0026-run-local-gate-and-shared-thread-principal-fix.md)

## What & why

A self-contained Converse tool-use driver for the **fan-out/fan-in** pipeline, run through the real
Aegis gate. It exercises the shared-thread principal fix from 0026 on **four** principals with **B and
C running concurrently** on one `thread_id` — a good stress of the gate's multi-principal-per-thread
path. No Rust change was needed (0026's fix already handles it).

## New — [pipelines/parallel-review/run_local.py](../pipelines/parallel-review/run_local.py)

Same design as the editorial driver, with the fan-out orchestration: `A → (B ∥ C) → D`. A dispatches;
B and C run **concurrently** (a 2-worker thread pool), both taking A's output and mediating on the
**shared** `thread_id`; D referees the two candidates. Clients: `MockConverse` (offline default),
`LiveConverse` (`--live`), and the real gate via `--gate ADDR` (`/mediate` + `/output/scan`). Reads
tools.json / broker.cedar / pipeline.json / code/pipeline.py — the production source of truth.

## Verified end-to-end through the gate

Started the gate in dev mode over `pipelines/parallel-review/policies` (loaded `tools=6 policies=8`),
then drove it:

- all **8** tool calls mediated by the real gate; B and C concurrent on one thread; each of A/B/C/D
  authorised as **itself** (0026's fix holds under concurrency — the gate sets `session.agent_id` and
  calls the broker atomically under the sessions lock, so the two peers never race the principal);
- per-principal enforcement spot-checks on the shared thread: `agent-d publish.final` → allow,
  `agent-b publish.final` → **deny** (a writer is not the referee), `agent-c dispatch.to_workers` →
  **deny** (only A dispatches).

## Tests — [pipelines/parallel-review/test_run_local.py](../pipelines/parallel-review/test_run_local.py) (5, no AWS)

profiles/terminals from the manifest (B and C are peers); allow-map from broker.cedar; `mediate`
allow / policy-deny / unknown-tool; the full A→(B∥C)→D flow over the mock (8 allowed calls in order,
two candidates, D publishes one); and the deny path (a rogue agent-b proposing `publish_final` is
refused, then its legit `submit_candidate` allowed).

## Note (Part 2 ledger)

In this single process the gate's per-thread session and ledger are guarded by mutexes, so concurrent
B/C writes serialize (no fork). The cross-process/cold-restart fork remains the
[ledger Part 2](../docs/ledger-continuity-part2-spec.md) concern, unchanged.

## Verification

`python3 -m unittest` green: parallel-review `test_run_local` (5) + `test_pipeline` (11); editorial
`test_run_local` (5) + `test_pipeline` (7). Rust workspace unchanged (green in 0026). README updated.
