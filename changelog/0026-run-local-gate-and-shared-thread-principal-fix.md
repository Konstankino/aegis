# 0026 — run_local `--gate` mode + fix: shared-thread principal pinning

- **Date:** 2026-09-17
- **Status:** Done
- **Type:** Reference driver + security/correctness fix (found via integration) + regression test
- **Follows:** [0025-editorial-bedrock-converse-tool-use.md](0025-editorial-bedrock-converse-tool-use.md)

## What & why

Wiring [`run_local.py`](../pipelines/editorial/run_local.py) to the **real Aegis inline-plane gate**
surfaced a genuine gate bug, which is fixed here (test-first).

## `--gate` mode

`run_local.py` gains `--gate ADDR`: instead of the in-process broker.cedar check, it routes every
`/mediate` and `/output/scan` to the actual gate — the same endpoints the deployed engine calls. Run
the gate locally in dev mode over the editorial policies (no Lambda, no AWS), then drive A→B→C through
it:

```bash
AEGIS_GATE_ADDR=127.0.0.1:8785 AEGIS_POLICY_DIR="$PWD/pipelines/editorial/policies" \
  cargo run -p aegis-extension
python3 pipelines/editorial/run_local.py --gate 127.0.0.1:8785 "he go to the stor yesterday"
```

Verified end-to-end: all six tool calls mediated by the real gate, outputs scanned, on one shared
`thread_id`, each authorised as its own principal from `broker.cedar`.

## Fix — the gate pinned a shared thread's principal to the first caller

**Bug:** `/mediate` authorizes against the **session's** `agent_id`, and the session is created once per
`thread_id`, seeded by the FIRST caller. A pipeline's principals (editorial's A/B/C, parallel-review's
A/B/C/D) all share one `thread_id`, so on a warm process the session stayed pinned to `agent-a` and
**every later stage was denied** ("policy denies this") even for its own tool. It only escaped in
production when a cold container re-created the session; warm-container reuse across sequential Step
Functions tasks would break the pipeline. (The broker acceptance tests use a fresh `Session` per call,
so it was masked.)

**Fix** ([gate.rs](../crates/aegis-extension/src/gate.rs)): the `/mediate` handler now sets
`session.agent_id = req.agent_id` immediately before the broker call. The session keeps the thread's
accumulated Rule-of-Two **taint** (never reset — that is the shared, per-conversation state); only the
principal label tracks the current caller. The first attempt in `ensure_thread_loaded` didn't work
because that function has a fast-path early return when the session is already resident — so the
principal must be updated at the authorization site, which always runs.

## Test-first

Per the new working rule (write the regression test before the fix):
`a_shared_thread_authorizes_each_caller_not_just_the_first` — a broker where agent-a may call only
`a.tool` and agent-b only `b.tool` (both benign, so no trifecta); on ONE shared thread, agent-a's
`a.tool` allows, agent-b's `b.tool` must **also** allow (regression), and each principal is still
denied the other's tool. Demonstrated: it **fails** against the unfixed code (agent-b → deny) and
**passes** after the fix.

`run_local`'s own deny-path test already covers the driver refusing an off-lane call.

## Verification

`cargo test -p aegis-extension` → 57 passed (incl. the new test); `python3 -m unittest` green:
`test_run_local` (5), `test_pipeline` (7); manual end-to-end through the live gate confirmed
(A `publish.final` denied, C `publish.final` allowed on the same thread).

## Follow-up note

This is adjacent to finding B1 in [future-improvements.md](../docs/future-improvements.md) (`/mediate`
still trusts a caller-asserted `agent_id`). This fix makes the multi-principal-per-thread model *work
correctly*; binding the principal cryptographically remains B1's separate scope.
