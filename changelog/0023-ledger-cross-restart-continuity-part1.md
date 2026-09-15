# 0023 — Audit-ledger cross-restart continuity (Part 1: resume the chain)

- **Date:** 2026-09-15
- **Status:** Done
- **Type:** Security hardening (audit durability) + intensive tests
- **Follows:** [0022-gate-hardening-provenance-path-output-scan-ledger.md](0022-gate-hardening-provenance-path-output-scan-ledger.md)

## Problem

The tamper-evident audit ledger's hash chain restarted on every cold Lambda. `append_ledger` did
`ledgers.entry(key).or_default()` → a fresh `Ledger` at seq 0 chained from genesis, so after a cold
start a thread that already had entries 0..N got a second `seq 0` (S3 key collision) and a chain that
`verify` rejects across the restart. Per-entry evidence was durable in S3, but **cross-restart chain
continuity was not anchored.**

## Part 1 — resume from the durable head (linear threads)

This closes the common case (linear pipelines like `editorial`, and every cold-start HITL resume: one
Lambda at a time per thread). Concurrent writers on one thread (the parallel fan-out) are Part 2 —
specced in [docs/ledger-continuity-part2-spec.md](../docs/ledger-continuity-part2-spec.md).

- **`aegis-ledger`** — `Ledger::resume(next_seq, head_hash)` continues a chain from a checkpoint:
  `append` uses `seq = start_seq + len` and chains from `start_head`; `verify` checks the in-memory
  segment relative to its checkpoint (full-history verification walks the immutable sink).
- **`aegis-extension::session_store`** — `save_ledger_head` / `load_ledger_head` (`(seq, hash)`),
  mirroring `save_cap`/`load_cap` across `Null` / `Dynamo` (`SK="aegis#ledger"`) / `Mem`.
- **gate.rs** — `ensure_ledger_loaded` rehydrates a thread's head on the first append in a cold
  environment (once per thread, guarded by `ledger_loaded`) and seeds a resumed `Ledger`;
  `record_ledger` appends, persists the entry (durable for tripwires), and **writes the new head
  back**. Every append site (the mediate decision, the JIT paths, the tripwire paths, the
  store-unavailable deny) now routes through it. Best-effort: a head-read/write failure is logged and
  the entry is still recorded (an audit event is never dropped because continuity couldn't be
  restored). Fixed a `!Send` regression (killswitch guard held across an await → scoped it).

## Tests (intensive)

- **`aegis-ledger`** (21 total): `resume_continues_the_chain_from_a_checkpoint`;
  `chain_is_byte_identical_across_multiple_resumes` (a chain rebuilt across three cold restarts is
  byte-for-byte identical to the single-process chain — the core continuity property);
  `tampering_a_resumed_segment_is_detected`; `resume_from_genesis_behaves_like_a_fresh_ledger`;
  `a_resumed_segment_that_starts_at_the_wrong_seq_fails_verify`.
- **gate integration** (56 total): `ledger_chain_survives_cold_resume` (seq resumes at 2 over a shared
  `MemStore`); `ledger_head_is_written_through_after_every_append`;
  `separate_threads_keep_independent_ledger_chains`; `ledger_resumes_across_three_cold_restarts`;
  `tripwire_ledger_resumes_on_a_cold_gate_and_quarantines`;
  `store_outage_still_records_a_deny_without_panicking`.

## Verification

`cargo test --workspace` green (56 groups, no failures); `cargo fmt --all --check` clean;
`cargo clippy --workspace --all-targets` and `-p aegis-extension --features s3,jit,dynamodb` clean;
`cargo build -p aegis-extension --features dynamodb` compiles.

## Not yet (Part 2)

A single-thread chain with CONCURRENT writers (Agents B and C in the parallel-review fan-out append to
the same `thread_id` from separate Lambdas at once) still forks: both resume from the same head and
write `seq N+1` with different hashes. Part 1's write-through is last-writer-wins on the head pointer.
The concurrency-safe design (conditional-write serialization vs. per-branch sub-chains joined at the
ASL fan-in) is specced separately.
