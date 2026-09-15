# 0022 — Gate hardening: provenance, sandbox path, output scan, ledger durability

- **Date:** 2026-09-15
- **Status:** Done
- **Type:** Security hardening + tests
- **Follows:** [0021-jit-ttl-fence-and-egress-boundary.md](0021-jit-ttl-fence-and-egress-boundary.md)

Closes the four lower-severity findings from the security review (#5–#8).

## #5 — Self-asserted `arg_provenance` at the gate

A caller could send `arg_provenance: "user"` on `/mediate` to suppress the Rule-of-Two untrusted-input
leg (leg A) and dodge trifecta escalation — the loopback caller is the (possibly prompt-injected)
agent, so its claim can't be trusted.

**Fix ([gate.rs](../crates/aegis-extension/src/gate.rs), [main.rs](../crates/aegis-extension/src/main.rs)):**
new `GateConfig.trust_arg_provenance` (default **false**). When off, every tool-call argument is
treated as `Untrusted` regardless of the claim — the safe default for an agentic loop (the reference
agent only ever sends `untrusted`). Enable via `AEGIS_TRUST_ARG_PROVENANCE=1` only where a
trustworthy out-of-band provenance signal exists. Tests: `caller_cannot_downgrade_provenance_by_default`,
`provenance_is_honored_only_when_explicitly_trusted`. (The sandbox's `approved`/`wants_root`/
`wants_network` flags are likewise caller-asserted advisories — the real containment is the runner's
no-IAM/no-network isolation — now documented as such in `aegis-sandbox`, not implied to be boundaries.)

## #6 — Sandbox path confinement crossed directory boundaries

`path.starts_with(working_dir)` accepted a SIBLING dir (`/tmp/aegis-sandbox-evil` shares the prefix of
`/tmp/aegis-sandbox`).

**Fix ([aegis-sandbox](../crates/aegis-sandbox/src/lib.rs)):** confine on a real path boundary —
`path == wd || path.starts_with("{wd}/")`. Test extended with `-evil`, `ED`, `.bak` siblings (denied)
and the working dir itself (allowed).

## #7 — Model output was never scanned in the agent loop

The generic `agent.py` returned final answers and stage handoffs without calling `/output/scan`, so
PHI/canary/system-prompt leaks (LLM02/LLM07) bypassed the deterministic output evaluators — contra the
editorial doc's claim.

**Fix ([agent.py](../deploy/terraform/agent-src/agent/agent.py)):** added `scan_output()` (fail-closed:
a deny OR an unreachable gate blocks the text) and `guarded_output()` (returns a `SAFE_BLOCK`
placeholder for content that fails). Both the final answer and every terminal handoff are now scanned
before they leave the stage. Engine tests `test_output_scan_blocks_a_failing_final_answer` and
`…_handoff`; the pipeline E2E harnesses stub `scan_output` (default allow).

## #8 — Ledger durability was best-effort, with no operator signal

`append_ledger` fire-and-forgets to S3, so a honeypot **tripwire's** evidence could be lost if the
environment is torn down right after the response; and a deployment with no Object-Lock bucket got no
warning that its audit trail is in-memory only.

**Fix:**
- `ledger_sink::persist_blocking` (awaited) + a new `append_ledger_durable` that both tripwire paths
  (mediate canary, sandbox decoy) now use — the immutable record is written **before** the gate
  responds; a real write failure is logged at ERROR. Routine decision entries stay fire-and-forget.
- Boot warning in `main.rs` when `AEGIS_LEDGER_BUCKET` is unset (audit trail is ephemeral).

## Verification

`cargo test --workspace` green (56 groups, no failures); `cargo fmt --all --check` clean;
`cargo clippy --workspace --all-targets` and `-p aegis-extension --features s3,jit` clean;
`cargo build -p aegis-extension --features s3` compiles; Python suites green (engine 10, editorial 7,
parallel-review 11); `py_compile` clean.

## Review status

All eight findings from the security review are now addressed (#1–#2 in 0020, #3–#4 in 0021, #5–#8
here). Residual, documented-by-design limitations: `/mediate` still authorizes on an unauthenticated
caller-asserted `agent_id` (the inline-plane trust boundary is the Lambda process; the credential-bound
`/credentials/issue` path, now subject-bound, is the model for a future signed `/mediate`); and the
ledger's in-process hash chain still restarts on a cold Lambda (per-entry evidence is durable in S3,
but cross-restart chain continuity is not yet anchored).
