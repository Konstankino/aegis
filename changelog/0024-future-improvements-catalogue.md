# 0024 — Pause ledger Part 2; catalogue all future improvements

- **Date:** 2026-09-16
- **Status:** Done (documentation)
- **Type:** Planning / documentation
- **Follows:** [0023-ledger-cross-restart-continuity-part1.md](0023-ledger-cross-restart-continuity-part1.md)

## What & why

Work on the audit-ledger concurrency fix (Part 2) is **paused** by request. Before pausing, every
aspect that is deliberately unfinished, could be hardened further, or would benefit from improvement —
across the security reviews, the ledger-continuity work, and the scaffold/infra — is catalogued in one
place so nothing is lost.

## Deliverable

[docs/future-improvements.md](../docs/future-improvements.md) — a prioritised catalogue
(🔴 security · 🟠 correctness · 🟢 quality), each item with What / Why / Approach / Effort / Refs. Areas:

- **A. Audit ledger** — Part 2 concurrent-writer continuity (specced), offline full-history verifier,
  explicit S3 Object Lock in Terraform, external head notarization.
- **B. Gate trust boundary** — `/mediate` authorizes on an unauthenticated caller-asserted `agent_id`
  (no signed-credential binding yet); agent-Lambda `agent_id` trusted from the payload; `trust_arg_provenance`
  is a coarse global flag; sandbox `approved`/`wants_*` advisories.
- **C. Egress** — name-based allowlist is blind to DNS-rebinding / internal-IP resolution;
  `web.fetch` gates but does not yet perform the fetch.
- **D. JIT** — validate the STS session-policy template at catalogue time; secret values can't be
  time-boxed once handed out; session-binding-to-`thread_id` convention; verify `AEGIS_JIT_EXTERNAL_ID`
  wiring end-to-end.
- **E. Agent scaffold** — **tool RESULTS are fed to the model without `/sanitize`** (the main injection
  surface); pipeline transform bodies are stubs; output scan blocks candidates wholesale.
- **F. Infrastructure** — only `terraform validate` run (no `plan`/`apply`); no missing-bundle-file
  precondition; checkpoint-table hot-partition under fan-out; RAG/Phoenix modules unexercised.
- **G. Docs & tooling** — stale doc generators; no unified CI harness for the mixed-language suite;
  `gate.rs` is a 2,700+ line module.

## Cross-cutting theme

Several 🔴 items (principal binding on `/mediate`, tool-result sanitization, concurrent-ledger) share a
root: the inline plane currently trusts its co-resident caller for identity/provenance/input and treats
the audit trail as best-effort. Addressing them moves Aegis from "correct when the agent code is honest"
toward "correct against a compromised in-process caller" — the milestone after the JIT subject-binding
(0020) already taken on the credential path.

## Verification

No code change; workspace remains green (0023). The catalogue references live files, changelogs, and the
Part 2 spec.
