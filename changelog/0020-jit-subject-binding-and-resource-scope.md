# 0020 — Security fixes: JIT subject binding + STS resource-scope fail-closed

- **Date:** 2026-09-15
- **Status:** Done
- **Type:** Security fix (identity/JIT) + tests
- **Follows:** [0019-parallel-review-pipeline.md](0019-parallel-review-pipeline.md)

## Context

A security review flagged two real holes in the JIT credential path. Both are fixed here, with tests,
and after first removing the **tautological checks** that hid them.

## #1 — JIT gate didn't bind the credential to the requester (bearer-token / confused-deputy + replay)

`credentials_issue` built the identity `RequestContext` **from the presented credential itself**
(`audience: &req.credential.audience`, `session_id: &req.credential.session_id`, …), so
`Credential::verify` compared the credential against itself — the audience/purpose/session checks were
no-ops. And `RequestContext` had no `subject` field at all, so the credential's `subject` was never
checked against the requesting `agent_id`. Net effect: any principal holding a validly-signed
credential could use it (bearer token), and a captured credential could be replayed into another
session.

**Fix:**
- `aegis-identity`: added `subject` to `RequestContext`; `Credential::verify` now denies
  `"subject mismatch"` when the presenter isn't the credential's subject
  ([lib.rs](../crates/aegis-identity/src/lib.rs)).
- `aegis-extension` `credentials_issue`: the context is now built from **independent request facts** —
  `subject = req.agent_id`, `audience = grant.audience`, `session_id = req.thread_id`,
  `purpose = req.purpose` (a new independent field on `IssueRequest`), `action_scope`. So `verify`
  enforces that the credential was issued **to this principal, for this resource, in this session**.
  Nothing is sourced from the credential — no check is a self-comparison.
- `aegis-cli` `test issue`: documented as a self-consistency dry-run (it has no independent requester,
  so it binds `subject` to the credential's own subject).

## #2 — STS grant with no `resource_arns` rendered a wildcard session policy (fail-open)

`Provider::rendered_session_policy` substituted `{resource}` with `"*"` when `resource_arns` was empty,
producing an inline session policy that **doesn't narrow** the assumed role at all — the opposite of
the control's purpose. `GrantCatalog::validate` didn't catch it, and the runtime loader
(`plane::load_grant_catalog`) never even called `validate`.

**Fix ([aegis-jit lib.rs](../crates/aegis-jit/src/lib.rs), [plane.rs](../crates/aegis-extension/src/plane.rs)):**
- `GrantCatalog::validate` now rejects an STS grant whose `resource_arns` is empty.
- `rendered_session_policy` substitutes a fail-closed sentinel (`NO_RESOURCE_SENTINEL`, an ARN that
  matches nothing) instead of `*`, as defense in depth.
- `plane::load_grant_catalog` now calls `validate()` at boot and fails **closed** to the empty
  deny-all catalog on any invalid/unparseable file (previously it trusted the parsed catalog unvalidated).

## De-tautologising the tests first (as requested)

Before adding the fixes, the existing tests were audited so every binding assertion mismatches exactly
ONE field against an independent request fact (never a value copied from the credential):
- `aegis-identity`: `ctx()` gained a `subject`; the delegation test now presents the child **as its
  delegatee** (agent-b) and asserts it's refused when presented as the parent — a real subject check.
- `aegis-jit`: `ctx_as(subject, scope)` lets the delegated-child case present as agent-b.
- `aegis-extension`: the gate test's `signed_cred` now binds the credential's session to the request
  thread and its purpose to the request purpose, so the happy path exercises real matches.

## New tests

- `aegis-identity::wrong_subject_is_denied` — valid credential for agent-a, presented as agent-b → deny.
- `aegis-jit::credential_subject_mismatch_is_denied`; `sts_grant_without_resource_arns_is_rejected`;
  `rendered_session_policy_substitutes_resource` updated to assert the sentinel (no `*`).
- `aegis-extension` gate: `issue_wrong_subject_is_denied`, `issue_wrong_session_is_denied`,
  `issue_wrong_purpose_is_denied` — each proves a previously-tautological check now binds to an
  independent request fact.

## Verification

`cargo test --workspace` green (no failures); `cargo clippy --workspace --all-targets` clean;
`cargo fmt --all --check` clean; `cargo build -p aegis-extension --features jit` compiles.

## Not fixed here (from the same review, lower severity — separate follow-ups)

STS 900s TTL floor vs the advisory `expires_at_ms` (#3); egress dotless-suffix match (#4); self-asserted
`arg_provenance`/`approved`/`agent_id` at the gate (#5); sandbox path prefix boundary (#6); output-scan
not wired into the agent loop (#7); best-effort ledger durability (#8).
