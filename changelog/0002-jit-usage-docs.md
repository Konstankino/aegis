# 0002 — JIT access credentials: usage documentation

- **Date:** 2026-09-12
- **Status:** Done
- **Type:** Documentation
- **Follows:** [0001-jit-access-credentials.md](0001-jit-access-credentials.md)

## What & why

The JIT credential feature (0001) shipped with code-level docs and a Ukrainian deep-dive PDF, but no
task-oriented **"how to use it"** guide for developers/operators. This adds one.

## Change

New [`docs/jit-credentials.md`](../docs/jit-credentials.md) — an end-to-end usage guide covering the
whole loop:

1. Mental model and where each piece lives.
2. **Authoring grants** with the `aegis jit` CLI (`add-sts`, `add-secret`, `set-ttl`, `rm`,
   `list`/`show`), including the leg (read=B / write=C) and `{resource}` session-policy substitution.
3. **Validating** (`aegis validate` / `doctor`).
4. **Dry-running** a decision with `aegis test issue` (no AWS), including the `--legs` trifecta
   preview and how to obtain a test credential.
5. **Deploying** the IAM plumbing via Terraform `var.jit_grants`, wiring `terraform output
   jit_role_arns` back into `grants.toml`, and the `jit` build feature + `AEGIS_JIT_EXTERNAL_ID`.
6. **Runtime** `POST /credentials/issue` — request shape and every response (200 grant / 202
   human-approve / 403 / 404 / 502 / 503), with example bodies.
7. How the decision is made (the 5 ordered checks) and the security properties.

It cross-links the crate, gate handler, mint providers, Terraform, grant-catalog example, and the
Ukrainian PDF. All commands and request/response shapes were checked against the implemented code.

## Verification

Doc-only change (no code touched). Content verified against `main.rs` (CLI flags), `gate.rs`
(request/response + status codes), `jit.rs` (minted payload shape), and `jit.tf`/`variables.tf`
(Terraform surface).
