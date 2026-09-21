# 0032 — ToDo logged: Secrets Manager JIT provider not deployable / not scoped

- **Date:** 2026-09-21
- **Status:** Logged (future work — not yet implemented)
- **Type:** Docs / backlog
- **Follows:** [0031-editorial-toctou-version-pin.md](0031-editorial-toctou-version-pin.md)

## What & why

While walking through KMS / secret access for the editorial S3 ingestion, we surfaced a real gap in the
**Secrets Manager JIT provider** (as opposed to the STS provider that editorial actually uses):

1. `jit::mint`'s `Secret` branch builds its client with `aws_config::load_from_env()` — the standing
   **agent execution role** — instead of a scoped, minted STS session like the `Sts` branch. So a
   `secret`-kind grant's `GetSecretValue` is authorized by the standing role, not a least-privilege
   per-call identity.
2. No Terraform grants the agent role `secretsmanager:GetSecretValue` on any secret ARN, nor
   `kms:Decrypt` on a secret's CMK — so with `--features jit` a `Secret` grant fails closed
   (AccessDenied) at runtime. The provider is code-complete but **not deployable**, and a blunt IAM
   grant would undercut the least-privilege guarantee JIT exists to provide.

This is intentionally **not** fixed now (editorial is STS-only). It is documented so it can be picked
up deliberately later.

## Change

Added item **D5** to [docs/future-improvements.md](../docs/future-improvements.md) (section
"D. JIT credentials"), with What / Why-it-matters / Approach (preferred per-grant secret role assumed
by the broker, mirroring `jit.tf`'s STS role; lower-effort alternative; cross-account key-policy note) /
Tests / Effort (~1–1.5 days) / Refs. Distinguished from the existing **D2** (un-revocable handed-out
secret) — D5 is about *how the fetch is authorized*.

No code or infrastructure changed.

## Verification

Documentation-only; `docs/future-improvements.md` renders the new D5 subsection under section D.
