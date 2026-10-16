# 0001 — JIT access credentials for agents (brokered short-lived cloud access)

- **Date:** 2026-09-12
- **Status:** Implemented (green)
- **Plan:** internal planning note (architecture-considerations, JIT credentials)
- **Type:** New feature (new crate + extension wiring + policy artifact + CLI + Terraform + docs)

## What & why

Aegis agents and their sandboxes today reach real data sources/destinations through the single,
long-lived **Lambda execution role** (`${project_name}-agent-role`). That is exactly the long-lived,
broad, role-based standing access we want to eliminate: any code that runs in the function inherits
the whole role for its whole lifetime, so a compromised/injected agent has a large, persistent blast
radius.

This change introduces **just-in-time (JIT) access credentials**: every real data-plane access is
minted per-call, scoped to exactly one resource+action, expires in 60–300s, is authorized by the
agent's own signed identity + a versioned grant catalog + the broker's Rule-of-Two taint, and is
fully audited. The standing Lambda role is stripped to `sts:AssumeRole` on narrow per-grant roles
only.

It **builds on the existing inter-agent identity/mesh** (`aegis-identity::Credential`,
`aegis-mesh`) rather than replacing it — the same signed JIT credential that authenticates an agent
on the mesh is what it presents to obtain a real cloud credential. **Agents are first-class
principals**: each has its own identity/keypair, grants, narrow-only delegation to other agents,
audit trail, and quarantine.

## The exchange

`identity Credential + grant_id + ttl` → gate `/credentials/issue` → killswitch/quarantine →
`Credential::verify` → `aegis_jit::decide` (pure, deterministic) → accumulate Rule-of-Two taint →
provider mint (STS AssumeRole + inline session policy, or Secrets Manager GetSecretValue) → ledger
append (metadata only, never the secret) → short-lived credential returned.

## Decisions locked with the user

1. **Code + Terraform** — implement the Rust code *and* the per-grant IAM roles / trust policies /
   session-policy scoping / secret resource policies under `deploy/terraform/**` (fully deployable).
2. **Both providers** — STS AssumeRole (inline session policy scoped to the exact resource ARN) *and*
   Secrets Manager JIT fetch (returned with a TTL, never persisted). `Provider` enum built to grow.
3. **Full trifecta gate** — minting feeds the broker's Rule-of-Two taint (read grant = leg B, write
   grant = leg C). If minting would complete the lethal trifecta on an irreversible write → deny or
   route to the same Step Functions human-approval pause as `/mediate`.
4. **Agents as first-class citizens** (mid-plan steer) — agents are full principals, not shims behind
   a human session.

## Also established this session

- **Changelog convention** (this file is the first): all plans/updates + reasoning tracked in
  `changelog/NNNN-*.md`, zero-padded, incrementing, one file per update.
- **Policy default split** (prior task, same session): committed `policies/*` live files are blank /
  default-deny; `aegis init` produces the populated set. `grants.toml` follows this convention
  (blank live file, populated `.example`).

## Scope of edits (planned)

- New crate `crates/aegis-jit` (pure deterministic core: `Grant`, `Provider`, `GrantCatalog`,
  `decide`).
- Extension: `src/jit.rs` (feature `jit`: aws-sdk-sts + aws-sdk-secretsmanager), `gate.rs`
  (`/credentials/issue`), `plane.rs`, `main.rs`, `s3.rs`, `Cargo.toml`.
- Policy: `policies/grants.toml` (blank) + `policies/grants.example.toml`; `policies/README.md`.
- CLI: `artifacts.rs`, `scaffold.rs`, `main.rs`, `validate.rs`, `testrun.rs`, `tui.rs`,
  `domains/jit.rs`.
- Terraform: new `jit.tf`; edits to `iam.tf`, `s3.tf`, `lambda.tf`, `variables.tf`, `outputs.tf`,
  `terraform.tfvars.example`, `build.sh`, `build.tf`.
- Docs: `docs/scripts/gen_jit_pdf.py` + README row; refresh identity/extension generators;
  `architecture-considerations.md` (+ `-uk`), `crate-coverage-matrix.md`.
- Workspace `Cargo.toml`: new member + pinned deps.

## Verification (planned)

`aegis-jit` unit tests (~95%); gate integration tests (no AWS, provider stubbed off); CLI
`test issue` dry-run; `cargo test --workspace` + broker acceptance green; clippy `-D warnings`; fmt;
`cargo build -p aegis-extension --features jit`; `terraform validate` + `plan` (no apply). Build with
`CARGO_TARGET_DIR=$HOME/.aegis-target` (SMB).

## Implementation outcome

- **New crate `aegis-jit`** (pure, no AWS): `Grant`/`Provider`/`GrantCatalog`/`decide`. 16→20 unit
  tests. **Coverage 98.6% lines.**
- **Extension**: `src/jit.rs` (real STS AssumeRole + inline session policy + session tags +
  ExternalId; Secrets Manager JIT fetch — behind feature `jit`, fail-closed stub otherwise) and a
  `POST /credentials/issue` gate handler wired into `GateConfig.grants` + `plane::load_grant_catalog`.
  6 new gate integration tests (lean build, no AWS). **gate.rs 96.8% lines.**
- **CLI**: `Artifact::Grants`, blank starter + populated `include_str!` example, `domains/jit.rs`
  (`add-sts`/`add-secret`/`set-ttl`/`rm`/`show`), `aegis test issue` dry-run (renders the session
  policy, no AWS). **domains/jit.rs 97.8%, testrun.rs 95.3%.**
- **Policy**: `policies/grants.toml` (blank/deny-all committed) + `policies/grants.example.toml`;
  README row.
- **Terraform**: `jit.tf` (per-grant STS roles trusted only by the agent role + ExternalId; agent
  role gains only `sts:AssumeRole` on those ARNs + `secretsmanager:GetSecretValue` on named secrets —
  no standing data-plane access); `var.jit_grants`; `jit_role_arns`/`jit_external_id` outputs;
  `grants.toml` added to the S3 upload map; `build.sh` builds `--features …,jit` and bakes
  `grants.toml` (+`sandbox.toml`) into the layer; `AEGIS_JIT_EXTERNAL_ID` env. (`terraform validate`
  not run here — terraform not installed on this host; HCL follows the existing file patterns.)
- **Docs**: `docs/scripts/gen_jit_pdf.py` → `docs/aegis-jit-uk.pdf` (built, verified render);
  `docs/scripts/README.md` row; `crate-coverage-matrix.md` row.

### Coverage note (the user's ~95% ask)

The new **logic** is all ≥95%: aegis-jit 98.6%, CLI jit domain 97.8%, CLI testrun 95.3%, gate handler
(in gate.rs) 96.8%. The only sub-95% file is `extension/src/jit.rs`, whose miss is exclusively the two
AWS-SDK `mint` bodies (STS/Secrets calls) — untestable without live AWS credentials, the same
"unavoidable glue" class the coverage convention excludes (cf. `s3.rs`, `ledger_sink.rs`,
`session_store.rs`). Its pure helpers (session-name sanitize, STS duration clamp, JSON pluck) are unit
tested under the `jit` feature.
