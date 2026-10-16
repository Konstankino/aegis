# 0034 — OWASP Agentic Skills (AST) Top 10 coverage + LLM-numbering reconciliation

- **Date:** 2026-10-15
- **Status:** Done
- **Type:** Feature (coverage) + tests + docs reconciliation
- **Follows:** [0009-t5-hardening-evidence.md](0009-t5-hardening-evidence.md) (the generated OWASP matrix spine)

## What & why

The plane mapped two OWASP GenAI lists — **LLM Applications (2025)** and **Agentic Applications /
ASI (2026)**. A coverage audit added the **third** list the task targets: the **OWASP Agentic
Skills Top 10 (AST, v1.0 2026 Edition)** — AST01 Malicious Skills, AST02 Supply Chain Compromise,
AST03 Over-Privileged Skills, AST04 Insecure Metadata, AST05 Untrusted External Instructions, AST06
Weak Isolation, AST07 Update Drift, AST08 Poor Scanning, AST09 No Governance, AST10 Cross-Platform
Reuse. AST is scoped to the security of agent **skills** (packaged, dynamically-loaded capability).
It is still in OWASP **public review / pre-release**; we pin to v1.0 (2026) and flag that.

The three lists are mapped **independently**: most AST items reuse the artifact-integrity /
isolation / taint machinery already serving LLM/ASI, but applied to the skill lifecycle, with the
overlaps called out rather than reused as one mapping. The audit found most AST items already
covered by existing crates; the genuine gaps were **AST04** (skill-manifest metadata hygiene),
**AST08** (scan-before-activate), and **AST10** (per-platform re-validation), closed below.

## Change

- **`aegis-core` (`Owasp` enum):** added `Ast01..Ast10` (code/title/`ALL`), so the enum now carries
  all 30 LLM+ASI+AST risks. Tests updated (`ALL.len() == 30`, AST code/title/serde, `AST` prefix).
- **`aegis-supply` (new skill-lifecycle gate):** `CapabilityKind::Skill`, `SkillManifest`,
  `SkillContext`, `ScanAttestation`/`ScanVerdict`, and **`verify_skill`** — a deterministic,
  fail-closed gate composed from the existing primitives plus the new checks:
  - **AST02/AST07/AST01** — immutable ref + embedded-digest match + pinset membership (shared helper
    `verify_pinned_ref`, factored out of `verify_runtime` so both reuse it, behavior unchanged).
  - **AST04** — name + every metadata key/value screened via **`aegis_ingress::is_clean`** (reused,
    not duplicated); a new `aegis-ingress` dep was added for this.
  - **AST03** — declared permissions must be within the host-allowed set (least privilege at load).
  - **AST08** — a digest-bound `Clean` scan attestation is required; unscanned / flagged / stale
    (replayed-from-another-build) scans fail closed.
  - **AST10** — the host platform must be among the skill's validated platforms.
  - 6 new unit tests cover the happy path + each failure path.
- **`aegis-redteam`:** 10 AST `coverage()` rows (so the fail-closed
  `coverage_matrix_covers_every_owasp_risk` test now enforces an AST row per risk); 6 new AST
  `Category` variants + `attack_*` functions driving `verify_skill` / `aegis-sandbox`, wired into
  `default_suite()` and asserted by a new `ast_skill_attacks_are_contained` test. Suite is now
  **31 attacks (was 25)**, all contained.
- **Generated artifact:** `docs/owasp-coverage-matrix.md` regenerated
  (`cargo run -p aegis-redteam -- --coverage`) — now 30 rows incl. AST01–AST10.
- **Docs:** new **§12** in `architecture-considerations.md` (AST threat-by-threat + matrix +
  residuals; the old "Open next step" became §13); AST column added to `crate-coverage-matrix.md`.
- **Reconciliation (approved):** `architecture-considerations.md` **§3** was renumbered to the
  canonical **LLM Applications 2025** order so the prose, the `aegis_core::Owasp` enum, and the
  generated matrix agree (previously §3 used an older ordering, e.g. Excessive Agency as LLM03
  instead of LLM06). The stale **divergent duplicate** copies of `architecture-considerations.md`
  and `crate-coverage-matrix.md` at the mount root (`/Volumes/home/aegis/`) were **synced** to the
  updated repo copies — not deleted, because the repo's own `Cargo.toml` and `README.md` reference
  `../architecture-considerations.md`, so deleting the outer copy would break those links.

## Verification

- `cargo fmt --all --check` — clean.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean (also `--features aegis-core/crypto`;
  `cargo build -p aegis-extension --features s3,otel` builds).
- `cargo test --workspace` — **423 passed, 0 failed**, including the 30-risk compliance test, the
  6 new `aegis-supply` skill tests, and `ast_skill_attacks_are_contained`.
- `cargo run -p aegis-redteam` — GATE PASS, **31/31 attacks contained**.

## Residual / recommendations (not code-fixable)

- **AST08 scanner quality** — Aegis enforces that a current, digest-matching, `Clean` attestation
  exists; the semantic depth of the external scanner is out of scope. Wire a real skill scanner to
  emit the `ScanAttestation`.
- **AST09 governance program** — the enforcement substrate (pinset inventory, immutable ledger,
  killswitch revocation, per-skill identity) is deterministic (◐); review cadence / approval
  staffing is process (○).
- **LLM-edition labels** — `README.md` and `architecture-considerations.md` §2/§11 still label the
  LLM list "(2026)"; the current LLM edition is **2025** (2026 is the Agentic edition). Left as a
  noted follow-up (outside the approved §3 reconciliation scope).
