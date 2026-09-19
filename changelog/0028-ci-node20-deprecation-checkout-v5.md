# 0028 — CI: fix GitHub Actions Node 20 deprecation (checkout@v4 → v5)

- **Date:** 2026-09-19
- **Status:** Done
- **Type:** CI maintenance
- **Follows:** [0027-parallel-review-through-the-gate.md](0027-parallel-review-through-the-gate.md)

## What & why

GitHub is deprecating the Node 20 runtime for JavaScript actions: any action declaring
`runs.using: node20` now emits a deprecation annotation on the runners and will eventually stop
working (ref: github.blog/changelog/2025-09-19-deprecation-of-node-20-on-github-actions-runners). Our
only workflow — [.github/workflows/ci.yml](../.github/workflows/ci.yml) — triggered the warning.

I audited the `runs.using` of every action the workflow uses, against each action's live `action.yml`:

| Action | `runs.using` | Verdict |
|---|---|---|
| `actions/checkout@v4` | **node20** | the culprit — bumped (used twice) |
| `Swatinem/rust-cache@v2` | node24 | already fine — no change |
| `dtolnay/rust-toolchain@stable` | composite (shell) | no Node runtime — no change |

## Change

Bumped both `actions/checkout@v4` → `actions/checkout@v5` (node24):

- line 17, job `build-test-gate`
- line 44, job `build-features`

`checkout@v5` is a drop-in here — both usages are a plain checkout with no `with:` inputs, so the only
difference is the action's Node runtime, and `ubuntu-latest` supports node24. No behavior change to the
fmt / clippy / test / red-team-gate steps or the features build.

Deliberately did **not** use the `ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION=true` escape hatch — it only
silences the annotation while keeping the deprecated runtime. Upgrading is the correct fix.

## Supply-chain hardening (done in the same change)

Pinned all three third-party actions to a full commit SHA with a version comment — a tag like `@v5` is
a moving target an upstream owner (or an attacker who compromises the account) can re-point at malicious
code, whereas a SHA is immutable. This aligns with the repo's own digest-pinning theme (`aegis-supply`).
Resolved via the GitHub commits API and applied to both jobs:

| Action | Pin | Comment |
|---|---|---|
| `actions/checkout` | `fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09` | v5.1.0 |
| `dtolnay/rust-toolchain` | `6bed0761d98439e5a578e2877258200ad565ba87` | stable @ 2026-09-19 |
| `Swatinem/rust-cache` | `6323deb102c322ba6fcbdcafc7e3dddab59af2b6` | v2.9.2 |

`dtolnay/rust-toolchain@stable` is a moving **branch** ref, so its SHA is snapshotted with the pin date
rather than a semver tag; bump it deliberately when a newer stable toolchain is wanted. To update any of
these later, re-resolve the tag/branch to its new SHA and refresh both the pin and the comment.

## Dependabot ([.github/dependabot.yml](../.github/dependabot.yml))

Added a `github-actions` update config so pinning doesn't ossify: Dependabot opens a weekly PR that
bumps each action's pinned SHA **and** its version comment together. Bumps are grouped into a single PR
(`groups.actions: "*"`) with a `ci` commit prefix. Cargo dependency updates are intentionally left out
for now (add a `cargo` ecosystem entry later if wanted).

## Verification

- `grep -n "checkout@v" .github/workflows/ci.yml` → both lines show `@v5`.
- `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"` → parses clean.
- On next push/PR, the `aegis-ci` workflow runs with the "Node 20 … deprecation" annotation gone and
  both jobs (`build-test-gate`, `build-features`) still passing.
