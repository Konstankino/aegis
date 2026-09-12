# Aegis policies — safe by default (default-deny)

Each policy artifact ships in two forms:

| Live file (`<name>`) | Example (`<name>.example.<ext>`) |
| --- | --- |
| **Blank safe-starter** — committed default (default-deny / inert) | **Populated reference** — a real, working example set |
| A default-deny starting point; you add rules deliberately | Used by `aegis init`, tests, and crate examples |

The **committed live files ship blank** so the checked-in default is *safe by default* — no tools
registered, no `permit` rules, no egress hosts, nothing pinned, inert honeypots, locked-down sandbox.
Every path is denied until you add a rule. The `*.example.*` files hold the populated reference set
(also read by the broker acceptance test). To start from working policies instead of blank ones, run
`aegis init` (populated by default) — see below.

| File | Blank (committed) content | Populated (`aegis init`) content |
| --- | --- | --- |
| `tools.json` | `[]` — every tool "unknown" → denied | the demo tool registry (`web.fetch`, `db.read_patient`, `email.send`, `code.run`, …) |
| `broker.cedar` | no `permit` → default-deny | least-privilege `permit`/`forbid` rules |
| `egress-allowlist.toml` | no hosts → all egress denied | allowlisted hosts/suffixes + permitted query params |
| `meter.toml` | empty → built-in `Limits::default()` | an explicit, tunable budget |
| `pins.json` | `{}` → nothing pinned (fail-closed) | a sample supply-chain pinset |
| `honeypots.json` | `{"decoys":[],"canaries":[]}` → inert | curated decoys + a static canary |
| `sandbox.toml` | empty → locked-down `SandboxPolicy::default()` | the locked-down exec profile (root/network/wall/memory) |

## Scaffold or reset

`aegis init` writes the **populated** example set into a policy dir (works even in a brand-new empty
dir — the example content is embedded in the tool). `aegis init --blank` writes the blank default-deny
starters — the same content committed here.

To reset the committed live files back to blank starters, run `aegis init --blank --dir policies`
(from the repo root), or regenerate the populated set from the reference copies:

```bash
for f in policies/*.example.*; do cp "$f" "${f/.example/}"; done
```

## Per project

A project points its own `policy_dir` at a directory of **plain-named** files (`tools.json`, …).
Run `aegis init` there to start from the populated example, or `aegis init --blank` for a default-deny
skeleton, then commit the project's own versions. The broker acceptance test
(`crates/aegis-broker/tests/policy_files.rs`) and the crate examples always read the `.example.*`
files, so they stay green regardless of the live files' state.
