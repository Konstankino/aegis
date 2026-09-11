# Aegis policies — populated by default

Each policy artifact ships in two forms:

| Live file (`<name>`) | Example (`<name>.example.<ext>`) |
| --- | --- |
| **Populated working set** — committed default | **Reference copy** — the same content, kept as the canonical source |
| A real, non-empty starting point you edit | Used to (re)generate the live files and by tests |

The **live files ship populated** so a fresh checkout — or `aegis init` — starts with working
policies, not empty files. The `*.example.*` files hold the canonical reference set (also read by the
broker acceptance test). For a *safe default-deny* start instead, use `aegis init --blank` (or the
blank starters below).

| File | Populated (default) content | Blank (`--blank`) means |
| --- | --- | --- |
| `tools.json` | the demo tool registry (`web.fetch`, `db.read_patient`, `email.send`, `code.run`, …) | `[]` — every tool "unknown" → denied |
| `broker.cedar` | least-privilege `permit`/`forbid` rules | no `permit` → default-deny |
| `egress-allowlist.toml` | allowlisted hosts/suffixes + permitted query params | no hosts → all egress denied |
| `meter.toml` | an explicit, tunable budget | empty → built-in `Limits::default()` |
| `pins.json` | a sample supply-chain pinset | `{}` → nothing pinned (fail-closed) |
| `honeypots.json` | curated decoys + a static canary | `{"decoys":[],"canaries":[]}` → inert |
| `sandbox.toml` | the locked-down exec profile (root/network/wall/memory) | empty → `SandboxPolicy::default()` |

## Scaffold or reset

`aegis init` writes the populated set into a policy dir (works even in a brand-new empty dir — the
example content is embedded in the tool). `aegis init --blank` writes the safe default-deny starters.

To regenerate the committed live files from the reference copies (run from the repo root):

```bash
for f in policies/*.example.*; do cp "$f" "${f/.example/}"; done
```

## Per project

A project points its own `policy_dir` at a directory of **plain-named** files (`tools.json`, …).
Start from these examples, then commit the project's own versions. The broker acceptance test
(`crates/aegis-broker/tests/policy_files.rs`) and the crate examples always read the `.example.*`
files, so they stay green regardless of whether you've activated the starters.
