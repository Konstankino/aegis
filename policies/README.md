# Aegis policies — starters + examples

Each policy artifact ships in two forms:

| Live file (`<name>`) | Example (`<name>.example.<ext>`) |
| --- | --- |
| **Blank safe starter** — committed default | **Populated reference** — the working demo set |
| Default-deny / built-in defaults / inert | Copy it in and trim to taste |

The **plain files are intentionally blank** so a fresh checkout (or a new project's policy
directory) is *safe by default*: default-deny, zero false positives — nothing is permitted until
you opt in. The `*.example.*` files hold the populated reference set the docs and demos use.

| File | Blank starter means | Example provides |
| --- | --- | --- |
| `tools.json` | `[]` — every tool is "unknown" → denied | the demo tool registry (`web.fetch`, `db.read_patient`, `email.send`, `code.run`, …) |
| `broker.cedar` | no `permit` → default-deny | least-privilege `permit`/`forbid` rules |
| `egress-allowlist.toml` | no hosts → all egress denied | allowlisted hosts/suffixes + permitted query params |
| `meter.toml` | empty → built-in `Limits::default()` | an explicit, tunable budget |
| `pins.json` | `{}` → nothing pinned (fail-closed) | a sample supply-chain pinset |
| `honeypots.json` | `{"decoys":[],"canaries":[]}` → inert | curated decoys + a static canary |

## Activate the reference set

Copy every example over its blank starter (run from the repo root):

```bash
for f in policies/*.example.*; do cp "$f" "${f/.example/}"; done
```

This makes the local dev gate, the crate examples, `build.sh` (layer bake) and the Terraform
uploads all use the populated set. Omit it to keep the safe deny-all defaults.

## Per project

A project points its own `policy_dir` at a directory of **plain-named** files (`tools.json`, …).
Start from these examples, then commit the project's own versions. The broker acceptance test
(`crates/aegis-broker/tests/policy_files.rs`) and the crate examples always read the `.example.*`
files, so they stay green regardless of whether you've activated the starters.
