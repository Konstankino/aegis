//! `aegis init` — scaffold a policy directory. By default it writes the **populated example set**
//! (so a fresh start is never empty); `--blank` writes the safe default-deny starters instead.
//!
//! The populated content is the repo's `policies/*.example.*` reference set, embedded at compile
//! time via `include_str!`, so `init` works in a brand-new empty directory (no files to copy from).

use anyhow::Result;

use crate::artifacts::Artifact;
use crate::io::{PolicyDir, WriteOutcome};

/// The blank, safe-by-default starter content (default-deny / inert; all validate).
fn starter(artifact: Artifact) -> &'static str {
    match artifact {
        Artifact::Tools => "[]\n",
        Artifact::BrokerCedar => {
            "// Aegis broker Cedar policy — default-deny (no `permit` rule yet).\n\
             // Managed by `aegis broker policy`.\n"
        }
        Artifact::Egress => {
            "# Aegis egress allowlist — STARTER (default-deny; no hosts → all egress denied).\n\
             # Managed by `aegis egress`.\n"
        }
        Artifact::Meter => {
            "# Aegis meter limits — STARTER (empty → built-in Limits::default()).\n\
             # Managed by `aegis meter`.\n"
        }
        Artifact::Pins => "{}\n",
        Artifact::Honeypots => "{\n  \"decoys\": [],\n  \"canaries\": []\n}\n",
        Artifact::Sandbox => {
            "# Aegis sandbox policy — STARTER (empty → locked-down SandboxPolicy::default()).\n\
             # Managed by `aegis sandbox`.\n"
        }
        Artifact::Grants => {
            "# Aegis JIT grant catalog — STARTER (default-deny; no grants → every request denied).\n\
             # Managed by `aegis jit`.\n\
             grants = []\n"
        }
    }
}

/// The populated reference content (the repo's `policies/*.example.*` set, embedded at build time),
/// so a fresh `init` starts with a working example instead of empty files.
fn populated(artifact: Artifact) -> &'static str {
    match artifact {
        Artifact::Tools => include_str!("../../../policies/tools.example.json"),
        Artifact::BrokerCedar => include_str!("../../../policies/broker.example.cedar"),
        Artifact::Egress => include_str!("../../../policies/egress-allowlist.example.toml"),
        Artifact::Meter => include_str!("../../../policies/meter.example.toml"),
        Artifact::Pins => include_str!("../../../policies/pins.example.json"),
        Artifact::Honeypots => include_str!("../../../policies/honeypots.example.json"),
        Artifact::Sandbox => include_str!("../../../policies/sandbox.example.toml"),
        Artifact::Grants => include_str!("../../../policies/grants.example.toml"),
    }
}

/// Scaffold every artifact. Default: the **populated example set**. With `blank`: the safe
/// default-deny starters. Returns per-artifact outcomes.
pub fn init(dir: &PolicyDir, blank: bool, dry_run: bool) -> Result<Vec<(Artifact, WriteOutcome)>> {
    let mut out = Vec::new();
    for a in Artifact::ALL {
        let content = if blank { starter(a) } else { populated(a) };
        out.push((a, dir.write(a, content, dry_run)?));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::unique_temp_dir;

    #[test]
    fn init_populated_is_non_empty_and_valid() {
        let dir = unique_temp_dir("init-pop");
        init(&dir, false, false).unwrap();
        // No artifact is empty, and the whole populated set validates strictly.
        for a in Artifact::ALL {
            let content = dir.read(a).unwrap().unwrap();
            assert!(!content.trim().is_empty(), "{} is empty", a.filename());
        }
        let findings = crate::validate::validate_all(&dir);
        assert!(crate::validate::all_ok(&findings), "{findings:?}");
        // The example set actually registers tools (not the empty default).
        assert!(!crate::domains::broker::load_tools(&dir).unwrap().is_empty());
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn init_blank_starters_all_validate() {
        let dir = unique_temp_dir("init-blank");
        init(&dir, true, false).unwrap();
        let findings = crate::validate::validate_all(&dir);
        assert!(crate::validate::all_ok(&findings), "{findings:?}");
        // Blank tools registry is empty (default-deny).
        assert!(crate::domains::broker::load_tools(&dir).unwrap().is_empty());
        std::fs::remove_dir_all(dir.root()).ok();
    }
}
