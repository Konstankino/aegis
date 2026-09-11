//! Per-domain policy logic: load, render (`show`), mutate (create/update/delete), each ending in a
//! re-validation through the owning crate's parser before the atomic write. UI-free.

pub mod broker;
pub mod egress;
pub mod honeypot;
pub mod meter;
pub mod sandbox;
pub mod supply;

use anyhow::Result;

use crate::artifacts::Artifact;
use crate::io::PolicyDir;
use crate::Format;

/// Pretty-print a serde value as JSON with a trailing newline (the canonical on-disk JSON form).
pub(crate) fn json_pretty<T: serde::Serialize>(value: &T) -> anyhow::Result<String> {
    let mut s = serde_json::to_string_pretty(value)?;
    s.push('\n');
    Ok(s)
}

/// A helpful template for an absent `broker.cedar` (Cedar has no serialized default to show).
const CEDAR_SEED: &str = "// Aegis broker Cedar policy — default-deny.\n\
     // Add least-privilege rules, e.g.:\n\
     //\n\
     //   permit ( principal, action == Action::\"invoke\", resource );\n";

/// The content to open in the editor for `artifact` (`aegis … edit` / TUI `e`).
///
/// If the file exists with content, edit it as-is. If it is **absent or blank**, pre-fill the editor
/// with the current **effective** config in the artifact's native format (the very values the tool
/// is using and displaying) — never an empty buffer. This is the fix for "editing an absent file
/// opens a blank buffer instead of the current values".
pub fn edit_seed(dir: &PolicyDir, artifact: Artifact) -> Result<String> {
    if let Some(raw) = dir.read(artifact)? {
        if !raw.trim().is_empty() {
            return Ok(raw);
        }
    }
    match artifact {
        Artifact::Tools => broker::tools_list(dir, Format::Json),
        Artifact::BrokerCedar => Ok(CEDAR_SEED.to_string()),
        Artifact::Egress => egress::show(dir, Format::Toml),
        Artifact::Meter => meter::show(dir, Format::Toml),
        Artifact::Pins => supply::show(dir, Format::Json),
        Artifact::Honeypots => honeypot::show(dir, Format::Json),
        Artifact::Sandbox => sandbox::show(dir, Format::Toml),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::unique_temp_dir;

    #[test]
    fn edit_seed_prefills_effective_values_for_absent_files() {
        let dir = unique_temp_dir("seed");
        // Absent meter.toml → seed carries the real default VALUES, not an empty buffer.
        let meter_seed = edit_seed(&dir, Artifact::Meter).unwrap();
        assert!(meter_seed.contains("max_steps"));
        assert!(meter_seed.contains("100000")); // max_tokens_per_request default
                                                // Absent sandbox → the locked-down defaults.
        assert!(edit_seed(&dir, Artifact::Sandbox)
            .unwrap()
            .contains("allow_root"));
        // Absent egress → default allowlist (https scheme).
        assert!(edit_seed(&dir, Artifact::Egress).unwrap().contains("https"));
        // JSON domains get canonical empties, cedar gets a template — all non-empty.
        assert!(!edit_seed(&dir, Artifact::Tools).unwrap().trim().is_empty());
        assert!(!edit_seed(&dir, Artifact::Pins).unwrap().trim().is_empty());
        assert!(edit_seed(&dir, Artifact::BrokerCedar)
            .unwrap()
            .contains("permit"));

        // When the file DOES exist, its raw content is used verbatim.
        dir.write(Artifact::Meter, "# custom\nmax_steps = 7\n", false)
            .unwrap();
        assert_eq!(
            edit_seed(&dir, Artifact::Meter).unwrap(),
            "# custom\nmax_steps = 7\n"
        );
        std::fs::remove_dir_all(dir.root()).ok();
    }
}
