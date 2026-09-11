//! `sandbox.toml` — the code-execution sandbox policy (`aegis_sandbox::SandboxPolicy`).

use anyhow::{bail, Context, Result};

use aegis_sandbox::SandboxPolicy;

use crate::artifacts::Artifact;
use crate::io::{PolicyDir, WriteOutcome};
use crate::Format;

const A: Artifact = Artifact::Sandbox;
const HEADER: &str = "# Aegis sandbox policy (ASI05) — managed by `aegis sandbox`.\n\n";

/// The fields `aegis sandbox set` can override.
#[derive(Debug, Default, Clone)]
pub struct SandboxOverrides {
    pub allow_root: Option<bool>,
    pub allow_network: Option<bool>,
    pub working_dir: Option<String>,
    pub max_wall_ms: Option<u64>,
    pub max_memory_mb: Option<u64>,
}

impl SandboxOverrides {
    fn is_empty(&self) -> bool {
        self.allow_root.is_none()
            && self.allow_network.is_none()
            && self.working_dir.is_none()
            && self.max_wall_ms.is_none()
            && self.max_memory_mb.is_none()
    }
}

/// Load the current policy (partial/empty/absent fill from the locked-down default).
pub fn load(dir: &PolicyDir) -> Result<SandboxPolicy> {
    match dir.read(A)? {
        Some(text) => SandboxPolicy::from_toml(&text).map_err(|e| anyhow::anyhow!(e.to_string())),
        None => Ok(SandboxPolicy::default()),
    }
}

/// Render for `show`.
pub fn show(dir: &PolicyDir, format: Format) -> Result<String> {
    let p = load(dir)?;
    Ok(match format {
        Format::Json => crate::domains::json_pretty(&p)?,
        Format::Toml => toml::to_string_pretty(&p)?,
        Format::Text => format!(
            "sandbox policy ({})\n\
             \x20 allow_root      {}\n\
             \x20 allow_network   {}\n\
             \x20 working_dir     {}\n\
             \x20 max_wall_ms     {}\n\
             \x20 max_memory_mb   {}\n",
            if dir.exists(A) {
                A.filename()
            } else {
                "locked-down default"
            },
            p.allow_root,
            p.allow_network,
            p.working_dir,
            p.max_wall_ms,
            p.max_memory_mb,
        ),
    })
}

/// Apply the overrides (comment-preserving) and write.
pub fn set(dir: &PolicyDir, ov: &SandboxOverrides, dry_run: bool) -> Result<WriteOutcome> {
    if ov.is_empty() {
        bail!("nothing to set — pass at least one field (e.g. --allow-network false)");
    }
    let current = dir.read(A)?;
    let mut doc = match &current {
        Some(t) => t
            .parse::<toml_edit::DocumentMut>()
            .with_context(|| format!("{} is not valid TOML", A.filename()))?,
        None => HEADER
            .parse::<toml_edit::DocumentMut>()
            .expect("header parses"),
    };
    if let Some(v) = ov.allow_root {
        doc["allow_root"] = toml_edit::value(v);
    }
    if let Some(v) = ov.allow_network {
        doc["allow_network"] = toml_edit::value(v);
    }
    if let Some(v) = &ov.working_dir {
        doc["working_dir"] = toml_edit::value(v.clone());
    }
    if let Some(v) = ov.max_wall_ms {
        doc["max_wall_ms"] = toml_edit::value(v as i64);
    }
    if let Some(v) = ov.max_memory_mb {
        doc["max_memory_mb"] = toml_edit::value(v as i64);
    }
    let out = doc.to_string();
    SandboxPolicy::from_toml(&out).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    dir.write(A, &out, dry_run)
}

/// Reset to the locked-down default (a complete, explicit file).
pub fn reset(dir: &PolicyDir, dry_run: bool) -> Result<WriteOutcome> {
    let out = format!("{HEADER}{}", toml::to_string(&SandboxPolicy::default())?);
    SandboxPolicy::from_toml(&out).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    dir.write(A, &out, dry_run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::unique_temp_dir;

    #[test]
    fn set_toggles_network_and_revalidates() {
        let dir = unique_temp_dir("sandbox");
        let ov = SandboxOverrides {
            allow_network: Some(true),
            max_memory_mb: Some(512),
            ..Default::default()
        };
        super::set(&dir, &ov, false).unwrap();
        let p = load(&dir).unwrap();
        assert!(p.allow_network);
        assert_eq!(p.max_memory_mb, 512);
        assert!(!p.allow_root, "unset field keeps the locked-down default");
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn empty_overrides_rejected_and_reset_is_default() {
        let dir = unique_temp_dir("sandbox2");
        assert!(super::set(&dir, &SandboxOverrides::default(), false).is_err());
        super::reset(&dir, false).unwrap();
        assert_eq!(load(&dir).unwrap(), SandboxPolicy::default());
        std::fs::remove_dir_all(dir.root()).ok();
    }
}
