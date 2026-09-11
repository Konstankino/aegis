//! `pins.json` — the supply-chain digest pinset (`aegis_supply::Pinset`, a transparent
//! `name → {algo:hex}` map).

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};

use aegis_supply::{Digest, Pinset};

use crate::artifacts::Artifact;
use crate::io::{PolicyDir, WriteOutcome};
use crate::Format;

const A: Artifact = Artifact::Pins;

/// Load the current pinset (absent/empty → an empty, fail-closed pinset).
pub fn load(dir: &PolicyDir) -> Result<Pinset> {
    match dir.read(A)? {
        Some(text) if !text.trim().is_empty() => {
            Pinset::from_json(&text).with_context(|| format!("{} is not valid JSON", A.filename()))
        }
        _ => Ok(Pinset::default()),
    }
}

/// Serialize sorted (stable diffs) and re-validate through the crate parser.
fn write(dir: &PolicyDir, pinset: &Pinset, dry_run: bool) -> Result<WriteOutcome> {
    let sorted: BTreeMap<&String, BTreeSet<&String>> = pinset
        .pins
        .iter()
        .map(|(k, v)| (k, v.iter().collect()))
        .collect();
    let out = crate::domains::json_pretty(&sorted)?;
    Pinset::from_json(&out).context("the resulting pins.json would be invalid")?;
    dir.write(A, &out, dry_run)
}

/// Render for `show`.
pub fn show(dir: &PolicyDir, format: Format) -> Result<String> {
    let p = load(dir)?;
    match format {
        Format::Json => crate::domains::json_pretty(&p),
        Format::Toml => bail!("pins is JSON; use --format json or text"),
        Format::Text => {
            let mut s = format!(
                "pinset ({}) — {} artifact(s)\n",
                if dir.exists(A) {
                    A.filename()
                } else {
                    "empty (fail-closed)"
                },
                p.pins.len()
            );
            let sorted: BTreeMap<&String, BTreeSet<&String>> = p
                .pins
                .iter()
                .map(|(k, v)| (k, v.iter().collect()))
                .collect();
            for (name, digests) in sorted {
                s.push_str(&format!("  {name}\n"));
                for d in digests {
                    s.push_str(&format!("      {d}\n"));
                }
            }
            Ok(s)
        }
    }
}

/// Pin a digest reference (`sha256:<hex>`) under `name`. Validates the digest format.
pub fn pin(dir: &PolicyDir, name: &str, digest_ref: &str, dry_run: bool) -> Result<WriteOutcome> {
    let digest = Digest::parse(digest_ref).ok_or_else(|| {
        anyhow::anyhow!("not a valid digest '{digest_ref}' (expected e.g. sha256:<64 hex>)")
    })?;
    add(dir, name, &digest, dry_run)
}

/// Pin a local file by hashing it (sha256) under `name`.
pub fn pin_file(dir: &PolicyDir, name: &str, path: &str, dry_run: bool) -> Result<WriteOutcome> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {path} to hash"))?;
    let digest = Digest::sha256(&bytes);
    add(dir, name, &digest, dry_run)
}

fn add(dir: &PolicyDir, name: &str, digest: &Digest, dry_run: bool) -> Result<WriteOutcome> {
    let mut p = load(dir)?;
    p.pins
        .entry(name.to_string())
        .or_default()
        .insert(digest.to_ref());
    write(dir, &p, dry_run)
}

/// Unpin: a specific digest, or the whole name when `digest_ref` is `None`. Errors if absent.
pub fn unpin(
    dir: &PolicyDir,
    name: &str,
    digest_ref: Option<&str>,
    dry_run: bool,
) -> Result<WriteOutcome> {
    let mut p = load(dir)?;
    match digest_ref {
        None => {
            if p.pins.remove(name).is_none() {
                bail!("no pins for '{name}'");
            }
        }
        Some(dref) => {
            let digest = Digest::parse(dref)
                .ok_or_else(|| anyhow::anyhow!("not a valid digest '{dref}'"))?;
            let set = p
                .pins
                .get_mut(name)
                .ok_or_else(|| anyhow::anyhow!("no pins for '{name}'"))?;
            if !set.remove(&digest.to_ref()) {
                bail!("'{name}' is not pinned to {}", digest.to_ref());
            }
            if set.is_empty() {
                p.pins.remove(name);
            }
        }
    }
    write(dir, &p, dry_run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::unique_temp_dir;

    #[test]
    fn pin_validates_and_round_trips_sorted() {
        let dir = unique_temp_dir("supply");
        let d = Digest::sha256(b"weights-v1").to_ref();
        pin(&dir, "model", &d, false).unwrap();
        pin(&dir, "model", &d, false).unwrap(); // idempotent (set)
        assert!(load(&dir).unwrap().pins["model"].contains(&d));
        // A malformed digest is rejected without writing.
        assert!(pin(&dir, "model", "not-a-digest", false).is_err());
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn pin_file_hashes_and_unpin_removes() {
        let dir = unique_temp_dir("supply2");
        let f = dir.root().join("artifact.bin");
        std::fs::write(&f, b"hello").unwrap();
        pin_file(&dir, "blob", f.to_str().unwrap(), false).unwrap();
        let expected = Digest::sha256(b"hello").to_ref();
        assert!(load(&dir).unwrap().pins["blob"].contains(&expected));
        // Unpin the specific digest removes the now-empty name.
        unpin(&dir, "blob", Some(&expected), false).unwrap();
        assert!(!load(&dir).unwrap().pins.contains_key("blob"));
        assert!(unpin(&dir, "blob", None, false).is_err()); // already gone
        std::fs::remove_dir_all(dir.root()).ok();
    }
}
