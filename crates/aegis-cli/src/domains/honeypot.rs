//! `honeypots.json` — deception decoys + canary tokens (`aegis_honeypot::Honeypots`).

use anyhow::{bail, Context, Result};

use aegis_honeypot::Honeypots;

use crate::artifacts::Artifact;
use crate::io::{PolicyDir, WriteOutcome};
use crate::Format;

const A: Artifact = Artifact::Honeypots;

/// Load the current set (absent/empty → an inert default).
pub fn load(dir: &PolicyDir) -> Result<Honeypots> {
    match dir.read(A)? {
        Some(text) if !text.trim().is_empty() => Honeypots::from_json(&text)
            .with_context(|| format!("{} is not valid JSON", A.filename())),
        _ => Ok(Honeypots::default()),
    }
}

fn write(dir: &PolicyDir, h: &Honeypots, dry_run: bool) -> Result<WriteOutcome> {
    let out = crate::domains::json_pretty(h)?;
    Honeypots::from_json(&out).context("the resulting honeypots.json would be invalid")?;
    dir.write(A, &out, dry_run)
}

/// Render for `show`.
pub fn show(dir: &PolicyDir, format: Format) -> Result<String> {
    let h = load(dir)?;
    Ok(match format {
        Format::Json => crate::domains::json_pretty(&h)?,
        Format::Toml => bail_toml()?,
        Format::Text => {
            let mut s = format!(
                "honeypots ({}) — {} decoy(s), {} canary(ies)\n",
                if dir.exists(A) {
                    A.filename()
                } else {
                    "inert default"
                },
                h.decoys.len(),
                h.canaries.len()
            );
            for d in &h.decoys {
                s.push_str(&format!("  decoy   {d}\n"));
            }
            for c in &h.canaries {
                s.push_str(&format!("  canary  {c}\n"));
            }
            s
        }
    })
}

fn bail_toml() -> Result<String> {
    bail!("honeypots is JSON; use --format json or text")
}

/// Add a decoy substring (idempotent).
pub fn add_decoy(dir: &PolicyDir, decoy: &str, dry_run: bool) -> Result<WriteOutcome> {
    let mut h = load(dir)?;
    if !h.decoys.iter().any(|d| d == decoy) {
        h.decoys.push(decoy.to_string());
    }
    write(dir, &h, dry_run)
}

/// Remove a decoy (error if absent, so a typo is caught).
pub fn rm_decoy(dir: &PolicyDir, decoy: &str, dry_run: bool) -> Result<WriteOutcome> {
    let mut h = load(dir)?;
    let before = h.decoys.len();
    h.decoys.retain(|d| d != decoy);
    if h.decoys.len() == before {
        bail!("decoy not found: {decoy}");
    }
    write(dir, &h, dry_run)
}

/// Add a canary token (idempotent).
pub fn add_canary(dir: &PolicyDir, canary: &str, dry_run: bool) -> Result<WriteOutcome> {
    let mut h = load(dir)?;
    if !h.canaries.iter().any(|c| c == canary) {
        h.canaries.push(canary.to_string());
    }
    write(dir, &h, dry_run)
}

/// Remove a canary (error if absent).
pub fn rm_canary(dir: &PolicyDir, canary: &str, dry_run: bool) -> Result<WriteOutcome> {
    let mut h = load(dir)?;
    let before = h.canaries.len();
    h.canaries.retain(|c| c != canary);
    if h.canaries.len() == before {
        bail!("canary not found: {canary}");
    }
    write(dir, &h, dry_run)
}

/// Generate a fresh unguessable canary token, add it, and return `(token, outcome)`.
pub fn gen_canary(dir: &PolicyDir, dry_run: bool) -> Result<(String, WriteOutcome)> {
    let token = random_token()?;
    let outcome = add_canary(dir, &token, dry_run)?;
    Ok((token, outcome))
}

/// 128 bits of OS entropy, hex-encoded, as an `aegis-canary-…` token.
fn random_token() -> Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").context("opening /dev/urandom for a canary")?;
    let mut buf = [0u8; 16];
    f.read_exact(&mut buf).context("reading entropy")?;
    let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("aegis-canary-{hex}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::unique_temp_dir;

    #[test]
    fn add_remove_decoy_and_canary_round_trip() {
        let dir = unique_temp_dir("hp");
        add_decoy(&dir, "169.254.169.254", false).unwrap();
        add_decoy(&dir, "169.254.169.254", false).unwrap(); // idempotent
        add_canary(&dir, "CANARY-x", false).unwrap();
        let h = load(&dir).unwrap();
        assert_eq!(h.decoys, vec!["169.254.169.254"]);
        assert_eq!(h.canaries, vec!["CANARY-x"]);
        rm_decoy(&dir, "169.254.169.254", false).unwrap();
        assert!(load(&dir).unwrap().decoys.is_empty());
        assert!(rm_canary(&dir, "nope", false).is_err()); // removing absent errors
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn gen_canary_is_unique_and_persisted() {
        let dir = unique_temp_dir("hp2");
        let (t1, _) = gen_canary(&dir, false).unwrap();
        let (t2, _) = gen_canary(&dir, false).unwrap();
        assert!(t1.starts_with("aegis-canary-") && t1.len() > 20);
        assert_ne!(t1, t2);
        assert!(load(&dir).unwrap().canaries.contains(&t1));
        std::fs::remove_dir_all(dir.root()).ok();
    }
}
