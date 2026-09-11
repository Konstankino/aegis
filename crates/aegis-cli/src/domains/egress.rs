//! `egress-allowlist.toml` — the egress firewall allowlist (`aegis_egress::Allowlist`).
//!
//! List/table edits go through `toml_edit` so comments and formatting survive; every write is
//! re-validated with `Allowlist::from_toml`.

use anyhow::{bail, Context, Result};
use toml_edit::{Array, DocumentMut, Item, Table};

use aegis_egress::Allowlist;

use crate::artifacts::Artifact;
use crate::io::{PolicyDir, WriteOutcome};
use crate::Format;

const A: Artifact = Artifact::Egress;
const HEADER: &str =
    "# Aegis egress allowlist (LLM02) — managed by `aegis egress`. Default-deny.\n\n";

/// Load the current allowlist (absent/empty → the default-deny defaults). Parse the empty case
/// through `from_toml` too, so serde field defaults apply (notably `schemes = ["https"]`) and the
/// CLI's view matches what the runtime actually loads — `Allowlist::default()` would wrongly show
/// `schemes = []`.
pub fn load(dir: &PolicyDir) -> Result<Allowlist> {
    let text = dir.read(A)?.unwrap_or_default();
    Allowlist::from_toml(&text).map_err(|e| anyhow::anyhow!(e.to_string()))
}

/// Render for `show`.
pub fn show(dir: &PolicyDir, format: Format) -> Result<String> {
    let a = load(dir)?;
    Ok(match format {
        Format::Json => crate::domains::json_pretty(&a)?,
        Format::Toml => toml::to_string_pretty(&a)?,
        Format::Text => {
            let mut s = format!(
                "egress allowlist ({}) — schemes {:?}\n",
                if dir.exists(A) {
                    A.filename()
                } else {
                    "default-deny default"
                },
                a.schemes
            );
            for h in &a.hosts {
                s.push_str(&format!("  host    {h}\n"));
            }
            for suf in &a.suffixes {
                s.push_str(&format!("  suffix  {suf}\n"));
            }
            for (host, params) in &a.permitted_params {
                s.push_str(&format!("  params  {host}: {}\n", params.join(", ")));
            }
            s
        }
    })
}

fn open(dir: &PolicyDir) -> Result<DocumentMut> {
    match dir.read(A)? {
        Some(t) => t
            .parse::<DocumentMut>()
            .with_context(|| format!("{} is not valid TOML", A.filename())),
        None => Ok(HEADER.parse::<DocumentMut>().expect("header parses")),
    }
}

fn finish(dir: &PolicyDir, doc: DocumentMut, dry_run: bool) -> Result<WriteOutcome> {
    let out = doc.to_string();
    Allowlist::from_toml(&out).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    dir.write(A, &out, dry_run)
}

fn ensure_array<'a>(doc: &'a mut DocumentMut, key: &str) -> Result<&'a mut Array> {
    if doc.get(key).is_none() {
        doc[key] = toml_edit::value(Array::new());
    }
    doc[key]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`{key}` in egress-allowlist.toml is not an array"))
}

fn add_to_list(dir: &PolicyDir, key: &str, value: &str, dry_run: bool) -> Result<WriteOutcome> {
    let mut doc = open(dir)?;
    let arr = ensure_array(&mut doc, key)?;
    if arr.iter().any(|v| v.as_str() == Some(value)) {
        return finish(dir, doc, dry_run); // idempotent
    }
    arr.push(value);
    finish(dir, doc, dry_run)
}

fn rm_from_list(dir: &PolicyDir, key: &str, value: &str, dry_run: bool) -> Result<WriteOutcome> {
    let mut doc = open(dir)?;
    let arr = ensure_array(&mut doc, key)?;
    let before = arr.len();
    arr.retain(|v| v.as_str() != Some(value));
    if arr.len() == before {
        bail!("`{value}` not found in {key}");
    }
    finish(dir, doc, dry_run)
}

/// `allow-host` / `rm-host`.
pub fn allow_host(dir: &PolicyDir, host: &str, dry_run: bool) -> Result<WriteOutcome> {
    add_to_list(dir, "hosts", host, dry_run)
}
pub fn rm_host(dir: &PolicyDir, host: &str, dry_run: bool) -> Result<WriteOutcome> {
    rm_from_list(dir, "hosts", host, dry_run)
}

/// `allow-suffix` / `rm-suffix`.
pub fn allow_suffix(dir: &PolicyDir, suffix: &str, dry_run: bool) -> Result<WriteOutcome> {
    add_to_list(dir, "suffixes", suffix, dry_run)
}
pub fn rm_suffix(dir: &PolicyDir, suffix: &str, dry_run: bool) -> Result<WriteOutcome> {
    rm_from_list(dir, "suffixes", suffix, dry_run)
}

/// `set-schemes` — replace the permitted scheme list.
pub fn set_schemes(dir: &PolicyDir, schemes: &[String], dry_run: bool) -> Result<WriteOutcome> {
    if schemes.is_empty() {
        bail!("at least one scheme is required (e.g. https)");
    }
    let mut doc = open(dir)?;
    let mut arr = Array::new();
    for s in schemes {
        arr.push(s.as_str());
    }
    doc["schemes"] = toml_edit::value(arr);
    finish(dir, doc, dry_run)
}

/// `permit-param <host> <param>` — allow one query parameter to survive for a host.
pub fn permit_param(
    dir: &PolicyDir,
    host: &str,
    param: &str,
    dry_run: bool,
) -> Result<WriteOutcome> {
    let mut doc = open(dir)?;
    if doc.get("permitted_params").is_none() {
        doc["permitted_params"] = Item::Table(Table::new());
    }
    let tbl = doc["permitted_params"]
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("`permitted_params` is not a table"))?;
    if tbl.get(host).is_none() {
        tbl[host] = toml_edit::value(Array::new());
    }
    let arr = tbl[host]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`permitted_params.{host}` is not an array"))?;
    if !arr.iter().any(|v| v.as_str() == Some(param)) {
        arr.push(param);
    }
    finish(dir, doc, dry_run)
}

/// `rm-param <host> <param>`.
pub fn rm_param(dir: &PolicyDir, host: &str, param: &str, dry_run: bool) -> Result<WriteOutcome> {
    let mut doc = open(dir)?;
    let tbl = doc
        .get_mut("permitted_params")
        .and_then(|i| i.as_table_mut())
        .ok_or_else(|| anyhow::anyhow!("no permitted_params for '{host}'"))?;
    let arr = tbl
        .get_mut(host)
        .and_then(|i| i.as_array_mut())
        .ok_or_else(|| anyhow::anyhow!("no permitted params for '{host}'"))?;
    let before = arr.len();
    arr.retain(|v| v.as_str() != Some(param));
    if arr.len() == before {
        bail!("'{param}' not permitted for '{host}'");
    }
    finish(dir, doc, dry_run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::unique_temp_dir;

    #[test]
    fn host_suffix_scheme_param_round_trip_with_comments() {
        let dir = unique_temp_dir("egress");
        dir.write(A, "# my allowlist\nhosts = [\"a.example\"]\n", false)
            .unwrap();
        allow_host(&dir, "b.example", false).unwrap();
        allow_host(&dir, "b.example", false).unwrap(); // idempotent
        allow_suffix(&dir, ".s3.amazonaws.com", false).unwrap();
        set_schemes(&dir, &["https".into()], false).unwrap();
        permit_param(&dir, "b.example", "page", false).unwrap();
        let text = dir.read(A).unwrap().unwrap();
        assert!(text.contains("# my allowlist"), "comment preserved");
        let a = load(&dir).unwrap();
        assert!(a.hosts.contains(&"a.example".to_string()));
        assert!(a.hosts.contains(&"b.example".to_string()));
        assert!(a.suffixes.contains(&".s3.amazonaws.com".to_string()));
        assert_eq!(a.permitted_params["b.example"], vec!["page".to_string()]);
        // Remove paths error when absent.
        assert!(rm_host(&dir, "nope.example", false).is_err());
        rm_host(&dir, "a.example", false).unwrap();
        assert!(!load(&dir).unwrap().hosts.contains(&"a.example".to_string()));
        std::fs::remove_dir_all(dir.root()).ok();
    }
}
