//! `grants.toml` — the JIT credential grant catalog (`aegis_jit::GrantCatalog`).
//!
//! Authoring stays a typed round-trip: load → mutate the typed catalog → re-serialize →
//! **re-parse + `validate()`** → atomic write, so the CLI can never persist a catalog the runtime
//! would reject. The catalog is machine-managed (like `tools.json`/`pins.json`), so writes are
//! canonical TOML under a fixed header rather than comment-preserving edits.

use anyhow::{bail, Result};

use aegis_core::Consequence;
use aegis_jit::{Grant, GrantCatalog, Provider};

use crate::artifacts::Artifact;
use crate::io::{PolicyDir, WriteOutcome};
use crate::Format;

const A: Artifact = Artifact::Grants;
const HEADER: &str = "# Aegis JIT grant catalog (ASI03/ASI06) — managed by `aegis jit`.\n\
     # Default-deny: no grants → every JIT credential request is denied.\n\n";

/// Which Rule-of-Two leg a grant contributes (a read source = leg B; a write/destination = leg C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    /// Reads sensitive/regulated data (leg B).
    Read,
    /// Produces an external effect — write / destination / outbound (leg C).
    Write,
}

/// Fields for `aegis jit add-sts`.
#[derive(Debug, Clone)]
pub struct StsGrantSpec {
    pub id: String,
    pub audience: String,
    pub scope: String,
    pub role_arn: String,
    pub resource_arns: Vec<String>,
    pub session_policy_template: String,
    pub max_ttl_secs: u64,
    pub leg: Leg,
    pub irreversible: bool,
}

/// Fields for `aegis jit add-secret`.
#[derive(Debug, Clone)]
pub struct SecretGrantSpec {
    pub id: String,
    pub audience: String,
    pub scope: String,
    pub secret_arn: String,
    pub json_key: Option<String>,
    pub max_ttl_secs: u64,
    pub leg: Leg,
    pub irreversible: bool,
}

fn legs_of(leg: Leg) -> (bool, bool) {
    match leg {
        Leg::Read => (true, false), // reads_sensitive, external_effect
        Leg::Write => (false, true),
    }
}

fn consequence_of(irreversible: bool) -> Consequence {
    if irreversible {
        Consequence::HighOrIrreversible
    } else {
        Consequence::LowReversible
    }
}

/// Load the catalog (absent/empty → the empty deny-all catalog).
pub fn load(dir: &PolicyDir) -> Result<GrantCatalog> {
    match dir.read(A)? {
        Some(text) if !text.trim().is_empty() => {
            GrantCatalog::from_toml(&text).map_err(|e| anyhow::anyhow!(e.to_string()))
        }
        _ => Ok(GrantCatalog::empty()),
    }
}

/// Serialize + re-validate the exact bytes and write atomically.
fn persist(dir: &PolicyDir, cat: &GrantCatalog, dry_run: bool) -> Result<WriteOutcome> {
    cat.validate().map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let body = cat.to_toml().map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let out = format!("{HEADER}{body}");
    // Re-parse the concrete bytes we are about to persist — belt and braces.
    GrantCatalog::from_toml(&out)
        .and_then(|c| c.validate())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    dir.write(A, &out, dry_run)
}

/// `show` — render the catalog in the requested format.
pub fn show(dir: &PolicyDir, format: Format) -> Result<String> {
    let cat = load(dir)?;
    Ok(match format {
        Format::Json => crate::domains::json_pretty(&cat)?,
        Format::Toml => format!(
            "{HEADER}{}",
            cat.to_toml().map_err(|e| anyhow::anyhow!(e.to_string()))?
        ),
        Format::Text => {
            let mut s = format!(
                "jit grants ({})\n",
                if dir.exists(A) {
                    A.filename()
                } else {
                    "empty (deny-all)"
                }
            );
            if cat.all().is_empty() {
                s.push_str("  (no grants — every JIT credential request is denied)\n");
            }
            for g in cat.all() {
                s.push_str(&format!(
                    "  {:<20} [{}] audience={} scope={} ttl<={}s legs={}{}{}\n",
                    g.id,
                    g.provider.kind(),
                    g.audience,
                    g.required_scope,
                    g.max_ttl_secs,
                    if g.reads_sensitive { "B" } else { "-" },
                    if g.external_effect { "C" } else { "-" },
                    if matches!(g.consequence, Consequence::HighOrIrreversible) {
                        " irreversible"
                    } else {
                        ""
                    },
                ));
            }
            s
        }
    })
}

/// Render a single grant (for `aegis jit show <id>`).
pub fn show_one(dir: &PolicyDir, id: &str, format: Format) -> Result<String> {
    let cat = load(dir)?;
    let g = cat
        .get(id)
        .ok_or_else(|| anyhow::anyhow!("no such grant: {id}"))?;
    Ok(match format {
        Format::Json => crate::domains::json_pretty(g)?,
        _ => toml::to_string_pretty(g)?,
    })
}

/// `add-sts` — add or replace an STS-session grant.
pub fn add_sts(dir: &PolicyDir, spec: StsGrantSpec, dry_run: bool) -> Result<WriteOutcome> {
    let (reads_sensitive, external_effect) = legs_of(spec.leg);
    let grant = Grant {
        id: spec.id,
        audience: spec.audience,
        required_scope: spec.scope,
        max_ttl_secs: spec.max_ttl_secs,
        reads_sensitive,
        external_effect,
        forbid_when_trifecta: true,
        consequence: consequence_of(spec.irreversible),
        provider: Provider::Sts {
            role_arn: spec.role_arn,
            resource_arns: spec.resource_arns,
            session_policy_template: spec.session_policy_template,
        },
    };
    let mut cat = load(dir)?;
    cat.upsert(grant);
    persist(dir, &cat, dry_run)
}

/// `add-secret` — add or replace a Secrets Manager grant.
pub fn add_secret(dir: &PolicyDir, spec: SecretGrantSpec, dry_run: bool) -> Result<WriteOutcome> {
    let (reads_sensitive, external_effect) = legs_of(spec.leg);
    let grant = Grant {
        id: spec.id,
        audience: spec.audience,
        required_scope: spec.scope,
        max_ttl_secs: spec.max_ttl_secs,
        reads_sensitive,
        external_effect,
        forbid_when_trifecta: true,
        consequence: consequence_of(spec.irreversible),
        provider: Provider::Secret {
            secret_arn: spec.secret_arn,
            json_key: spec.json_key,
        },
    };
    let mut cat = load(dir)?;
    cat.upsert(grant);
    persist(dir, &cat, dry_run)
}

/// `set-ttl` — change a grant's TTL ceiling.
pub fn set_ttl(dir: &PolicyDir, id: &str, secs: u64, dry_run: bool) -> Result<WriteOutcome> {
    if secs == 0 {
        bail!("max_ttl_secs must be positive");
    }
    let mut cat = load(dir)?;
    let mut g = cat
        .get(id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no such grant: {id}"))?;
    g.max_ttl_secs = secs;
    cat.upsert(g);
    persist(dir, &cat, dry_run)
}

/// `rm` — remove a grant.
pub fn rm(dir: &PolicyDir, id: &str, dry_run: bool) -> Result<WriteOutcome> {
    let mut cat = load(dir)?;
    if !cat.remove(id) {
        bail!("no such grant: {id}");
    }
    persist(dir, &cat, dry_run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::unique_temp_dir;

    fn sts_spec(id: &str) -> StsGrantSpec {
        StsGrantSpec {
            id: id.into(),
            audience: "patient-db".into(),
            scope: "db.read".into(),
            role_arn: "arn:aws:iam::111122223333:role/aegis-jit-read".into(),
            resource_arns: vec!["arn:aws:rds-db:us-east-1:111122223333:dbuser/db/reader".into()],
            session_policy_template: "{\"Version\":\"2012-10-17\"}".into(),
            max_ttl_secs: 300,
            leg: Leg::Read,
            irreversible: false,
        }
    }

    #[test]
    fn add_sts_then_load_round_trips_and_validates() {
        let dir = unique_temp_dir("jit-sts");
        add_sts(&dir, sts_spec("read-1"), false).unwrap();
        let cat = load(&dir).unwrap();
        assert_eq!(cat.all().len(), 1);
        let g = cat.get("read-1").unwrap();
        assert!(g.reads_sensitive && !g.external_effect);
        assert_eq!(g.provider.kind(), "sts");
        // The written bytes validate strictly.
        cat.validate().unwrap();
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn add_secret_write_leg_and_set_ttl_and_rm() {
        let dir = unique_temp_dir("jit-secret");
        add_secret(
            &dir,
            SecretGrantSpec {
                id: "key-1".into(),
                audience: "payments".into(),
                scope: "payments.charge".into(),
                secret_arn: "arn:aws:secretsmanager:us-east-1:111122223333:secret:k".into(),
                json_key: Some("api_key".into()),
                max_ttl_secs: 60,
                leg: Leg::Write,
                irreversible: true,
            },
            false,
        )
        .unwrap();
        let g = load(&dir).unwrap().get("key-1").unwrap().clone();
        assert!(g.external_effect && !g.reads_sensitive);
        assert!(matches!(g.consequence, Consequence::HighOrIrreversible));

        set_ttl(&dir, "key-1", 30, false).unwrap();
        assert_eq!(load(&dir).unwrap().get("key-1").unwrap().max_ttl_secs, 30);

        rm(&dir, "key-1", false).unwrap();
        assert!(load(&dir).unwrap().all().is_empty());
        assert!(
            rm(&dir, "key-1", false).is_err(),
            "removing a missing grant errors"
        );
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn upsert_replaces_by_id() {
        let dir = unique_temp_dir("jit-upsert");
        add_sts(&dir, sts_spec("g"), false).unwrap();
        let mut spec = sts_spec("g");
        spec.max_ttl_secs = 120;
        add_sts(&dir, spec, false).unwrap();
        let cat = load(&dir).unwrap();
        assert_eq!(cat.all().len(), 1);
        assert_eq!(cat.get("g").unwrap().max_ttl_secs, 120);
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn show_text_lists_grants_and_empty_is_deny_all() {
        let dir = unique_temp_dir("jit-show");
        assert!(show(&dir, Format::Text).unwrap().contains("no grants"));
        add_sts(&dir, sts_spec("read-1"), false).unwrap();
        let text = show(&dir, Format::Text).unwrap();
        assert!(text.contains("read-1") && text.contains("[sts]"));
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn show_json_and_toml_and_show_one() {
        let dir = unique_temp_dir("jit-fmt");
        let mut spec = sts_spec("read-1");
        spec.irreversible = true; // exercise the "irreversible" text label too
        add_sts(&dir, spec, false).unwrap();
        assert!(show(&dir, Format::Text).unwrap().contains("irreversible"));
        assert!(show(&dir, Format::Json).unwrap().contains("\"read-1\""));
        assert!(show(&dir, Format::Toml).unwrap().contains("read-1"));
        // show_one both formats.
        assert!(show_one(&dir, "read-1", Format::Json)
            .unwrap()
            .contains("read-1"));
        assert!(show_one(&dir, "read-1", Format::Toml)
            .unwrap()
            .contains("read-1"));
        assert!(show_one(&dir, "nope", Format::Toml).is_err());
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn set_ttl_zero_and_missing_are_rejected() {
        let dir = unique_temp_dir("jit-ttl0");
        add_sts(&dir, sts_spec("g"), false).unwrap();
        assert!(set_ttl(&dir, "g", 0, false).is_err());
        assert!(set_ttl(&dir, "missing", 30, false).is_err());
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn add_dry_run_writes_nothing() {
        let dir = unique_temp_dir("jit-dry");
        let out = add_sts(&dir, sts_spec("g"), true).unwrap();
        assert!(matches!(out, WriteOutcome::DryRun(_)));
        assert!(load(&dir).unwrap().all().is_empty());
        std::fs::remove_dir_all(dir.root()).ok();
    }
}
