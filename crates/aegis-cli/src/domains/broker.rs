//! The broker domain: `tools.json` (a `Vec<ToolSpec>`) and `broker.cedar` (opaque, validated text).
//!
//! Tool specs round-trip through serde; Cedar is edited as text and validated with
//! `PolicyEngine::from_cedar`. Any change to either file is cross-checked with `Broker::from_sources`
//! so the two always compile together.

use anyhow::{bail, Context, Result};

use aegis_broker::{Broker, PolicyEngine, ToolRegistry, ToolSpec};
use aegis_core::Consequence;

use crate::artifacts::Artifact;
use crate::io::{PolicyDir, WriteOutcome};
use crate::Format;

const TOOLS: Artifact = Artifact::Tools;
const CEDAR: Artifact = Artifact::BrokerCedar;

// ── tools.json ──────────────────────────────────────────────────────────────────────────────────

/// Load the tool specs (absent/empty → an empty registry = every tool denied).
pub fn load_tools(dir: &PolicyDir) -> Result<Vec<ToolSpec>> {
    match dir.read(TOOLS)? {
        Some(text) if !text.trim().is_empty() => serde_json::from_str::<Vec<ToolSpec>>(&text)
            .with_context(|| format!("{} is not a valid tool array", TOOLS.filename())),
        _ => Ok(Vec::new()),
    }
}

/// The current Cedar source (absent → empty = default-deny, which parses fine).
fn cedar_src(dir: &PolicyDir) -> Result<String> {
    Ok(dir.read(CEDAR)?.unwrap_or_default())
}

/// Serialize the specs, re-validate them (schemas compile) AND cross-check with the current Cedar
/// via `Broker::from_sources`, then write.
fn write_tools(dir: &PolicyDir, specs: &[ToolSpec], dry_run: bool) -> Result<WriteOutcome> {
    let out = crate::domains::json_pretty(&specs)?;
    ToolRegistry::from_json(&out).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Broker::from_sources(&out, &cedar_src(dir)?)
        .map_err(|e| anyhow::anyhow!("tools + cedar do not compile together: {e}"))?;
    dir.write(TOOLS, &out, dry_run)
}

fn consequence_from_str(s: &str) -> Result<Consequence> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).with_context(|| {
        format!("bad consequence '{s}' (expected low_reversible|high_or_irreversible)")
    })
}

fn consequence_str(c: &Consequence) -> &'static str {
    match c {
        Consequence::LowReversible => "low_reversible",
        Consequence::HighOrIrreversible => "high_or_irreversible",
    }
}

/// A new tool spec from `tools add`. `schema_json` is inline JSON text (already resolved from a file
/// / stdin by the caller); `None` defaults to a permissive object schema.
#[derive(Debug, Clone)]
pub struct NewTool {
    pub name: String,
    pub consequence: String,
    pub reaches_sensitive: bool,
    pub external_effect: bool,
    pub version: Option<String>,
    pub schema_json: Option<String>,
}

/// `tools list`.
pub fn tools_list(dir: &PolicyDir, format: Format) -> Result<String> {
    let specs = load_tools(dir)?;
    Ok(match format {
        Format::Json => crate::domains::json_pretty(&specs)?,
        Format::Toml => bail_toml()?,
        Format::Text => {
            let mut s = format!(
                "tools ({}) — {} registered\n",
                TOOLS.filename(),
                specs.len()
            );
            for t in &specs {
                s.push_str(&format!(
                    "  {:<24} consequence={:<20} sensitive={} external={}{}\n",
                    t.name,
                    consequence_str(&t.consequence),
                    t.reaches_sensitive_data,
                    t.has_external_effect,
                    t.version
                        .as_deref()
                        .map(|v| format!(" v{v}"))
                        .unwrap_or_default(),
                ));
            }
            s
        }
    })
}

fn bail_toml() -> Result<String> {
    bail!("tools is JSON; use --format json or text")
}

/// `tools show <name>` — the one spec, pretty JSON.
pub fn tools_show(dir: &PolicyDir, name: &str) -> Result<String> {
    let specs = load_tools(dir)?;
    let spec = specs
        .iter()
        .find(|t| t.name == name)
        .ok_or_else(|| anyhow::anyhow!("no such tool '{name}'"))?;
    crate::domains::json_pretty(spec)
}

/// `tools add`.
pub fn tools_add(dir: &PolicyDir, new: &NewTool, dry_run: bool) -> Result<WriteOutcome> {
    let mut specs = load_tools(dir)?;
    if specs.iter().any(|t| t.name == new.name) {
        bail!(
            "tool '{}' already exists (use `tools set` to modify it)",
            new.name
        );
    }
    let schema: serde_json::Value = match &new.schema_json {
        Some(js) => serde_json::from_str(js).context("--schema is not valid JSON")?,
        None => serde_json::json!({ "type": "object" }),
    };
    specs.push(ToolSpec {
        name: new.name.clone(),
        version: new.version.clone(),
        reaches_sensitive_data: new.reaches_sensitive,
        has_external_effect: new.external_effect,
        consequence: consequence_from_str(&new.consequence)?,
        schema,
    });
    write_tools(dir, &specs, dry_run)
}

/// Fields `tools set` can change (each optional).
#[derive(Debug, Default, Clone)]
pub struct ToolUpdate {
    pub consequence: Option<String>,
    pub reaches_sensitive: Option<bool>,
    pub external_effect: Option<bool>,
    pub version: Option<Option<String>>, // Some(None) clears the version
    pub schema_json: Option<String>,
}

/// `tools set <name>`.
pub fn tools_set(
    dir: &PolicyDir,
    name: &str,
    up: &ToolUpdate,
    dry_run: bool,
) -> Result<WriteOutcome> {
    let mut specs = load_tools(dir)?;
    let spec = specs
        .iter_mut()
        .find(|t| t.name == name)
        .ok_or_else(|| anyhow::anyhow!("no such tool '{name}'"))?;
    if let Some(c) = &up.consequence {
        spec.consequence = consequence_from_str(c)?;
    }
    if let Some(b) = up.reaches_sensitive {
        spec.reaches_sensitive_data = b;
    }
    if let Some(b) = up.external_effect {
        spec.has_external_effect = b;
    }
    if let Some(v) = &up.version {
        spec.version = v.clone();
    }
    if let Some(js) = &up.schema_json {
        spec.schema = serde_json::from_str(js).context("--schema is not valid JSON")?;
    }
    write_tools(dir, &specs, dry_run)
}

/// `tools rm <name>`.
pub fn tools_rm(dir: &PolicyDir, name: &str, dry_run: bool) -> Result<WriteOutcome> {
    let mut specs = load_tools(dir)?;
    let before = specs.len();
    specs.retain(|t| t.name != name);
    if specs.len() == before {
        bail!("no such tool '{name}'");
    }
    write_tools(dir, &specs, dry_run)
}

// ── broker.cedar ────────────────────────────────────────────────────────────────────────────────

/// `policy show`.
pub fn cedar_show(dir: &PolicyDir) -> Result<String> {
    Ok(dir.read(CEDAR)?.unwrap_or_default())
}

/// Validate `broker.cedar` alone and together with `tools.json`. Returns a human summary or errors.
pub fn cedar_validate(dir: &PolicyDir) -> Result<String> {
    let cedar = cedar_src(dir)?;
    let engine = PolicyEngine::from_cedar(&cedar).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let tools = dir.read(TOOLS)?.unwrap_or_else(|| "[]".to_string());
    Broker::from_sources(&tools, &cedar)
        .map_err(|e| anyhow::anyhow!("tools + cedar do not compile together: {e}"))?;
    Ok(format!("cedar OK — {} policy statement(s)", engine.len()))
}

/// `policy set <file>` — replace the Cedar source from a file, validated before writing.
pub fn cedar_set_from_file(dir: &PolicyDir, path: &str, dry_run: bool) -> Result<WriteOutcome> {
    let src = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    write_cedar(dir, &src, dry_run)
}

fn write_cedar(dir: &PolicyDir, src: &str, dry_run: bool) -> Result<WriteOutcome> {
    PolicyEngine::from_cedar(src).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let tools = dir.read(TOOLS)?.unwrap_or_else(|| "[]".to_string());
    Broker::from_sources(&tools, src)
        .map_err(|e| anyhow::anyhow!("tools + cedar do not compile together: {e}"))?;
    dir.write(CEDAR, src, dry_run)
}

/// `policy add-forbid-tool <tool>` — append a least-privilege forbid rule (optionally scoped).
pub fn cedar_add_forbid_tool(
    dir: &PolicyDir,
    tool: &str,
    when_untrusted: bool,
    unless_agent: Option<&str>,
    dry_run: bool,
) -> Result<WriteOutcome> {
    let mut rule = format!(
        "\n// added by `aegis broker policy add-forbid-tool`\nforbid (\n    principal,\n    action == Action::\"invoke\",\n    resource == Tool::\"{tool}\"\n)"
    );
    if when_untrusted {
        rule.push_str("\nwhen { context.reads_untrusted }");
    }
    if let Some(agent) = unless_agent {
        rule.push_str(&format!("\nunless {{ principal == Agent::\"{agent}\" }}"));
    }
    rule.push_str(";\n");
    let src = format!("{}{rule}", cedar_src(dir)?);
    write_cedar(dir, &src, dry_run)
}

/// `policy add-permit` — append a baseline permit rule (optionally restricted to one tool/agent).
pub fn cedar_add_permit(
    dir: &PolicyDir,
    tool: Option<&str>,
    agent: Option<&str>,
    dry_run: bool,
) -> Result<WriteOutcome> {
    let principal = agent
        .map(|a| format!("principal == Agent::\"{a}\""))
        .unwrap_or_else(|| "principal".to_string());
    let resource = tool
        .map(|t| format!("resource == Tool::\"{t}\""))
        .unwrap_or_else(|| "resource".to_string());
    let rule = format!(
        "\n// added by `aegis broker policy add-permit`\npermit (\n    {principal},\n    action == Action::\"invoke\",\n    {resource}\n);\n"
    );
    let src = format!("{}{rule}", cedar_src(dir)?);
    write_cedar(dir, &src, dry_run)
}

/// `policy fmt` — pretty-print `broker.cedar` (validated first, then reformatted).
pub fn cedar_fmt(dir: &PolicyDir, dry_run: bool) -> Result<WriteOutcome> {
    let src = cedar_src(dir)?;
    PolicyEngine::from_cedar(&src).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let config = cedar_policy_formatter::Config {
        line_width: 100,
        indent_width: 4,
    };
    let pretty = cedar_policy_formatter::policies_str_to_pretty(&src, &config)
        .map_err(|e| anyhow::anyhow!("cedar format failed: {e:?}"))?;
    write_cedar(dir, &pretty, dry_run)
}

/// Write arbitrary Cedar text (used by the `$EDITOR` flow after an edit): validate, then persist.
pub fn cedar_write_validated(dir: &PolicyDir, src: &str, dry_run: bool) -> Result<WriteOutcome> {
    write_cedar(dir, src, dry_run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::unique_temp_dir;

    fn seed_permit(dir: &PolicyDir) {
        dir.write(
            CEDAR,
            "permit ( principal, action == Action::\"invoke\", resource );\n",
            false,
        )
        .unwrap();
    }

    #[test]
    fn add_set_rm_tool_round_trip_and_reject_dupes() {
        let dir = unique_temp_dir("broker");
        seed_permit(&dir);
        let new = NewTool {
            name: "web.fetch".into(),
            consequence: "low_reversible".into(),
            reaches_sensitive: false,
            external_effect: true,
            version: None,
            schema_json: Some(
                r#"{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}"#
                    .into(),
            ),
        };
        tools_add(&dir, &new, false).unwrap();
        assert!(tools_add(&dir, &new, false).is_err(), "duplicate rejected");
        assert_eq!(load_tools(&dir).unwrap().len(), 1);

        let up = ToolUpdate {
            consequence: Some("high_or_irreversible".into()),
            ..Default::default()
        };
        tools_set(&dir, "web.fetch", &up, false).unwrap();
        assert_eq!(
            consequence_str(&load_tools(&dir).unwrap()[0].consequence),
            "high_or_irreversible"
        );

        tools_rm(&dir, "web.fetch", false).unwrap();
        assert!(load_tools(&dir).unwrap().is_empty());
        assert!(tools_rm(&dir, "web.fetch", false).is_err());
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn bad_schema_is_rejected_without_writing() {
        let dir = unique_temp_dir("broker2");
        seed_permit(&dir);
        let new = NewTool {
            name: "x".into(),
            consequence: "low_reversible".into(),
            reaches_sensitive: false,
            external_effect: false,
            version: None,
            schema_json: Some("{ not json".into()),
        };
        assert!(tools_add(&dir, &new, false).is_err());
        assert!(load_tools(&dir).unwrap().is_empty());
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn cedar_validate_and_forbid_snippet() {
        let dir = unique_temp_dir("broker3");
        seed_permit(&dir);
        assert!(cedar_validate(&dir).unwrap().contains("cedar OK"));
        cedar_add_forbid_tool(&dir, "os.shell_exec", true, Some("system"), false).unwrap();
        let src = cedar_show(&dir).unwrap();
        assert!(src.contains("forbid"));
        assert!(src.contains("Tool::\"os.shell_exec\""));
        assert!(src.contains("context.reads_untrusted"));
        // Still valid after appending.
        assert!(cedar_validate(&dir).is_ok());
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn cedar_set_rejects_malformed() {
        let dir = unique_temp_dir("broker4");
        let bad = dir.root().join("bad.cedar");
        std::fs::write(&bad, "this is not cedar!!!").unwrap();
        assert!(cedar_set_from_file(&dir, bad.to_str().unwrap(), false).is_err());
        std::fs::remove_dir_all(dir.root()).ok();
    }
}
