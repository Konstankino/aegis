//! Strict, aggregate validation (`validate`) and higher-level lints (`doctor`).
//!
//! Unlike the extension's boot loaders — which fail *open* to defaults — this composes each crate's
//! own parser so a malformed artifact is surfaced as an error, and cross-checks that `tools.json`
//! and `broker.cedar` compile together. UI-free: returns typed findings the CLI/TUI colorize.

use aegis_broker::{Broker, PolicyEngine, ToolRegistry};
use aegis_egress::Allowlist;
use aegis_honeypot::Honeypots;
use aegis_meter::Limits;
use aegis_sandbox::SandboxPolicy;
use aegis_supply::Pinset;

use crate::artifacts::Artifact;
use crate::io::PolicyDir;

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Valid / healthy.
    Ok,
    /// Informational (a deliberate fail-closed default, e.g. nothing pinned).
    Info,
    /// A likely misconfiguration worth attention (not fatal).
    Warn,
    /// Invalid — the runtime would reject or ignore it.
    Error,
}

/// One validation/lint result.
#[derive(Debug, Clone)]
pub struct Finding {
    pub artifact: Option<Artifact>,
    pub status: Status,
    pub message: String,
}

impl Finding {
    fn new(artifact: Option<Artifact>, status: Status, message: impl Into<String>) -> Self {
        Self {
            artifact,
            status,
            message: message.into(),
        }
    }
}

/// Whether a finding set has no errors.
pub fn all_ok(findings: &[Finding]) -> bool {
    findings.iter().all(|f| f.status != Status::Error)
}

/// Validate raw artifact text through its owning crate's parser (used by the TUI/`edit` flow before
/// persisting). `Ok(())` means the runtime would accept it.
pub fn validate_text(artifact: Artifact, text: &str) -> Result<(), String> {
    let e = |e: String| e;
    match artifact {
        Artifact::Tools => ToolRegistry::from_json(text)
            .map(|_| ())
            .map_err(|x| e(x.to_string())),
        Artifact::BrokerCedar => PolicyEngine::from_cedar(text)
            .map(|_| ())
            .map_err(|x| x.to_string()),
        Artifact::Egress => Allowlist::from_toml(text)
            .map(|_| ())
            .map_err(|x| x.to_string()),
        Artifact::Meter => toml::from_str::<Limits>(text)
            .map(|_| ())
            .map_err(|x| x.to_string()),
        Artifact::Pins => Pinset::from_json(text)
            .map(|_| ())
            .map_err(|x| x.to_string()),
        Artifact::Honeypots => Honeypots::from_json(text)
            .map(|_| ())
            .map_err(|x| x.to_string()),
        Artifact::Sandbox => SandboxPolicy::from_toml(text)
            .map(|_| ())
            .map_err(|x| x.to_string()),
    }
}

/// Reduce `validate_all` to one status+message per artifact (worst status wins), for the TUI list.
pub fn per_artifact(dir: &PolicyDir) -> Vec<(Artifact, Status, String)> {
    let findings = validate_all(dir);
    Artifact::ALL
        .iter()
        .map(|&a| {
            let mut status = Status::Ok;
            let mut msg = String::from("ok");
            for f in findings.iter().filter(|f| f.artifact == Some(a)) {
                if f.status == Status::Error {
                    status = Status::Error;
                    msg = f.message.clone();
                    break;
                }
                msg = f.message.clone();
            }
            (a, status, msg)
        })
        .collect()
}

/// Validate one artifact via a parser closure returning `Ok(summary)` / `Err(message)`.
fn check(
    dir: &PolicyDir,
    artifact: Artifact,
    parse: impl FnOnce(&str) -> Result<String, String>,
) -> Finding {
    match dir.read(artifact) {
        Ok(Some(text)) if !text.trim().is_empty() => match parse(&text) {
            Ok(summary) => Finding::new(Some(artifact), Status::Ok, summary),
            Err(e) => Finding::new(Some(artifact), Status::Error, e),
        },
        Ok(_) => Finding::new(
            Some(artifact),
            Status::Ok,
            "absent/empty → built-in default",
        ),
        Err(e) => Finding::new(Some(artifact), Status::Error, e.to_string()),
    }
}

/// Strictly validate every artifact + the broker tools/cedar cross-check.
pub fn validate_all(dir: &PolicyDir) -> Vec<Finding> {
    let mut out = Vec::new();

    out.push(check(dir, Artifact::Tools, |t| {
        ToolRegistry::from_json(t)
            .map(|r| format!("{} tool(s), all schemas compile", r.len()))
            .map_err(|e| e.to_string())
    }));
    out.push(check(dir, Artifact::BrokerCedar, |t| {
        PolicyEngine::from_cedar(t)
            .map(|e| format!("{} policy statement(s)", e.len()))
            .map_err(|e| e.to_string())
    }));
    // Cross-check: the two broker files must compile together.
    let tools = dir
        .read(Artifact::Tools)
        .ok()
        .flatten()
        .unwrap_or_else(|| "[]".into());
    let cedar = dir
        .read(Artifact::BrokerCedar)
        .ok()
        .flatten()
        .unwrap_or_default();
    if let Err(e) = Broker::from_sources(&tools, &cedar) {
        out.push(Finding::new(
            Some(Artifact::BrokerCedar),
            Status::Error,
            format!("tools.json + broker.cedar do not compile together: {e}"),
        ));
    }

    out.push(check(dir, Artifact::Egress, |t| {
        Allowlist::from_toml(t)
            .map(|_| "valid".to_string())
            .map_err(|e| e.to_string())
    }));
    out.push(check(dir, Artifact::Meter, |t| {
        toml::from_str::<Limits>(t)
            .map(|_| "valid".to_string())
            .map_err(|e| e.to_string())
    }));
    out.push(check(dir, Artifact::Pins, |t| {
        Pinset::from_json(t)
            .map(|p| format!("{} artifact(s) pinned", p.pins.len()))
            .map_err(|e| e.to_string())
    }));
    out.push(check(dir, Artifact::Honeypots, |t| {
        Honeypots::from_json(t)
            .map(|h| {
                format!(
                    "{} decoy(s), {} canary(ies)",
                    h.decoys.len(),
                    h.canaries.len()
                )
            })
            .map_err(|e| e.to_string())
    }));
    out.push(check(dir, Artifact::Sandbox, |t| {
        SandboxPolicy::from_toml(t)
            .map(|_| "valid".to_string())
            .map_err(|e| e.to_string())
    }));

    out
}

/// `validate_all` plus higher-level lints (default-deny notices, risky toggles). Lints are only
/// computed for artifacts that parsed cleanly.
pub fn doctor(dir: &PolicyDir) -> Vec<Finding> {
    let mut findings = validate_all(dir);
    let errored = |findings: &[Finding], a: Artifact| {
        findings
            .iter()
            .any(|f| f.artifact == Some(a) && f.status == Status::Error)
    };

    // broker tools
    if !errored(&findings, Artifact::Tools) {
        if let Ok(specs) = crate::domains::broker::load_tools(dir) {
            if specs.is_empty() {
                findings.push(Finding::new(
                    Some(Artifact::Tools),
                    Status::Warn,
                    "no tools registered → every tool call is denied (default-deny)",
                ));
            }
        }
    }
    // broker cedar
    if !errored(&findings, Artifact::BrokerCedar) {
        let src = dir
            .read(Artifact::BrokerCedar)
            .ok()
            .flatten()
            .unwrap_or_default();
        if !src.contains("permit") {
            findings.push(Finding::new(
                Some(Artifact::BrokerCedar),
                Status::Info,
                "no `permit` rule → Cedar authorizes nothing (default-deny)",
            ));
        }
    }
    // egress
    if !errored(&findings, Artifact::Egress) {
        if let Ok(a) = crate::domains::egress::load(dir) {
            if a.hosts.is_empty() && a.suffixes.is_empty() {
                findings.push(Finding::new(
                    Some(Artifact::Egress),
                    Status::Warn,
                    "no hosts or suffixes → all egress is denied",
                ));
            }
        }
    }
    // supply
    if !errored(&findings, Artifact::Pins) {
        if let Ok(p) = crate::domains::supply::load(dir) {
            if p.pins.is_empty() {
                findings.push(Finding::new(
                    Some(Artifact::Pins),
                    Status::Info,
                    "nothing pinned → supply verification fails closed",
                ));
            }
        }
    }
    // honeypot
    if !errored(&findings, Artifact::Honeypots) {
        if let Ok(h) = crate::domains::honeypot::load(dir) {
            if h.is_empty() {
                findings.push(Finding::new(
                    Some(Artifact::Honeypots),
                    Status::Info,
                    "no decoys/canaries → the deception layer is inert",
                ));
            }
        }
    }
    // meter
    if !dir.exists(Artifact::Meter) {
        findings.push(Finding::new(
            Some(Artifact::Meter),
            Status::Info,
            "no meter.toml → using built-in default budget",
        ));
    }
    // sandbox risky toggles
    if !errored(&findings, Artifact::Sandbox) {
        if let Ok(s) = crate::domains::sandbox::load(dir) {
            if s.allow_network {
                findings.push(Finding::new(
                    Some(Artifact::Sandbox),
                    Status::Warn,
                    "sandbox allows network — code can reach out directly (prefer egress-only)",
                ));
            }
            if s.allow_root {
                findings.push(Finding::new(
                    Some(Artifact::Sandbox),
                    Status::Warn,
                    "sandbox allows root",
                ));
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::unique_temp_dir;

    #[test]
    fn clean_set_validates_and_doctor_notes_defaults() {
        let dir = unique_temp_dir("val");
        // A minimal, valid broker set.
        dir.write(Artifact::Tools, "[]", false).unwrap();
        dir.write(
            Artifact::BrokerCedar,
            "permit ( principal, action == Action::\"invoke\", resource );\n",
            false,
        )
        .unwrap();
        let f = validate_all(&dir);
        assert!(all_ok(&f), "clean set validates: {f:?}");

        let d = doctor(&dir);
        // Empty tools → warn; empty pins → info; inert honeypots → info; no meter → info.
        assert!(d
            .iter()
            .any(|x| x.status == Status::Warn && x.artifact == Some(Artifact::Tools)));
        assert!(d
            .iter()
            .any(|x| x.status == Status::Info && x.artifact == Some(Artifact::Meter)));
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn malformed_artifact_is_an_error() {
        let dir = unique_temp_dir("val2");
        dir.write(Artifact::Meter, "max_steps = = 3", false)
            .unwrap();
        let f = validate_all(&dir);
        assert!(!all_ok(&f));
        assert!(f
            .iter()
            .any(|x| x.artifact == Some(Artifact::Meter) && x.status == Status::Error));
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn cross_check_catches_bad_cedar() {
        let dir = unique_temp_dir("val3");
        dir.write(Artifact::Tools, "[]", false).unwrap();
        dir.write(Artifact::BrokerCedar, "this is not cedar", false)
            .unwrap();
        let f = validate_all(&dir);
        assert!(!all_ok(&f));
        std::fs::remove_dir_all(dir.root()).ok();
    }
}
