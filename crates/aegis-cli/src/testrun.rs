//! Dry-run the **real** deterministic logic against the current policy dir — the investigate /
//! troubleshoot engine. No deploy, no side effects: it loads the policies and runs the same
//! `broker.mediate` / `Allowlist::decide` / `Pinset::verify` / honeypot / sandbox code the runtime
//! uses, and reports the decision.

use anyhow::{Context, Result};

use aegis_broker::{Broker, Decision, Session, ToolCall};
use aegis_core::{Capability, Provenance};
use aegis_egress::{Allowlist, EgressDecision};
use aegis_sandbox::{ExecRequest, SandboxPolicy};
use aegis_supply::Digest;

use crate::artifacts::Artifact;
use crate::domains;
use crate::io::PolicyDir;

/// One mediated call in a `test mediate` chain.
#[derive(Debug, Clone)]
pub struct MediateStep {
    pub tool: String,
    /// `allow` | `human_approve` | `deny`.
    pub decision: String,
    pub reason: Option<String>,
    /// The session capability *after* this call (accumulated Rule-of-Two taint).
    pub cap: Capability,
}

/// The result of a `test mediate` chain over one session.
#[derive(Debug, Clone)]
pub struct MediateTrace {
    pub steps: Vec<MediateStep>,
}

/// Parse a provenance string (`system|user|semi_trusted|untrusted`).
pub fn parse_provenance(s: &str) -> Result<Provenance> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).with_context(|| {
        format!("bad provenance '{s}' (expected system|user|semi_trusted|untrusted)")
    })
}

/// Run a chain of tool calls through the real broker against the current `tools.json` + `broker.cedar`.
/// Each call is `(tool, args_json, provenance)`; taint accumulates across the chain on one session.
pub fn mediate(
    dir: &PolicyDir,
    agent: &str,
    thread: &str,
    calls: &[(String, String, String)],
) -> Result<MediateTrace> {
    let tools = dir
        .read(Artifact::Tools)?
        .unwrap_or_else(|| "[]".to_string());
    let cedar = dir.read(Artifact::BrokerCedar)?.unwrap_or_default();
    let broker = Broker::from_sources(&tools, &cedar)
        .map_err(|e| anyhow::anyhow!("policies do not load: {e}"))?;
    let mut session = Session::new(agent, "test-run", thread);
    let mut steps = Vec::new();
    for (tool, args_json, prov) in calls {
        let args: serde_json::Value = serde_json::from_str(args_json)
            .with_context(|| format!("args for '{tool}' are not JSON"))?;
        let call = ToolCall::new(tool.clone(), args, parse_provenance(prov)?);
        let (decision, reason) = match broker.mediate(&mut session, &call) {
            Decision::Allow => ("allow".to_string(), None),
            Decision::HumanApprove => ("human_approve".to_string(), None),
            Decision::Deny(r) => ("deny".to_string(), Some(r.to_string())),
        };
        steps.push(MediateStep {
            tool: tool.clone(),
            decision,
            reason,
            cap: session.cap,
        });
    }
    Ok(MediateTrace { steps })
}

/// `test egress --url` against the current allowlist.
pub fn egress(dir: &PolicyDir, url: &str) -> Result<String> {
    let allow: Allowlist = domains::egress::load(dir)?;
    Ok(match allow.decide(url) {
        EgressDecision::Allow(sanitized) => format!("allow  {sanitized}"),
        EgressDecision::Deny(reason) => format!("deny   {reason}"),
    })
}

/// `test supply --name --digest` against the current pinset.
pub fn supply(dir: &PolicyDir, name: &str, digest_ref: &str) -> Result<String> {
    let pinset = domains::supply::load(dir)?;
    let digest = Digest::parse(digest_ref)
        .ok_or_else(|| anyhow::anyhow!("not a valid digest '{digest_ref}'"))?;
    Ok(match pinset.verify(name, &digest) {
        Ok(()) => "verified".to_string(),
        Err(e) => format!("rejected  {e}"),
    })
}

/// `test honeypot` — a command/path decoy check and/or an outbound-text canary scan.
pub fn honeypot(
    dir: &PolicyDir,
    command: Option<&str>,
    path: Option<&str>,
    text: Option<&str>,
) -> Result<String> {
    let h = domains::honeypot::load(dir)?;
    let mut out = String::new();
    if let Some(cmd) = command {
        match h.match_exec(cmd, path) {
            Some(d) => out.push_str(&format!("decoy TRIPWIRE  matched '{d}'\n")),
            None => out.push_str("decoy clean\n"),
        }
    }
    if let Some(t) = text {
        match h.scan(t) {
            Some(c) => out.push_str(&format!("canary TRIPWIRE  found '{c}'\n")),
            None => out.push_str("canary clean\n"),
        }
    }
    if out.is_empty() {
        anyhow::bail!("pass --command and/or --text to test honeypots");
    }
    Ok(out)
}

/// `test sandbox --command …` against the current sandbox policy.
pub fn sandbox(
    dir: &PolicyDir,
    command: &str,
    wants_root: bool,
    wants_network: bool,
    approved: bool,
    target_path: Option<String>,
) -> Result<String> {
    let policy: SandboxPolicy = domains::sandbox::load(dir)?;
    let req = ExecRequest {
        command: command.to_string(),
        wants_root,
        wants_network,
        target_path,
        approved,
    };
    Ok(match policy.validate(&req) {
        aegis_sandbox::ExecDecision::Allow => "allow".to_string(),
        aegis_sandbox::ExecDecision::Deny(reason) => format!("deny   {reason}"),
    })
}

// ── test pipeline: one tool call through the whole deterministic gate chain ──────────────────────

/// One stage of a `test pipeline` run.
#[derive(Debug, Clone)]
pub struct PipelineStage {
    pub name: String,
    /// `ok` | `allow` | `human_approve` | `deny` | `tripwire` | `skip`.
    pub verdict: String,
    pub detail: String,
}

/// The result of running one tool call through the deterministic gates.
#[derive(Debug, Clone)]
pub struct PipelineTrace {
    pub stages: Vec<PipelineStage>,
    /// `ALLOWED` | `NEEDS HUMAN APPROVAL` | `BLOCKED`.
    pub outcome: String,
}

/// Inputs for a single-call pipeline test.
#[derive(Debug, Clone, Default)]
pub struct PipelineInput {
    pub tool: String,
    pub args_json: String,
    pub prov: String,
    /// Untrusted text to run through ingress (defaults to the args JSON).
    pub input: Option<String>,
    /// URL for the egress stage (defaults to `args.url`).
    pub url: Option<String>,
    /// Code/command for the sandbox stage (defaults to `args.code`/`args.command`).
    pub command: Option<String>,
}

fn stage(name: &str, verdict: &str, detail: impl Into<String>) -> PipelineStage {
    PipelineStage {
        name: name.into(),
        verdict: verdict.into(),
        detail: detail.into(),
    }
}

/// Run one tool call through the deterministic inline-plane gates in order — **ingress → honeypot
/// canary → broker mediate → egress → sandbox** — against the current policies, and report each
/// stage plus an overall outcome. This is an end-to-end view for a *single* call; unlike the running
/// gate it keeps no server-side state across calls (use `test mediate` for a taint-accumulating
/// chain, or the extension dev gate for the full stateful pipeline).
pub fn pipeline(dir: &PolicyDir, inp: &PipelineInput) -> Result<PipelineTrace> {
    let args: serde_json::Value =
        serde_json::from_str(&inp.args_json).context("args are not valid JSON")?;
    let mut stages = Vec::new();
    let mut blocked = false;

    // 1. ingress — normalize untrusted input (strip invisibles/bidi/tags, NFC).
    let ingress_src = inp.input.clone().unwrap_or_else(|| inp.args_json.clone());
    let san = aegis_ingress::sanitize(&ingress_src);
    stages.push(stage(
        "ingress · sanitize",
        "ok",
        format!(
            "removed {} char(s){}{}",
            san.removed,
            if san.had_bidi { " · bidi" } else { "" },
            if san.normalized { " · nfc" } else { "" }
        ),
    ));

    // 2. honeypot canary — a planted token in the args is proof of exfiltration (the /mediate
    //    tripwire). A hit stops the pipeline immediately.
    let honeypots = domains::honeypot::load(dir)?;
    if honeypots.scan(&args.to_string()).is_some() {
        stages.push(stage(
            "honeypot · canary",
            "tripwire",
            "canary token in tool args → exfiltration",
        ));
        return Ok(PipelineTrace {
            stages,
            outcome: "BLOCKED".into(),
        });
    }
    stages.push(stage("honeypot · canary", "ok", "clean"));

    // 3. broker · mediate — schema + Rule of Two + Cedar + graduated enforcement.
    let tools = dir.read(Artifact::Tools)?.unwrap_or_else(|| "[]".into());
    let cedar = dir.read(Artifact::BrokerCedar)?.unwrap_or_default();
    let broker = Broker::from_sources(&tools, &cedar)
        .map_err(|e| anyhow::anyhow!("policies do not load: {e}"))?;
    let mut session = Session::new("pipeline", "test", "pipeline-thread");
    let call = ToolCall::new(inp.tool.clone(), args.clone(), parse_provenance(&inp.prov)?);
    let decision = broker.mediate(&mut session, &call);
    let cap = session.cap;
    let (verdict, reason) = match decision {
        Decision::Allow => ("allow", None),
        Decision::HumanApprove => ("human_approve", None),
        Decision::Deny(r) => ("deny", Some(r.to_string())),
    };
    let legs = format!(
        "A{} B{} C{}{}",
        cap.reads_untrusted as u8,
        cap.reads_sensitive as u8,
        cap.external_effect as u8,
        if cap.is_trifecta() { " TRIFECTA" } else { "" }
    );
    stages.push(stage(
        "broker · mediate",
        verdict,
        format!(
            "[{legs}]{}",
            reason
                .as_deref()
                .map(|r| format!("  {r}"))
                .unwrap_or_default()
        ),
    ));
    if verdict == "deny" {
        return Ok(PipelineTrace {
            stages,
            outcome: "BLOCKED".into(),
        });
    }

    // The tool's registered classification — does it have an external effect?
    let specs = domains::broker::load_tools(dir)?;
    let external = specs
        .iter()
        .find(|t| t.name == inp.tool)
        .map(|s| s.has_external_effect)
        .unwrap_or(false);

    // 4. egress — only meaningful for an external-effect tool with a URL to check.
    let egress_url = inp
        .url
        .clone()
        .or_else(|| args.get("url").and_then(|v| v.as_str()).map(str::to_string));
    if external {
        match egress_url {
            Some(u) => {
                let allow = domains::egress::load(dir)?;
                match allow.decide(&u) {
                    EgressDecision::Allow(s) => stages.push(stage("egress · decide", "allow", s)),
                    EgressDecision::Deny(r) => {
                        stages.push(stage("egress · decide", "deny", r));
                        blocked = true;
                    }
                }
            }
            None => stages.push(stage(
                "egress · decide",
                "skip",
                "external-effect tool but no URL (pass --url or set args.url)",
            )),
        }
    } else {
        stages.push(stage(
            "egress · decide",
            "skip",
            "tool has no external effect",
        ));
    }

    // 5. sandbox — only when there is code/command to run; honeypot decoy checked first.
    let cmd = inp.command.clone().or_else(|| {
        args.get("code")
            .or_else(|| args.get("command"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    });
    match cmd {
        Some(c) => {
            let hp = domains::honeypot::load(dir)?;
            if let Some(d) = hp.match_exec(&c, None) {
                stages.push(stage(
                    "sandbox · honeypot decoy",
                    "tripwire",
                    format!("decoy touched: {d}"),
                ));
                blocked = true;
            } else {
                let policy = domains::sandbox::load(dir)?;
                let req = ExecRequest {
                    command: c,
                    wants_root: false,
                    wants_network: false,
                    target_path: None,
                    approved: true,
                };
                match policy.validate(&req) {
                    aegis_sandbox::ExecDecision::Allow => stages.push(stage(
                        "sandbox · validate",
                        "allow",
                        "approved · within policy",
                    )),
                    aegis_sandbox::ExecDecision::Deny(r) => {
                        stages.push(stage("sandbox · validate", "deny", r));
                        blocked = true;
                    }
                }
            }
        }
        None => stages.push(stage("sandbox · validate", "skip", "no code to run")),
    }

    let outcome = if blocked {
        "BLOCKED"
    } else if verdict == "human_approve" {
        "NEEDS HUMAN APPROVAL"
    } else {
        "ALLOWED"
    };
    Ok(PipelineTrace {
        stages,
        outcome: outcome.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::unique_temp_dir;

    fn seed_broker(dir: &PolicyDir) {
        dir.write(
            Artifact::Tools,
            r#"[
              {"name":"web.fetch","reaches_sensitive_data":false,"has_external_effect":true,
               "consequence":"low_reversible",
               "schema":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}},
              {"name":"db.read","reaches_sensitive_data":true,"has_external_effect":false,
               "consequence":"low_reversible",
               "schema":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}}
            ]"#,
            false,
        )
        .unwrap();
        dir.write(
            Artifact::BrokerCedar,
            "permit ( principal, action == Action::\"invoke\", resource );\n",
            false,
        )
        .unwrap();
    }

    #[test]
    fn mediate_chain_accumulates_into_the_trifecta() {
        let dir = unique_temp_dir("tr-mediate");
        seed_broker(&dir);
        let trace = mediate(
            &dir,
            "a",
            "t1",
            &[
                (
                    "web.fetch".into(),
                    r#"{"url":"https://x"}"#.into(),
                    "untrusted".into(),
                ),
                ("db.read".into(), r#"{"id":"p1"}"#.into(), "user".into()),
            ],
        )
        .unwrap();
        assert_eq!(trace.steps[0].decision, "allow");
        assert!(trace.steps[0].cap.reads_untrusted && trace.steps[0].cap.external_effect);
        // Accumulated untrusted+external, now a sensitive read completes the trifecta.
        assert_eq!(trace.steps[1].decision, "human_approve");
        assert!(trace.steps[1].cap.is_trifecta());
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn mediate_reports_schema_and_unknown_tool_denials() {
        let dir = unique_temp_dir("tr-mediate2");
        seed_broker(&dir);
        let t = mediate(
            &dir,
            "a",
            "t",
            &[("nope".into(), "{}".into(), "user".into())],
        )
        .unwrap();
        assert_eq!(t.steps[0].decision, "deny");
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn egress_supply_honeypot_sandbox_runners() {
        let dir = unique_temp_dir("tr-rest");
        // egress
        crate::domains::egress::allow_host(&dir, "api.example", false).unwrap();
        assert!(egress(&dir, "https://api.example/x")
            .unwrap()
            .starts_with("allow"));
        assert!(egress(&dir, "https://evil.example/x")
            .unwrap()
            .starts_with("deny"));
        // supply
        let d = Digest::sha256(b"v1").to_ref();
        crate::domains::supply::pin(&dir, "model", &d, false).unwrap();
        assert_eq!(supply(&dir, "model", &d).unwrap(), "verified");
        assert!(supply(&dir, "model", &Digest::sha256(b"evil").to_ref())
            .unwrap()
            .starts_with("rejected"));
        // honeypot
        crate::domains::honeypot::add_decoy(&dir, "169.254.169.254", false).unwrap();
        assert!(
            honeypot(&dir, Some("curl http://169.254.169.254/"), None, None)
                .unwrap()
                .contains("TRIPWIRE")
        );
        assert!(honeypot(&dir, Some("echo hi"), None, None)
            .unwrap()
            .contains("clean"));
        // sandbox
        assert_eq!(
            sandbox(&dir, "python x.py", false, false, true, None).unwrap(),
            "allow"
        );
        assert!(sandbox(&dir, "python x.py", false, false, false, None)
            .unwrap()
            .starts_with("deny"));
        std::fs::remove_dir_all(dir.root()).ok();
    }

    fn pin(tool: &str, args: &str, prov: &str) -> PipelineInput {
        PipelineInput {
            tool: tool.into(),
            args_json: args.into(),
            prov: prov.into(),
            ..Default::default()
        }
    }

    #[test]
    fn pipeline_allow_and_egress_deny() {
        let dir = unique_temp_dir("pipe");
        seed_broker(&dir); // web.fetch (external), db.read (sensitive)
        crate::domains::egress::allow_host(&dir, "api.example", false).unwrap();

        // ALLOWED: untrusted fetch to an allowlisted host — every gate passes.
        let t = pipeline(
            &dir,
            &pin(
                "web.fetch",
                r#"{"url":"https://api.example/x"}"#,
                "untrusted",
            ),
        )
        .unwrap();
        assert_eq!(t.outcome, "ALLOWED", "{:?}", t.stages);
        assert!(t.stages.iter().any(|s| s.name.contains("ingress")));
        assert!(t
            .stages
            .iter()
            .any(|s| s.name.contains("egress") && s.verdict == "allow"));

        // BLOCKED at egress: a disallowed host.
        let t = pipeline(
            &dir,
            &pin("web.fetch", r#"{"url":"https://evil.example/x"}"#, "user"),
        )
        .unwrap();
        assert_eq!(t.outcome, "BLOCKED");
        assert!(t
            .stages
            .iter()
            .any(|s| s.name.contains("egress") && s.verdict == "deny"));
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn pipeline_broker_deny_sandbox_allow_and_decoy_tripwire() {
        let dir = unique_temp_dir("pipe2");
        seed_broker(&dir);
        crate::domains::broker::tools_add(
            &dir,
            &crate::domains::broker::NewTool {
                name: "code.run".into(),
                consequence: "low_reversible".into(),
                reaches_sensitive: false,
                external_effect: false,
                version: None,
                schema_json: Some(r#"{"type":"object"}"#.into()),
            },
            false,
        )
        .unwrap();

        // Unknown tool → broker deny → BLOCKED before egress/sandbox.
        let t = pipeline(&dir, &pin("nope", "{}", "user")).unwrap();
        assert_eq!(t.outcome, "BLOCKED");
        assert!(t
            .stages
            .iter()
            .any(|s| s.name.contains("broker") && s.verdict == "deny"));

        // code.run + a benign command → sandbox allow → ALLOWED.
        let t = pipeline(
            &dir,
            &PipelineInput {
                command: Some("python analyze.py".into()),
                ..pin("code.run", "{}", "user")
            },
        )
        .unwrap();
        assert_eq!(t.outcome, "ALLOWED", "{:?}", t.stages);
        assert!(t
            .stages
            .iter()
            .any(|s| s.name.contains("sandbox") && s.verdict == "allow"));

        // A decoy in the command trips the sandbox honeypot → BLOCKED.
        crate::domains::honeypot::add_decoy(&dir, "169.254.169.254", false).unwrap();
        let t = pipeline(
            &dir,
            &PipelineInput {
                command: Some("curl http://169.254.169.254/".into()),
                ..pin("code.run", "{}", "user")
            },
        )
        .unwrap();
        assert_eq!(t.outcome, "BLOCKED");
        assert!(t.stages.iter().any(|s| s.verdict == "tripwire"));
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn pipeline_canary_in_args_is_blocked() {
        let dir = unique_temp_dir("pipe3");
        seed_broker(&dir);
        crate::domains::honeypot::add_canary(&dir, "CANARY-xyz", false).unwrap();
        let t = pipeline(
            &dir,
            &pin("web.fetch", r#"{"url":"https://x/?d=CANARY-xyz"}"#, "user"),
        )
        .unwrap();
        assert_eq!(t.outcome, "BLOCKED");
        assert!(t.stages.iter().any(|s| s.verdict == "tripwire"));
        // The canary tripwire stops before the broker even decides.
        assert!(!t.stages.iter().any(|s| s.name.contains("broker")));
        std::fs::remove_dir_all(dir.root()).ok();
    }
}
