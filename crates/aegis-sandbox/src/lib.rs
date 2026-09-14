//! # aegis-sandbox — isolated code-execution policy (ASI05)
//!
//! A `● Contain` control (architecture-considerations.md §11.1/§11.2 ASI05). Agent-generated
//! code is run in a non-root, ephemeral, network-restricted environment, and — critically —
//! **generation is separated from execution**: code runs only after it has passed the broker's
//! validation gate. This crate is the deterministic *policy* (the enforcement is the container
//! runtime): it decides whether a proposed execution request is permitted.
//!
//! Denials are deterministic: unapproved code, a request for root or network the policy forbids,
//! or a path escaping the ephemeral working directory. A small pattern denylist adds a `◐`
//! best-effort screen for obviously destructive commands.

use serde::{Deserialize, Serialize};

/// The sandbox configuration a request is checked against.
///
/// `#[serde(default)]` at the container level means a partial `sandbox.toml` fills any missing field
/// from the locked-down [`SandboxPolicy::default`] — so an incomplete or minimal file is safe, never
/// a parse error, and never accidentally permissive.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxPolicy {
    /// Whether the container may run as root (default false).
    pub allow_root: bool,
    /// Whether the container may reach the network directly (default false — route via egress).
    pub allow_network: bool,
    /// The dedicated, ephemeral working directory; paths must stay within it.
    pub working_dir: String,
    /// Wall-clock ceiling (ms).
    pub max_wall_ms: u64,
    /// Memory ceiling (MB).
    pub max_memory_mb: u64,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            allow_root: false,
            allow_network: false,
            working_dir: "/tmp/aegis-sandbox".to_string(),
            max_wall_ms: 5_000,
            max_memory_mb: 256,
        }
    }
}

/// A proposed code execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecRequest {
    /// The command / code to run.
    pub command: String,
    /// Whether the code needs root.
    #[serde(default)]
    pub wants_root: bool,
    /// Whether the code needs network access.
    #[serde(default)]
    pub wants_network: bool,
    /// An absolute path the code intends to touch (must be inside the working dir).
    #[serde(default)]
    pub target_path: Option<String>,
    /// Whether this code passed the broker's generation→execution validation gate. Code that
    /// has not been validated is never executed.
    #[serde(default)]
    pub approved: bool,
}

/// The decision on an execution request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecDecision {
    /// Permitted to run in the sandbox.
    Allow,
    /// Refused — a fixed, non-sensitive reason.
    Deny(&'static str),
}

impl ExecDecision {
    /// Whether execution is permitted.
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, ExecDecision::Allow)
    }
}

/// Obviously destructive command fragments (a `◐` best-effort screen; the real containment is
/// the non-root, network-restricted, ephemeral container).
const DENYLIST: [&str; 5] = ["rm -rf /", ":(){", "mkfs", "> /dev/sd", "dd if="];

impl SandboxPolicy {
    /// Load a sandbox policy from TOML text (`sandbox.toml`). Missing fields fall back to the
    /// locked-down [`Default`] (see the container `#[serde(default)]`), so a partial file is safe.
    pub fn from_toml(src: &str) -> Result<Self, aegis_core::AegisError> {
        toml::from_str(src)
            .map_err(|e| aegis_core::AegisError::Config(format!("bad sandbox policy: {e}")))
    }

    /// Decide whether `req` may execute under this policy.
    #[must_use]
    pub fn validate(&self, req: &ExecRequest) -> ExecDecision {
        // 1. Generation vs execution: unvalidated code never runs.
        if !req.approved {
            return ExecDecision::Deny("code must pass the generation→execution gate first");
        }
        // 2. Privilege.
        if req.wants_root && !self.allow_root {
            return ExecDecision::Deny("root not permitted in the sandbox");
        }
        // 3. Network (must go through the egress proxy, not the sandbox directly).
        if req.wants_network && !self.allow_network {
            return ExecDecision::Deny("network not permitted (route via egress)");
        }
        // 4. Path confinement to the ephemeral working directory.
        if let Some(path) = &req.target_path {
            if path.contains("..") || !path.starts_with(&self.working_dir) {
                return ExecDecision::Deny("path escapes the sandbox working directory");
            }
        }
        // 5. Best-effort destructive-command screen.
        if DENYLIST.iter().any(|p| req.command.contains(p)) {
            return ExecDecision::Deny("command matches a destructive-pattern denylist");
        }
        ExecDecision::Allow
    }
}

/// Map into the plane-wide [`PolicyDecision`](aegis_core::PolicyDecision) vocabulary (Roadmap T0).
impl From<ExecDecision> for aegis_core::PolicyDecision {
    fn from(d: ExecDecision) -> Self {
        match d {
            ExecDecision::Allow => aegis_core::PolicyDecision::Allow,
            ExecDecision::Deny(reason) => aegis_core::PolicyDecision::deny(reason),
        }
    }
}

#[cfg(test)]
mod policy_decision_adapter_tests {
    use super::*;
    #[test]
    fn maps_into_policy_decision() {
        use aegis_core::PolicyDecision;
        assert!(PolicyDecision::from(ExecDecision::Allow).is_allow());
        assert!(PolicyDecision::from(ExecDecision::Deny("root")).is_deny());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approved(command: &str) -> ExecRequest {
        ExecRequest {
            command: command.into(),
            wants_root: false,
            wants_network: false,
            target_path: None,
            approved: true,
        }
    }

    #[test]
    fn from_toml_parses_full_partial_and_rejects_garbage() {
        // Full file round-trips every field.
        let p = SandboxPolicy::from_toml(
            "allow_root = true\nallow_network = true\nworking_dir = \"/w\"\n\
             max_wall_ms = 1000\nmax_memory_mb = 64\n",
        )
        .unwrap();
        assert!(p.allow_root && p.allow_network);
        assert_eq!(p.working_dir, "/w");
        assert_eq!(p.max_wall_ms, 1000);
        assert_eq!(p.max_memory_mb, 64);

        // Partial file fills missing fields from the locked-down default (container serde default).
        let p = SandboxPolicy::from_toml("allow_network = true\n").unwrap();
        assert!(p.allow_network);
        assert!(!p.allow_root); // default
        assert_eq!(p.working_dir, "/tmp/aegis-sandbox"); // default
        assert_eq!(p.max_memory_mb, 256); // default
        assert_eq!(
            SandboxPolicy::from_toml("").unwrap(),
            SandboxPolicy::default()
        );

        // Invalid TOML is a config error, not a silent default.
        assert!(SandboxPolicy::from_toml("allow_root = = nope").is_err());
    }

    #[test]
    fn unapproved_code_is_never_executed() {
        let mut req = approved("echo hi");
        req.approved = false;
        assert_eq!(
            SandboxPolicy::default().validate(&req),
            ExecDecision::Deny("code must pass the generation→execution gate first")
        );
    }

    #[test]
    fn root_and_network_are_denied_by_default() {
        let p = SandboxPolicy::default();
        let mut r = approved("echo hi");
        r.wants_root = true;
        assert_eq!(
            p.validate(&r),
            ExecDecision::Deny("root not permitted in the sandbox")
        );
        let mut r = approved("echo hi");
        r.wants_network = true;
        assert_eq!(
            p.validate(&r),
            ExecDecision::Deny("network not permitted (route via egress)")
        );
    }

    #[test]
    fn network_allowed_when_policy_permits() {
        let p = SandboxPolicy {
            allow_network: true,
            ..Default::default()
        };
        let mut r = approved("echo hi");
        r.wants_network = true;
        assert!(p.validate(&r).is_allow());
    }

    #[test]
    fn path_must_stay_within_working_dir() {
        let p = SandboxPolicy::default();
        let mut r = approved("write");
        r.target_path = Some("/etc/passwd".into());
        assert_eq!(
            p.validate(&r),
            ExecDecision::Deny("path escapes the sandbox working directory")
        );
        let mut r = approved("write");
        r.target_path = Some("/tmp/aegis-sandbox/out.txt".into());
        assert!(p.validate(&r).is_allow());
        // Traversal within the prefix is still rejected.
        let mut r = approved("write");
        r.target_path = Some("/tmp/aegis-sandbox/../../etc/passwd".into());
        assert!(!p.validate(&r).is_allow());
    }

    #[test]
    fn destructive_commands_are_screened() {
        let p = SandboxPolicy::default();
        assert_eq!(
            p.validate(&approved("rm -rf / --no-preserve-root")),
            ExecDecision::Deny("command matches a destructive-pattern denylist")
        );
        assert!(p.validate(&approved("python analyze.py")).is_allow());
    }
}
