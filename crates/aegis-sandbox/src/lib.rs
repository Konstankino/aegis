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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
