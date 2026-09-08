//! # aegis-killswitch — emergency revocation + quarantine (ASI08, ASI10)
//!
//! A `● Contain` control (architecture-considerations.md §11.1). It can **instantly disable** a
//! specific tool, prompt, agent connection, or agent across all deployments, and **quarantine**
//! a suspicious agent. Reintegration is gated: a quarantined agent may return only after **fresh
//! attestation AND human approval** — never automatically.
//!
//! The broker/mesh consult [`Killswitch::is_revoked`] before acting, so a revoked capability is
//! refused deterministically even mid-run.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// A thing that can be revoked.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Target {
    /// A tool, by fully-qualified name.
    Tool(String),
    /// An agent, by id.
    Agent(String),
    /// A prompt/template, by id.
    Prompt(String),
    /// An inter-agent connection, by id.
    Connection(String),
}

/// The outcome of a reintegration attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reintegration {
    /// The agent was reintegrated (un-quarantined + its agent-target un-revoked).
    Restored,
    /// Refused — a fixed, non-sensitive reason.
    Denied(&'static str),
}

/// The revocation/quarantine registry. Cloneable and cheap to share behind a lock.
///
/// Derives `Serialize`/`Deserialize` so the gate can persist it durably (both fields are
/// serializable and `Target` already round-trips): a quarantine raised before a HITL pause must
/// survive a cold restart, or a quarantined agent would silently un-quarantine on resume. Both
/// fields are `#[serde(default)]` so a partial/older record still loads.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Killswitch {
    #[serde(default)]
    revoked: HashSet<Target>,
    #[serde(default)]
    quarantined: HashSet<String>,
}

impl Killswitch {
    /// A new, empty killswitch (nothing revoked).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Revoke a target. Idempotent.
    pub fn revoke(&mut self, target: Target) {
        self.revoked.insert(target);
    }

    /// Whether a target is currently revoked. An agent is also considered revoked while
    /// quarantined.
    #[must_use]
    pub fn is_revoked(&self, target: &Target) -> bool {
        if self.revoked.contains(target) {
            return true;
        }
        match target {
            Target::Agent(id) => self.quarantined.contains(id),
            _ => false,
        }
    }

    /// Quarantine a suspicious agent: it is treated as revoked until reintegrated.
    pub fn quarantine(&mut self, agent_id: impl Into<String>) {
        self.quarantined.insert(agent_id.into());
    }

    /// Whether an agent is quarantined.
    #[must_use]
    pub fn is_quarantined(&self, agent_id: &str) -> bool {
        self.quarantined.contains(agent_id)
    }

    /// Attempt to reintegrate a quarantined agent. Requires **both** fresh attestation and
    /// explicit human approval; otherwise refused. On success the agent is un-quarantined and its
    /// agent-target revocation cleared.
    pub fn reintegrate(
        &mut self,
        agent_id: &str,
        fresh_attestation: bool,
        human_approved: bool,
    ) -> Reintegration {
        if !self.is_quarantined(agent_id) && !self.revoked.contains(&Target::Agent(agent_id.into()))
        {
            return Reintegration::Denied("agent is not quarantined");
        }
        if !fresh_attestation {
            return Reintegration::Denied("fresh attestation required");
        }
        if !human_approved {
            return Reintegration::Denied("human approval required");
        }
        self.quarantined.remove(agent_id);
        self.revoked.remove(&Target::Agent(agent_id.into()));
        Reintegration::Restored
    }

    /// Number of currently revoked targets (excluding quarantine-only agents).
    #[must_use]
    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_and_check_targets() {
        let mut ks = Killswitch::new();
        assert!(!ks.is_revoked(&Target::Tool("db.write".into())));
        ks.revoke(Target::Tool("db.write".into()));
        assert!(ks.is_revoked(&Target::Tool("db.write".into())));
        assert!(!ks.is_revoked(&Target::Tool("db.read".into())));
        assert_eq!(ks.revoked_count(), 1);
        // Idempotent.
        ks.revoke(Target::Tool("db.write".into()));
        assert_eq!(ks.revoked_count(), 1);
    }

    #[test]
    fn quarantined_agent_is_treated_as_revoked() {
        let mut ks = Killswitch::new();
        ks.quarantine("agent-7");
        assert!(ks.is_quarantined("agent-7"));
        assert!(ks.is_revoked(&Target::Agent("agent-7".into())));
        assert!(!ks.is_revoked(&Target::Agent("agent-8".into())));
    }

    #[test]
    fn reintegration_requires_attestation_and_human_approval() {
        let mut ks = Killswitch::new();
        ks.quarantine("agent-7");
        assert_eq!(
            ks.reintegrate("agent-7", false, true),
            Reintegration::Denied("fresh attestation required")
        );
        assert_eq!(
            ks.reintegrate("agent-7", true, false),
            Reintegration::Denied("human approval required")
        );
        // Still quarantined after failed attempts.
        assert!(ks.is_quarantined("agent-7"));
        // Both present -> restored.
        assert_eq!(
            ks.reintegrate("agent-7", true, true),
            Reintegration::Restored
        );
        assert!(!ks.is_quarantined("agent-7"));
        assert!(!ks.is_revoked(&Target::Agent("agent-7".into())));
    }

    #[test]
    fn registry_round_trips_through_json() {
        // A registry with a revoked tool + a quarantined agent must survive a durable-store
        // round-trip so revocations/quarantines persist across a cold restart.
        let mut ks = Killswitch::new();
        ks.revoke(Target::Tool("db.write".into()));
        ks.quarantine("agent-7");
        let json = serde_json::to_string(&ks).unwrap();
        let restored: Killswitch = serde_json::from_str(&json).unwrap();
        assert!(restored.is_revoked(&Target::Tool("db.write".into())));
        assert!(restored.is_quarantined("agent-7"));
        assert!(restored.is_revoked(&Target::Agent("agent-7".into())));
        // An empty object still loads (both fields default).
        let empty: Killswitch = serde_json::from_str("{}").unwrap();
        assert_eq!(empty.revoked_count(), 0);
    }

    #[test]
    fn reintegrating_a_healthy_agent_is_refused() {
        let mut ks = Killswitch::new();
        assert_eq!(
            ks.reintegrate("agent-x", true, true),
            Reintegration::Denied("agent is not quarantined")
        );
    }

    #[test]
    fn revoked_agent_can_be_reintegrated() {
        let mut ks = Killswitch::new();
        ks.revoke(Target::Agent("a1".into()));
        assert!(ks.is_revoked(&Target::Agent("a1".into())));
        assert_eq!(ks.reintegrate("a1", true, true), Reintegration::Restored);
        assert!(!ks.is_revoked(&Target::Agent("a1".into())));
    }
}
