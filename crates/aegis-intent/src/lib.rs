//! # aegis-intent — signed goal/intent envelope (ASI01)
//!
//! A `● Contain` control (architecture-considerations.md §11.2 ASI01). An **intent capsule** is
//! a signed goal + scope bound to one execution cycle. The broker validates each action against
//! the capsule and refuses anything outside the declared scope, so an attacker who redirects the
//! model's *goal* (prompt injection, forged tool output) still cannot get an out-of-scope action
//! executed. A stable goal id drives drift detection.

use aegis_core::signing::{Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

/// A signed goal/scope envelope for one execution cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentCapsule {
    /// Stable goal identifier (drives drift alerting across cycles).
    pub goal_id: String,
    /// Human-readable declared goal.
    pub goal: String,
    /// Tools the agent is permitted to use in pursuit of this goal.
    pub allowed_tools: Vec<String>,
    /// The execution cycle this capsule is bound to.
    pub cycle_id: String,
    /// Issue time (Unix ms).
    pub issued_at: u64,
    /// Expiry (Unix ms).
    pub expires_at: u64,
    /// The issuer's public key (the orchestrator, not the agent).
    pub issuer: PublicKey,
    /// Signature over the canonical body.
    pub signature: Signature,
}

/// The decision on an action against the current intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentDecision {
    /// The action is within the declared goal scope.
    Proceed,
    /// The action deviates from the intent (blocked / paused) — a fixed reason.
    Deviation(&'static str),
}

impl IntentDecision {
    /// Whether the action may proceed.
    #[must_use]
    pub fn is_proceed(&self) -> bool {
        matches!(self, IntentDecision::Proceed)
    }
}

fn canonical_body(
    goal_id: &str,
    goal: &str,
    allowed_tools: &[String],
    cycle_id: &str,
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut field = |bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(bytes);
        out.push(0x1e);
    };
    field(goal_id.as_bytes());
    field(goal.as_bytes());
    for t in allowed_tools {
        field(t.as_bytes());
    }
    field(b"|");
    field(cycle_id.as_bytes());
    field(&issued_at.to_le_bytes());
    field(&expires_at.to_le_bytes());
    out
}

impl IntentCapsule {
    /// Issue and sign a capsule with the orchestrator's keypair.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn issue(
        keypair: &Keypair,
        goal_id: impl Into<String>,
        goal: impl Into<String>,
        allowed_tools: Vec<String>,
        cycle_id: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        let goal_id = goal_id.into();
        let goal = goal.into();
        let cycle_id = cycle_id.into();
        let body = canonical_body(
            &goal_id,
            &goal,
            &allowed_tools,
            &cycle_id,
            issued_at,
            expires_at,
        );
        let signature = keypair.sign(&body);
        Self {
            goal_id,
            goal,
            allowed_tools,
            cycle_id,
            issued_at,
            expires_at,
            issuer: keypair.public(),
            signature,
        }
    }

    /// Whether the capsule's signature is valid for its issuer.
    #[must_use]
    pub fn signature_valid(&self) -> bool {
        let body = canonical_body(
            &self.goal_id,
            &self.goal,
            &self.allowed_tools,
            &self.cycle_id,
            self.issued_at,
            self.expires_at,
        );
        self.issuer.verify(&body, &self.signature)
    }

    /// Whether the capsule is still within its validity window.
    #[must_use]
    pub fn is_current(&self, now_ms: u64) -> bool {
        now_ms >= self.issued_at && now_ms < self.expires_at
    }

    /// Validate a proposed action (a tool) against the capsule. Fails closed on a bad signature,
    /// an expired capsule, or a tool outside the declared scope.
    #[must_use]
    pub fn validate_action(&self, tool: &str, now_ms: u64) -> IntentDecision {
        if !self.signature_valid() {
            return IntentDecision::Deviation("intent capsule signature invalid");
        }
        if !self.is_current(now_ms) {
            return IntentDecision::Deviation("intent capsule expired");
        }
        if !self.allowed_tools.iter().any(|t| t == tool) {
            return IntentDecision::Deviation("action outside declared intent scope");
        }
        IntentDecision::Proceed
    }

    /// Goal drift: the pursued goal id differs from the declared one.
    #[must_use]
    pub fn is_goal_drift(&self, pursued_goal_id: &str) -> bool {
        self.goal_id != pursued_goal_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capsule(now: u64, ttl: u64) -> (Keypair, IntentCapsule) {
        let kp = Keypair::from_seed(&[1u8; 32]);
        let c = IntentCapsule::issue(
            &kp,
            "summarize-inbox",
            "Summarize the user's unread email",
            vec!["email.read".into(), "db.read".into()],
            "cycle-1",
            now,
            now + ttl,
        );
        (kp, c)
    }

    #[test]
    fn valid_capsule_allows_in_scope_action() {
        let (_kp, c) = capsule(100, 1000);
        assert!(c.signature_valid());
        assert_eq!(
            c.validate_action("email.read", 200),
            IntentDecision::Proceed
        );
    }

    #[test]
    fn out_of_scope_action_is_a_deviation() {
        let (_kp, c) = capsule(100, 1000);
        assert_eq!(
            c.validate_action("email.send", 200),
            IntentDecision::Deviation("action outside declared intent scope")
        );
    }

    #[test]
    fn expired_capsule_is_a_deviation() {
        let (_kp, c) = capsule(100, 50);
        assert_eq!(
            c.validate_action("email.read", 1000),
            IntentDecision::Deviation("intent capsule expired")
        );
    }

    #[test]
    fn tampered_capsule_fails_signature() {
        let (_kp, mut c) = capsule(100, 1000);
        // An attacker widens the scope after signing.
        c.allowed_tools.push("email.send".into());
        assert!(!c.signature_valid());
        assert_eq!(
            c.validate_action("email.send", 200),
            IntentDecision::Deviation("intent capsule signature invalid")
        );
    }

    #[test]
    fn goal_drift_detected() {
        let (_kp, c) = capsule(100, 1000);
        assert!(!c.is_goal_drift("summarize-inbox"));
        assert!(c.is_goal_drift("wire-transfer-funds"));
    }
}
