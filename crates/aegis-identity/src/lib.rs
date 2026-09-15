//! # aegis-identity — per-agent identity + delegation control (ASI03)
//!
//! A `● Contain` control (architecture-considerations.md §11.2 ASI03). Each non-human agent gets
//! a **JIT, short-lived, scoped credential** bound to subject / audience / purpose / session /
//! duration and to the **original user intent**. Delegation re-validates that intent and forbids
//! privilege escalation (the confused-deputy defense): a delegated credential can only *narrow*
//! scope and must carry the same intent binding. A context switch (new audience/session) forces
//! re-auth.

use aegis_core::signing::{Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

/// A JIT, scoped, signed credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// The agent this credential is for.
    pub subject: String,
    /// The intended audience (the resource/service it may be presented to).
    pub audience: String,
    /// The declared purpose.
    pub purpose: String,
    /// The session it is bound to.
    pub session_id: String,
    /// Hash binding to the original user intent (the confused-deputy anchor).
    pub intent_hash: String,
    /// The scopes (permissions) granted.
    pub scopes: Vec<String>,
    /// Issue time (Unix ms).
    pub issued_at: u64,
    /// Expiry (Unix ms) — short-lived.
    pub expires_at: u64,
    /// Issuer public key.
    pub issuer: PublicKey,
    /// Signature over the canonical body.
    pub signature: Signature,
}

/// The context a credential is being presented in.
///
/// Every field is an **independent** fact about the presentation — the presenting principal, the
/// resource being reached, the session it happens in — supplied by the verifier, NOT copied from the
/// credential. Populating any field from the credential itself turns the corresponding check in
/// [`Credential::verify`] into a tautology (a value compared to itself), so callers must derive these
/// from the request they are authorizing.
#[derive(Debug, Clone)]
pub struct RequestContext<'a> {
    /// The principal actually presenting the credential — must equal the credential's `subject`.
    /// This is the confused-deputy / bearer-token defense: a validly-signed credential is only
    /// usable by the subject it was issued to.
    pub subject: &'a str,
    pub audience: &'a str,
    pub purpose: &'a str,
    pub session_id: &'a str,
    /// The scope the current action requires.
    pub action_scope: &'a str,
}

/// Errors from identity / delegation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    /// Delegation tried to widen scope beyond the parent's.
    #[error("privilege escalation: delegated scope exceeds parent")]
    ScopeEscalation,
    /// Delegation changed the original-intent binding.
    #[error("delegation altered the original user intent")]
    IntentMismatch,
}

/// Why a credential was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthDecision {
    /// Valid and sufficient for the requested action.
    Allow,
    /// Refused — a fixed reason.
    Deny(&'static str),
}

impl AuthDecision {
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, AuthDecision::Allow)
    }
}

// The canonical bytes a credential's signature commits to. Length-prefixed + record-separated so
// no field boundary is ambiguous. (Many fields by nature — this is the credential's whole body.)
#[allow(clippy::too_many_arguments)]
fn canonical_body(
    subject: &str,
    audience: &str,
    purpose: &str,
    session_id: &str,
    intent_hash: &str,
    scopes: &[String],
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut field = |bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(bytes);
        out.push(0x1e);
    };
    for s in [subject, audience, purpose, session_id, intent_hash] {
        field(s.as_bytes());
    }
    for s in scopes {
        field(s.as_bytes());
    }
    field(b"|");
    field(&issued_at.to_le_bytes());
    field(&expires_at.to_le_bytes());
    out
}

impl Credential {
    /// Mint and sign a credential.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn issue(
        keypair: &Keypair,
        subject: impl Into<String>,
        audience: impl Into<String>,
        purpose: impl Into<String>,
        session_id: impl Into<String>,
        intent_hash: impl Into<String>,
        scopes: Vec<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        let (subject, audience, purpose, session_id, intent_hash) = (
            subject.into(),
            audience.into(),
            purpose.into(),
            session_id.into(),
            intent_hash.into(),
        );
        let body = canonical_body(
            &subject,
            &audience,
            &purpose,
            &session_id,
            &intent_hash,
            &scopes,
            issued_at,
            expires_at,
        );
        let signature = keypair.sign(&body);
        Self {
            subject,
            audience,
            purpose,
            session_id,
            intent_hash,
            scopes,
            issued_at,
            expires_at,
            issuer: keypair.public(),
            signature,
        }
    }

    /// Whether the signature is valid for the issuer.
    #[must_use]
    pub fn signature_valid(&self) -> bool {
        let body = canonical_body(
            &self.subject,
            &self.audience,
            &self.purpose,
            &self.session_id,
            &self.intent_hash,
            &self.scopes,
            self.issued_at,
            self.expires_at,
        );
        self.issuer.verify(&body, &self.signature)
    }

    /// Verify the credential against a presentation context: signature, expiry, matching
    /// audience/purpose/session, and that the action scope is granted. Fails closed.
    #[must_use]
    pub fn verify(&self, now_ms: u64, ctx: &RequestContext<'_>) -> AuthDecision {
        if !self.signature_valid() {
            return AuthDecision::Deny("credential signature invalid");
        }
        if now_ms >= self.expires_at {
            return AuthDecision::Deny("credential expired");
        }
        // Subject binding: the credential is usable ONLY by the principal it was issued to. Without
        // this a validly-signed credential is a bearer token — any holder could present it (the
        // confused-deputy hole). `ctx.subject` is the actual requester, never the credential's own.
        if self.subject != ctx.subject {
            return AuthDecision::Deny("subject mismatch");
        }
        if self.audience != ctx.audience {
            return AuthDecision::Deny("audience mismatch");
        }
        if self.purpose != ctx.purpose {
            return AuthDecision::Deny("purpose mismatch");
        }
        if self.session_id != ctx.session_id {
            return AuthDecision::Deny("session mismatch (re-auth required)");
        }
        if !self.scopes.iter().any(|s| s == ctx.action_scope) {
            return AuthDecision::Deny("action scope not granted");
        }
        AuthDecision::Allow
    }

    /// Delegate a **narrower** credential to another subject. The requested scopes must be a
    /// subset of this credential's (no escalation) and the original-intent binding must be
    /// preserved (the confused-deputy defense). The child is freshly signed by `keypair`.
    pub fn delegate(
        &self,
        keypair: &Keypair,
        delegatee: impl Into<String>,
        requested_scopes: Vec<String>,
        intent_hash: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Credential, IdentityError> {
        if intent_hash != self.intent_hash {
            return Err(IdentityError::IntentMismatch);
        }
        if !requested_scopes.iter().all(|s| self.scopes.contains(s)) {
            return Err(IdentityError::ScopeEscalation);
        }
        Ok(Credential::issue(
            keypair,
            delegatee,
            self.audience.clone(),
            self.purpose.clone(),
            self.session_id.clone(),
            self.intent_hash.clone(),
            requested_scopes,
            issued_at,
            expires_at,
        ))
    }

    /// Whether presenting into `ctx` is a context switch that requires re-auth (audience or
    /// session changed).
    #[must_use]
    pub fn needs_reauth(&self, ctx: &RequestContext<'_>) -> bool {
        self.audience != ctx.audience || self.session_id != ctx.session_id
    }
}

/// Map into the plane-wide [`PolicyDecision`](aegis_core::PolicyDecision) vocabulary (Roadmap T0).
impl From<AuthDecision> for aegis_core::PolicyDecision {
    fn from(d: AuthDecision) -> Self {
        match d {
            AuthDecision::Allow => aegis_core::PolicyDecision::Allow,
            AuthDecision::Deny(reason) => aegis_core::PolicyDecision::deny(reason),
        }
    }
}

#[cfg(test)]
mod policy_decision_adapter_tests {
    use super::*;
    #[test]
    fn maps_into_policy_decision() {
        use aegis_core::PolicyDecision;
        assert!(PolicyDecision::from(AuthDecision::Allow).is_allow());
        assert_eq!(
            PolicyDecision::from(AuthDecision::Deny("expired")).reason(),
            Some("expired")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred() -> (Keypair, Credential) {
        let kp = Keypair::from_seed(&[2u8; 32]);
        let c = Credential::issue(
            &kp,
            "agent-a",
            "billing-service",
            "refund",
            "sess-1",
            "intent-abc",
            vec!["refund.read".into(), "refund.write".into()],
            100,
            1_000,
        );
        (kp, c)
    }

    // The presentation context for the legitimate holder (`agent-a`). Tests that exercise a binding
    // check mutate exactly ONE field to a value that differs from the credential, so the assertion
    // proves the check fires — never a value copied from the credential (which would be tautological).
    fn ctx<'a>(scope: &'a str) -> RequestContext<'a> {
        RequestContext {
            subject: "agent-a",
            audience: "billing-service",
            purpose: "refund",
            session_id: "sess-1",
            action_scope: scope,
        }
    }

    #[test]
    fn valid_credential_allows_in_scope_action() {
        let (_kp, c) = cred();
        assert_eq!(c.verify(200, &ctx("refund.read")), AuthDecision::Allow);
    }

    #[test]
    fn wrong_subject_is_denied() {
        // A validly-signed credential for agent-a, presented by a different principal, is refused —
        // it is not a bearer token. (Audience/session/scope all still match, so only the subject
        // binding can be what denies: a genuine, non-tautological check.)
        let (_kp, c) = cred();
        let mut cx = ctx("refund.read");
        cx.subject = "agent-b";
        assert_eq!(c.verify(200, &cx), AuthDecision::Deny("subject mismatch"));
    }

    #[test]
    fn wrong_audience_session_or_scope_is_denied() {
        let (_kp, c) = cred();
        let mut cx = ctx("refund.read");
        cx.audience = "other-service";
        assert_eq!(c.verify(200, &cx), AuthDecision::Deny("audience mismatch"));
        let mut cx = ctx("refund.read");
        cx.session_id = "sess-2";
        assert_eq!(
            c.verify(200, &cx),
            AuthDecision::Deny("session mismatch (re-auth required)")
        );
        assert_eq!(
            c.verify(200, &ctx("refund.delete")),
            AuthDecision::Deny("action scope not granted")
        );
    }

    #[test]
    fn expired_credential_denied() {
        let (_kp, c) = cred();
        assert_eq!(
            c.verify(2_000, &ctx("refund.read")),
            AuthDecision::Deny("credential expired")
        );
    }

    #[test]
    fn delegation_cannot_escalate_scope() {
        let (kp, c) = cred();
        let err = c
            .delegate(
                &kp,
                "agent-b",
                vec!["refund.admin".into()],
                "intent-abc",
                200,
                500,
            )
            .unwrap_err();
        assert_eq!(err, IdentityError::ScopeEscalation);
    }

    #[test]
    fn delegation_must_preserve_original_intent() {
        let (kp, c) = cred();
        let err = c
            .delegate(
                &kp,
                "agent-b",
                vec!["refund.read".into()],
                "intent-DIFFERENT",
                200,
                500,
            )
            .unwrap_err();
        assert_eq!(err, IdentityError::IntentMismatch);
    }

    #[test]
    fn narrowing_delegation_succeeds_and_verifies() {
        let (kp, c) = cred();
        let child = c
            .delegate(
                &kp,
                "agent-b",
                vec!["refund.read".into()],
                "intent-abc",
                200,
                500,
            )
            .unwrap();
        assert_eq!(child.subject, "agent-b");
        assert!(child.signature_valid());
        // The delegated child is bound to its NEW subject (agent-b), so it must be presented as
        // agent-b — proving subject binding survives delegation.
        let mut as_b = ctx("refund.read");
        as_b.subject = "agent-b";
        assert_eq!(child.verify(300, &as_b), AuthDecision::Allow);
        // Presented as the parent (agent-a), the child is refused — it is not the delegatee's to lend.
        assert_eq!(
            child.verify(300, &ctx("refund.read")),
            AuthDecision::Deny("subject mismatch")
        );
        // And even as agent-b the narrowed child no longer grants the write scope.
        as_b.action_scope = "refund.write";
        assert_eq!(
            child.verify(300, &as_b),
            AuthDecision::Deny("action scope not granted")
        );
    }

    #[test]
    fn context_switch_requires_reauth() {
        let (_kp, c) = cred();
        assert!(!c.needs_reauth(&ctx("refund.read")));
        let mut cx = ctx("refund.read");
        cx.session_id = "sess-2";
        assert!(c.needs_reauth(&cx));
    }
}
