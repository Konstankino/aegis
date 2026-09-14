//! The Cedar-backed policy engine (step 3 of [`crate::mediate`]).
//!
//! Cedar (Amazon's Rust-native policy language) is the deterministic authorization core
//! (architecture-considerations.md §3 LLM03, §4). All Cedar 4.x API contact is isolated in
//! this module so a version bump touches exactly one file (§1.5/§9 version caution).
//!
//! Authorization is **default-deny**: a request is authorized only if some `permit` matches
//! and no `forbid` overrides it. Policies are loaded from a versioned artifact
//! (`policies/broker.cedar`) and evaluated locally — no per-decision network call.

use aegis_core::{AegisError, Capability, Consequence, Provenance};
use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request,
};

use crate::registry::ToolCall;

/// A compiled Cedar policy set plus an authorizer. Cheap to reuse across many decisions.
pub struct PolicyEngine {
    policies: PolicySet,
    authorizer: Authorizer,
}

/// The identity and accumulated state the policy engine evaluates a call against.
///
/// Mirrors the broker's [`crate::Session`] but is passed explicitly so the policy layer stays
/// independent of the broker's mutable session handling.
pub struct PolicyPrincipal<'a> {
    /// The agent's stable identity (the Cedar principal id).
    pub agent_id: &'a str,
    /// The tenant this session belongs to (Roadmap T1). Exposed as `context.tenant` so policies can
    /// scope per-tenant ACLs; defaults to `"default"` for single-tenant deployments.
    pub tenant: &'a str,
    /// The session's accumulated Rule-of-Two capability taint.
    pub cap: Capability,
}

impl PolicyEngine {
    /// Parse a Cedar policy set from source text.
    pub fn from_cedar(src: &str) -> Result<Self, AegisError> {
        let policies: PolicySet = src
            .parse()
            .map_err(|e| AegisError::Policy(format!("cannot parse Cedar policies: {e}")))?;
        Ok(Self {
            policies,
            authorizer: Authorizer::new(),
        })
    }

    /// Decide whether `principal` is authorized to invoke `call` on tool `resource`, given the
    /// call's static classification. Returns `Ok(true)` for Allow, `Ok(false)` for Deny.
    pub fn is_authorized(
        &self,
        principal: &PolicyPrincipal<'_>,
        call: &ToolCall,
        reaches_sensitive: bool,
        has_external_effect: bool,
        consequence: Consequence,
    ) -> Result<bool, AegisError> {
        let principal_uid = euid("Agent", principal.agent_id)?;
        let action_uid = euid("Action", "invoke")?;
        let resource_uid = euid("Tool", &call.tool)?;

        // Everything a policy can key off travels in the request context: the session's
        // accumulated legs, the properties of this specific call, and its provenance.
        let ctx_json = serde_json::json!({
            "reads_untrusted": principal.cap.reads_untrusted,
            "reads_sensitive": principal.cap.reads_sensitive,
            "external_effect": principal.cap.external_effect,
            "call_reaches_sensitive": reaches_sensitive,
            "call_external_effect": has_external_effect,
            "is_trifecta": principal.cap.is_trifecta(),
            "active_legs": i64::from(principal.cap.active_legs()),
            "consequence": consequence_str(consequence),
            "arg_provenance": provenance_str(call.arg_provenance),
            "tenant": principal.tenant,
        });
        let context = Context::from_json_value(ctx_json, None)
            .map_err(|e| AegisError::Policy(format!("cannot build request context: {e}")))?;

        let request = Request::new(principal_uid, action_uid, resource_uid, context, None)
            .map_err(|e| AegisError::Policy(format!("invalid authorization request: {e}")))?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &Entities::empty());
        Ok(response.decision() == CedarDecision::Allow)
    }

    /// Number of policies loaded (for diagnostics).
    pub fn len(&self) -> usize {
        self.policies.policies().count()
    }

    /// Whether the policy set is empty (which, under default-deny, forbids everything).
    pub fn is_empty(&self) -> bool {
        self.policies.policies().next().is_none()
    }
}

/// Build a Cedar `EntityUid` from a type name and an id, escaping the id safely so a tool name
/// containing quotes or backslashes cannot break out of the entity literal.
fn euid(type_name: &str, id: &str) -> Result<EntityUid, AegisError> {
    let type_name: EntityTypeName = type_name
        .parse()
        .map_err(|e| AegisError::Policy(format!("invalid entity type '{type_name}': {e}")))?;
    let id = EntityId::new(id);
    Ok(EntityUid::from_type_name_and_id(type_name, id))
}

const fn consequence_str(c: Consequence) -> &'static str {
    match c {
        Consequence::LowReversible => "low_reversible",
        Consequence::HighOrIrreversible => "high_or_irreversible",
    }
}

const fn provenance_str(p: Provenance) -> &'static str {
    match p {
        Provenance::System => "system",
        Provenance::User => "user",
        Provenance::SemiTrusted => "semi_trusted",
        Provenance::Untrusted => "untrusted",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal() -> PolicyPrincipal<'static> {
        PolicyPrincipal {
            agent_id: "agent",
            tenant: "default",
            cap: Capability::NONE,
        }
    }

    #[test]
    fn per_tenant_policy_scopes_by_context_tenant() {
        // A per-tenant ACL: only tenant "acme" may invoke.
        let engine = PolicyEngine::from_cedar(
            r#"permit ( principal, action, resource ) when { context.tenant == "acme" };"#,
        )
        .unwrap();
        let call = ToolCall::new("t", serde_json::json!({}), Provenance::User);
        let acme = PolicyPrincipal {
            agent_id: "a",
            tenant: "acme",
            cap: Capability::NONE,
        };
        let other = PolicyPrincipal {
            agent_id: "a",
            tenant: "other",
            cap: Capability::NONE,
        };
        assert!(engine
            .is_authorized(&acme, &call, false, false, Consequence::LowReversible)
            .unwrap());
        assert!(!engine
            .is_authorized(&other, &call, false, false, Consequence::LowReversible)
            .unwrap());
    }

    #[test]
    fn empty_policy_set_is_empty_and_denies_by_default() {
        let engine = PolicyEngine::from_cedar("").unwrap();
        assert!(engine.is_empty());
        assert_eq!(engine.len(), 0);
        let call = ToolCall::new("t", serde_json::json!({}), Provenance::User);
        // Default-deny: no permit means not authorized.
        assert!(!engine
            .is_authorized(
                &principal(),
                &call,
                false,
                false,
                Consequence::LowReversible
            )
            .unwrap());
    }

    #[test]
    fn authorizes_across_all_provenance_and_consequence_encodings() {
        let engine =
            PolicyEngine::from_cedar(r#"permit ( principal, action, resource );"#).unwrap();
        assert!(!engine.is_empty());
        assert_eq!(engine.len(), 1);
        for prov in [
            Provenance::System,
            Provenance::User,
            Provenance::SemiTrusted,
            Provenance::Untrusted,
        ] {
            let call = ToolCall::new("t", serde_json::json!({}), prov);
            for cons in [Consequence::LowReversible, Consequence::HighOrIrreversible] {
                assert!(engine
                    .is_authorized(&principal(), &call, true, true, cons)
                    .unwrap());
            }
        }
    }

    #[test]
    fn rejects_malformed_cedar() {
        assert!(PolicyEngine::from_cedar("this is not cedar!!!").is_err());
    }
}
