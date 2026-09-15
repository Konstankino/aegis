//! # aegis-jit — the just-in-time credential broker (ASI03/ASI06)
//!
//! A `● Contain` control. It is the deterministic gatekeeper that exchanges a **validated internal
//! identity credential** ([`aegis_identity::Credential`]) for a **real, short-lived, tightly-scoped
//! cloud credential** — an AWS STS session (narrowed by an inline session policy) or a
//! just-in-time secret — and nothing else.
//!
//! ## Why this exists
//!
//! Agents and their sandboxes otherwise reach data through a single, long-lived execution role: a
//! compromised agent inherits that whole standing identity for its whole lifetime. This crate makes
//! every real data-plane access **minted per call**, scoped to exactly one resource+action,
//! expiring in seconds-to-minutes, authorized by the agent's own signed identity + a versioned
//! [`GrantCatalog`] + the broker's Rule-of-Two taint, and fully audited.
//!
//! ## Separation of concerns
//!
//! This crate is **pure and provider-agnostic**: it has no AWS/network dependency. [`decide`] is a
//! deterministic function of (credential, request context, grant, accumulated session capability,
//! clock, requested TTL). Only *after* it returns [`JitDecision::Grant`] does the host
//! (`aegis-extension`, behind a feature flag) call the real STS / Secrets Manager APIs. The
//! [`Provider`] enum describes *what* to mint; the host knows *how*.
//!
//! ## Co-existence with inter-agent identity
//!
//! The credential presented here is the same [`aegis_identity::Credential`] that authenticates an
//! agent on the mesh, with the same intent binding and the same **narrow-only delegation** — a
//! delegated (narrowed) credential still resolves a grant it retains scope for; an escalated one is
//! refused by [`aegis_identity::Credential::verify`] before this crate even inspects the grant.
//! Agents are first-class principals: a grant is bound to an *audience* + *scope*, not to a human.

use aegis_core::{Capability, Consequence};
use aegis_identity::{AuthDecision, Credential, RequestContext};
use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}
fn default_consequence() -> Consequence {
    Consequence::LowReversible
}

/// Which real-world credential a [`Grant`] mints. The core treats provider fields as opaque data;
/// the host (extension) renders and calls them. Internally tagged by `kind` so a grant's provider
/// reads as one TOML table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Provider {
    /// Mint a short-lived AWS STS session by assuming `role_arn`, narrowed at mint time by an
    /// inline **session policy** rendered from `session_policy_template` against `resource_arns`
    /// (so even a broad role yields a session scoped to exactly this resource + action).
    Sts {
        /// The (narrow) role the host assumes on the caller's behalf.
        role_arn: String,
        /// The concrete resource ARNs this grant may touch (substituted into the template).
        #[serde(default)]
        resource_arns: Vec<String>,
        /// Inline session-policy template (opaque here; the host renders `{resource}` etc.).
        #[serde(default)]
        session_policy_template: String,
    },
    /// Fetch a secret just-in-time from Secrets Manager. The value is returned to the caller with an
    /// advisory TTL and is **never** persisted to disk or the ledger.
    Secret {
        /// The secret's ARN (or name).
        secret_arn: String,
        /// Optional JSON key to pluck out of a JSON secret value.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        json_key: Option<String>,
    },
}

impl Provider {
    /// A short, non-sensitive label for logs/ledger (never includes secret material).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Provider::Sts { .. } => "sts",
            Provider::Secret { .. } => "secret",
        }
    }

    /// For an STS provider, render the inline session policy by substituting `{resource}` with the
    /// grant's resource ARN(s) (one ARN verbatim, several as a JSON array, none as `*`). The host
    /// passes this to `AssumeRole` so even a broad role yields a session scoped to exactly this
    /// resource. `None` for a non-STS provider.
    #[must_use]
    pub fn rendered_session_policy(&self) -> Option<String> {
        match self {
            Provider::Sts {
                session_policy_template,
                resource_arns,
                ..
            } => {
                let replacement = match resource_arns.as_slice() {
                    // Fail CLOSED, never open: a grant with no resource ARNs must NOT widen the
                    // session policy to `*` (which would leave the assumed role un-narrowed — the
                    // whole point of the inline policy is to scope it down). `GrantCatalog::validate`
                    // rejects such grants; this sentinel is defense in depth if one slips through —
                    // it matches no real ARN, so the session grants nothing.
                    [] => NO_RESOURCE_SENTINEL.to_string(),
                    [one] => one.clone(),
                    many => serde_json::to_string(many)
                        .unwrap_or_else(|_| NO_RESOURCE_SENTINEL.to_string()),
                };
                Some(session_policy_template.replace("{resource}", &replacement))
            }
            Provider::Secret { .. } => None,
        }
    }
}

/// A syntactically-valid ARN that matches no real resource. Used as the fail-closed substitution for
/// an STS grant with no `resource_arns`, so its inline session policy grants access to nothing rather
/// than everything.
pub const NO_RESOURCE_SENTINEL: &str = "arn:aws:iam::000000000000:role/aegis-no-resource-deny";

/// Format a Unix timestamp (seconds, UTC) as ISO-8601 `YYYY-MM-DDTHH:MM:SSZ` — the shape AWS expects
/// for an `aws:CurrentTime` policy condition. Pure (no external date crate) via Howard Hinnant's
/// civil-from-days, so it is fully unit-testable.
#[must_use]
pub fn unix_to_iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let z = days + 719_468; // shift epoch so the era arithmetic stays non-negative
    let era = z / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Time-fence a rendered STS inline session policy: append an explicit `Deny *` on everything after
/// `expiry_unix_secs`.
///
/// **Why:** STS enforces a 900-second FLOOR on a session token's `DurationSeconds`, so a credential
/// meant to live 60–300s would otherwise be usable for the full 15 minutes — the returned
/// `expires_at_ms` alone is only advisory. An explicit `Deny` guarded by
/// `DateGreaterThan aws:CurrentTime` makes AWS itself refuse every action once the intended (short)
/// TTL elapses, and an explicit Deny overrides the operator's `Allow`(s), which are preserved so the
/// resource narrowing still holds before expiry.
///
/// The operator's statements are kept as-is and the fence is appended. If `rendered` is empty or not
/// a JSON object, the result is the fence alone — a session policy with no `Allow` grants nothing
/// (fail-closed).
#[must_use]
pub fn fence_session_policy(rendered: &str, expiry_unix_secs: u64) -> String {
    let fence = serde_json::json!({
        "Sid": "AegisJitExpiry",
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": { "DateGreaterThan": { "aws:CurrentTime": unix_to_iso8601(expiry_unix_secs) } }
    });

    let mut doc = match serde_json::from_str::<serde_json::Value>(rendered.trim()) {
        Ok(v @ serde_json::Value::Object(_)) => v,
        _ => serde_json::json!({}),
    };
    let obj = doc.as_object_mut().expect("doc is an object");
    obj.entry("Version".to_string())
        .or_insert_with(|| serde_json::Value::String("2012-10-17".into()));
    let mut statements = match obj.remove("Statement") {
        Some(serde_json::Value::Array(a)) => a,
        Some(other) => vec![other], // a single-statement object → wrap into an array
        None => vec![],
    };
    statements.push(fence);
    obj.insert(
        "Statement".to_string(),
        serde_json::Value::Array(statements),
    );
    serde_json::to_string(&doc).unwrap_or_default()
}

/// One entry of the versioned grant catalog (`grants.toml`). Declares who may mint what, for how
/// long, and the Rule-of-Two effect that minting represents. Scalar fields precede `provider` so the
/// TOML serializes cleanly (scalars, then the provider table).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Grant {
    /// Stable grant id (what a caller names).
    pub id: String,
    /// The audience this grant is for — must equal the presented credential's `audience`.
    pub audience: String,
    /// The scope the credential must carry (and the action scope requested) to use this grant.
    pub required_scope: String,
    /// Ceiling on the minted credential's lifetime, in seconds (e.g. 60, 300). A request may ask
    /// for less; it can never get more, nor outlive the presenting credential.
    pub max_ttl_secs: u64,
    /// Rule-of-Two **leg B**: using this grant reaches private/regulated data.
    #[serde(default)]
    pub reads_sensitive: bool,
    /// Rule-of-Two **leg C**: using this grant produces an external effect (write / destination /
    /// outbound communication).
    #[serde(default)]
    pub external_effect: bool,
    /// When issuing would complete the lethal trifecta, route to human approval instead of minting.
    /// Defaults to `true` (fail-safe).
    #[serde(default = "default_true")]
    pub forbid_when_trifecta: bool,
    /// The consequence class of *using* the minted credential. Irreversible/high-impact effects
    /// escalate to a human even outside the trifecta (graduated enforcement).
    #[serde(default = "default_consequence")]
    pub consequence: Consequence,
    /// What to mint (kept last so the provider table follows the scalar fields in TOML).
    pub provider: Provider,
}

impl Grant {
    /// The Rule-of-Two legs that minting this credential contributes to the session (never
    /// `reads_untrusted` — a JIT credential is a capability the agent *gains*, not untrusted input
    /// it *reads*; leg A is accumulated by the broker from tool calls).
    #[must_use]
    pub fn legs(&self) -> Capability {
        Capability {
            reads_untrusted: false,
            reads_sensitive: self.reads_sensitive,
            external_effect: self.external_effect,
        }
    }
}

/// The versioned grant catalog — the deterministic policy artifact behind the JIT broker.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrantCatalog {
    /// The grants, in declaration order.
    #[serde(default)]
    grants: Vec<Grant>,
}

impl GrantCatalog {
    /// An empty catalog — no grants, so every request is denied (safe by default).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parse a catalog from `grants.toml`. An empty/absent file parses to the empty catalog.
    pub fn from_toml(src: &str) -> Result<Self, aegis_core::AegisError> {
        toml::from_str(src).map_err(|e| aegis_core::AegisError::Policy(format!("grants.toml: {e}")))
    }

    /// Serialize the catalog back to TOML (non-comment-preserving; the CLI uses `toml_edit` for
    /// comment-preserving edits).
    pub fn to_toml(&self) -> Result<String, aegis_core::AegisError> {
        toml::to_string_pretty(self)
            .map_err(|e| aegis_core::AegisError::Policy(format!("serialize grants.toml: {e}")))
    }

    /// All grants, in declaration order.
    #[must_use]
    pub fn all(&self) -> &[Grant] {
        &self.grants
    }

    /// Look up a grant by id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Grant> {
        self.grants.iter().find(|g| g.id == id)
    }

    /// Insert or replace a grant by id (idempotent by id). Returns whether an existing grant was
    /// replaced.
    pub fn upsert(&mut self, grant: Grant) -> bool {
        if let Some(existing) = self.grants.iter_mut().find(|g| g.id == grant.id) {
            *existing = grant;
            true
        } else {
            self.grants.push(grant);
            false
        }
    }

    /// Remove a grant by id. Returns whether one was removed.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.grants.len();
        self.grants.retain(|g| g.id != id);
        self.grants.len() != before
    }

    /// Structural validation: unique ids, positive TTL ceilings, non-empty required fields.
    /// Fail-closed — a malformed catalog is refused rather than silently trusted.
    pub fn validate(&self) -> Result<(), aegis_core::AegisError> {
        let mut seen = std::collections::HashSet::new();
        for g in &self.grants {
            if g.id.trim().is_empty() {
                return Err(aegis_core::AegisError::Policy("grant with empty id".into()));
            }
            if !seen.insert(g.id.as_str()) {
                return Err(aegis_core::AegisError::Policy(format!(
                    "duplicate grant id: {}",
                    g.id
                )));
            }
            if g.audience.trim().is_empty() {
                return Err(aegis_core::AegisError::Policy(format!(
                    "grant {} has empty audience",
                    g.id
                )));
            }
            if g.required_scope.trim().is_empty() {
                return Err(aegis_core::AegisError::Policy(format!(
                    "grant {} has empty required_scope",
                    g.id
                )));
            }
            if g.max_ttl_secs == 0 {
                return Err(aegis_core::AegisError::Policy(format!(
                    "grant {} has max_ttl_secs = 0 (no positive lifetime)",
                    g.id
                )));
            }
            // An STS grant MUST name at least one resource ARN. With none, the rendered inline
            // session policy would scope the assumed role to `*` — i.e. NOT narrow it at all, the
            // opposite of this control's purpose. Refuse it rather than mint a wildcard credential.
            if let Provider::Sts { resource_arns, .. } = &g.provider {
                if resource_arns.iter().all(|a| a.trim().is_empty()) {
                    return Err(aegis_core::AegisError::Policy(format!(
                        "STS grant {} has no resource_arns (would scope the session policy to all \
                         resources); name the exact resource(s) it may reach",
                        g.id
                    )));
                }
            }
        }
        Ok(())
    }
}

/// The deterministic outcome of a JIT credential request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JitDecision {
    /// Mint a credential: for `ttl_secs`, contributing `legs` to the session's Rule-of-Two taint,
    /// with the given consequence class. Only here does the host call the real cloud API.
    Grant {
        /// The clamped lifetime (≤ requested, ≤ grant ceiling, ≤ the presenting credential's life).
        ttl_secs: u64,
        /// The Rule-of-Two legs the host must accumulate onto the session before minting.
        legs: Capability,
        /// Consequence class (for the audit record).
        consequence: Consequence,
    },
    /// Allowed in principle but requires a human first (lethal trifecta, or an irreversible effect):
    /// route to the same Step Functions `waitForTaskToken` pause the broker uses.
    HumanApprove(&'static str),
    /// Refused. The reason is a fixed, non-sensitive string safe to log and return.
    Deny(&'static str),
}

/// **The complete JIT-issue gate.** Deterministically decide whether to mint a credential for
/// `grant` on behalf of the holder of `cred`, given the session's accumulated capability. Pure and
/// fail-closed — no network, same input ⇒ same decision.
///
/// Order of controls (mirrors the broker's `mediate`):
/// 1. The identity credential must verify in this context (signature, expiry, audience/purpose/
///    session, scope) — reuses [`aegis_identity::Credential::verify`].
/// 2. The grant must match the credential (audience, scope) and the requested action scope.
/// 3. TTL ceiling: `ttl = min(requested, grant.max_ttl_secs, remaining credential life)`.
/// 4. Rule of Two: if minting would complete the lethal trifecta, route to a human.
/// 5. Graduated enforcement: an irreversible/high-consequence credential escalates to a human.
#[must_use]
pub fn decide(
    cred: &Credential,
    ctx: &RequestContext<'_>,
    grant: &Grant,
    session_cap: &Capability,
    now_ms: u64,
    requested_ttl_secs: u64,
) -> JitDecision {
    // 1. The identity credential must verify in this presentation context.
    if let AuthDecision::Deny(reason) = cred.verify(now_ms, ctx) {
        return JitDecision::Deny(reason);
    }

    // 2. Grant/credential coherence. `verify` already checked the credential carries `action_scope`
    //    and that the context matches the credential; here we bind the *grant* to the same facts.
    if grant.audience != cred.audience {
        return JitDecision::Deny("grant audience does not match credential");
    }
    if grant.required_scope != ctx.action_scope {
        return JitDecision::Deny("grant scope does not match requested action scope");
    }

    // 3. TTL ceiling. The minted credential may not outlive the grant ceiling, the request, or the
    //    presenting credential itself — a cloud credential can never survive its authorization.
    if requested_ttl_secs == 0 {
        return JitDecision::Deny("requested ttl must be positive");
    }
    let remaining_secs = cred.expires_at.saturating_sub(now_ms) / 1000;
    let ttl = requested_ttl_secs
        .min(grant.max_ttl_secs)
        .min(remaining_secs);
    if ttl == 0 {
        return JitDecision::Deny("no positive ttl within grant ceiling and credential lifetime");
    }

    // 4. Rule of Two: the lethal trifecta is never auto-minted.
    let legs = grant.legs();
    let would = session_cap.union(&legs);
    if grant.forbid_when_trifecta && would.is_trifecta() {
        return JitDecision::HumanApprove(
            "issuing this credential would complete the lethal trifecta",
        );
    }

    // 5. Graduated enforcement: an irreversible/high-consequence credential escalates to a human.
    match grant.consequence {
        Consequence::LowReversible => JitDecision::Grant {
            ttl_secs: ttl,
            legs,
            consequence: grant.consequence,
        },
        Consequence::HighOrIrreversible => {
            JitDecision::HumanApprove("issuing an irreversible/high-consequence credential")
        }
    }
}

/// Map into the plane-wide [`PolicyDecision`](aegis_core::PolicyDecision) vocabulary (Roadmap T0).
/// `Grant` is an allow; `HumanApprove` an escalation; `Deny` carries its reason.
impl From<JitDecision> for aegis_core::PolicyDecision {
    fn from(d: JitDecision) -> Self {
        match d {
            JitDecision::Grant { .. } => aegis_core::PolicyDecision::Allow,
            JitDecision::HumanApprove(reason) => aegis_core::PolicyDecision::escalate(reason),
            JitDecision::Deny(reason) => aegis_core::PolicyDecision::deny(reason),
        }
    }
}

#[cfg(test)]
mod policy_decision_adapter_tests {
    use super::*;
    #[test]
    fn maps_into_policy_decision() {
        use aegis_core::{Capability, Consequence, PolicyDecision};
        let grant = JitDecision::Grant {
            ttl_secs: 60,
            legs: Capability::NONE,
            consequence: Consequence::LowReversible,
        };
        assert!(PolicyDecision::from(grant).is_allow());
        assert!(PolicyDecision::from(JitDecision::HumanApprove("trifecta")).is_escalate());
        assert_eq!(
            PolicyDecision::from(JitDecision::Deny("no grant")).reason(),
            Some("no grant")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::signing::Keypair;

    const DAY_MS: u64 = 86_400_000;

    fn issuer() -> Keypair {
        Keypair::from_seed(&[7u8; 32])
    }

    // A credential for agent-a to read the patient DB, valid [0, DAY_MS).
    fn read_cred(kp: &Keypair) -> Credential {
        Credential::issue(
            kp,
            "agent-a",
            "patient-db",
            "triage",
            "sess-1",
            "intent-xyz",
            vec!["db.read".into(), "db.write".into()],
            0,
            DAY_MS,
        )
    }

    // The presentation context, parameterised by the presenting principal. `ctx` is the legitimate
    // holder (agent-a); `ctx_as` lets a test present the credential as a DIFFERENT principal so the
    // subject-binding check is exercised for real rather than compared against the credential itself.
    fn ctx_as<'a>(subject: &'a str, scope: &'a str) -> RequestContext<'a> {
        RequestContext {
            subject,
            audience: "patient-db",
            purpose: "triage",
            session_id: "sess-1",
            action_scope: scope,
        }
    }

    fn ctx<'a>(scope: &'a str) -> RequestContext<'a> {
        ctx_as("agent-a", scope)
    }

    fn read_grant() -> Grant {
        Grant {
            id: "patient-db-read".into(),
            audience: "patient-db".into(),
            required_scope: "db.read".into(),
            max_ttl_secs: 300,
            reads_sensitive: true,
            external_effect: false,
            forbid_when_trifecta: true,
            consequence: Consequence::LowReversible,
            provider: Provider::Sts {
                role_arn: "arn:aws:iam::111122223333:role/aegis-patient-db-read".into(),
                resource_arns: vec!["arn:aws:rds-db:us-east-1:111122223333:dbuser/db/reader".into()],
                session_policy_template: "{\"Version\":\"2012-10-17\"}".into(),
            },
        }
    }

    fn write_grant() -> Grant {
        Grant {
            id: "patient-db-write".into(),
            audience: "patient-db".into(),
            required_scope: "db.write".into(),
            max_ttl_secs: 60,
            reads_sensitive: false,
            external_effect: true,
            forbid_when_trifecta: true,
            consequence: Consequence::LowReversible,
            provider: Provider::Secret {
                secret_arn: "arn:aws:secretsmanager:us-east-1:111122223333:secret:db-writer".into(),
                json_key: Some("password".into()),
            },
        }
    }

    #[test]
    fn happy_path_grants_a_read_credential() {
        let kp = issuer();
        let d = decide(
            &read_cred(&kp),
            &ctx("db.read"),
            &read_grant(),
            &Capability::NONE,
            1_000,
            60,
        );
        assert_eq!(
            d,
            JitDecision::Grant {
                ttl_secs: 60,
                legs: Capability {
                    reads_untrusted: false,
                    reads_sensitive: true,
                    external_effect: false
                },
                consequence: Consequence::LowReversible,
            }
        );
    }

    #[test]
    fn ttl_is_clamped_to_the_grant_ceiling() {
        let kp = issuer();
        // Ask for 3600s against a 300s ceiling → clamped to 300.
        let d = decide(
            &read_cred(&kp),
            &ctx("db.read"),
            &read_grant(),
            &Capability::NONE,
            1_000,
            3_600,
        );
        match d {
            JitDecision::Grant { ttl_secs, .. } => assert_eq!(ttl_secs, 300),
            other => panic!("expected Grant, got {other:?}"),
        }
    }

    #[test]
    fn ttl_cannot_outlive_the_presenting_credential() {
        let kp = issuer();
        let cred = read_cred(&kp); // expires at DAY_MS
                                   // now is 40s before expiry; ask for 300s → clamped to 40s.
        let now = DAY_MS - 40_000;
        let d = decide(
            &cred,
            &ctx("db.read"),
            &read_grant(),
            &Capability::NONE,
            now,
            300,
        );
        match d {
            JitDecision::Grant { ttl_secs, .. } => assert_eq!(ttl_secs, 40),
            other => panic!("expected Grant clamped to remaining life, got {other:?}"),
        }
    }

    #[test]
    fn expired_credential_is_denied() {
        let kp = issuer();
        let d = decide(
            &read_cred(&kp),
            &ctx("db.read"),
            &read_grant(),
            &Capability::NONE,
            DAY_MS,
            60,
        );
        assert_eq!(d, JitDecision::Deny("credential expired"));
    }

    #[test]
    fn forged_credential_is_denied() {
        let kp = issuer();
        let mut cred = read_cred(&kp);
        cred.scopes.push("db.admin".into()); // mutate after signing → signature no longer valid
        let d = decide(
            &cred,
            &ctx("db.read"),
            &read_grant(),
            &Capability::NONE,
            1_000,
            60,
        );
        assert_eq!(d, JitDecision::Deny("credential signature invalid"));
    }

    #[test]
    fn scope_not_granted_is_denied_by_identity() {
        let kp = issuer();
        // The credential does not carry db.delete, so identity verify denies before the grant.
        let mut g = read_grant();
        g.required_scope = "db.delete".into();
        let d = decide(
            &read_cred(&kp),
            &ctx("db.delete"),
            &g,
            &Capability::NONE,
            1_000,
            60,
        );
        assert_eq!(d, JitDecision::Deny("action scope not granted"));
    }

    #[test]
    fn grant_audience_mismatch_is_denied() {
        let kp = issuer();
        let mut g = read_grant();
        g.audience = "other-service".into();
        let d = decide(
            &read_cred(&kp),
            &ctx("db.read"),
            &g,
            &Capability::NONE,
            1_000,
            60,
        );
        assert_eq!(
            d,
            JitDecision::Deny("grant audience does not match credential")
        );
    }

    #[test]
    fn grant_scope_mismatch_with_context_is_denied() {
        let kp = issuer();
        // Credential + context are for db.write, but the grant requires db.read.
        let g = read_grant();
        let d = decide(
            &read_cred(&kp),
            &ctx("db.write"),
            &g,
            &Capability::NONE,
            1_000,
            60,
        );
        assert_eq!(
            d,
            JitDecision::Deny("grant scope does not match requested action scope")
        );
    }

    #[test]
    fn completing_the_trifecta_routes_to_human_approval() {
        let kp = issuer();
        // Session already has legs A (untrusted) + B (sensitive). A leg-C (external_effect) grant
        // would complete the trifecta.
        let session = Capability {
            reads_untrusted: true,
            reads_sensitive: true,
            external_effect: false,
        };
        let mut g = write_grant();
        g.required_scope = "db.write".into();
        let d = decide(&read_cred(&kp), &ctx("db.write"), &g, &session, 1_000, 30);
        assert_eq!(
            d,
            JitDecision::HumanApprove("issuing this credential would complete the lethal trifecta")
        );
    }

    #[test]
    fn irreversible_grant_escalates_even_without_trifecta() {
        let kp = issuer();
        let mut g = write_grant();
        g.required_scope = "db.write".into();
        g.consequence = Consequence::HighOrIrreversible;
        let d = decide(
            &read_cred(&kp),
            &ctx("db.write"),
            &g,
            &Capability::NONE,
            1_000,
            30,
        );
        assert_eq!(
            d,
            JitDecision::HumanApprove("issuing an irreversible/high-consequence credential")
        );
    }

    #[test]
    fn delegated_narrowed_credential_still_resolves_a_retained_grant() {
        let kp = issuer();
        let parent = read_cred(&kp);
        // Delegate a read-only child (drops db.write) to agent-b, same intent.
        let child = parent
            .delegate(
                &kp,
                "agent-b",
                vec!["db.read".into()],
                "intent-xyz",
                10,
                DAY_MS,
            )
            .unwrap();
        // The child is bound to agent-b, so it must be presented as agent-b.
        let d = decide(
            &child,
            &ctx_as("agent-b", "db.read"),
            &read_grant(),
            &Capability::NONE,
            1_000,
            60,
        );
        match d {
            JitDecision::Grant { ttl_secs, .. } => assert_eq!(ttl_secs, 60),
            other => panic!("expected Grant for narrowed child, got {other:?}"),
        }
        // But the child cannot obtain the write grant it delegated away.
        let mut wg = write_grant();
        wg.required_scope = "db.write".into();
        let d2 = decide(
            &child,
            &ctx_as("agent-b", "db.write"),
            &wg,
            &Capability::NONE,
            1_000,
            30,
        );
        assert_eq!(d2, JitDecision::Deny("action scope not granted"));
    }

    #[test]
    fn credential_subject_mismatch_is_denied() {
        // read_cred was issued to agent-a; presenting it as agent-b is refused (bearer-token defense)
        // before the grant is even consulted.
        let kp = issuer();
        let d = decide(
            &read_cred(&kp),
            &ctx_as("agent-b", "db.read"),
            &read_grant(),
            &Capability::NONE,
            1_000,
            60,
        );
        assert_eq!(d, JitDecision::Deny("subject mismatch"));
    }

    #[test]
    fn zero_requested_ttl_is_denied() {
        let kp = issuer();
        let d = decide(
            &read_cred(&kp),
            &ctx("db.read"),
            &read_grant(),
            &Capability::NONE,
            1_000,
            0,
        );
        assert_eq!(d, JitDecision::Deny("requested ttl must be positive"));
    }

    #[test]
    fn ttl_below_the_credentials_remaining_life_denies() {
        let kp = issuer();
        let cred = read_cred(&kp); // expires at DAY_MS
                                   // now is 500ms before expiry → remaining < 1s → no whole-second ttl → deny.
        let now = DAY_MS - 500;
        let d = decide(
            &cred,
            &ctx("db.read"),
            &read_grant(),
            &Capability::NONE,
            now,
            60,
        );
        assert_eq!(
            d,
            JitDecision::Deny("no positive ttl within grant ceiling and credential lifetime")
        );
    }

    #[test]
    fn provider_kind_labels() {
        assert_eq!(read_grant().provider.kind(), "sts");
        assert_eq!(write_grant().provider.kind(), "secret");
    }

    #[test]
    fn rendered_session_policy_substitutes_resource() {
        // Single resource → substituted verbatim.
        let single = Provider::Sts {
            role_arn: "arn:r".into(),
            resource_arns: vec!["arn:aws:rds-db:us-east-1:111122223333:dbuser/db/reader".into()],
            session_policy_template: "{\"Resource\":\"{resource}\"}".into(),
        };
        let pol = single.rendered_session_policy().unwrap();
        assert!(pol.contains("dbuser/db/reader") && !pol.contains("{resource}"));

        // Multiple resources → a JSON array.
        let multi = Provider::Sts {
            role_arn: "arn:r".into(),
            resource_arns: vec!["arn:a".into(), "arn:b".into()],
            session_policy_template: "R={resource}".into(),
        };
        assert_eq!(
            multi.rendered_session_policy().unwrap(),
            "R=[\"arn:a\",\"arn:b\"]"
        );

        // No resources → the fail-closed sentinel (matches nothing), NEVER a `*` wildcard.
        let none = Provider::Sts {
            role_arn: "arn:r".into(),
            resource_arns: vec![],
            session_policy_template: "R={resource}".into(),
        };
        let rendered = none.rendered_session_policy().unwrap();
        assert_eq!(rendered, format!("R={NO_RESOURCE_SENTINEL}"));
        assert!(
            !rendered.contains('*'),
            "empty resources must not render a wildcard"
        );

        // Secret provider has no session policy.
        assert!(write_grant().provider.rendered_session_policy().is_none());
    }

    #[test]
    fn unix_to_iso8601_formats_utc() {
        assert_eq!(unix_to_iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
        // A leap day.
        assert_eq!(unix_to_iso8601(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn fence_appends_a_time_bounded_deny_and_keeps_the_allow() {
        // Operator policy: allow reading one resource.
        let rendered = r#"{"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","Action":"rds-db:connect","Resource":"arn:aws:rds-db:us-east-1:111:dbuser/db/reader"}
        ]}"#;
        let fenced = fence_session_policy(rendered, 1_700_000_060);
        let v: serde_json::Value = serde_json::from_str(&fenced).unwrap();
        let stmts = v["Statement"].as_array().unwrap();
        assert_eq!(stmts.len(), 2, "operator allow preserved + fence appended");
        // The original Allow survives (narrowing still applies before expiry).
        assert!(stmts.iter().any(|s| s["Effect"] == "Allow"
            && s["Resource"] == "arn:aws:rds-db:us-east-1:111:dbuser/db/reader"));
        // The fence is a Deny-* gated on the intended expiry.
        let deny = stmts.iter().find(|s| s["Effect"] == "Deny").unwrap();
        assert_eq!(deny["Action"], "*");
        assert_eq!(deny["Resource"], "*");
        assert_eq!(
            deny["Condition"]["DateGreaterThan"]["aws:CurrentTime"],
            "2023-11-14T22:14:20Z"
        );
    }

    #[test]
    fn fence_wraps_a_single_statement_object() {
        // A policy whose Statement is a lone object (not an array) is normalized, not dropped.
        let rendered = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:x"}}"#;
        let v: serde_json::Value =
            serde_json::from_str(&fence_session_policy(rendered, 100)).unwrap();
        let stmts = v["Statement"].as_array().unwrap();
        assert_eq!(stmts.len(), 2);
        assert!(stmts.iter().any(|s| s["Effect"] == "Allow"));
        assert!(stmts.iter().any(|s| s["Effect"] == "Deny"));
    }

    #[test]
    fn fence_of_empty_or_garbage_is_deny_only_fail_closed() {
        for src in ["", "   ", "not json", "[]", "42"] {
            let v: serde_json::Value =
                serde_json::from_str(&fence_session_policy(src, 100)).unwrap();
            let stmts = v["Statement"].as_array().unwrap();
            assert_eq!(stmts.len(), 1, "no operator Allow to preserve for {src:?}");
            assert_eq!(stmts[0]["Effect"], "Deny", "fail-closed for {src:?}");
            assert_eq!(v["Version"], "2012-10-17");
        }
    }

    #[test]
    fn validate_rejects_each_malformed_field() {
        let base = read_grant();
        // empty id
        let mut c = GrantCatalog::empty();
        let mut g = base.clone();
        g.id = "  ".into();
        c.upsert(g);
        assert!(c.validate().is_err());
        // empty audience
        let mut c = GrantCatalog::empty();
        let mut g = base.clone();
        g.audience = "".into();
        c.upsert(g);
        assert!(c.validate().is_err());
        // empty scope
        let mut c = GrantCatalog::empty();
        let mut g = base.clone();
        g.required_scope = "".into();
        c.upsert(g);
        assert!(c.validate().is_err());
        // zero ttl
        let mut c = GrantCatalog::empty();
        let mut g = base.clone();
        g.max_ttl_secs = 0;
        c.upsert(g);
        assert!(c.validate().is_err());
    }

    #[test]
    fn sts_grant_without_resource_arns_is_rejected() {
        // An STS grant that names no resource would render a wildcard session policy (un-narrowed
        // role) → refuse it at validation.
        let mut bad = read_grant();
        bad.id = "bad-sts".into();
        bad.provider = Provider::Sts {
            role_arn: "arn:aws:iam::111122223333:role/x".into(),
            resource_arns: vec![],
            session_policy_template: "{}".into(),
        };
        let mut c = GrantCatalog::empty();
        c.upsert(bad);
        assert!(c.validate().is_err());

        // A Secret grant needs no resource_arns — unaffected.
        let mut ok = GrantCatalog::empty();
        ok.upsert(write_grant());
        assert!(ok.validate().is_ok());

        // The same STS grant WITH a resource passes.
        let mut good = GrantCatalog::empty();
        good.upsert(read_grant());
        assert!(good.validate().is_ok());
    }

    #[test]
    fn catalog_round_trips_through_toml() {
        let mut cat = GrantCatalog::empty();
        cat.upsert(read_grant());
        cat.upsert(write_grant());
        cat.validate().unwrap();
        let toml_src = cat.to_toml().unwrap();
        let back = GrantCatalog::from_toml(&toml_src).unwrap();
        assert_eq!(back.all(), cat.all());
        assert_eq!(back.get("patient-db-read"), Some(&read_grant()));
    }

    #[test]
    fn empty_or_absent_catalog_denies_everything() {
        let cat = GrantCatalog::from_toml("").unwrap();
        assert!(cat.all().is_empty());
        assert!(cat.get("anything").is_none());
        cat.validate().unwrap();
    }

    #[test]
    fn upsert_is_idempotent_by_id_and_remove_works() {
        let mut cat = GrantCatalog::empty();
        assert!(!cat.upsert(read_grant()));
        assert!(cat.upsert(read_grant())); // replaced
        assert_eq!(cat.all().len(), 1);
        assert!(cat.remove("patient-db-read"));
        assert!(!cat.remove("patient-db-read"));
        assert!(cat.all().is_empty());
    }

    #[test]
    fn duplicate_ids_fail_validation() {
        // Build a catalog with a duplicate id directly via TOML (bypassing upsert's dedup).
        let src = r#"
[[grants]]
id = "dup"
audience = "a"
required_scope = "s"
max_ttl_secs = 60
[grants.provider]
kind = "secret"
secret_arn = "arn:x"

[[grants]]
id = "dup"
audience = "b"
required_scope = "s"
max_ttl_secs = 60
[grants.provider]
kind = "secret"
secret_arn = "arn:y"
"#;
        let cat = GrantCatalog::from_toml(src).unwrap();
        assert!(cat.validate().is_err());
    }
}
