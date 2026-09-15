//! JIT credential **minting** — the real STS / Secrets Manager calls the gate makes ONLY after the
//! deterministic `aegis_jit::decide` has returned `Grant`. The provider-agnostic *decision* lives in
//! `aegis-jit`; this module knows *how* to mint against AWS.
//!
//! Compiled with the `jit` feature (pulls the AWS SDK). Without it, [`mint`] is a fail-closed stub
//! so the gate still compiles and refuses deterministically in a lean build.
//!
//! Secret material returned here is handed straight back to the caller over loopback and is **never
//! logged or written to the audit ledger** (the ledger records only grant id / audience / ttl /
//! expiry / decision).

use aegis_core::AegisError;
use aegis_jit::Provider;

/// Non-secret attribution carried into the mint (CloudTrail session tags / correlation).
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "jit"), allow(dead_code))] // fields read only by the real (feature) mint
pub struct MintContext {
    pub agent_id: String,
    pub thread_id: String,
    pub intent_hash: String,
}

/// The secret payload of a minted credential. Serialized straight to the caller; never logged.
#[derive(Debug, serde::Serialize)]
#[serde(untagged)]
#[cfg_attr(not(feature = "jit"), allow(dead_code))] // constructed only by the real (feature) mint
pub enum MintPayload {
    /// A temporary STS session (the caller uses these as AWS credentials until `expires_at_ms`).
    Sts {
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
    },
    /// A just-in-time secret value (optionally a single plucked JSON key).
    Secret { secret: String },
}

/// A minted, short-lived credential.
#[derive(Debug, serde::Serialize)]
#[cfg_attr(not(feature = "jit"), allow(dead_code))] // constructed only by the real (feature) mint
pub struct MintedCredential {
    /// `sts` | `secret` — safe to log.
    pub kind: &'static str,
    /// The secret material (never logged/persisted).
    #[serde(flatten)]
    pub payload: MintPayload,
    /// Expiry (Unix ms): now + the decision's clamped TTL. For STS this is ENFORCED by the inline
    /// session policy's time fence (not merely advisory); for a static secret it is advisory only.
    pub expires_at_ms: u64,
}

#[cfg_attr(not(feature = "jit"), allow(dead_code))] // used only by the real (feature) mint
fn expiry_ms(ttl_secs: u64) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    now.saturating_add(ttl_secs.saturating_mul(1000))
}

/// Mint a real, short-lived cloud credential for a granted provider. `ttl_secs` is the clamped TTL
/// the decision already bounded (≤ grant ceiling, ≤ the presenting credential's remaining life).
#[cfg(feature = "jit")]
pub async fn mint(
    provider: &Provider,
    ttl_secs: u64,
    ctx: &MintContext,
) -> Result<MintedCredential, AegisError> {
    let config = aws_config::load_from_env().await;
    match provider {
        Provider::Sts { role_arn, .. } => {
            let client = aws_sdk_sts::Client::new(&config);
            // Session name: non-secret, aids CloudTrail correlation (≤ 64 chars, restricted charset).
            let session_name = sanitize_session_name(&format!("aegis-{}", ctx.thread_id));
            let mut req = client
                .assume_role()
                .role_arn(role_arn)
                // STS enforces a 900s floor on the token; the session policy below fences the REAL
                // (short) expiry, so this is only the outer token lifetime.
                .duration_seconds(clamp_sts_duration(ttl_secs))
                .role_session_name(session_name)
                // Session tags land in CloudTrail for per-agent attribution.
                .tags(tag("aegis:agent", &ctx.agent_id))
                .tags(tag("aegis:thread", &ctx.thread_id))
                .tags(tag("aegis:intent", &ctx.intent_hash));
            // The inline session policy narrows the (already narrow) role to exactly this resource
            // AND is time-fenced to the intended TTL: an explicit `Deny *` after `now + ttl` makes
            // AWS refuse the credential once the short TTL elapses, defeating the 900s STS floor.
            // An empty operator template means "narrow via the role only", so start from an allow-all
            // the role intersects down; the fence still bounds it in time.
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let base = provider.rendered_session_policy().unwrap_or_default();
            let base = if base.trim().is_empty() {
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#
                    .to_string()
            } else {
                base
            };
            let fenced = aegis_jit::fence_session_policy(&base, now_secs.saturating_add(ttl_secs));
            req = req.policy(fenced);
            // ExternalId ties the assume-call to this project (the per-grant role trust policy
            // requires it — jit.tf). Set from AEGIS_JIT_EXTERNAL_ID when present.
            if let Ok(external_id) = std::env::var("AEGIS_JIT_EXTERNAL_ID") {
                if !external_id.is_empty() {
                    req = req.external_id(external_id);
                }
            }
            let resp = req
                .send()
                .await
                .map_err(|e| AegisError::Config(format!("sts assume_role failed: {e}")))?;
            let creds = resp
                .credentials()
                .ok_or_else(|| AegisError::Config("sts returned no credentials".into()))?;
            Ok(MintedCredential {
                kind: "sts",
                payload: MintPayload::Sts {
                    access_key_id: creds.access_key_id().to_string(),
                    secret_access_key: creds.secret_access_key().to_string(),
                    session_token: creds.session_token().to_string(),
                },
                expires_at_ms: expiry_ms(ttl_secs),
            })
        }
        Provider::Secret {
            secret_arn,
            json_key,
        } => {
            let client = aws_sdk_secretsmanager::Client::new(&config);
            let resp = client
                .get_secret_value()
                .secret_id(secret_arn)
                .send()
                .await
                .map_err(|e| AegisError::Config(format!("secretsmanager get failed: {e}")))?;
            let raw = resp
                .secret_string()
                .ok_or_else(|| AegisError::Config("secret has no string value".into()))?
                .to_string();
            let secret = match json_key {
                Some(key) => pluck_json_key(&raw, key)?,
                None => raw,
            };
            Ok(MintedCredential {
                kind: "secret",
                payload: MintPayload::Secret { secret },
                expires_at_ms: expiry_ms(ttl_secs),
            })
        }
    }
}

/// Fail-closed stub for lean builds (feature `jit` off): the gate compiles and refuses minting
/// deterministically, with no AWS dependency.
#[cfg(not(feature = "jit"))]
pub async fn mint(
    _provider: &Provider,
    _ttl_secs: u64,
    _ctx: &MintContext,
) -> Result<MintedCredential, AegisError> {
    Err(AegisError::Config(
        "jit provider not built — rebuild the extension with --features jit".into(),
    ))
}

#[cfg(feature = "jit")]
fn tag(key: &str, value: &str) -> aws_sdk_sts::types::Tag {
    aws_sdk_sts::types::Tag::builder()
        .key(key)
        .value(value)
        .build()
        // key/value are set above, so this never errors; fall back defensively.
        .unwrap_or_else(|_| {
            aws_sdk_sts::types::Tag::builder()
                .key("aegis")
                .value("x")
                .build()
                .expect("static tag builds")
        })
}

/// STS `DurationSeconds` must be within [900, 43200]. A JIT credential is intentionally short, but
/// STS refuses anything under 900s, so clamp the TOKEN lifetime up to the floor. The decision's own,
/// tighter TTL is enforced separately by the inline session policy's `DateGreaterThan aws:CurrentTime`
/// fence (see `aegis_jit::fence_session_policy`), so a 60s grant is unusable after 60s even though the
/// token string remains parseable for 900s.
#[cfg(feature = "jit")]
fn clamp_sts_duration(ttl_secs: u64) -> i32 {
    ttl_secs.clamp(900, 43_200) as i32
}

/// STS role-session-name charset is `[\w+=,.@-]{2,64}`; replace anything else with `-`.
#[cfg(feature = "jit")]
fn sanitize_session_name(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "+=,.@-_".contains(c) {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect();
    if cleaned.len() < 2 {
        "aegis-session".to_string()
    } else {
        cleaned
    }
}

#[cfg(feature = "jit")]
fn pluck_json_key(raw: &str, key: &str) -> Result<String, AegisError> {
    let v: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| AegisError::Config(format!("secret is not JSON but json_key was set: {e}")))?;
    match v.get(key) {
        Some(serde_json::Value::String(s)) => Ok(s.clone()),
        Some(other) => Ok(other.to_string()),
        None => Err(AegisError::Config(format!("secret has no key '{key}'"))),
    }
}

#[cfg(all(test, feature = "jit"))]
mod tests {
    use super::*;

    #[test]
    fn session_name_is_sanitized_and_bounded() {
        let n = sanitize_session_name("aegis-thread/with spaces:and*stuff");
        assert!(n
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+=,.@-_".contains(c)));
        assert!(n.len() <= 64 && n.len() >= 2);
    }

    #[test]
    fn sts_duration_is_clamped_to_the_sts_floor() {
        assert_eq!(clamp_sts_duration(60), 900);
        assert_eq!(clamp_sts_duration(300), 900);
        assert_eq!(clamp_sts_duration(3600), 3600);
        assert_eq!(clamp_sts_duration(1_000_000), 43_200);
    }

    #[test]
    fn pluck_json_key_extracts_string_value() {
        assert_eq!(
            pluck_json_key(r#"{"api_key":"abc"}"#, "api_key").unwrap(),
            "abc"
        );
        assert!(pluck_json_key(r#"{"x":1}"#, "missing").is_err());
    }
}
