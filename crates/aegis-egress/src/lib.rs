//! # aegis-egress — the network egress firewall (LLM02/LLM06)
//!
//! Architectural containment, the most reliable kind (architecture-considerations.md §2.4):
//! the agent runs in a private subnet with **no default route**, and every outbound request
//! goes through this default-deny allowlist. A fooled model cannot exfiltrate to an endpoint
//! the allowlist does not name, and cannot smuggle data in a query string that the allowlist
//! strips.
//!
//! The crate is split so the *decision* is pure and unit-testable ([`Allowlist::decide`]) and
//! the runtime proxy (`src/bin/proxy.rs`, and [`app`]) is a thin shell over it.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use url::Url;

/// A default-deny egress allowlist. Only destinations that match an entry are permitted, and
/// even then every query parameter not explicitly permitted is stripped before the request is
/// allowed out.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Allowlist {
    /// Exact hostnames that are permitted (e.g. `api.internal.example`).
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Domain suffixes that are permitted (e.g. `.s3.amazonaws.com`); matched against the host.
    #[serde(default)]
    pub suffixes: Vec<String>,
    /// Query-parameter names that may survive, keyed by host. A host absent from this map (or
    /// present with an empty list) has **all** query parameters stripped.
    #[serde(default)]
    pub permitted_params: HashMap<String, Vec<String>>,
    /// Schemes that are permitted. Defaults to `https` only.
    #[serde(default = "default_schemes")]
    pub schemes: Vec<String>,
    /// Honeypot canary tokens (§11, ASI08). Unique planted secrets; any outbound URL containing one
    /// is proof of exfiltration and is denied outright, before host/param logic. Injected at boot
    /// from the per-project `AEGIS_CANARY`, so it is empty in a plain `from_toml` load.
    /// Never serialized when empty, so a policy tool that writes the allowlist back never persists
    /// the runtime-injected canary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub canaries: Vec<String>,
}

fn default_schemes() -> Vec<String> {
    vec!["https".to_string()]
}

/// The result of an egress decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressDecision {
    /// Permitted. Carries the **sanitized** URL (disallowed query params stripped).
    Allow(String),
    /// Denied, with a fixed, non-sensitive reason safe to log.
    Deny(&'static str),
}

impl Allowlist {
    /// Load an allowlist from TOML text.
    pub fn from_toml(src: &str) -> Result<Self, aegis_core::AegisError> {
        toml::from_str(src)
            .map_err(|e| aegis_core::AegisError::Config(format!("bad egress allowlist: {e}")))
    }

    /// Decide whether an outbound URL is permitted, returning a sanitized URL on allow.
    ///
    /// Default-deny: unparsable URLs, disallowed schemes, and unlisted hosts are denied. On
    /// allow, every query parameter not in [`permitted_params`](Allowlist::permitted_params)
    /// for that host is removed — closing the query-string exfiltration channel.
    pub fn decide(&self, raw_url: &str) -> EgressDecision {
        // Canary tripwire (ASI08) first: a planted canary token in the outbound URL is proof of
        // exfiltration — deny regardless of host/scheme/param rules, even for an otherwise-valid URL.
        if self.canaries.iter().any(|c| raw_url.contains(c.as_str())) {
            return EgressDecision::Deny("canary token in outbound url");
        }

        let Ok(mut url) = Url::parse(raw_url) else {
            return EgressDecision::Deny("unparsable url");
        };

        let schemes = if self.schemes.is_empty() {
            default_schemes()
        } else {
            self.schemes.clone()
        };
        if !schemes.iter().any(|s| s == url.scheme()) {
            return EgressDecision::Deny("scheme not allowed");
        }

        let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
            return EgressDecision::Deny("no host");
        };

        if !self.host_allowed(&host) {
            return EgressDecision::Deny("host not on allowlist");
        }

        // Strip every query parameter not explicitly permitted for this host.
        let permitted = self
            .permitted_params
            .get(&host)
            .cloned()
            .unwrap_or_default();
        let kept: Vec<(String, String)> = url
            .query_pairs()
            .filter(|(k, _)| permitted.iter().any(|p| p == k.as_ref()))
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        if kept.is_empty() {
            url.set_query(None);
        } else {
            let mut serializer = url.query_pairs_mut();
            serializer.clear();
            for (k, v) in &kept {
                serializer.append_pair(k, v);
            }
            drop(serializer);
        }
        url.set_fragment(None);

        EgressDecision::Allow(url.to_string())
    }

    fn host_allowed(&self, host: &str) -> bool {
        if self.hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
            return true;
        }
        self.suffixes.iter().any(|suf| {
            let suf = suf.to_ascii_lowercase();
            // A suffix like ".example.com" matches host or any subdomain of it.
            host == suf.trim_start_matches('.') || host.ends_with(&suf)
        })
    }
}

/// Build the axum router that enforces `allowlist`. Kept in the library so it can be tested by
/// booting it on an ephemeral port; the binary is a thin `main` around it.
pub mod app {
    use std::sync::Arc;

    use axum::{
        extract::{Query, State},
        http::StatusCode,
        response::IntoResponse,
        routing::get,
        Json, Router,
    };
    use serde::Deserialize;

    use super::{Allowlist, EgressDecision};

    /// Query parameters for the `/decide` endpoint.
    #[derive(Debug, Deserialize)]
    pub struct DecideQuery {
        /// The outbound URL the agent wants to reach.
        pub url: String,
    }

    /// Construct the egress-proxy router. `POST`/`GET /decide?url=...` returns the decision;
    /// a real deployment would forward allowed requests, but the authorization gate is the
    /// same call — [`Allowlist::decide`] — so the decision endpoint is the testable core.
    pub fn router(allowlist: Allowlist) -> Router {
        let state = Arc::new(allowlist);
        Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route("/decide", get(decide))
            .with_state(state)
    }

    async fn decide(
        State(allowlist): State<Arc<Allowlist>>,
        Query(q): Query<DecideQuery>,
    ) -> impl IntoResponse {
        match allowlist.decide(&q.url) {
            EgressDecision::Allow(sanitized) => (
                StatusCode::OK,
                Json(serde_json::json!({ "decision": "allow", "url": sanitized })),
            ),
            EgressDecision::Deny(reason) => (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "decision": "deny", "reason": reason })),
            ),
        }
    }
}

/// Map into the plane-wide [`PolicyDecision`](aegis_core::PolicyDecision) vocabulary (Roadmap T0).
impl From<EgressDecision> for aegis_core::PolicyDecision {
    fn from(d: EgressDecision) -> Self {
        match d {
            EgressDecision::Allow(_) => aegis_core::PolicyDecision::Allow,
            EgressDecision::Deny(reason) => aegis_core::PolicyDecision::deny(reason),
        }
    }
}

#[cfg(test)]
mod policy_decision_adapter_tests {
    use super::*;
    #[test]
    fn maps_into_policy_decision() {
        use aegis_core::PolicyDecision;
        assert!(PolicyDecision::from(EgressDecision::Allow("https://x".into())).is_allow());
        assert_eq!(
            PolicyDecision::from(EgressDecision::Deny("blocked host")).reason(),
            Some("blocked host")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowlist() -> Allowlist {
        let toml = r#"
            hosts = ["api.internal.example"]
            suffixes = [".s3.amazonaws.com"]
            schemes = ["https"]

            [permitted_params]
            "api.internal.example" = ["page"]
        "#;
        Allowlist::from_toml(toml).unwrap()
    }

    #[test]
    fn allowlisted_host_is_permitted() {
        let a = allowlist();
        assert_eq!(
            a.decide("https://api.internal.example/v1/orders"),
            EgressDecision::Allow("https://api.internal.example/v1/orders".to_string())
        );
    }

    #[test]
    fn unlisted_host_is_denied() {
        let a = allowlist();
        assert_eq!(
            a.decide("https://evil.example/collect"),
            EgressDecision::Deny("host not on allowlist")
        );
    }

    #[test]
    fn non_https_scheme_denied() {
        let a = allowlist();
        assert_eq!(
            a.decide("http://api.internal.example/x"),
            EgressDecision::Deny("scheme not allowed")
        );
    }

    #[test]
    fn suffix_rule_matches_subdomain() {
        let a = allowlist();
        match a.decide("https://my-bucket.s3.amazonaws.com/key") {
            EgressDecision::Allow(_) => {}
            other => panic!("expected allow, got {other:?}"),
        }
    }

    #[test]
    fn data_bearing_params_are_stripped_but_permitted_ones_kept() {
        let a = allowlist();
        // `page` is permitted, `leak` is not -> only `page` survives.
        match a.decide("https://api.internal.example/v1?page=2&leak=SECRET") {
            EgressDecision::Allow(url) => {
                assert!(url.contains("page=2"));
                assert!(!url.contains("leak"));
                assert!(!url.contains("SECRET"));
            }
            other => panic!("expected allow, got {other:?}"),
        }
    }

    #[test]
    fn params_fully_stripped_for_host_without_permit_list() {
        let a = allowlist();
        // s3 host has no permitted params -> everything stripped.
        match a.decide("https://b.s3.amazonaws.com/k?sig=1&data=2") {
            EgressDecision::Allow(url) => {
                assert!(
                    !url.contains('?'),
                    "all query params must be stripped: {url}"
                );
            }
            other => panic!("expected allow, got {other:?}"),
        }
    }

    #[test]
    fn unparsable_url_denied() {
        let a = allowlist();
        assert_eq!(
            a.decide("not a url"),
            EgressDecision::Deny("unparsable url")
        );
    }

    #[test]
    fn empty_schemes_falls_back_to_https_only() {
        let a = Allowlist {
            hosts: vec!["h.example".to_string()],
            schemes: vec![], // exercises the default_schemes() fallback in decide()
            ..Default::default()
        };
        assert!(matches!(
            a.decide("https://h.example/x"),
            EgressDecision::Allow(_)
        ));
        assert_eq!(
            a.decide("http://h.example/x"),
            EgressDecision::Deny("scheme not allowed")
        );
    }

    #[test]
    fn url_with_allowed_scheme_but_no_host_is_denied() {
        let a = Allowlist {
            schemes: vec!["data".to_string()],
            ..Default::default()
        };
        assert_eq!(
            a.decide("data:text/plain,hello"),
            EgressDecision::Deny("no host")
        );
    }

    #[test]
    fn from_toml_defaults_schemes_to_https() {
        let a = Allowlist::from_toml("hosts = [\"h.example\"]").unwrap();
        assert_eq!(a.schemes, vec!["https".to_string()]);
    }

    #[test]
    fn from_toml_rejects_malformed_toml() {
        assert!(Allowlist::from_toml("= = not toml").is_err());
    }

    #[test]
    fn canary_token_in_outbound_url_is_denied() {
        // A planted canary in the URL is exfiltration — denied even for an allowlisted host.
        let mut a = allowlist();
        a.canaries = vec!["CANARY-7f3a9b21e4c05d68".to_string()];
        assert_eq!(
            a.decide("https://api.internal.example/v1?page=CANARY-7f3a9b21e4c05d68"),
            EgressDecision::Deny("canary token in outbound url")
        );
        // Without the canary the same allowlisted request is permitted.
        match a.decide("https://api.internal.example/v1?page=2") {
            EgressDecision::Allow(_) => {}
            other => panic!("expected allow, got {other:?}"),
        }
    }
}
