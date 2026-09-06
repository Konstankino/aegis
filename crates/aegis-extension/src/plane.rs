//! The resident inline plane and how it is loaded. Kept separate from `main.rs` so the loading
//! logic is unit-testable without the Lambda/async runtime glue.

use std::path::{Path, PathBuf};

use aegis_broker::Broker;
use aegis_egress::Allowlist;

/// Everything the extension loads once and reuses for the life of the execution environment.
pub struct InlinePlane {
    pub broker: Broker,
    pub allowlist: Allowlist,
}

impl InlinePlane {
    /// Build the plane from the three raw artifact strings, whatever their source.
    pub fn from_sources(
        tools_json: &str,
        broker_cedar: &str,
        egress_allowlist: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let broker = Broker::from_sources(tools_json, broker_cedar)?;
        let allowlist = Allowlist::from_toml(egress_allowlist)?;
        Ok(Self { broker, allowlist })
    }

    /// Load all Phase-0 artifacts from a local policy directory (dev, or the layer's
    /// `/opt/policies` fallback).
    pub fn load(policy_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let tools = std::fs::read_to_string(policy_dir.join("tools.json"))
            .map_err(|e| format!("cannot read tools.json: {e}"))?;
        let cedar = std::fs::read_to_string(policy_dir.join("broker.cedar"))
            .map_err(|e| format!("cannot read broker.cedar: {e}"))?;
        let allow = std::fs::read_to_string(policy_dir.join("egress-allowlist.toml"))
            .map_err(|e| format!("cannot read egress-allowlist.toml: {e}"))?;
        Self::from_sources(&tools, &cedar, &allow)
    }

    /// Load the plane from the configured source: S3 when `AEGIS_POLICY_S3_BUCKET` is set (the
    /// §2.4 production shape), otherwise the local policy directory. Fails closed on any error.
    pub async fn load_configured() -> Result<Self, Box<dyn std::error::Error>> {
        if let Ok(bucket) = std::env::var("AEGIS_POLICY_S3_BUCKET") {
            let prefix =
                std::env::var("AEGIS_POLICY_S3_PREFIX").unwrap_or_else(|_| "policies".to_string());
            #[cfg(feature = "s3")]
            {
                tracing::info!("loading policies from s3://{bucket}/{prefix}");
                let b = crate::s3::load(&bucket, &prefix).await?;
                return Self::from_sources(&b.tools_json, &b.broker_cedar, &b.egress_allowlist);
            }
            #[cfg(not(feature = "s3"))]
            {
                let _ = (bucket, prefix);
                return Err(
                    "AEGIS_POLICY_S3_BUCKET is set but the extension was built without the \
                            `s3` feature"
                        .into(),
                );
            }
        }
        Self::load(&policy_dir())
    }

    /// A one-line readiness summary of what was loaded.
    pub fn summary(&self) -> String {
        format!(
            "tools={} policies={} egress_hosts={} egress_suffixes={}",
            self.broker.registry().len(),
            self.broker.engine().len(),
            self.allowlist.hosts.len(),
            self.allowlist.suffixes.len(),
        )
    }
}

/// The local policy directory (`AEGIS_POLICY_DIR`, default `policies`).
pub fn policy_dir() -> PathBuf {
    std::env::var("AEGIS_POLICY_DIR")
        .unwrap_or_else(|_| "policies".to_string())
        .into()
}

/// Load Phase-1 meter limits from `<dir>/meter.toml`, falling back to defaults when the file is
/// absent or unparseable (the meter is always active; the file only tunes the ceilings).
pub fn load_meter_limits(policy_dir: &Path) -> aegis_meter::Limits {
    match std::fs::read_to_string(policy_dir.join("meter.toml")) {
        Ok(src) => toml::from_str(&src).unwrap_or_default(),
        Err(_) => aegis_meter::Limits::default(),
    }
}

/// Load the Phase-2 supply-chain pinset from `<dir>/pins.json`, or an empty pinset when absent
/// (an empty pinset fails closed: nothing verifies until pins are provided).
pub fn load_pinset(policy_dir: &Path) -> aegis_supply::Pinset {
    match std::fs::read_to_string(policy_dir.join("pins.json")) {
        Ok(src) => aegis_supply::Pinset::from_json(&src).unwrap_or_default(),
        Err(_) => aegis_supply::Pinset::default(),
    }
}

/// Load the honeypot decoys/canaries from `<dir>/honeypots.json`, or an empty set when absent or
/// unparseable (§11, ASI05/ASI08). An empty set is inert — nothing to trip — so a deployment has
/// zero false positives until decoys/canaries are deliberately configured.
pub fn load_honeypots(policy_dir: &Path) -> aegis_honeypot::Honeypots {
    match std::fs::read_to_string(policy_dir.join("honeypots.json")) {
        Ok(src) => aegis_honeypot::Honeypots::from_json(&src).unwrap_or_default(),
        Err(_) => aegis_honeypot::Honeypots::default(),
    }
}

/// Load the honeypot set **per project**: from `s3://$AEGIS_POLICY_S3_BUCKET/$prefix/honeypots.json`
/// when configured (so each project ships its own decoys/canaries), otherwise from the baked/local
/// policy dir. A missing or unreadable S3 object falls back to [`load_honeypots`] — the shared
/// layer-baked `honeypots.json`. The per-project runtime canary (`AEGIS_CANARY`) is merged in by
/// the caller on top of whatever this returns.
pub async fn load_honeypots_configured() -> aegis_honeypot::Honeypots {
    #[cfg(feature = "s3")]
    {
        if let Ok(bucket) = std::env::var("AEGIS_POLICY_S3_BUCKET") {
            if !bucket.is_empty() {
                let prefix = std::env::var("AEGIS_POLICY_S3_PREFIX")
                    .unwrap_or_else(|_| "policies".to_string());
                if let Some(src) = crate::s3::load_text_opt(&bucket, &prefix, "honeypots.json").await
                {
                    return aegis_honeypot::Honeypots::from_json(&src).unwrap_or_default();
                }
            }
        }
    }
    load_honeypots(&policy_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid minimal artifacts.
    const TOOLS: &str = "[]";
    const CEDAR: &str = r#"permit ( principal, action == Action::"invoke", resource );"#;
    const ALLOW: &str = "hosts = [\"api.internal.example\"]\nsuffixes = [\".s3.amazonaws.com\"]\n";

    fn unique_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aegis-plane-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_artifacts(dir: &Path) {
        std::fs::write(dir.join("tools.json"), TOOLS).unwrap();
        std::fs::write(dir.join("broker.cedar"), CEDAR).unwrap();
        std::fs::write(dir.join("egress-allowlist.toml"), ALLOW).unwrap();
    }

    #[test]
    fn from_sources_ok_and_summary() {
        let plane = InlinePlane::from_sources(TOOLS, CEDAR, ALLOW).unwrap();
        let s = plane.summary();
        assert!(s.contains("tools=0"));
        assert!(s.contains("egress_hosts=1"));
        assert!(s.contains("egress_suffixes=1"));
    }

    #[test]
    fn from_sources_rejects_bad_tools_and_bad_cedar() {
        assert!(InlinePlane::from_sources("not json", CEDAR, ALLOW).is_err());
        assert!(InlinePlane::from_sources(TOOLS, "definitely not cedar!!!", ALLOW).is_err());
        assert!(InlinePlane::from_sources(TOOLS, CEDAR, "= = not toml").is_err());
    }

    #[test]
    fn load_reads_a_directory_and_reports_missing_files() {
        let dir = unique_dir("load");
        assert!(InlinePlane::load(&dir).is_err(), "empty dir must fail");
        write_artifacts(&dir);
        assert!(InlinePlane::load(&dir).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_meter_limits_reads_file_or_falls_back_to_default() {
        let dir = unique_dir("meter");
        // Absent file -> defaults.
        assert_eq!(load_meter_limits(&dir), aegis_meter::Limits::default());
        // Present file -> parsed override.
        std::fs::write(dir.join("meter.toml"), "max_steps = 7\ntokens_per_minute = 123\nmax_tokens_per_request = 10\ntokens_per_day = 10\nmax_cost_per_request_usd = 1.0\nhard_cost_cap_usd = 2.0\nmax_recursion_depth = 2\nmax_wall_clock_ms = 1000\nloop_repeat_threshold = 2\n").unwrap();
        let limits = load_meter_limits(&dir);
        assert_eq!(limits.max_steps, 7);
        assert_eq!(limits.tokens_per_minute, 123);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_pinset_reads_file_or_falls_back_to_empty() {
        let dir = unique_dir("pins");
        // Absent -> empty pinset (fails closed).
        assert!(load_pinset(&dir).pins.is_empty());
        // Present -> parsed.
        std::fs::write(dir.join("pins.json"), r#"{"model":["sha256:abc"]}"#).unwrap();
        let pins = load_pinset(&dir);
        assert!(pins.pins.contains_key("model"));
        std::fs::remove_dir_all(&dir).ok();
    }

    // All env-touching assertions live in ONE test so there is no cross-test race on the
    // process-global environment (and no lock held across an `.await`). This is the only test
    // in the crate that mutates AEGIS_POLICY_* env vars.
    #[tokio::test]
    async fn policy_dir_env_and_configured_loading() {
        std::env::remove_var("AEGIS_POLICY_DIR");
        std::env::remove_var("AEGIS_POLICY_S3_BUCKET");

        // policy_dir(): default, then env override.
        assert_eq!(policy_dir(), PathBuf::from("policies"));
        std::env::set_var("AEGIS_POLICY_DIR", "/custom/policies");
        assert_eq!(policy_dir(), PathBuf::from("/custom/policies"));

        // load_configured(): no bucket -> reads the local dir.
        let dir = unique_dir("cfg");
        write_artifacts(&dir);
        std::env::set_var("AEGIS_POLICY_DIR", &dir);
        assert!(InlinePlane::load_configured().await.is_ok());

        // Without the `s3` feature, asking for an S3 bucket must fail closed, never be ignored.
        #[cfg(not(feature = "s3"))]
        {
            std::env::set_var("AEGIS_POLICY_S3_BUCKET", "some-bucket");
            let result = InlinePlane::load_configured().await;
            std::env::remove_var("AEGIS_POLICY_S3_BUCKET");
            let msg = result.err().expect("must fail closed").to_string();
            assert!(msg.contains("s3"));
        }

        std::env::remove_var("AEGIS_POLICY_DIR");
        std::fs::remove_dir_all(&dir).ok();
    }
}
