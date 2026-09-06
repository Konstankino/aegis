//! Load the policy artifacts from S3 at cold start (architecture-considerations.md §2.4:
//! "Policies (Cedar) live versioned in S3"). Compiled only with the `s3` feature.
//!
//! The three artifacts are fetched from `s3://<bucket>/<prefix>/{tools.json, broker.cedar,
//! egress-allowlist.toml}` using the function's execution-role credentials (the default AWS
//! provider chain). In a no-default-route VPC this reaches S3 through the S3 gateway endpoint
//! that the Terraform provisions — no internet required.

use aegis_core::AegisError;

/// The three policy artifacts, as strings, in the order the broker/egress expect them.
pub struct PolicyBundle {
    pub tools_json: String,
    pub broker_cedar: String,
    pub egress_allowlist: String,
}

/// Fetch the policy bundle from `s3://bucket/prefix/...`. Any missing object or transport error
/// is returned as `AegisError::Config` so the caller fails closed (the extension refuses to
/// come up with a broken guardrail plane).
pub async fn load(bucket: &str, prefix: &str) -> Result<PolicyBundle, AegisError> {
    let config = aws_config::load_from_env().await;
    let client = aws_sdk_s3::Client::new(&config);
    let prefix = prefix.trim_matches('/');

    let get = |name: &'static str| {
        let key = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        let client = client.clone();
        let bucket = bucket.to_string();
        async move {
            let resp = client
                .get_object()
                .bucket(&bucket)
                .key(&key)
                .send()
                .await
                .map_err(|e| {
                    AegisError::Config(format!("s3 get s3://{bucket}/{key} failed: {e}"))
                })?;
            let bytes = resp.body.collect().await.map_err(|e| {
                AegisError::Config(format!("s3 read s3://{bucket}/{key} failed: {e}"))
            })?;
            String::from_utf8(bytes.to_vec())
                .map_err(|e| AegisError::Config(format!("s3 object {key} is not UTF-8: {e}")))
        }
    };

    // Fetch the three artifacts concurrently.
    let (tools_json, broker_cedar, egress_allowlist) = tokio::try_join!(
        get("tools.json"),
        get("broker.cedar"),
        get("egress-allowlist.toml"),
    )?;

    Ok(PolicyBundle {
        tools_json,
        broker_cedar,
        egress_allowlist,
    })
}

/// Best-effort fetch of a single **optional** artifact (e.g. `honeypots.json`) from
/// `s3://bucket/prefix/name`. Unlike [`load`], a missing object or any transport error yields
/// `None` (the caller falls back to the layer-baked default) rather than failing the cold start:
/// honeypots are a detection aid layered on top of the hard containment, not a boundary whose
/// absence should refuse startup.
pub async fn load_text_opt(bucket: &str, prefix: &str, name: &str) -> Option<String> {
    let config = aws_config::load_from_env().await;
    let client = aws_sdk_s3::Client::new(&config);
    let prefix = prefix.trim_matches('/');
    let key = if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    };
    match client.get_object().bucket(bucket).key(&key).send().await {
        Ok(resp) => match resp.body.collect().await {
            Ok(bytes) => match String::from_utf8(bytes.to_vec()) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!("s3 object {key} not UTF-8 ({e}); using baked default");
                    None
                }
            },
            Err(e) => {
                tracing::warn!("s3 read {key} failed ({e}); using baked default");
                None
            }
        },
        Err(e) => {
            tracing::warn!("s3 get {key} failed ({e}); using baked default");
            None
        }
    }
}
