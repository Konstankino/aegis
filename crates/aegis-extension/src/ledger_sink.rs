//! Persist audit-ledger entries to the immutable (S3 Object Lock) sink. Folded in from Phase 1.
//!
//! The tamper-evident hash chain is produced in-process by `aegis-ledger`; this best-effort sink
//! writes each new entry to the Object Lock bucket so the audit trail is durable and write-once.
//! Behind the `s3` feature (reusing the AWS SDK already pulled for policy fetch); a no-op
//! otherwise, so the always-compiled call site stays feature-agnostic.

/// Fire-and-forget: persist one ledger entry (`body`, already JSON) at `key` in `bucket`.
/// No-op when `bucket` is `None` or the `s3` feature is off.
pub fn persist(bucket: Option<String>, key: String, body: String) {
    #[cfg(feature = "s3")]
    if let Some(bucket) = bucket {
        tokio::spawn(async move {
            if let Err(e) = put_object(&bucket, &key, body).await {
                tracing::warn!("ledger persist to s3://{bucket}/{key} failed: {e}");
            }
        });
        return;
    }
    // Without the s3 feature (or with no bucket configured), persistence is a no-op.
    let _ = (bucket, key, body);
}

#[cfg(feature = "s3")]
async fn put_object(bucket: &str, key: &str, body: String) -> Result<(), String> {
    use tokio::sync::OnceCell;
    static CLIENT: OnceCell<aws_sdk_s3::Client> = OnceCell::const_new();
    let client = CLIENT
        .get_or_init(|| async {
            let config = aws_config::load_from_env().await;
            aws_sdk_s3::Client::new(&config)
        })
        .await;
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(body.into_bytes().into())
        .content_type("application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn persist_is_a_noop_without_a_bucket() {
        // Must never panic; with no bucket (or no s3 feature) it simply does nothing.
        super::persist(None, "k".to_string(), "{}".to_string());
    }
}
