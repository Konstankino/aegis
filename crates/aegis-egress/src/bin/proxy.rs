//! The `aegis-egress` proxy binary: a thin runtime shell around [`aegis_egress::Allowlist`].
//!
//! The agent lives in a private subnet with no default route; all outbound traffic is directed
//! here, and only allowlisted, query-sanitized destinations are permitted. The authorization
//! decision is [`aegis_egress::Allowlist::decide`] — the same code the unit tests exercise.
//!
//! Usage:
//! ```text
//! AEGIS_EGRESS_ALLOWLIST=policies/egress-allowlist.toml \
//! AEGIS_EGRESS_ADDR=127.0.0.1:8080 \
//!   cargo run -p aegis-egress --bin aegis-egress
//! ```
//! Then: `curl 'http://127.0.0.1:8080/decide?url=https://api.internal.example/v1?leak=secret'`

use std::net::SocketAddr;

use aegis_egress::{app, Allowlist};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_egress=info".into()),
        )
        .init();

    let path = std::env::var("AEGIS_EGRESS_ALLOWLIST")
        .unwrap_or_else(|_| "policies/egress-allowlist.toml".to_string());
    let src = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read allowlist '{path}': {e}"))?;
    let allowlist = Allowlist::from_toml(&src)?;
    tracing::info!(
        hosts = allowlist.hosts.len(),
        suffixes = allowlist.suffixes.len(),
        "loaded egress allowlist from {path}"
    );

    let addr: SocketAddr = std::env::var("AEGIS_EGRESS_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("aegis-egress proxy listening on http://{addr}");
    axum::serve(listener, app::router(allowlist)).await?;
    Ok(())
}
