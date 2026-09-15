//! # aegis-extension — the inline-plane host
//!
//! A single static binary that runs as a **Lambda external extension** co-located with each
//! agent Lambda (architecture-considerations.md §2.4): in-process, no network hop. It boots
//! once per execution environment, loads the Phase-0 consequence-side artifacts (the tool
//! registry + Cedar policies for [`aegis_broker`], and the egress allowlist for
//! [`aegis_egress`]), and keeps them resident for the life of the sandbox.
//!
//! It also serves the **inline-plane gate** — a loopback HTTP server (`/decide`, `/mediate`,
//! `/encode`, `/healthz`) so a non-Rust handler can use the same deterministic gates.
//!
//! It runs in three modes:
//! * **Lambda mode** (`AWS_LAMBDA_RUNTIME_API` set): serves the gate in the background and
//!   registers as an extension, processing the invoke/shutdown lifecycle.
//! * **Dev gate** (`AEGIS_GATE_ADDR` set, no Lambda runtime): serves the gate in the
//!   foreground for local curl/tests — no AWS environment needed.
//! * **Dev self-check** (neither set): loads and validates the artifacts, prints a readiness
//!   summary, and exits.

mod gate;
mod jit;
mod ledger_sink;
#[cfg(feature = "otel")]
mod otel;
mod plane;
#[cfg(feature = "s3")]
mod s3;
mod session_store;
mod telemetry;
mod trace_sink;

use std::sync::Arc;

use lambda_extension::{service_fn, Error, Extension, LambdaEvent, NextEvent};

use plane::InlinePlane;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Telemetry init. With the `otel` feature, this installs the OTLP exporters (when
    // OTEL_EXPORTER_OTLP_ENDPOINT is set) plus a stdout layer, and returns a flush guard kept
    // alive for the whole run. Without it, a plain structured-log subscriber.
    #[cfg(feature = "otel")]
    let _telemetry = otel::init();
    #[cfg(not(feature = "otel"))]
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_extension=info".into()),
        )
        .without_time()
        .init();

    // Fail fast if the consequence-side artifacts cannot be loaded — a Lambda with a broken
    // guardrail plane must not come up serving traffic. Source is S3 or a local dir (see
    // load_configured).
    let plane = InlinePlane::load_configured()
        .await
        .map_err(|e| lambda_extension::Error::from(e.to_string()))?;
    tracing::info!("aegis inline plane loaded: {}", plane.summary());

    // The inline-plane gate: a loopback HTTP server the agent handler (Rust or not) reaches
    // co-located, with no default route out (§2.4):
    //   /decide   — egress allowlist check (aegis-egress)
    //   /mediate  — broker tool-call decision, taint accumulated server-side (aegis-broker)
    //   /encode   — context-aware sink encoding (aegis-output)
    //   /healthz  — liveness
    let summary = plane.summary();
    let InlinePlane {
        broker,
        mut allowlist,
    } = plane;

    // Per-project honeypot canary (ASI08): a unique secret planted in the runner's ephemeral working
    // dir (AEGIS_CANARY). Injected here into BOTH the egress allowlist (denies it in an outbound URL)
    // and the gate honeypots below (detects it in tool-call args), so exfiltrating the canary trips a
    // tripwire at either chokepoint. Empty in dev/local runs where AEGIS_CANARY is unset.
    let canary = std::env::var("AEGIS_CANARY").ok().filter(|s| !s.is_empty());
    if let Some(c) = &canary {
        allowlist.canaries.push(c.clone());
    }

    let gate_addr =
        std::env::var("AEGIS_GATE_ADDR").or_else(|_| std::env::var("AEGIS_EGRESS_ADDR"));
    let in_lambda = std::env::var("AWS_LAMBDA_RUNTIME_API").is_ok();

    // Dev mode with no explicit gate address: self-check and exit, so the wiring is verifiable
    // locally without registering against the Extensions API and without holding a port.
    if !in_lambda && gate_addr.is_err() {
        tracing::info!(
            "dev mode (no AWS_LAMBDA_RUNTIME_API, no AEGIS_GATE_ADDR): inline plane ready, exiting"
        );
        return Ok(());
    }

    let addr: std::net::SocketAddr = gate_addr
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .map_err(|e| Error::from(format!("bad AEGIS_GATE_ADDR: {e}")))?;
    // Gate configuration: Phase-1 meter limits (policies/meter.toml), Phase-2 supply pinset
    // (policies/pins.json), the immutable ledger sink bucket (AEGIS_LEDGER_BUCKET), and the
    // honeypot decoys/canaries (policies/honeypots.json, ASI05/ASI08).
    // Durable per-thread gate state (Rule-of-Two taint + meter snapshot) + per-agent quarantine,
    // so they survive a cold restart across a human-approval pause. Backed by the existing
    // checkpoint table (AEGIS_CHECKPOINT_TABLE) when built with `dynamodb`; a no-op Null store
    // otherwise, which preserves the prior in-memory-only behaviour.
    let session_store = {
        #[cfg(feature = "dynamodb")]
        {
            match std::env::var("AEGIS_CHECKPOINT_TABLE")
                .ok()
                .filter(|s| !s.is_empty())
            {
                Some(table) => {
                    tracing::info!("durable session store: dynamodb table {table}");
                    session_store::SessionStore::dynamo(table)
                }
                None => {
                    tracing::warn!(
                        "durable session store DISABLED (AEGIS_CHECKPOINT_TABLE unset): \
                         Rule-of-Two taint will not survive a cold-start HITL resume"
                    );
                    session_store::SessionStore::null()
                }
            }
        }
        #[cfg(not(feature = "dynamodb"))]
        {
            session_store::SessionStore::null()
        }
    };

    let gate_config = gate::GateConfig {
        limits: plane::load_meter_limits(&plane::policy_dir()),
        // Per-tenant meter budgets (Roadmap T1): none configured yet, so every tenant uses the
        // default limits above. A future loader can populate this from per-tenant config.
        tenant_limits: std::collections::HashMap::new(),
        pinset: plane::load_pinset(&plane::policy_dir()),
        sandbox: plane::load_sandbox_policy(&plane::policy_dir()),
        grants: plane::load_grant_catalog(&plane::policy_dir()),
        ledger_bucket: std::env::var("AEGIS_LEDGER_BUCKET")
            .ok()
            .filter(|s| !s.is_empty()),
        store: Some(session_store),
        // Off unless explicitly enabled: by default the gate ignores a caller's provenance claim and
        // treats every tool-call argument as untrusted (a compromised agent must not downgrade taint).
        trust_arg_provenance: matches!(
            std::env::var("AEGIS_TRUST_ARG_PROVENANCE").as_deref(),
            Ok("1") | Ok("true")
        ),
        honeypots: {
            // Per-project decoys/static canaries from S3 (honeypots.json), with the layer-baked
            // file as fallback, plus the per-project RUNTIME canary (AEGIS_CANARY) merged on top.
            let mut h = plane::load_honeypots_configured().await;
            if let Some(c) = &canary {
                h.canaries.push(c.clone());
            }
            h
        },
    };

    // Surface the audit-trail durability posture at boot: without an Object-Lock bucket the ledger is
    // in-memory only (lost on cold start), and even tripwire evidence cannot be durably anchored.
    if gate_config.ledger_bucket.is_none() {
        tracing::warn!(
            "durable audit ledger DISABLED (AEGIS_LEDGER_BUCKET unset): the tamper-evident chain is \
             in-memory only and is lost on a cold start; configure an S3 Object Lock bucket in prod"
        );
    }

    // Every gate request gets an HTTP span (method/path/status/latency); combined with the OTLP
    // layer these export as traces, and are plain logs otherwise.
    let app = aegis_egress::app::router(allowlist)
        .merge(gate::router(Arc::new(broker), gate_config))
        .layer(tower_http::trace::TraceLayer::new_for_http());

    // Dev mode with an explicit AEGIS_GATE_ADDR: serve the gate in the foreground so it can be
    // exercised locally (curl, integration tests) without a Lambda runtime.
    if !in_lambda {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| Error::from(format!("cannot bind gate on {addr}: {e}")))?;
        tracing::info!("dev gate serving on http://{addr} (/decide /mediate /encode /healthz)");
        axum::serve(listener, app)
            .await
            .map_err(|e| Error::from(e.to_string()))?;
        return Ok(());
    }

    // Lambda mode: bind the gate BEFORE registering the extension, so the socket is already
    // accepting connections by the time Lambda unblocks the function on the first invoke (no
    // cold-start race). Then serve in the background and process the extension lifecycle.
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| Error::from(format!("cannot bind inline-plane gate on {addr}: {e}")))?;
    tracing::info!(
        "inline-plane gate listening on http://{addr} (/decide /mediate /encode /healthz)"
    );
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("inline-plane gate stopped: {e}");
        }
    });

    Extension::new()
        .with_events_processor(service_fn(move |event: LambdaEvent| {
            let summary = summary.clone();
            async move {
                match event.next {
                    NextEvent::Invoke(_) => {
                        tracing::debug!("invoke: inline plane resident ({summary})");
                    }
                    NextEvent::Shutdown(_) => {
                        tracing::info!("shutdown: tearing down inline plane");
                    }
                }
                Ok::<(), Error>(())
            }
        }))
        .run()
        .await
}
