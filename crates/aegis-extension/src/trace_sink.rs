//! The gate's [`TraceCollector`] (Roadmap T0 wiring). Each typed [`Span`] the gate emits is
//! forwarded to `tracing` on the `aegis.trace` target, so it flows into the extension's existing
//! structured-log / OTLP pipeline with no new transport. OTel- and Postgres-native collectors are a
//! later track; this is the minimal, non-leaking sink that proves the spine end to end.
//!
//! Fields are non-sensitive by construction — decision labels/reasons are fixed strings and span
//! attributes carry ids and counts, never payloads or secrets.

use aegis_core::TenantId;
use aegis_trace::{Span, TraceCollector, TraceId};

/// Forwards spans to `tracing`. Cheap and non-panicking; runs on the emitter's drain thread.
pub struct TracingCollector;

impl TraceCollector for TracingCollector {
    fn record_span(&self, trace_id: &TraceId, tenant: &TenantId, span: &Span) {
        let decision = span.decision.as_ref().map(|d| d.label()).unwrap_or("none");
        let risks = span
            .risks
            .iter()
            .map(|r| r.code())
            .collect::<Vec<_>>()
            .join(",");
        tracing::info!(
            target: "aegis.trace",
            trace_id = %trace_id,
            span_id = %span.span_id,
            tenant = %tenant,
            stage = span.stage.as_str(),
            name = %span.name,
            decision,
            reason = span.decision.as_ref().and_then(|d| d.reason()),
            risks = %risks,
            duration_ms = span.duration_ms(),
            error = span.error.as_deref(),
        );
    }
}
