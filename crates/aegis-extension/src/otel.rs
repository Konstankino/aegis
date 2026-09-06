//! OpenTelemetry (OTLP) export for traces and metrics, behind the `otel` feature.
//!
//! **Ready out of the box:** it reads the standard `OTEL_*` environment variables and activates
//! OTLP export only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set (e.g. `http://localhost:4317`,
//! the ADOT collector's gRPC endpoint on Lambda). With no endpoint it degrades cleanly to
//! structured stdout logs — no connection errors, no configuration required.
//!
//! Signals emitted:
//! * **Traces** — a span per gate request (`aegis.mediate`, `aegis.encode`) plus an HTTP span
//!   from the tower-http trace layer; decisions are recorded as span fields.
//! * **Metrics** — `aegis.broker.decisions` (a `u64` counter, attributes `decision` + `trifecta`).
//!
//! Only non-sensitive fields (verdict, trifecta flag, tool name, thread id) are recorded —
//! never tool arguments.

use std::sync::OnceLock;

use opentelemetry::metrics::Counter;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing_subscriber::prelude::*;

static DECISIONS: OnceLock<Counter<u64>> = OnceLock::new();

/// Flushes and shuts the OTLP providers down on drop (so buffered spans/metrics are exported
/// before the process exits).
pub struct OtelGuard {
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Some(tp) = self.tracer_provider.take() {
            let _ = tp.shutdown();
        }
        if let Some(mp) = self.meter_provider.take() {
            let _ = mp.shutdown();
        }
    }
}

fn resource() -> Resource {
    let service = std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "aegis".to_string());
    Resource::builder().with_service_name(service).build()
}

/// Initialize the tracing subscriber (fmt + optional OTLP layer) and, when an endpoint is
/// configured, the OTLP trace and metric exporters. Returns a guard that flushes on drop.
pub fn init() -> OtelGuard {
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .filter(|e| !e.is_empty());

    let mut guard = OtelGuard {
        tracer_provider: None,
        meter_provider: None,
    };
    let mut otel_layer = None;

    if let Some(ep) = endpoint.as_deref() {
        // Traces.
        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(ep)
            .build()
            .expect("build OTLP span exporter");
        let tracer_provider = SdkTracerProvider::builder()
            .with_resource(resource())
            .with_batch_exporter(span_exporter)
            .build();
        global::set_tracer_provider(tracer_provider.clone());
        let tracer = tracer_provider.tracer("aegis");
        otel_layer = Some(tracing_opentelemetry::layer().with_tracer(tracer));
        guard.tracer_provider = Some(tracer_provider);

        // Metrics.
        let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(ep)
            .build()
            .expect("build OTLP metric exporter");
        let meter_provider = SdkMeterProvider::builder()
            .with_resource(resource())
            .with_periodic_exporter(metric_exporter)
            .build();
        global::set_meter_provider(meter_provider.clone());
        let counter = global::meter("aegis")
            .u64_counter("aegis.broker.decisions")
            .with_description("Broker decisions by verdict")
            .build();
        let _ = DECISIONS.set(counter);
        guard.meter_provider = Some(meter_provider);
    }

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "aegis_extension=info,aegis=info".into());
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().without_time())
        .with(otel_layer)
        .init();

    match endpoint {
        Some(ep) => tracing::info!("OpenTelemetry OTLP export enabled -> {ep}"),
        None => tracing::info!(
            "otel feature built, OTEL_EXPORTER_OTLP_ENDPOINT unset -> structured logs only"
        ),
    }
    guard
}

/// Increment the decisions counter. No-op until [`init`] has installed a meter provider.
pub fn record_decision(verdict: &str, is_trifecta: bool) {
    if let Some(counter) = DECISIONS.get() {
        counter.add(
            1,
            &[
                KeyValue::new("decision", verdict.to_string()),
                KeyValue::new("trifecta", is_trifecta),
            ],
        );
    }
}
