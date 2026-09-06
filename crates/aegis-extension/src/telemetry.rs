//! A tiny always-compiled telemetry shim so instrumentation call sites (e.g. the gate) stay
//! feature-agnostic. Domain events are emitted via `tracing` unconditionally; the OTLP metric
//! counter is incremented only when the `otel` feature is built in.

/// Record a broker decision as a metric (and, via `tracing`, an event/span field).
///
/// `verdict` is one of `allow` / `human_approve` / `deny`. Deliberately records only the
/// non-sensitive verdict and trifecta flag — never tool arguments.
pub fn record_decision(verdict: &str, is_trifecta: bool) {
    #[cfg(feature = "otel")]
    crate::otel::record_decision(verdict, is_trifecta);
    #[cfg(not(feature = "otel"))]
    {
        let _ = (verdict, is_trifecta);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn record_decision_is_callable_without_a_collector() {
        // Without the otel feature (default test build) this is a no-op; it must never panic.
        super::record_decision("allow", false);
        super::record_decision("human_approve", true);
        super::record_decision("deny", false);
    }
}
