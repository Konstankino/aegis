//! # aegis-trace — the observability spine (Roadmap T0)
//!
//! A typed record of what the plane did to one request. Every gate emits a [`Span`] into a
//! [`Trace`]; a [`TraceCollector`] is the pluggable sink (in-memory for tests, OTel or Postgres in
//! production), fed through a **non-blocking** [`SpanEmitter`] so pipeline latency is never gated on
//! trace writes.
//!
//! This is the foundation the evaluation harness, drift detection, and per-tenant dashboards all
//! build on: they read structured traces rather than scraping logs.
//!
//! ## Design
//!
//! * A [`Span`] is a uniform record tagged with a [`Stage`] and an open `attributes` bag, rather
//!   than a per-stage enum — so one collector stores every stage, and the eval harness reads any
//!   span generically. Common fields (ids, timing, decision, OWASP risks, error) are first-class;
//!   stage-specific data (tokens, chunk ids, cost) goes in `attributes`.
//! * A [`Span`] carries a [`aegis_core::PolicyDecision`] and zero or more [`aegis_core::Owasp`] ids,
//!   so a trace is self-describing for audit and the coverage matrix.
//! * The crate performs **no I/O of its own** and holds no clock: timestamps are caller-supplied
//!   (`now_ms`), so traces are deterministic and testable. [`now_ms`] is offered for hosts.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use aegis_core::{Owasp, PolicyDecision, TenantId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A request-scoped trace identifier (UUID v4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TraceId(Uuid);

/// A single span identifier (UUID v4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SpanId(Uuid);

macro_rules! uuid_newtype {
    ($ty:ident) => {
        impl $ty {
            /// A fresh random id.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
            /// The nil id (all zeroes) — a stable placeholder for tests.
            #[must_use]
            pub fn nil() -> Self {
                Self(Uuid::nil())
            }
            /// The underlying UUID.
            #[must_use]
            pub fn as_uuid(&self) -> Uuid {
                self.0
            }
            /// Construct from an existing UUID (e.g. rehydrating from storage).
            #[must_use]
            pub fn from_uuid(u: Uuid) -> Self {
                Self(u)
            }
        }
        impl Default for $ty {
            fn default() -> Self {
                Self::new()
            }
        }
        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}
uuid_newtype!(TraceId);
uuid_newtype!(SpanId);

/// The pipeline stage a span belongs to. Mirrors the deterministic control chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Input hygiene / sanitization (`aegis-ingress`).
    Ingress,
    /// Capability mediation (`aegis-broker`).
    BrokerCheck,
    /// RAG retrieval authorization + scan (`aegis-retrieval`).
    Retrieval,
    /// Prompt assembly / model routing (`aegis-prompt`).
    Prompt,
    /// The model call itself.
    LlmCall,
    /// Output scanning / encoding (`aegis-output`, `aegis-redact`).
    OutputScan,
    /// Tool / URL / agent boundary (`aegis-egress`).
    Egress,
    /// JIT credential issue (`aegis-jit`).
    CredentialIssue,
    /// Anything not covered above.
    Other,
}

impl Stage {
    /// A short, stable label for logs and metrics.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Stage::Ingress => "ingress",
            Stage::BrokerCheck => "broker_check",
            Stage::Retrieval => "retrieval",
            Stage::Prompt => "prompt",
            Stage::LlmCall => "llm_call",
            Stage::OutputScan => "output_scan",
            Stage::Egress => "egress",
            Stage::CredentialIssue => "credential_issue",
            Stage::Other => "other",
        }
    }
}

/// One recorded step in the pipeline. Uniform shape, tagged by [`Stage`], with an open attribute bag
/// for stage-specific data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Span {
    /// This span's id.
    pub span_id: SpanId,
    /// Which pipeline stage produced it.
    pub stage: Stage,
    /// A human label, e.g. `"broker.mediate"` or `"egress.decide"`.
    pub name: String,
    /// Start time (Unix ms, caller-supplied).
    pub started_at_ms: u64,
    /// End time (Unix ms), once the step completes.
    pub ended_at_ms: Option<u64>,
    /// The unified decision this step reached, if it is a gate.
    pub decision: Option<PolicyDecision>,
    /// OWASP risk ids this step pertains to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risks: Vec<Owasp>,
    /// Stage-specific structured data (tokens, cost, chunk ids, …).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, serde_json::Value>,
    /// An error message if the step failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Span {
    /// Begin a span at `now_ms`. Fill in the decision/attributes with the builder methods, then
    /// [`end`](Span::end) it.
    #[must_use]
    pub fn start(stage: Stage, name: impl Into<String>, now_ms: u64) -> Self {
        Self {
            span_id: SpanId::new(),
            stage,
            name: name.into(),
            started_at_ms: now_ms,
            ended_at_ms: None,
            decision: None,
            risks: Vec::new(),
            attributes: BTreeMap::new(),
            error: None,
        }
    }

    /// Stamp the end time.
    pub fn end(&mut self, now_ms: u64) {
        self.ended_at_ms = Some(now_ms);
    }

    /// Elapsed time in ms, once ended.
    #[must_use]
    pub fn duration_ms(&self) -> Option<u64> {
        self.ended_at_ms
            .map(|e| e.saturating_sub(self.started_at_ms))
    }

    /// Builder: attach the gate decision.
    #[must_use]
    pub fn with_decision(mut self, decision: PolicyDecision) -> Self {
        self.decision = Some(decision);
        self
    }

    /// Builder: tag an OWASP risk this span addresses.
    #[must_use]
    pub fn with_risk(mut self, risk: Owasp) -> Self {
        if !self.risks.contains(&risk) {
            self.risks.push(risk);
        }
        self
    }

    /// Builder: set a stage-specific attribute (silently ignores a value that won't serialize).
    #[must_use]
    pub fn attr(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.attributes.insert(key.into(), v);
        }
        self
    }

    /// Builder: record an error message.
    #[must_use]
    pub fn with_error(mut self, msg: impl Into<String>) -> Self {
        self.error = Some(msg.into());
        self
    }
}

/// All spans from one request, plus request-scoped context. This is the unit the eval harness and
/// dashboards consume.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trace {
    /// The request-scoped id.
    pub trace_id: TraceId,
    /// The tenant this request belongs to.
    pub tenant: TenantId,
    /// When the request started (Unix ms).
    pub started_at_ms: u64,
    /// The spans, in the order they were pushed.
    pub spans: Vec<Span>,
    /// Request-scoped cross-cutting context (agent id, thread id, route, …).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

impl Trace {
    /// Start a new trace with a fresh id for `tenant`.
    #[must_use]
    pub fn new(tenant: TenantId, now_ms: u64) -> Self {
        Self::with_id(TraceId::new(), tenant, now_ms)
    }

    /// Start a trace with a caller-supplied id (e.g. correlating with an incoming request id).
    #[must_use]
    pub fn with_id(trace_id: TraceId, tenant: TenantId, now_ms: u64) -> Self {
        Self {
            trace_id,
            tenant,
            started_at_ms: now_ms,
            spans: Vec::new(),
            attributes: BTreeMap::new(),
        }
    }

    /// Append a span.
    pub fn push(&mut self, span: Span) {
        self.spans.push(span);
    }

    /// Builder: set a request-scoped attribute.
    #[must_use]
    pub fn attr(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.attributes.insert(key.into(), v);
        }
        self
    }

    /// The most severe decision across the trace: `Deny` > `Escalate` > `Allow` > none. This is the
    /// request's overall verdict for audit.
    #[must_use]
    pub fn outcome(&self) -> Option<PolicyDecision> {
        let mut best: Option<&PolicyDecision> = None;
        let rank = |d: &PolicyDecision| match d {
            PolicyDecision::Deny(_) => 3,
            PolicyDecision::Escalate(_) => 2,
            PolicyDecision::Allow => 1,
        };
        for d in self.spans.iter().filter_map(|s| s.decision.as_ref()) {
            if best.is_none_or(|b| rank(d) > rank(b)) {
                best = Some(d);
            }
        }
        best.cloned()
    }

    /// The distinct OWASP risks touched anywhere in the trace, in `Owasp::ALL` order.
    #[must_use]
    pub fn risks(&self) -> Vec<Owasp> {
        Owasp::ALL
            .into_iter()
            .filter(|r| self.spans.iter().any(|s| s.risks.contains(r)))
            .collect()
    }

    /// Emit every span through `emitter` (e.g. after assembling a trace synchronously).
    pub fn emit_through(&self, emitter: &SpanEmitter) {
        for s in &self.spans {
            emitter.emit(&self.trace_id, &self.tenant, s.clone());
        }
    }
}

/// A pluggable trace sink. Implementations receive completed spans (or whole traces) and persist or
/// forward them — an in-memory buffer for tests, an OTLP exporter, a Postgres table. Must be cheap
/// and non-panicking: it runs on the collector's drain thread.
pub trait TraceCollector: Send + Sync {
    /// Record one span within a trace.
    fn record_span(&self, trace_id: &TraceId, tenant: &TenantId, span: &Span);

    /// Record a whole assembled trace. Defaults to recording each span in turn.
    fn record_trace(&self, trace: &Trace) {
        for s in &trace.spans {
            self.record_span(&trace.trace_id, &trace.tenant, s);
        }
    }
}

/// An in-memory collector — the default for tests and local runs. Cheap, clonable (shares one
/// store), and inspectable. Not for production volume.
#[derive(Clone, Default)]
pub struct InMemoryCollector {
    spans: Arc<Mutex<HashMap<TraceId, Vec<Span>>>>,
}

impl InMemoryCollector {
    /// A fresh, empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The spans recorded for a trace, in arrival order.
    #[must_use]
    pub fn spans_for(&self, trace_id: &TraceId) -> Vec<Span> {
        self.spans
            .lock()
            .expect("trace store poisoned")
            .get(trace_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Every trace id seen.
    #[must_use]
    pub fn trace_ids(&self) -> Vec<TraceId> {
        self.spans
            .lock()
            .expect("trace store poisoned")
            .keys()
            .copied()
            .collect()
    }

    /// Total spans recorded across all traces.
    #[must_use]
    pub fn total_spans(&self) -> usize {
        self.spans
            .lock()
            .expect("trace store poisoned")
            .values()
            .map(Vec::len)
            .sum()
    }
}

impl TraceCollector for InMemoryCollector {
    fn record_span(&self, trace_id: &TraceId, _tenant: &TenantId, span: &Span) {
        self.spans
            .lock()
            .expect("trace store poisoned")
            .entry(*trace_id)
            .or_default()
            .push(span.clone());
    }
}

// ── Non-blocking emitter ──────────────────────────────────────────────────────────────────────────

struct Envelope {
    trace_id: TraceId,
    tenant: TenantId,
    span: Span,
}

enum Msg {
    Span(Box<Envelope>),
    /// A flush barrier: the drain thread acks once every prior span has been recorded.
    Flush(Sender<()>),
}

/// A lightweight, clonable handle each crate holds to emit spans. [`emit`](SpanEmitter::emit) never
/// blocks: a full buffer drops the span (and increments [`dropped`](SpanEmitter::dropped)) rather
/// than stalling the request path.
#[derive(Clone)]
pub struct SpanEmitter {
    tx: SyncSender<Msg>,
    dropped: Arc<AtomicU64>,
}

/// Owns the background drain thread that feeds spans to the collector. Keep it alive for as long as
/// spans are emitted; [`join`](CollectorHandle::join) drains and stops it (after all emitters drop).
pub struct CollectorHandle {
    join: Option<JoinHandle<()>>,
}

impl SpanEmitter {
    /// Spawn a background drain feeding `collector`, buffered to `capacity` spans. Returns the
    /// (clonable) emitter and the handle that owns the drain thread.
    #[must_use]
    pub fn spawn<C: TraceCollector + 'static>(
        collector: C,
        capacity: usize,
    ) -> (SpanEmitter, CollectorHandle) {
        let (tx, rx) = sync_channel::<Msg>(capacity.max(1));
        let join = std::thread::Builder::new()
            .name("aegis-trace".into())
            .spawn(move || {
                for msg in rx {
                    match msg {
                        Msg::Span(env) => {
                            collector.record_span(&env.trace_id, &env.tenant, &env.span)
                        }
                        Msg::Flush(ack) => {
                            let _ = ack.send(());
                        }
                    }
                }
            })
            .expect("spawn aegis-trace drain thread");
        (
            SpanEmitter {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            CollectorHandle { join: Some(join) },
        )
    }

    /// Emit a span. Never blocks: if the buffer is full (or the collector has stopped), the span is
    /// dropped and the dropped counter is bumped.
    pub fn emit(&self, trace_id: &TraceId, tenant: &TenantId, span: Span) {
        let env = Box::new(Envelope {
            trace_id: *trace_id,
            tenant: tenant.clone(),
            span,
        });
        if self.tx.try_send(Msg::Span(env)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Block until every span emitted before this call has been recorded. For tests and graceful
    /// shutdown — not the request path.
    pub fn flush(&self) {
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        if self.tx.send(Msg::Flush(ack_tx)).is_ok() {
            let _ = ack_rx.recv();
        }
    }

    /// How many spans have been dropped because the buffer was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl CollectorHandle {
    /// Join the drain thread. Returns once every emitter has been dropped and the buffer is drained.
    pub fn join(mut self) {
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Wall-clock milliseconds since the Unix epoch — a convenience for hosts supplying `now_ms`. The
/// crate itself never calls this, so traces stay deterministic in tests.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_display_as_uuid() {
        let a = TraceId::new();
        let b = TraceId::new();
        assert_ne!(a, b);
        assert_eq!(a.to_string().len(), 36); // hyphenated uuid
        assert_eq!(
            SpanId::nil().to_string(),
            "00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn span_builder_records_decision_risk_attr_and_duration() {
        let s = Span::start(Stage::BrokerCheck, "broker.mediate", 1_000)
            .with_decision(PolicyDecision::escalate("lethal trifecta"))
            .with_risk(Owasp::Llm06)
            .with_risk(Owasp::Llm06) // deduped
            .attr("steps", 3u32);
        assert_eq!(s.risks, vec![Owasp::Llm06]);
        assert_eq!(s.attributes.get("steps").unwrap(), &serde_json::json!(3));
        let mut s = s;
        s.end(1_040);
        assert_eq!(s.duration_ms(), Some(40));
        assert!(s.decision.unwrap().is_escalate());
    }

    #[test]
    fn trace_outcome_is_the_most_severe_decision() {
        let tenant = TenantId::default();
        let mut t = Trace::new(tenant, 0);
        t.push(Span::start(Stage::Ingress, "sanitize", 0).with_decision(PolicyDecision::Allow));
        t.push(
            Span::start(Stage::BrokerCheck, "mediate", 1)
                .with_decision(PolicyDecision::escalate("trifecta")),
        );
        t.push(Span::start(Stage::Egress, "decide", 2).with_decision(PolicyDecision::deny("host")));
        assert!(t.outcome().unwrap().is_deny());
    }

    #[test]
    fn trace_risks_are_distinct_and_ordered() {
        let mut t = Trace::new(TenantId::default(), 0);
        t.push(Span::start(Stage::Egress, "e", 0).with_risk(Owasp::Asi02));
        t.push(Span::start(Stage::Ingress, "i", 0).with_risk(Owasp::Llm01));
        t.push(Span::start(Stage::BrokerCheck, "b", 0).with_risk(Owasp::Llm01));
        // Ordered by Owasp::ALL (LLM01 before ASI02), distinct.
        assert_eq!(t.risks(), vec![Owasp::Llm01, Owasp::Asi02]);
    }

    #[test]
    fn trace_serde_round_trips() {
        let mut t = Trace::new(TenantId::new("clinic-7").unwrap(), 100).attr("agent", "a1");
        t.push(Span::start(Stage::LlmCall, "call", 100).attr("input_tokens", 512u32));
        let j = serde_json::to_string(&t).unwrap();
        let back: Trace = serde_json::from_str(&j).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn emitter_records_through_the_collector() {
        let collector = InMemoryCollector::new();
        let (emitter, handle) = SpanEmitter::spawn(collector.clone(), 64);
        let tid = TraceId::new();
        let tenant = TenantId::default();
        emitter.emit(&tid, &tenant, Span::start(Stage::Ingress, "sanitize", 0));
        emitter.emit(&tid, &tenant, Span::start(Stage::BrokerCheck, "mediate", 1));
        emitter.flush(); // deterministic: both spans are recorded before we read
        assert_eq!(collector.spans_for(&tid).len(), 2);
        assert_eq!(collector.total_spans(), 2);
        assert_eq!(emitter.dropped(), 0);
        drop(emitter);
        handle.join();
    }

    #[test]
    fn emitter_drops_rather_than_blocks_when_full() {
        // A collector that blocks forever would stall a naive emitter; ours drops instead.
        struct Slow;
        impl TraceCollector for Slow {
            fn record_span(&self, _t: &TraceId, _n: &TenantId, _s: &Span) {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        let (emitter, _handle) = SpanEmitter::spawn(Slow, 1);
        let tid = TraceId::new();
        let tenant = TenantId::default();
        // Fire many spans fast; with capacity 1 and a slow sink, most must be dropped, not blocked.
        for _ in 0..200 {
            emitter.emit(&tid, &tenant, Span::start(Stage::LlmCall, "x", 0));
        }
        assert!(
            emitter.dropped() > 0,
            "a full buffer must drop, never block the caller"
        );
    }

    #[test]
    fn stage_labels_uuid_helpers_error_and_now() {
        // Every stage has a non-empty snake_case label.
        for st in [
            Stage::Ingress,
            Stage::BrokerCheck,
            Stage::Retrieval,
            Stage::Prompt,
            Stage::LlmCall,
            Stage::OutputScan,
            Stage::Egress,
            Stage::CredentialIssue,
            Stage::Other,
        ] {
            assert!(!st.as_str().is_empty());
        }
        // UUID newtype helpers.
        let u = uuid::Uuid::new_v4();
        assert_eq!(TraceId::from_uuid(u).as_uuid(), u);
        assert_eq!(SpanId::from_uuid(u).as_uuid(), u);
        // Error builder.
        let s = Span::start(Stage::LlmCall, "call", 0).with_error("backend 500");
        assert_eq!(s.error.as_deref(), Some("backend 500"));
        // now_ms is a plausible wall clock (> year 2020 in ms).
        assert!(now_ms() > 1_600_000_000_000);
        // A span with no decision doesn't affect a trace's outcome.
        let mut t = Trace::new(TenantId::default(), 0);
        t.push(Span::start(Stage::Other, "noop", 0));
        assert!(t.outcome().is_none());
        assert!(t.risks().is_empty());
    }

    #[test]
    fn record_trace_default_records_every_span() {
        let collector = InMemoryCollector::new();
        let mut t = Trace::new(TenantId::default(), 0);
        t.push(Span::start(Stage::Ingress, "a", 0));
        t.push(Span::start(Stage::OutputScan, "b", 1));
        collector.record_trace(&t); // default trait method
        assert_eq!(collector.spans_for(&t.trace_id).len(), 2);
        assert_eq!(collector.trace_ids(), vec![t.trace_id]);
    }

    #[test]
    fn emit_through_pushes_all_spans() {
        let collector = InMemoryCollector::new();
        let (emitter, handle) = SpanEmitter::spawn(collector.clone(), 64);
        let mut t = Trace::new(TenantId::default(), 0);
        t.push(Span::start(Stage::Ingress, "a", 0));
        t.push(Span::start(Stage::Egress, "b", 1));
        t.emit_through(&emitter);
        emitter.flush();
        assert_eq!(collector.spans_for(&t.trace_id).len(), 2);
        drop(emitter);
        handle.join();
    }
}
