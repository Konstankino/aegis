//! The loopback **gate** server: exposes the deterministic Aegis controls over HTTP so a
//! non-Rust agent handler (e.g. a Python/LangGraph Lambda) can use them the same way an
//! in-process Rust handler would. All state (Rule-of-Two taint, meter budget, audit ledger) is
//! kept server-side, keyed by `thread_id`, so the client can neither reset nor forge it.
//!
//! Endpoints:
//! * `POST /mediate` — broker decision, meter circuit breaker in front, audit-ledger entry after (Phase 0/1).
//! * `POST /encode` — context-aware sink encoding (output, Phase 0).
//! * `POST /sanitize` — Unicode input hygiene (ingress, Phase 1).
//! * `POST /redact` — PII/secret redaction of text (redact, Phase 2).
//! * `POST /meter/preflight` — token/cost pre-flight before a model call (meter, Phase 1).
//! * `POST /meter/record` — record actual usage after a model call (meter, Phase 1).
//! * `POST /memory/gate` — long-term memory-write gating (ledger, Phase 1).
//! * `POST /retrieval/authorize` — authorize a retrieval query in-scope (retrieval, Phase 2).
//! * `POST /supply/verify` — verify an artifact digest against the pinset (supply, Phase 2).
//! * `GET /ledger/verify` — verify a thread's tamper-evident chain (ledger, Phase 1).
//! * `POST /killswitch/revoke`, `GET /killswitch/status` — emergency revocation (§11, ASI08/10).
//! * `POST /sandbox/validate` — gate a proposed code execution (§11, ASI05).
//! * `POST /intent/validate` — validate an action against a signed intent capsule (§11, ASI01).
//!
//! `/mediate` also consults the killswitch before every decision, so a revoked tool is refused
//! immediately across all in-flight sessions.
//!
//! This runs only on loopback, co-located with the function; it is not a public API.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use aegis_broker::registry::ToolCall;
use aegis_broker::{Broker, Decision, Session};
use aegis_core::{Capability, Provenance};
use aegis_ledger::{gate_memory_write, EntryKind, Ledger};
use aegis_meter::{Limits, Meter, Verdict};
use aegis_output::{encode, Sink};
use aegis_retrieval::{authorize_query, QueryRequest, RetrievalContext};
use aegis_supply::{Digest, Pinset};
// Agentic/ASI controls (§11): emergency revocation, sandbox exec policy, intent envelope, honeypots.
use aegis_honeypot::Honeypots;
use aegis_intent::IntentCapsule;
use aegis_killswitch::{Killswitch, Target};
use aegis_sandbox::{ExecRequest, SandboxPolicy};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

/// Static configuration for the gate (loaded once at boot from the policy artifacts + env).
#[derive(Clone, Default)]
pub struct GateConfig {
    /// Meter budget limits (Phase 1).
    pub limits: Limits,
    /// Immutable S3 sink for audit-ledger entries, if configured (`AEGIS_LEDGER_BUCKET`).
    pub ledger_bucket: Option<String>,
    /// Supply-chain digest pinset (Phase 2).
    pub pinset: Pinset,
    /// Planted decoys / canaries whose use is a tripwire (§11, ASI05/ASI08).
    pub honeypots: Honeypots,
}

/// Shared state for the gate: the compiled broker + config, plus the per-thread session / meter
/// / ledger stores.
#[derive(Clone)]
struct GateState {
    broker: Arc<Broker>,
    config: Arc<GateConfig>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    meters: Arc<Mutex<HashMap<String, Meter>>>,
    ledgers: Arc<Mutex<HashMap<String, Ledger>>>,
    // Agentic emergency-revocation registry (ASI08/10): consulted before every mediation.
    killswitch: Arc<Mutex<Killswitch>>,
}

/// Build the gate router. Returned fully-stated so it can be `.merge()`d with the egress router.
pub fn router(broker: Arc<Broker>, config: GateConfig) -> Router {
    let state = GateState {
        broker,
        config: Arc::new(config),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        meters: Arc::new(Mutex::new(HashMap::new())),
        ledgers: Arc::new(Mutex::new(HashMap::new())),
        killswitch: Arc::new(Mutex::new(Killswitch::new())),
    };
    Router::new()
        // Phase 0/1/2.
        .route("/mediate", post(mediate))
        .route("/encode", post(encode_handler))
        .route("/sanitize", post(sanitize_handler))
        .route("/redact", post(redact_handler))
        .route("/meter/preflight", post(meter_preflight))
        .route("/meter/record", post(meter_record))
        .route("/memory/gate", post(memory_gate))
        .route("/retrieval/authorize", post(retrieval_authorize))
        .route("/supply/verify", post(supply_verify))
        .route("/ledger/verify", get(ledger_verify))
        // Agentic/ASI (§11).
        .route("/killswitch/revoke", post(killswitch_revoke))
        .route("/killswitch/status", get(killswitch_status))
        .route("/sandbox/validate", post(sandbox_validate))
        .route("/intent/validate", post(intent_validate))
        .with_state(state)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A stable hash of a tool call's identity + arguments, for loop detection.
fn state_hash(tool: &str, args: &serde_json::Value) -> u64 {
    let mut h = DefaultHasher::new();
    tool.hash(&mut h);
    args.to_string().hash(&mut h);
    h.finish()
}

/// A tool-call mediation request. `thread_id` selects the session whose taint accumulates.
#[derive(Debug, Deserialize)]
struct MediateRequest {
    agent_id: String,
    run_id: String,
    thread_id: String,
    tool: String,
    #[serde(default)]
    args: serde_json::Value,
    #[serde(default)]
    arg_provenance: Option<Provenance>,
}

#[tracing::instrument(
    name = "aegis.mediate",
    skip_all,
    fields(
        tool = %req.tool,
        thread_id = %req.thread_id,
        decision = tracing::field::Empty,
        trifecta = tracing::field::Empty,
    )
)]
async fn mediate(
    State(st): State<GateState>,
    Json(req): Json<MediateRequest>,
) -> impl IntoResponse {
    let now = now_ms();
    let prov = req.arg_provenance.unwrap_or(Provenance::Untrusted);
    let key = req.thread_id.clone();
    let loop_hash = state_hash(&req.tool, &req.args);

    // Canary tripwire (ASI08, honeypot Phase B): a planted canary token appearing in the tool-call
    // arguments is proof of exfiltration. Record it immutably, quarantine the agent, and refuse the
    // call — the same detect→evidence→escalate loop as a sandbox decoy hit. The token value is
    // never logged (it is a secret); only the tool name is recorded.
    if st.config.honeypots.scan(&req.args.to_string()).is_some() {
        let (ledger_seq, ledger_hash) = append_ledger(
            &st,
            &key,
            EntryKind::Tripwire,
            format!("honeypot canary in tool args: tool={}", req.tool),
            now,
        );
        st.killswitch
            .lock()
            .expect("killswitch poisoned")
            .quarantine(req.agent_id.clone());
        crate::telemetry::record_decision("tripwire", false);
        tracing::warn!(tool = %req.tool, agent = %req.agent_id, "honeypot canary tripwire: agent quarantined");
        return Json(serde_json::json!({
            "decision": "deny",
            "tripwire": true,
            "reason": "honeypot canary in tool arguments",
            "ledger": { "seq": ledger_seq, "hash": ledger_hash },
        }));
    }

    // 0. Killswitch (ASI08/10): an emergency-revoked tool — or a quarantined agent (e.g. one that
    //    tripped a honeypot) — is refused outright, even mid-run, before any other check. Consulted
    //    on every mediation so a revocation/quarantine takes effect immediately across all in-flight
    //    sessions.
    let revoked_reason: Option<&'static str> = {
        let ks = st.killswitch.lock().expect("killswitch poisoned");
        if ks.is_revoked(&Target::Agent(req.agent_id.clone())) {
            Some("agent quarantined (killswitch)")
        } else if ks.is_revoked(&Target::Tool(req.tool.clone())) {
            Some("tool revoked (killswitch)")
        } else {
            None
        }
    };

    // 1. Meter circuit breaker (Phase 1): a step + loop-detection check BEFORE the broker. A
    //    tripped/over-budget meter denies the call deterministically. Skipped when already
    //    revoked (the killswitch decision wins).
    let meter_verdict = if let Some(reason) = revoked_reason {
        Verdict::reject(reason)
    } else {
        let mut meters = st.meters.lock().expect("meter store poisoned");
        let meter = meters
            .entry(key.clone())
            .or_insert_with(|| Meter::new(st.config.limits.clone()));
        let step = meter.step(now);
        if step.is_proceed() {
            meter.observe_state(loop_hash)
        } else {
            step
        }
    };

    // 2. Decision: killswitch/meter breaker wins; otherwise the broker decides.
    let (verdict, reason, cap): (&str, Option<String>, Capability) = match meter_verdict {
        Verdict::Reject(r) => (
            "deny",
            Some(format!("circuit breaker: {r}")),
            session_cap(&st, &key),
        ),
        Verdict::Proceed => {
            let call = ToolCall::new(req.tool.clone(), req.args.clone(), prov);
            let (decision, cap) = {
                let mut sessions = st.sessions.lock().expect("gate session store poisoned");
                let session = sessions
                    .entry(key.clone())
                    .or_insert_with(|| Session::new(req.agent_id, req.run_id, req.thread_id));
                (st.broker.mediate(session, &call), session.cap)
            };
            match decision {
                Decision::Allow => ("allow", None, cap),
                Decision::HumanApprove => ("human_approve", None, cap),
                Decision::Deny(r) => ("deny", Some(r.to_string()), cap),
            }
        }
    };

    // 3. Audit ledger (Phase 1): append a tamper-evident entry for this decision.
    let (ledger_seq, ledger_hash) = {
        let mut ledgers = st.ledgers.lock().expect("ledger store poisoned");
        let ledger = ledgers.entry(key.clone()).or_default();
        let entry = ledger.append(
            EntryKind::Decision,
            key.as_str(),
            key.as_str(),
            format!("{verdict} tool={}", req.tool),
            now,
        );
        // Fold-in: persist the entry to the immutable (Object Lock) sink, best-effort.
        crate::ledger_sink::persist(
            st.config.ledger_bucket.clone(),
            format!("{key}/{:020}-{}.json", entry.seq, entry.hash),
            serde_json::to_string(entry).unwrap_or_default(),
        );
        (entry.seq, entry.hash.clone())
    };

    // Meter snapshot for the response + telemetry.
    let (tripped, steps, total_cost) = {
        let meters = st.meters.lock().expect("meter store poisoned");
        meters
            .get(&key)
            .map(|m| (m.is_tripped(), m.steps(), m.total_cost_usd()))
            .unwrap_or((false, 0, 0.0))
    };

    let span = tracing::Span::current();
    span.record("decision", verdict);
    span.record("trifecta", cap.is_trifecta());
    crate::telemetry::record_decision(verdict, cap.is_trifecta());

    Json(serde_json::json!({
        "decision": verdict,
        "reason": reason,
        "capability": {
            "reads_untrusted": cap.reads_untrusted,
            "reads_sensitive": cap.reads_sensitive,
            "external_effect": cap.external_effect,
            "is_trifecta": cap.is_trifecta(),
        },
        "meter": { "tripped": tripped, "steps": steps, "total_cost_usd": total_cost },
        "ledger": { "seq": ledger_seq, "hash": ledger_hash },
    }))
}

/// Read a thread's accumulated capability without creating a session.
fn session_cap(st: &GateState, thread_id: &str) -> Capability {
    st.sessions
        .lock()
        .expect("gate session store poisoned")
        .get(thread_id)
        .map(|s| s.cap)
        .unwrap_or(Capability::NONE)
}

/// A sink-encode request: encode `value` so it is inert in `sink`.
#[derive(Debug, Deserialize)]
struct EncodeRequest {
    sink: Sink,
    value: String,
}

#[tracing::instrument(name = "aegis.encode", skip_all, fields(sink = ?req.sink))]
async fn encode_handler(Json(req): Json<EncodeRequest>) -> impl IntoResponse {
    match encode(req.sink, &req.value) {
        Ok(encoded) => (
            StatusCode::OK,
            Json(serde_json::json!({ "encoded": encoded })),
        ),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

/// An ingress-hygiene request.
#[derive(Debug, Deserialize)]
struct SanitizeRequest {
    text: String,
}

#[tracing::instrument(name = "aegis.sanitize", skip_all)]
async fn sanitize_handler(Json(req): Json<SanitizeRequest>) -> impl IntoResponse {
    let s = aegis_ingress::sanitize(&req.text);
    Json(serde_json::json!({
        "text": s.text,
        "removed": s.removed,
        "had_bidi": s.had_bidi,
        "normalized": s.normalized,
    }))
}

/// A meter pre-flight request (before a model call).
#[derive(Debug, Deserialize)]
struct PreflightRequest {
    thread_id: String,
    est_tokens: u64,
    #[serde(default)]
    est_cost_usd: f64,
}

async fn meter_preflight(
    State(st): State<GateState>,
    Json(req): Json<PreflightRequest>,
) -> impl IntoResponse {
    let now = now_ms();
    let mut meters = st.meters.lock().expect("meter store poisoned");
    let meter = meters
        .entry(req.thread_id)
        .or_insert_with(|| Meter::new(st.config.limits.clone()));
    let verdict = meter.preflight(now, req.est_tokens, req.est_cost_usd);
    let (decision, reason) = match &verdict {
        Verdict::Proceed => ("proceed", None),
        Verdict::Reject(r) => ("reject", Some(r.to_string())),
    };
    Json(serde_json::json!({
        "decision": decision,
        "reason": reason,
        "tripped": meter.is_tripped(),
        "total_cost_usd": meter.total_cost_usd(),
    }))
}

/// A usage-record request (after a model call).
#[derive(Debug, Deserialize)]
struct RecordRequest {
    thread_id: String,
    tokens: u64,
    #[serde(default)]
    cost_usd: f64,
}

async fn meter_record(
    State(st): State<GateState>,
    Json(req): Json<RecordRequest>,
) -> impl IntoResponse {
    let now = now_ms();
    let mut meters = st.meters.lock().expect("meter store poisoned");
    let meter = meters
        .entry(req.thread_id)
        .or_insert_with(|| Meter::new(st.config.limits.clone()));
    meter.record(now, req.tokens, req.cost_usd);
    Json(serde_json::json!({
        "tripped": meter.is_tripped(),
        "trip_reason": meter.trip_reason(),
        "total_cost_usd": meter.total_cost_usd(),
    }))
}

/// A memory-write gating request.
#[derive(Debug, Deserialize)]
struct MemoryGateRequest {
    thread_id: String,
    content_origin: Provenance,
}

async fn memory_gate(
    State(st): State<GateState>,
    Json(req): Json<MemoryGateRequest>,
) -> impl IntoResponse {
    let cap = session_cap(&st, &req.thread_id);
    let decision = gate_memory_write(&cap, req.content_origin);
    let (verdict, reason) = match decision {
        aegis_ledger::MemoryDecision::Allow => ("allow", None),
        aegis_ledger::MemoryDecision::HumanApprove => ("human_approve", None),
        aegis_ledger::MemoryDecision::Deny(r) => ("deny", Some(r)),
    };
    Json(serde_json::json!({ "decision": verdict, "reason": reason }))
}

/// Query for `/ledger/verify`.
#[derive(Debug, Deserialize)]
struct LedgerQuery {
    thread_id: String,
}

async fn ledger_verify(
    State(st): State<GateState>,
    Query(q): Query<LedgerQuery>,
) -> impl IntoResponse {
    let ledgers = st.ledgers.lock().expect("ledger store poisoned");
    let ledger = ledgers.get(&q.thread_id);
    let (len, head, verified, error) = match ledger {
        Some(l) => match l.verify() {
            Ok(()) => (l.len(), l.head().to_string(), true, None),
            Err(e) => (l.len(), l.head().to_string(), false, Some(e.to_string())),
        },
        None => (0, aegis_ledger::GENESIS_HASH.to_string(), true, None),
    };
    Json(serde_json::json!({
        "verified": verified,
        "entries": len,
        "head": head,
        "error": error,
    }))
}

/// A redaction request (text or trace fragment).
#[derive(Debug, Deserialize)]
struct RedactRequest {
    text: String,
}

#[tracing::instrument(name = "aegis.redact", skip_all)]
async fn redact_handler(Json(req): Json<RedactRequest>) -> impl IntoResponse {
    let r = aegis_redact::redact(&req.text);
    Json(serde_json::json!({ "text": r.text, "findings": r.findings, "total": r.total() }))
}

/// A retrieval-authorization request: the caller's entitlement + the requested scope (both
/// flattened, so the request is a single flat JSON object).
#[derive(Debug, Deserialize)]
struct RetrievalAuthorizeRequest {
    #[serde(flatten)]
    ctx: RetrievalContext,
    #[serde(flatten)]
    request: QueryRequest,
}

async fn retrieval_authorize(Json(req): Json<RetrievalAuthorizeRequest>) -> impl IntoResponse {
    match authorize_query(&req.ctx, &req.request) {
        Ok(auth) => (
            StatusCode::OK,
            Json(serde_json::json!({ "authorized": true, "query": auth })),
        ),
        Err(e) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "authorized": false, "error": e.to_string() })),
        ),
    }
}

/// A supply-chain verification request: an artifact name + its content digest.
#[derive(Debug, Deserialize)]
struct SupplyVerifyRequest {
    name: String,
    digest: String,
}

async fn supply_verify(
    State(st): State<GateState>,
    Json(req): Json<SupplyVerifyRequest>,
) -> impl IntoResponse {
    let Some(digest) = Digest::parse(&req.digest) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "verified": false, "error": "unparseable digest" })),
        );
    };
    match st.config.pinset.verify(&req.name, &digest) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "verified": true })),
        ),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "verified": false, "error": e.to_string() })),
        ),
    }
}

// ── Agentic/ASI endpoints (§11) ─────────────────────────────────────────────────────────────

/// Revoke a target (tool/agent/prompt/connection) via the killswitch. Takes effect immediately
/// for all in-flight sessions, since `/mediate` consults the killswitch on every call.
async fn killswitch_revoke(
    State(st): State<GateState>,
    Json(target): Json<Target>,
) -> impl IntoResponse {
    let mut ks = st.killswitch.lock().expect("killswitch poisoned");
    ks.revoke(target);
    Json(serde_json::json!({ "revoked_count": ks.revoked_count() }))
}

/// Report how many targets are currently revoked.
async fn killswitch_status(State(st): State<GateState>) -> impl IntoResponse {
    let ks = st.killswitch.lock().expect("killswitch poisoned");
    Json(serde_json::json!({ "revoked_count": ks.revoked_count() }))
}

/// Append a ledger entry for `key`'s thread and persist it to the immutable (Object Lock) sink,
/// best-effort — the same audit step `mediate` performs, factored out for reuse by the tripwire
/// path. Returns the new entry's `(seq, hash)`.
fn append_ledger(
    st: &GateState,
    key: &str,
    kind: EntryKind,
    summary: String,
    now: u64,
) -> (u64, String) {
    let mut ledgers = st.ledgers.lock().expect("ledger store poisoned");
    let ledger = ledgers.entry(key.to_string()).or_default();
    let entry = ledger.append(kind, key, key, summary, now);
    crate::ledger_sink::persist(
        st.config.ledger_bucket.clone(),
        format!("{key}/{:020}-{}.json", entry.seq, entry.hash),
        serde_json::to_string(entry).unwrap_or_default(),
    );
    (entry.seq, entry.hash.clone())
}

/// A proposed code execution plus the identity needed to attribute a honeypot tripwire (`agent_id`
/// to quarantine, `thread_id` to key the ledger). The `ExecRequest` fields are flattened, so the
/// body is a single flat object.
#[derive(Debug, Deserialize)]
struct SandboxValidateRequest {
    #[serde(flatten)]
    exec: ExecRequest,
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    thread_id: String,
}

/// Validate a proposed code execution (ASI05). The real isolation is the container runtime; this is
/// the deterministic policy gate in front of it. A honeypot decoy is checked **first**: touching a
/// planted decoy is high-signal evidence of compromise, so it is attributed as a **tripwire**
/// (immutable ledger entry + agent quarantine, ASI05/ASI08) rather than a routine deny.
#[tracing::instrument(name = "aegis.sandbox_validate", skip_all)]
async fn sandbox_validate(
    State(st): State<GateState>,
    Json(req): Json<SandboxValidateRequest>,
) -> impl IntoResponse {
    let now = now_ms();

    // Honeypot tripwire FIRST — a decoy hit is treated as an attack regardless of what the sandbox
    // policy would otherwise decide.
    if let Some(decoy) = st
        .config
        .honeypots
        .match_exec(&req.exec.command, req.exec.target_path.as_deref())
    {
        // (a) Immutable evidence. The summary carries only the decoy id, never the payload (the
        //     ledger non-sensitivity rule). Keyed by thread when present, else the agent id.
        let key = if req.thread_id.is_empty() {
            req.agent_id.clone()
        } else {
            req.thread_id.clone()
        };
        let (seq, hash) = append_ledger(
            &st,
            &key,
            EntryKind::Tripwire,
            format!("honeypot decoy touched: {decoy}"),
            now,
        );
        // (b) Escalate at the agent level: quarantine (reintegration needs fresh attestation + a
        //     human). A subsequent `/mediate` for this agent is then refused deterministically.
        let quarantined = !req.agent_id.is_empty();
        if quarantined {
            st.killswitch
                .lock()
                .expect("killswitch poisoned")
                .quarantine(req.agent_id.clone());
        }
        crate::telemetry::record_decision("tripwire", false);
        tracing::warn!(decoy, agent = %req.agent_id, "honeypot tripwire: agent quarantined");
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "allow": false,
                "tripwire": true,
                "reason": "honeypot decoy touched",
                "quarantined": quarantined,
                "ledger": { "seq": seq, "hash": hash },
            })),
        );
    }

    // No decoy: the deterministic sandbox policy decides as before. (A production deployment would
    // load a tuned SandboxPolicy from config; the default is the locked-down profile.)
    match SandboxPolicy::default().validate(&req.exec) {
        aegis_sandbox::ExecDecision::Allow => (
            StatusCode::OK,
            Json(serde_json::json!({ "allow": true, "tripwire": false })),
        ),
        aegis_sandbox::ExecDecision::Deny(reason) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "allow": false, "tripwire": false, "reason": reason })),
        ),
    }
}

/// Validate an action against a signed intent capsule (ASI01): the capsule's signature must be
/// valid, unexpired, and the tool within its declared scope.
#[derive(Debug, Deserialize)]
struct IntentValidateRequest {
    capsule: IntentCapsule,
    tool: String,
    now_ms: u64,
}

async fn intent_validate(Json(req): Json<IntentValidateRequest>) -> impl IntoResponse {
    match req.capsule.validate_action(&req.tool, req.now_ms) {
        aegis_intent::IntentDecision::Proceed => {
            (StatusCode::OK, Json(serde_json::json!({ "proceed": true })))
        }
        aegis_intent::IntentDecision::Deviation(reason) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "proceed": false, "reason": reason })),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt; // for `oneshot`

    fn test_broker() -> Arc<Broker> {
        let tools = serde_json::json!([
            {
                "name": "web.fetch", "reaches_sensitive_data": false, "has_external_effect": true,
                "consequence": "low_reversible",
                "schema": { "type": "object", "properties": { "url": {"type": "string"} },
                            "required": ["url"], "additionalProperties": false }
            },
            {
                "name": "db.read_patient", "reaches_sensitive_data": true, "has_external_effect": false,
                "consequence": "low_reversible",
                "schema": { "type": "object", "properties": { "patient_id": {"type": "string"} },
                            "required": ["patient_id"], "additionalProperties": false }
            }
        ])
        .to_string();
        let cedar = r#"permit ( principal, action == Action::"invoke", resource );"#;
        Arc::new(Broker::from_sources(&tools, cedar).unwrap())
    }

    fn app() -> Router {
        router(test_broker(), GateConfig::default())
    }

    fn app_with(limits: Limits) -> Router {
        router(
            test_broker(),
            GateConfig {
                limits,
                ..Default::default()
            },
        )
    }

    fn app_with_honeypots() -> Router {
        router(
            test_broker(),
            GateConfig {
                honeypots: aegis_honeypot::Honeypots {
                    decoys: vec!["169.254.169.254".into()],
                    canaries: vec![],
                },
                ..Default::default()
            },
        )
    }

    fn app_with_canary() -> Router {
        router(
            test_broker(),
            GateConfig {
                honeypots: aegis_honeypot::Honeypots {
                    decoys: vec![],
                    canaries: vec!["CANARY-7f3a9b21e4c05d68".into()],
                },
                ..Default::default()
            },
        )
    }

    async fn post(
        app: Router,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn get(app: Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn call(thread: &str, tool: &str, args: serde_json::Value, prov: &str) -> serde_json::Value {
        serde_json::json!({
            "agent_id": "a", "run_id": "r", "thread_id": thread,
            "tool": tool, "args": args, "arg_provenance": prov
        })
    }

    #[tokio::test]
    async fn mediate_accumulates_taint_across_requests_into_a_trifecta() {
        let app = app();
        let (status, body) = post(
            app.clone(),
            "/mediate",
            call(
                "t1",
                "web.fetch",
                serde_json::json!({"url": "https://x"}),
                "untrusted",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["decision"], "allow");
        // A ledger entry was appended.
        assert_eq!(body["ledger"]["seq"], 0);

        let (_s, body) = post(
            app.clone(),
            "/mediate",
            call(
                "t1",
                "db.read_patient",
                serde_json::json!({"patient_id": "p1"}),
                "user",
            ),
        )
        .await;
        assert_eq!(body["decision"], "human_approve");
        assert_eq!(body["capability"]["is_trifecta"], true);
        assert_eq!(body["ledger"]["seq"], 1);
    }

    #[tokio::test]
    async fn separate_threads_do_not_share_taint() {
        let app = app();
        post(
            app.clone(),
            "/mediate",
            call(
                "t1",
                "web.fetch",
                serde_json::json!({"url": "https://x"}),
                "untrusted",
            ),
        )
        .await;
        let (_s, body) = post(
            app.clone(),
            "/mediate",
            call(
                "t2",
                "db.read_patient",
                serde_json::json!({"patient_id": "p1"}),
                "user",
            ),
        )
        .await;
        assert_eq!(body["decision"], "allow");
        assert_eq!(body["capability"]["is_trifecta"], false);
    }

    #[tokio::test]
    async fn mediate_denies_schema_violation() {
        let (_s, body) = post(
            app(),
            "/mediate",
            call("t3", "web.fetch", serde_json::json!({"bad": 1}), "user"),
        )
        .await;
        assert_eq!(body["decision"], "deny");
        assert_eq!(body["reason"], "argument schema violation");
    }

    #[tokio::test]
    async fn meter_step_breaker_trips_after_max_steps() {
        // Two calls allowed, the third exceeds max_steps=2 -> circuit-breaker deny.
        let limits = Limits {
            max_steps: 2,
            ..Limits::default()
        };
        let app = app_with(limits);
        let ok = |b: &serde_json::Value| b["decision"] == "allow";
        let (_s, b1) = post(
            app.clone(),
            "/mediate",
            call(
                "t",
                "web.fetch",
                serde_json::json!({"url":"https://x"}),
                "user",
            ),
        )
        .await;
        let (_s, b2) = post(
            app.clone(),
            "/mediate",
            call(
                "t",
                "web.fetch",
                serde_json::json!({"url":"https://y"}),
                "user",
            ),
        )
        .await;
        let (_s, b3) = post(
            app.clone(),
            "/mediate",
            call(
                "t",
                "web.fetch",
                serde_json::json!({"url":"https://z"}),
                "user",
            ),
        )
        .await;
        assert!(ok(&b1) && ok(&b2));
        assert_eq!(b3["decision"], "deny");
        assert!(b3["reason"].as_str().unwrap().contains("circuit breaker"));
        assert_eq!(b3["meter"]["tripped"], true);
    }

    #[tokio::test]
    async fn meter_loop_breaker_trips_on_repeated_identical_call() {
        let limits = Limits {
            loop_repeat_threshold: 2,
            max_steps: 100,
            ..Limits::default()
        };
        let app = app_with(limits);
        let same = || {
            call(
                "t",
                "web.fetch",
                serde_json::json!({"url":"https://same"}),
                "user",
            )
        };
        post(app.clone(), "/mediate", same()).await; // state count 1
        post(app.clone(), "/mediate", same()).await; // 2
        let (_s, b3) = post(app.clone(), "/mediate", same()).await; // 3 > threshold -> loop deny
        assert_eq!(b3["decision"], "deny");
        assert!(b3["reason"].as_str().unwrap().contains("loop"));
    }

    #[tokio::test]
    async fn preflight_and_record_enforce_hard_cost_cap() {
        let limits = Limits {
            hard_cost_cap_usd: 2.0,
            max_cost_per_request_usd: 5.0,
            ..Limits::default()
        };
        let app = app_with(limits);
        // Record $1.50, then a preflight that would cross $2.00 trips the breaker.
        let (_s, _b) = post(
            app.clone(),
            "/meter/record",
            serde_json::json!({"thread_id":"t","tokens":10,"cost_usd":1.5}),
        )
        .await;
        let (_s, pf) = post(
            app.clone(),
            "/meter/preflight",
            serde_json::json!({"thread_id":"t","est_tokens":10,"est_cost_usd":1.0}),
        )
        .await;
        assert_eq!(pf["decision"], "reject");
        assert_eq!(pf["tripped"], true);
        assert!(pf["reason"].as_str().unwrap().contains("hard spending cap"));
    }

    #[tokio::test]
    async fn sanitize_strips_invisible_characters() {
        let (status, body) = post(
            app(),
            "/sanitize",
            serde_json::json!({ "text": "hi\u{200B}\u{E0041}there\u{202E}" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["text"], "hithere");
        assert_eq!(body["removed"], 3);
        assert_eq!(body["had_bidi"], true);
    }

    #[tokio::test]
    async fn memory_gate_denies_untrusted_and_reflects_session_taint() {
        let app = app();
        // Untrusted content is refused regardless of session.
        let (_s, b) = post(
            app.clone(),
            "/memory/gate",
            serde_json::json!({"thread_id":"m","content_origin":"untrusted"}),
        )
        .await;
        assert_eq!(b["decision"], "deny");

        // Taint thread "m" by fetching untrusted content, then a user-origin write needs a human.
        post(
            app.clone(),
            "/mediate",
            call(
                "m",
                "web.fetch",
                serde_json::json!({"url":"https://x"}),
                "untrusted",
            ),
        )
        .await;
        let (_s, b) = post(
            app.clone(),
            "/memory/gate",
            serde_json::json!({"thread_id":"m","content_origin":"user"}),
        )
        .await;
        assert_eq!(b["decision"], "human_approve");
    }

    #[tokio::test]
    async fn ledger_verify_reports_intact_chain() {
        let app = app();
        post(
            app.clone(),
            "/mediate",
            call(
                "t",
                "web.fetch",
                serde_json::json!({"url":"https://x"}),
                "user",
            ),
        )
        .await;
        post(
            app.clone(),
            "/mediate",
            call(
                "t",
                "web.fetch",
                serde_json::json!({"url":"https://y"}),
                "user",
            ),
        )
        .await;
        let (status, body) = get(app.clone(), "/ledger/verify?thread_id=t").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["verified"], true);
        assert_eq!(body["entries"], 2);
        assert_ne!(body["head"], aegis_ledger::GENESIS_HASH);
    }

    #[tokio::test]
    async fn redact_endpoint_removes_pii() {
        let (status, body) = post(
            app(),
            "/redact",
            serde_json::json!({ "text": "email alice@example.com ip 10.0.0.1" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body["text"].as_str().unwrap().contains('@'));
        assert_eq!(body["total"], 2);
    }

    #[tokio::test]
    async fn retrieval_authorize_intersects_and_forbids() {
        // Allowed intersection -> authorized.
        let (status, body) = post(
            app(),
            "/retrieval/authorize",
            serde_json::json!({
                "allowed_namespaces": ["tenant-a", "shared"],
                "max_tier": "sensitive",
                "namespaces": ["tenant-a", "tenant-x"]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["query"]["namespaces"], serde_json::json!(["tenant-a"]));

        // Only-forbidden request -> 403.
        let (status, body) = post(
            app(),
            "/retrieval/authorize",
            serde_json::json!({
                "allowed_namespaces": ["tenant-a"],
                "max_tier": "internal",
                "namespaces": ["tenant-x"]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["authorized"], false);
    }

    #[tokio::test]
    async fn supply_verify_checks_the_pinset() {
        let d = Digest::sha256(b"weights-v1");
        let pins = Pinset::from_json(&format!(r#"{{"model":["{}"]}}"#, d.to_ref())).unwrap();
        let app = router(
            test_broker(),
            GateConfig {
                pinset: pins,
                ..Default::default()
            },
        );
        // Pinned digest -> verified.
        let (status, body) = post(
            app.clone(),
            "/supply/verify",
            serde_json::json!({ "name": "model", "digest": d.to_ref() }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["verified"], true);
        // Wrong digest -> 422.
        let (status, body) = post(
            app,
            "/supply/verify",
            serde_json::json!({ "name": "model", "digest": Digest::sha256(b"evil").to_ref() }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["verified"], false);
    }

    #[tokio::test]
    async fn killswitch_revokes_a_tool_mid_flight() {
        let app = app();
        // Initially the tool mediates normally.
        let (_s, b) = post(
            app.clone(),
            "/mediate",
            call(
                "k",
                "web.fetch",
                serde_json::json!({"url": "https://x"}),
                "user",
            ),
        )
        .await;
        assert_eq!(b["decision"], "allow");
        // Revoke web.fetch via the killswitch.
        let (_s, b) = post(
            app.clone(),
            "/killswitch/revoke",
            serde_json::json!({ "kind": "tool", "id": "web.fetch" }),
        )
        .await;
        assert_eq!(b["revoked_count"], 1);
        // The same call is now refused outright.
        let (_s, b) = post(
            app.clone(),
            "/mediate",
            call(
                "k",
                "web.fetch",
                serde_json::json!({"url": "https://x"}),
                "user",
            ),
        )
        .await;
        assert_eq!(b["decision"], "deny");
        assert!(b["reason"].as_str().unwrap().contains("revoked"));
    }

    #[tokio::test]
    async fn sandbox_validate_gates_unapproved_and_root() {
        // Unapproved code is refused.
        let (status, body) = post(
            app(),
            "/sandbox/validate",
            serde_json::json!({ "command": "echo hi", "approved": false }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["allow"], false);
        // Approved, non-root, no-network code is allowed.
        let (status, body) = post(
            app(),
            "/sandbox/validate",
            serde_json::json!({ "command": "python x.py", "approved": true }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["allow"], true);
    }

    #[tokio::test]
    async fn honeypot_decoy_trips_wire_and_quarantines_agent() {
        let app = app_with_honeypots();
        // Probing the planted metadata-service decoy is a tripwire, not a routine deny.
        let (status, body) = post(
            app.clone(),
            "/sandbox/validate",
            serde_json::json!({
                "command": "curl http://169.254.169.254/latest/meta-data/",
                "approved": true,
                "agent_id": "a",
                "thread_id": "t1"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["tripwire"], true);
        assert_eq!(body["quarantined"], true);

        // The now-quarantined agent's next tool call is refused deterministically.
        let (_s, body) = post(
            app.clone(),
            "/mediate",
            call(
                "t1",
                "web.fetch",
                serde_json::json!({"url": "https://x"}),
                "user",
            ),
        )
        .await;
        assert_eq!(body["decision"], "deny");
        assert_eq!(
            body["reason"],
            "circuit breaker: agent quarantined (killswitch)"
        );

        // The tamper-evident chain (including the tripwire entry) still verifies.
        let (_s, body) = get(app.clone(), "/ledger/verify?thread_id=t1").await;
        assert_eq!(body["verified"], true);

        // A benign, non-decoy request on a fresh agent is unaffected.
        let (status, body) = post(
            app.clone(),
            "/sandbox/validate",
            serde_json::json!({ "command": "python x.py", "approved": true, "agent_id": "b" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["allow"], true);
    }

    #[tokio::test]
    async fn mediate_canary_in_tool_args_trips_wire_and_quarantines() {
        let app = app_with_canary();
        // A tool call whose args carry the planted canary is exfiltration → deny + tripwire, and the
        // agent is quarantined (Phase B: the /mediate chokepoint, reusing the Phase A escalation).
        let (status, body) = post(
            app.clone(),
            "/mediate",
            serde_json::json!({
                "agent_id": "a", "run_id": "r", "thread_id": "t1",
                "tool": "web.fetch",
                "args": {"url": "https://x/?d=CANARY-7f3a9b21e4c05d68"},
                "arg_provenance": "user"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["decision"], "deny");
        assert_eq!(body["tripwire"], true);

        // The now-quarantined agent's next (clean) call is refused deterministically.
        let (_s, body) = post(
            app.clone(),
            "/mediate",
            call(
                "t1",
                "web.fetch",
                serde_json::json!({"url": "https://x"}),
                "user",
            ),
        )
        .await;
        assert_eq!(body["decision"], "deny");
        assert_eq!(
            body["reason"],
            "circuit breaker: agent quarantined (killswitch)"
        );
    }

    #[tokio::test]
    async fn intent_validate_enforces_scope() {
        // Build a signed capsule in-process (the client would normally hold one), serialize it to
        // JSON, and post it back through the endpoint to exercise the wire path.
        use aegis_core::signing::Keypair;
        let kp = Keypair::from_seed(&[5u8; 32]);
        let capsule = IntentCapsule::issue(
            &kp,
            "summarize",
            "summarize inbox",
            vec!["email.read".into()],
            "cycle-1",
            0,
            10_000,
        );
        let capsule_json = serde_json::to_value(&capsule).unwrap();
        // In-scope tool -> proceed.
        let (status, body) = post(
            app(),
            "/intent/validate",
            serde_json::json!({ "capsule": capsule_json, "tool": "email.read", "now_ms": 100 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["proceed"], true);
        // Out-of-scope tool -> deviation.
        let (status, body) = post(
            app(),
            "/intent/validate",
            serde_json::json!({ "capsule": capsule_json, "tool": "email.send", "now_ms": 100 }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["proceed"], false);
    }

    #[tokio::test]
    async fn encode_html_and_reject_bad_path() {
        let app = app();
        let (status, body) = post(
            app.clone(),
            "/encode",
            serde_json::json!({ "sink": "html", "value": "<script>x</script>" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["encoded"], "&lt;script&gt;x&lt;/script&gt;");

        let (status, body) = post(
            app,
            "/encode",
            serde_json::json!({ "sink": "path", "value": "../etc/passwd" }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }
}
