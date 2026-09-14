//! The loopback **gate** server: exposes the deterministic Aegis controls over HTTP so a
//! non-Rust agent handler (e.g. a Python/LangGraph Lambda) can use them the same way an
//! in-process Rust handler would. All state (Rule-of-Two taint, meter budget, audit ledger) is
//! kept server-side, keyed by `thread_id`, so the client can neither reset nor forge it.
//!
//! Per-thread taint + meter and per-agent quarantine are additionally **durably backed** (see
//! [`crate::session_store`]): the in-memory maps are a cache, write-through on change and
//! read-through (rehydrate) on a cold-start cache miss, so a human-approval (`waitForTaskToken`)
//! pause that resumes on a fresh execution environment does not silently lose the accumulated
//! taint/budget/quarantine. When no store is configured this is a no-op and behaviour is unchanged.
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
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::session_store::{SessionStore, StoreResult};

use aegis_broker::registry::ToolCall;
use aegis_broker::{Broker, Decision, Session};
use aegis_core::{Capability, Owasp, PolicyDecision, Provenance, TenantId};
use aegis_ledger::{gate_memory_write, EntryKind, Ledger};
use aegis_meter::{Limits, Meter, Verdict};
use aegis_output::{encode, Sink};
use aegis_retrieval::{authorize_query, QueryRequest, RetrievalContext};
use aegis_supply::{Digest, Pinset};
use aegis_trace::{Span, SpanEmitter, Stage, TraceId};
// Agentic/ASI controls (§11): emergency revocation, sandbox exec policy, intent envelope, honeypots.
use aegis_honeypot::Honeypots;
use aegis_identity::{Credential, RequestContext};
use aegis_intent::IntentCapsule;
use aegis_jit::{decide as jit_decide, GrantCatalog, JitDecision};
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
    /// Default meter budget limits (Phase 1) — used for any tenant without an explicit override.
    pub limits: Limits,
    /// Per-tenant meter budget overrides (Roadmap T1). A tenant absent here uses [`limits`]. Empty
    /// by default, so single-tenant deployments are unaffected.
    pub tenant_limits: HashMap<TenantId, Limits>,
    /// Immutable S3 sink for audit-ledger entries, if configured (`AEGIS_LEDGER_BUCKET`).
    pub ledger_bucket: Option<String>,
    /// Supply-chain digest pinset (Phase 2).
    pub pinset: Pinset,
    /// Planted decoys / canaries whose use is a tripwire (§11, ASI05/ASI08).
    pub honeypots: Honeypots,
    /// Sandbox exec policy (§11, ASI05). Loaded from `sandbox.toml`; `Default` is the locked-down
    /// profile, so an absent file keeps the prior behaviour.
    pub sandbox: SandboxPolicy,
    /// JIT credential grant catalog (§11, ASI03/ASI06). Loaded from `grants.toml`; `Default` is the
    /// empty catalog, so an absent file denies every credential request (safe by default).
    pub grants: GrantCatalog,
    /// Durable backing store for per-thread taint + meter + per-agent quarantine, so they survive
    /// a cold restart across a human-approval pause. `None` ⇒ the no-durability `Null` store (prior
    /// in-memory-only behaviour). Set from `AEGIS_CHECKPOINT_TABLE` in production (feature
    /// `dynamodb`).
    pub store: Option<Arc<SessionStore>>,
}

impl GateConfig {
    /// The meter limits for a tenant: its override if present, else the default (Roadmap T1).
    fn limits_for(&self, tenant: &TenantId) -> Limits {
        self.tenant_limits
            .get(tenant)
            .cloned()
            .unwrap_or_else(|| self.limits.clone())
    }
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
    // Durable backing store for per-thread taint/meter + per-agent quarantine (survives a cold
    // restart across a HITL pause). `Null` when unconfigured — then everything above is purely
    // in-memory, exactly as before.
    store: Arc<SessionStore>,
    // Agents whose durable quarantine this process has already consulted, so the store is read at
    // most once per agent per cold environment rather than on every mediation.
    quarantine_checked: Arc<Mutex<HashSet<String>>>,
    // Non-blocking typed-span emitter (Roadmap T0): each gate decision is recorded as a `Span` into
    // a `Trace` keyed by the thread id, forwarded to the trace collector on a background thread.
    emitter: SpanEmitter,
}

/// Build the gate router. Returned fully-stated so it can be `.merge()`d with the egress router.
///
/// Spawns the typed-span drain (Roadmap T0) feeding [`TracingCollector`](crate::trace_sink::
/// TracingCollector); the drain thread is detached and lives for the process. Tests use
/// [`router_with_emitter`] to inspect emitted spans.
pub fn router(broker: Arc<Broker>, config: GateConfig) -> Router {
    // 4096 buffered spans: generous headroom; a burst that overruns it drops spans rather than
    // stalling the request path (the emitter counts drops).
    let (emitter, handle) = SpanEmitter::spawn(crate::trace_sink::TracingCollector, 4096);
    // Detach: the drain thread runs for the life of the process, draining as spans arrive.
    drop(handle);
    router_with_emitter(broker, config, emitter)
}

/// Build the gate router with a caller-supplied [`SpanEmitter`], so a test can wire an
/// `InMemoryCollector` and assert on the spans the gate emits.
pub fn router_with_emitter(
    broker: Arc<Broker>,
    config: GateConfig,
    emitter: SpanEmitter,
) -> Router {
    // The durable store (or the no-op Null store when none is configured).
    let store = config.store.clone().unwrap_or_else(SessionStore::null);
    let state = GateState {
        broker,
        config: Arc::new(config),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        meters: Arc::new(Mutex::new(HashMap::new())),
        ledgers: Arc::new(Mutex::new(HashMap::new())),
        killswitch: Arc::new(Mutex::new(Killswitch::new())),
        store,
        quarantine_checked: Arc::new(Mutex::new(HashSet::new())),
        emitter,
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
        .route("/credentials/issue", post(credentials_issue))
        .route("/output/scan", post(output_scan))
        .with_state(state)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Derive a stable [`TraceId`] from the thread id (UUID v5), so every span for a thread groups into
/// one trace even across handlers and cold restarts. (Tenancy is Roadmap T1; the tenant is the
/// default until then.)
fn trace_id_for(thread_id: &str) -> TraceId {
    TraceId::from_uuid(uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_OID,
        thread_id.as_bytes(),
    ))
}

/// Build a [`PolicyDecision`] from a handler's already-reduced string verdict + optional reason.
fn policy_from(verdict: &str, reason: &Option<String>) -> PolicyDecision {
    match verdict {
        "allow" => PolicyDecision::Allow,
        "human_approve" => PolicyDecision::escalate("requires human approval"),
        _ => match reason {
            Some(r) => PolicyDecision::Deny(std::borrow::Cow::Owned(r.clone())),
            None => PolicyDecision::deny("denied"),
        },
    }
}

/// Emit one gate span, best-effort and non-blocking (a full buffer drops it, never stalls the
/// request). Keyed by the thread's derived trace id and tagged with the tenant.
fn emit_span(st: &GateState, thread_id: &str, tenant: &TenantId, span: Span) {
    st.emitter.emit(&trace_id_for(thread_id), tenant, span);
}

/// Resolve the request's tenant (Roadmap T1): absent/empty ⇒ the default tenant; a present but
/// malformed id fails closed (`Err`), so the caller denies rather than silently cross-tenant.
fn tenant_of(raw: &Option<String>) -> Result<TenantId, &'static str> {
    match raw.as_deref() {
        None | Some("") => Ok(TenantId::default()),
        Some(s) => TenantId::new(s).map_err(|_| "invalid tenant id"),
    }
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
    /// The tenant this request belongs to (Roadmap T1). Absent ⇒ the default tenant.
    #[serde(default)]
    tenant: Option<String>,
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

    // Resolve the tenant (Roadmap T1). A malformed id fails closed rather than defaulting.
    let tenant = match tenant_of(&req.tenant) {
        Ok(t) => t,
        Err(reason) => {
            crate::telemetry::record_decision("deny", false);
            return Json(serde_json::json!({ "decision": "deny", "reason": reason }));
        }
    };

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
        // Durably record the quarantine so it survives a cold restart (best-effort: the in-memory
        // quarantine already refuses this call; durability guards the *next* cold environment).
        if let Err(e) = st
            .store
            .save_quarantine(&req.agent_id, "honeypot canary in tool arguments")
            .await
        {
            tracing::warn!("quarantine persist failed: {e}");
        }
        crate::telemetry::record_decision("tripwire", false);
        tracing::warn!(tool = %req.tool, agent = %req.agent_id, "honeypot canary tripwire: agent quarantined");
        return Json(serde_json::json!({
            "decision": "deny",
            "tripwire": true,
            "reason": "honeypot canary in tool arguments",
            "ledger": { "seq": ledger_seq, "hash": ledger_hash },
        }));
    }

    // Durable rehydrate (fixes taint loss across a HITL pause): on a cold-start cache miss, restore
    // this thread's Rule-of-Two taint + meter budget from the store BEFORE any decision, and seed
    // the killswitch from any durable quarantine for this agent. Both fail CLOSED — a configured
    // store that cannot be read denies rather than proceed with reset taint.
    if let Err(e) = ensure_thread_loaded(&st, &key, &req.agent_id, &req.run_id, &tenant).await {
        tracing::error!(thread_id = %key, "taint rehydrate failed, denying: {e}");
        return store_unavailable_deny(&st, &key, now, &req.tool);
    }
    if let Err(e) = ensure_quarantine_loaded(&st, &req.agent_id).await {
        tracing::error!(agent = %req.agent_id, "quarantine rehydrate failed, denying: {e}");
        return store_unavailable_deny(&st, &key, now, &req.tool);
    }

    // 0. Killswitch (ASI08/10, Roadmap T1): the global stop, the tenant, a quarantined/revoked agent,
    //    or a revoked tool refuses the call outright, before any other check. Consulted on every
    //    mediation so a revocation takes effect immediately across all in-flight sessions.
    let revoked_reason: Option<&'static str> = {
        let ks = st.killswitch.lock().expect("killswitch poisoned");
        ks.blocks(tenant.as_str(), Some(&req.agent_id), Some(&req.tool))
    };

    // 1. Meter circuit breaker (Phase 1): a step + loop-detection check BEFORE the broker. A
    //    tripped/over-budget meter denies the call deterministically. Skipped when already
    //    revoked (the killswitch decision wins).
    let meter_verdict = if let Some(reason) = revoked_reason {
        Verdict::reject(reason)
    } else {
        let mut meters = st.meters.lock().expect("meter store poisoned");
        // Present because `ensure_thread_loaded` seeded (or rehydrated) it above.
        let meter = meters
            .get_mut(&key)
            .expect("meter seeded by ensure_thread_loaded");
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
                // Present because `ensure_thread_loaded` seeded (or rehydrated) it above.
                let session = sessions
                    .get_mut(&key)
                    .expect("session seeded by ensure_thread_loaded");
                (st.broker.mediate(session, &call), session.cap)
            };
            match decision {
                Decision::Allow => ("allow", None, cap),
                Decision::HumanApprove => ("human_approve", None, cap),
                Decision::Deny(r) => ("deny", Some(r.to_string()), cap),
            }
        }
    };

    // Write-through: persist this thread's updated taint + meter so a cold-start HITL resume
    // rehydrates them instead of resetting to zero (the core of the fix). Best-effort for
    // allow/deny; a `human_approve` is about to pause the run, so its taint MUST be durable first —
    // else fail closed rather than risk resuming with reset taint.
    let cap_result = st.store.save_cap(&key, &cap).await;
    let meter_result = {
        let snap = st
            .meters
            .lock()
            .expect("meter store poisoned")
            .get(&key)
            .map(|m| m.snapshot());
        match snap {
            Some(s) => st.store.save_meter(&key, &s).await,
            None => Ok(()),
        }
    };
    if verdict == "human_approve" {
        if let Some(e) = cap_result.err().or(meter_result.err()) {
            tracing::error!(thread_id = %key, "session-state persist failed before HITL pause: {e}");
            return store_unavailable_deny(&st, &key, now, &req.tool);
        }
    } else {
        if let Err(e) = cap_result {
            tracing::warn!(thread_id = %key, "cap persist failed ({verdict}): {e}");
        }
        if let Err(e) = meter_result {
            tracing::warn!(thread_id = %key, "meter persist failed ({verdict}): {e}");
        }
    }

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

    // Typed span into the trace spine (Roadmap T0). Excessive agency (LLM06) is the risk the broker
    // governs; the trifecta and step count travel as attributes.
    let mut trace_span = Span::start(
        Stage::BrokerCheck,
        format!("broker.mediate {}", req.tool),
        now,
    )
    .with_decision(policy_from(verdict, &reason))
    .with_risk(Owasp::Llm06)
    .attr("tool", &req.tool)
    .attr("tenant", tenant.as_str())
    .attr("trifecta", cap.is_trifecta())
    .attr("steps", steps);
    trace_span.end(now_ms());
    emit_span(&st, &req.thread_id, &tenant, trace_span);

    Json(serde_json::json!({
        "decision": verdict,
        "reason": reason,
        "tenant": tenant.as_str(),
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

/// Rehydrate a thread's in-memory `Session` + `Meter` from the durable store on a cache miss, so
/// Rule-of-Two taint and the meter budget are not reset by a cold-start HITL resume. Idempotent
/// and lock-cheap on a cache hit; all store I/O happens OUTSIDE the maps' mutexes (never `.await`
/// while holding a `std::sync::Mutex`). Returns `Err` only when a configured store could not be
/// read — the caller MUST fail closed (deny) rather than proceed with empty taint. With the `Null`
/// store `load_*` returns `Ok(None)`, so unconfigured deployments behave exactly as before.
async fn ensure_thread_loaded(
    st: &GateState,
    key: &str,
    agent_id: &str,
    run_id: &str,
    tenant: &TenantId,
) -> StoreResult<()> {
    // Fast path: both already resident this process.
    {
        let have_session = st
            .sessions
            .lock()
            .expect("gate session store poisoned")
            .contains_key(key);
        let have_meter = st
            .meters
            .lock()
            .expect("meter store poisoned")
            .contains_key(key);
        if have_session && have_meter {
            return Ok(());
        }
    }
    // Cache miss: consult the durable store with no lock held (fail closed on error).
    let stored_cap = st.store.load_cap(key).await?;
    let stored_meter = st.store.load_meter(key).await?;

    // Seed the session (insert-if-absent; monotonic taint makes a concurrent race safe to merge).
    {
        let mut sessions = st.sessions.lock().expect("gate session store poisoned");
        match sessions.get_mut(key) {
            Some(s) => {
                if let Some(c) = stored_cap {
                    s.cap.accumulate(&c);
                }
            }
            None => {
                let mut s = Session::new(agent_id, run_id, key).with_tenant(tenant.clone());
                if let Some(c) = stored_cap {
                    s.cap = c;
                }
                sessions.insert(key.to_string(), s);
            }
        }
    }
    // Seed the meter from its snapshot, or fresh when the thread is new — with the tenant's budget.
    {
        let limits = st.config.limits_for(tenant);
        let mut meters = st.meters.lock().expect("meter store poisoned");
        meters
            .entry(key.to_string())
            .or_insert_with(|| match stored_meter {
                Some(snap) => Meter::from_snapshot(limits, snap),
                None => Meter::new(limits),
            });
    }
    Ok(())
}

/// Meter-only rehydrate for the `/meter/*` endpoints (which carry no `agent_id`, so cannot seed a
/// session). Restores the meter budget on a cold-start cache miss; fails closed on a store error.
async fn ensure_meter_loaded(st: &GateState, key: &str) -> StoreResult<()> {
    if st
        .meters
        .lock()
        .expect("meter store poisoned")
        .contains_key(key)
    {
        return Ok(());
    }
    let stored_meter = st.store.load_meter(key).await?;
    let mut meters = st.meters.lock().expect("meter store poisoned");
    meters
        .entry(key.to_string())
        .or_insert_with(|| match stored_meter {
            Some(snap) => Meter::from_snapshot(st.config.limits.clone(), snap),
            None => Meter::new(st.config.limits.clone()),
        });
    Ok(())
}

/// Seed the in-memory killswitch from the durable per-agent quarantine, consulting the store at
/// most once per agent per cold environment. So an agent quarantined before a HITL pause is still
/// refused after a cold resume. Fails closed on a store error.
async fn ensure_quarantine_loaded(st: &GateState, agent_id: &str) -> StoreResult<()> {
    if st
        .quarantine_checked
        .lock()
        .expect("quarantine set poisoned")
        .contains(agent_id)
    {
        return Ok(());
    }
    if st.store.load_quarantine(agent_id).await? {
        st.killswitch
            .lock()
            .expect("killswitch poisoned")
            .quarantine(agent_id.to_string());
    }
    st.quarantine_checked
        .lock()
        .expect("quarantine set poisoned")
        .insert(agent_id.to_string());
    Ok(())
}

/// Write-through the current meter snapshot for a thread (best-effort — a lost meter write only
/// risks a later cold start under-counting the budget, not a taint bypass). Used by `/meter/*`.
async fn persist_meter(st: &GateState, key: &str) {
    let snap = st
        .meters
        .lock()
        .expect("meter store poisoned")
        .get(key)
        .map(|m| m.snapshot());
    if let Some(snap) = snap {
        if let Err(e) = st.store.save_meter(key, &snap).await {
            tracing::warn!(thread_id = %key, "meter persist failed: {e}");
        }
    }
}

/// The fail-closed response for a store outage: record a `deny` in the audit ledger and refuse.
/// Used when the durable taint/meter/quarantine store cannot be consulted — the gate must never
/// proceed with possibly-reset taint.
fn store_unavailable_deny(
    st: &GateState,
    key: &str,
    now: u64,
    tool: &str,
) -> Json<serde_json::Value> {
    let (seq, hash) = append_ledger(
        st,
        key,
        EntryKind::Decision,
        format!("deny (session state unavailable) tool={tool}"),
        now,
    );
    crate::telemetry::record_decision("deny", false);
    Json(serde_json::json!({
        "decision": "deny",
        "reason": "session state unavailable",
        "unavailable": true,
        "ledger": { "seq": seq, "hash": hash },
    }))
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
    let key = req.thread_id.clone();
    // Rehydrate the budget so a cold-start resume doesn't hand back a fresh one. Fail closed.
    if let Err(e) = ensure_meter_loaded(&st, &key).await {
        tracing::error!(thread_id = %key, "meter rehydrate failed (preflight): {e}");
        return Json(serde_json::json!({
            "decision": "reject",
            "reason": "session state unavailable",
            "tripped": true,
            "total_cost_usd": 0.0,
        }));
    }
    let (decision, reason, tripped, total_cost) = {
        let mut meters = st.meters.lock().expect("meter store poisoned");
        let meter = meters
            .get_mut(&key)
            .expect("meter seeded by ensure_meter_loaded");
        let verdict = meter.preflight(now, req.est_tokens, req.est_cost_usd);
        let (decision, reason) = match &verdict {
            Verdict::Proceed => ("proceed", None),
            Verdict::Reject(r) => ("reject", Some(r.to_string())),
        };
        (decision, reason, meter.is_tripped(), meter.total_cost_usd())
    };
    // Preflight can trip the hard-cap breaker — persist the change.
    persist_meter(&st, &key).await;
    Json(serde_json::json!({
        "decision": decision,
        "reason": reason,
        "tripped": tripped,
        "total_cost_usd": total_cost,
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
    let key = req.thread_id.clone();
    // Rehydrate so recorded cost accumulates onto the durable total, not a fresh one. Fail closed.
    if let Err(e) = ensure_meter_loaded(&st, &key).await {
        tracing::error!(thread_id = %key, "meter rehydrate failed (record): {e}");
        return Json(serde_json::json!({
            "tripped": true,
            "trip_reason": "session state unavailable",
            "total_cost_usd": 0.0,
        }));
    }
    let (tripped, trip_reason, total_cost) = {
        let mut meters = st.meters.lock().expect("meter store poisoned");
        let meter = meters
            .get_mut(&key)
            .expect("meter seeded by ensure_meter_loaded");
        meter.record(now, req.tokens, req.cost_usd);
        (
            meter.is_tripped(),
            meter.trip_reason().map(str::to_string),
            meter.total_cost_usd(),
        )
    };
    persist_meter(&st, &key).await;
    Json(serde_json::json!({
        "tripped": tripped,
        "trip_reason": trip_reason,
        "total_cost_usd": total_cost,
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
    // Prefer the in-memory session taint; on a cold-start cache miss fall back to the DURABLE
    // taint so a memory write isn't gated against reset (empty) taint. Read-only — no session is
    // created here (this endpoint carries no agent_id). Fails closed if the store errors.
    let cached = st
        .sessions
        .lock()
        .expect("gate session store poisoned")
        .get(&req.thread_id)
        .map(|s| s.cap);
    let cap = match cached {
        Some(c) => c,
        None => match st.store.load_cap(&req.thread_id).await {
            Ok(Some(c)) => c,
            Ok(None) => Capability::NONE,
            Err(e) => {
                tracing::error!(thread_id = %req.thread_id, "memory_gate cap rehydrate failed: {e}");
                return Json(serde_json::json!({
                    "decision": "deny",
                    "reason": "session state unavailable",
                }));
            }
        },
    };
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
/// A JIT credential-issue request: present a signed identity credential and name a grant; the gate
/// deterministically decides, then (on `Grant`) mints a real short-lived cloud credential.
#[derive(Debug, Deserialize)]
struct IssueRequest {
    agent_id: String,
    #[serde(default)]
    run_id: String,
    thread_id: String,
    /// The signed `aegis-identity` credential the agent presents (same one it uses on the mesh).
    credential: Credential,
    /// The grant id from `grants.toml`.
    grant_id: String,
    /// Requested lifetime in seconds (clamped to the grant ceiling and the credential's life).
    requested_ttl_secs: u64,
    /// The action scope requested (defaults to the grant's `required_scope`).
    #[serde(default)]
    action_scope: Option<String>,
    /// The tenant this request belongs to (Roadmap T1). Absent ⇒ the default tenant.
    #[serde(default)]
    tenant: Option<String>,
}

/// **The JIT credential-issue gate** (§11, ASI03/ASI06). Exchanges a validated identity credential
/// for a real, short-lived, tightly-scoped cloud credential. Order of controls mirrors `/mediate`:
/// durable rehydrate → killswitch/quarantine → `aegis_jit::decide` (identity verify + grant + TTL +
/// Rule-of-Two trifecta gate) → on `Grant`, accumulate taint + persist (write-through) → mint →
/// audit ledger (metadata only; never the secret material). `HumanApprove` defers the mint to the
/// same Step Functions `waitForTaskToken` pause the broker uses; nothing is minted until approved.
#[tracing::instrument(
    name = "aegis.credentials_issue",
    skip_all,
    fields(grant = %req.grant_id, thread_id = %req.thread_id, decision = tracing::field::Empty)
)]
async fn credentials_issue(
    State(st): State<GateState>,
    Json(req): Json<IssueRequest>,
) -> impl IntoResponse {
    let now = now_ms();
    let key = req.thread_id.clone();

    // Resolve the tenant (Roadmap T1). A malformed id fails closed.
    let tenant = match tenant_of(&req.tenant) {
        Ok(t) => t,
        Err(reason) => return jit_deny_response(StatusCode::FORBIDDEN, reason),
    };

    // Durable rehydrate + quarantine seed (fail closed exactly like /mediate).
    if let Err(e) = ensure_thread_loaded(&st, &key, &req.agent_id, &req.run_id, &tenant).await {
        tracing::error!(thread_id = %key, "taint rehydrate failed, denying jit issue: {e}");
        return jit_deny_response(StatusCode::SERVICE_UNAVAILABLE, "session state unavailable");
    }
    if let Err(e) = ensure_quarantine_loaded(&st, &req.agent_id).await {
        tracing::error!(agent = %req.agent_id, "quarantine rehydrate failed, denying jit issue: {e}");
        return jit_deny_response(StatusCode::SERVICE_UNAVAILABLE, "session state unavailable");
    }

    // Killswitch (Roadmap T1): the global stop, the tenant, or a quarantined/revoked agent gets no
    // credential, full stop.
    if let Some(reason) = st.killswitch.lock().expect("killswitch poisoned").blocks(
        tenant.as_str(),
        Some(&req.agent_id),
        None,
    ) {
        append_ledger(
            &st,
            &key,
            EntryKind::Decision,
            format!("jit deny ({reason}) grant={}", req.grant_id),
            now,
        );
        crate::telemetry::record_decision("jit_deny", false);
        return jit_deny_response(StatusCode::FORBIDDEN, reason);
    }

    // The grant must exist (no grant → deny, the default-deny catalog).
    let Some(grant) = st.config.grants.get(&req.grant_id).cloned() else {
        crate::telemetry::record_decision("jit_deny", false);
        return jit_deny_response(StatusCode::NOT_FOUND, "no such grant");
    };

    // Deterministic decision (identity verify + grant coherence + TTL ceiling + trifecta gate).
    let action_scope = req
        .action_scope
        .clone()
        .unwrap_or_else(|| grant.required_scope.clone());
    let ctx = RequestContext {
        audience: &req.credential.audience,
        purpose: &req.credential.purpose,
        session_id: &req.credential.session_id,
        action_scope: &action_scope,
    };
    let session_cap = session_cap(&st, &key);
    let decision = jit_decide(
        &req.credential,
        &ctx,
        &grant,
        &session_cap,
        now,
        req.requested_ttl_secs,
    );

    // Typed span into the trace spine (Roadmap T0). Identity/privilege abuse (ASI03) is the risk the
    // JIT broker governs.
    let mut trace_span = Span::start(
        Stage::CredentialIssue,
        format!("jit.issue {}", req.grant_id),
        now,
    )
    .with_decision(PolicyDecision::from(decision.clone()))
    .with_risk(Owasp::Asi03)
    .attr("grant", &req.grant_id)
    .attr("tenant", tenant.as_str());
    trace_span.end(now_ms());
    emit_span(&st, &req.thread_id, &tenant, trace_span);

    match decision {
        JitDecision::Deny(reason) => {
            append_ledger(
                &st,
                &key,
                EntryKind::Decision,
                format!("jit deny ({reason}) grant={}", req.grant_id),
                now,
            );
            tracing::Span::current().record("decision", "deny");
            crate::telemetry::record_decision("jit_deny", false);
            jit_deny_response(StatusCode::FORBIDDEN, reason)
        }
        JitDecision::HumanApprove(reason) => {
            // Defer to the HITL pause; nothing minted, no taint accrued yet.
            let (seq, hash) = append_ledger(
                &st,
                &key,
                EntryKind::Decision,
                format!("jit human_approve ({reason}) grant={}", req.grant_id),
                now,
            );
            tracing::Span::current().record("decision", "human_approve");
            crate::telemetry::record_decision("jit_human_approve", false);
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "decision": "human_approve",
                    "reason": reason,
                    "grant_id": req.grant_id,
                    "ledger": { "seq": seq, "hash": hash },
                })),
            )
        }
        JitDecision::Grant {
            ttl_secs,
            legs,
            consequence,
        } => {
            // Accumulate the Rule-of-Two taint this credential grants, then persist BEFORE minting —
            // a minted write credential is an external effect whose taint must survive a cold resume.
            let cap = {
                let mut sessions = st.sessions.lock().expect("gate session store poisoned");
                let session = sessions
                    .get_mut(&key)
                    .expect("session seeded by ensure_thread_loaded");
                session.cap.accumulate(&legs);
                session.cap
            };
            if let Err(e) = st.store.save_cap(&key, &cap).await {
                tracing::error!(thread_id = %key, "cap persist failed before jit mint: {e}");
                return jit_deny_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "session state unavailable",
                );
            }

            // Mint the real credential (feature `jit`; a lean build fails closed here).
            let mint_ctx = crate::jit::MintContext {
                agent_id: req.agent_id.clone(),
                thread_id: req.thread_id.clone(),
                intent_hash: req.credential.intent_hash.clone(),
            };
            match crate::jit::mint(&grant.provider, ttl_secs, &mint_ctx).await {
                Ok(minted) => {
                    // Audit: grant id / audience / ttl / expiry / provider kind — NEVER the secret.
                    let (seq, hash) = append_ledger(
                        &st,
                        &key,
                        EntryKind::Decision,
                        format!(
                            "jit issue grant={} audience={} provider={} ttl={}s exp={} consequence={:?}",
                            req.grant_id, grant.audience, minted.kind, ttl_secs, minted.expires_at_ms, consequence
                        ),
                        now,
                    );
                    tracing::Span::current().record("decision", "grant");
                    crate::telemetry::record_decision("jit_issue", true);
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "decision": "grant",
                            "grant_id": req.grant_id,
                            "provider": minted.kind,
                            "expires_at_ms": minted.expires_at_ms,
                            "credential": minted,
                            "capability": {
                                "reads_untrusted": cap.reads_untrusted,
                                "reads_sensitive": cap.reads_sensitive,
                                "external_effect": cap.external_effect,
                                "is_trifecta": cap.is_trifecta(),
                            },
                            "ledger": { "seq": seq, "hash": hash },
                        })),
                    )
                }
                Err(e) => {
                    // Mint failed — record a deny (no secret in the message) and fail closed.
                    append_ledger(
                        &st,
                        &key,
                        EntryKind::Decision,
                        format!("jit mint failed grant={}", req.grant_id),
                        now,
                    );
                    tracing::error!(grant = %req.grant_id, "jit mint failed: {e}");
                    crate::telemetry::record_decision("jit_deny", false);
                    jit_deny_response(StatusCode::BAD_GATEWAY, "credential mint failed")
                }
            }
        }
    }
}

/// A JIT deny/unavailable response: a fixed non-sensitive reason + status. (No ledger side effect —
/// callers that need an audit entry append it themselves before calling.)
fn jit_deny_response(status: StatusCode, reason: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(serde_json::json!({ "decision": "deny", "reason": reason })),
    )
}

/// A request to scan a model response before it reaches the user (Roadmap T3 wiring: eval on live
/// traffic). Carries the response text and the thread it belongs to.
#[derive(Debug, Deserialize)]
struct OutputScanRequest {
    #[serde(default)]
    thread_id: String,
    #[serde(default)]
    tenant: Option<String>,
    response: String,
}

/// **Output scan** (§3 LLM02/LLM07): run the deterministic output evaluators — PHI/PII leak, plus a
/// canary (system-prompt-leak) check built from the gate's honeypot canaries — over a model
/// response, emit a typed `OutputScan` span, and block the response if it fails. This is how eval
/// runs on live traffic; the LLM-judge evaluators run in a separate sampled job.
#[tracing::instrument(name = "aegis.output_scan", skip_all, fields(thread_id = %req.thread_id))]
async fn output_scan(
    State(st): State<GateState>,
    Json(req): Json<OutputScanRequest>,
) -> impl IntoResponse {
    let now = now_ms();
    let tenant = match tenant_of(&req.tenant) {
        Ok(t) => t,
        Err(reason) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "decision": "deny", "reason": reason })),
            )
        }
    };

    // Deterministic output evaluators: PHI leak always; canary/system-prompt-leak when the gate has
    // canaries configured.
    let mut evaluators: Vec<Box<dyn aegis_eval::Evaluator>> =
        vec![Box::new(aegis_eval::PhiLeakEvaluator)];
    let canaries = st.config.honeypots.canaries.clone();
    if !canaries.is_empty() {
        evaluators.push(Box::new(aegis_eval::ForbiddenTermEvaluator::new(
            canaries,
            Some(Owasp::Llm07),
        )));
    }
    let sample = aegis_eval::EvalSample {
        tenant: tenant.clone(),
        response: req.response.clone(),
        ..Default::default()
    };
    let report = aegis_eval::ThresholdEngine::new().run(&evaluators, &sample);

    let (verdict, policy) = if report.passed {
        ("allow", PolicyDecision::Allow)
    } else {
        // A fixed, non-sensitive reason — never echo the response or the finding text.
        (
            "deny",
            PolicyDecision::deny("output failed a safety evaluator"),
        )
    };

    let mut span = Span::start(Stage::OutputScan, "output.scan", now)
        .with_decision(policy)
        .with_risk(Owasp::Llm02)
        .attr("tenant", tenant.as_str())
        .attr("min_score", report.min_score());
    span.end(now_ms());
    emit_span(&st, &req.thread_id, &tenant, span);
    crate::telemetry::record_decision(verdict, false);

    let status = if report.passed {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    (
        status,
        Json(serde_json::json!({
            "decision": verdict,
            "tenant": tenant.as_str(),
            "min_score": report.min_score(),
            "scores": report.scores,
        })),
    )
}

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
            // Durably record the quarantine so it survives a cold restart (best-effort).
            if let Err(e) = st
                .store
                .save_quarantine(&req.agent_id, "honeypot decoy touched")
                .await
            {
                tracing::warn!("quarantine persist failed: {e}");
            }
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

    // No decoy: the deterministic sandbox policy decides. Loaded from `sandbox.toml` into
    // `GateConfig` at boot (the locked-down profile is the default when the file is absent).
    match st.config.sandbox.validate(&req.exec) {
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

    use crate::session_store::mem::MemStore;

    /// A router backed by a shared in-memory durable store, so a second router built over the same
    /// `MemStore` simulates a cold-restart handoff (fresh process, same DynamoDB).
    fn app_with_store(store: MemStore) -> Router {
        router(
            test_broker(),
            GateConfig {
                store: Some(std::sync::Arc::new(SessionStore::Mem(store))),
                ..Default::default()
            },
        )
    }

    fn app_with_store_limits(store: MemStore, limits: Limits) -> Router {
        router(
            test_broker(),
            GateConfig {
                store: Some(std::sync::Arc::new(SessionStore::Mem(store))),
                limits,
                ..Default::default()
            },
        )
    }

    fn app_with_store_canary(store: MemStore) -> Router {
        router(
            test_broker(),
            GateConfig {
                store: Some(std::sync::Arc::new(SessionStore::Mem(store))),
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

    // ── Durable per-thread state across a HITL pause (cold-resume regression) ────────────────────
    //
    // A second router built over the SAME `MemStore` models a cold resume: a fresh process with
    // empty in-memory maps but the same durable store. These prove the fix — taint, meter budget
    // and quarantine survive the handoff, and a store outage fails closed.

    #[tokio::test]
    async fn taint_survives_cold_resume() {
        let store = MemStore::default();
        // Gate #1 accumulates untrusted + external taint (legs A+C) on thread t1.
        let g1 = app_with_store(store.clone());
        let (_s, b) = post(
            g1,
            "/mediate",
            call(
                "t1",
                "web.fetch",
                serde_json::json!({"url": "https://x"}),
                "untrusted",
            ),
        )
        .await;
        assert_eq!(b["decision"], "allow");
        assert_eq!(b["capability"]["reads_untrusted"], true);
        assert_eq!(b["capability"]["external_effect"], true);

        // Gate #2 is a COLD process sharing the same store. The next mediation reads sensitive data
        // (leg B); without rehydration the session would look like NONE and be allowed. With the
        // fix the taint is restored -> lethal trifecta -> human_approve.
        let g2 = app_with_store(store.clone());
        let (_s, b) = post(
            g2,
            "/mediate",
            call(
                "t1",
                "db.read_patient",
                serde_json::json!({"patient_id": "p1"}),
                "user",
            ),
        )
        .await;
        assert_eq!(b["decision"], "human_approve");
        assert_eq!(b["capability"]["is_trifecta"], true);
    }

    #[tokio::test]
    async fn without_a_store_taint_is_lost_on_a_cold_gate() {
        // Control (the bug this fixes): with the Null store, two separate gates share no state, so
        // a cold gate has no memory of the earlier untrusted fetch.
        let g1 = app();
        post(
            g1,
            "/mediate",
            call(
                "t1",
                "web.fetch",
                serde_json::json!({"url": "https://x"}),
                "untrusted",
            ),
        )
        .await;
        let g2 = app();
        let (_s, b) = post(
            g2,
            "/mediate",
            call(
                "t1",
                "db.read_patient",
                serde_json::json!({"patient_id": "p1"}),
                "user",
            ),
        )
        .await;
        // Single leg B only -> allowed, NOT a trifecta.
        assert_eq!(b["decision"], "allow");
        assert_eq!(b["capability"]["is_trifecta"], false);
    }

    #[tokio::test]
    async fn store_unavailable_fails_closed() {
        let store = MemStore::default();
        store.set_failing(true);
        let app = app_with_store(store);
        let (status, b) = post(
            app,
            "/mediate",
            call(
                "t1",
                "web.fetch",
                serde_json::json!({"url": "https://x"}),
                "user",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(b["decision"], "deny");
        assert_eq!(b["reason"], "session state unavailable");
        assert_eq!(b["unavailable"], true);
    }

    #[tokio::test]
    async fn meter_budget_survives_cold_resume() {
        let store = MemStore::default();
        let limits = Limits {
            max_steps: 2,
            ..Limits::default()
        };
        // Gate #1 uses one step.
        let g1 = app_with_store_limits(store.clone(), limits.clone());
        let (_s, b) = post(
            g1,
            "/mediate",
            call(
                "t",
                "web.fetch",
                serde_json::json!({"url": "https://a"}),
                "user",
            ),
        )
        .await;
        assert_eq!(b["decision"], "allow");
        assert_eq!(b["meter"]["steps"], 1);

        // Gate #2 (cold) shares the store: the step count is rehydrated (1), so it has budget for
        // exactly one more call before the breaker trips — proving the meter persisted, not reset.
        let g2 = app_with_store_limits(store.clone(), limits);
        let (_s, b1) = post(
            g2.clone(),
            "/mediate",
            call(
                "t",
                "web.fetch",
                serde_json::json!({"url": "https://b"}),
                "user",
            ),
        )
        .await;
        assert_eq!(b1["decision"], "allow"); // step 2 == max, allowed
        let (_s, b2) = post(
            g2,
            "/mediate",
            call(
                "t",
                "web.fetch",
                serde_json::json!({"url": "https://c"}),
                "user",
            ),
        )
        .await;
        assert_eq!(b2["decision"], "deny"); // step 3 > max -> circuit breaker
        assert!(b2["reason"].as_str().unwrap().contains("circuit breaker"));
    }

    #[tokio::test]
    async fn quarantine_survives_cold_resume() {
        let store = MemStore::default();
        // Gate #1: a canary in the tool args trips the wire and quarantines agent "a" (persisted).
        let g1 = app_with_store_canary(store.clone());
        let (_s, b) = post(
            g1,
            "/mediate",
            serde_json::json!({
                "agent_id": "a", "run_id": "r", "thread_id": "t1",
                "tool": "web.fetch",
                "args": {"url": "https://x/?d=CANARY-7f3a9b21e4c05d68"},
                "arg_provenance": "user"
            }),
        )
        .await;
        assert_eq!(b["decision"], "deny");
        assert_eq!(b["tripwire"], true);

        // Gate #2 (cold) shares the store: agent "a" is still refused — the durable quarantine is
        // seeded into the fresh killswitch — even though nothing was quarantined in THIS process.
        let g2 = app_with_store(store.clone());
        let (_s, b) = post(
            g2,
            "/mediate",
            call(
                "t2",
                "web.fetch",
                serde_json::json!({"url": "https://clean"}),
                "user",
            ),
        )
        .await;
        assert_eq!(b["decision"], "deny");
        assert!(b["reason"].as_str().unwrap().contains("quarantined"));
    }

    // ── JIT credential issue (§11, ASI03/ASI06) ─────────────────────────────────────────────────
    //
    // These exercise the deterministic decision path at the gate. The real mint is behind the
    // `jit` feature (off in tests), so a `Grant` decision reaches the fail-closed stub and returns
    // 502 — proving the decision passed and the provider is correctly gated, with no AWS call.

    use aegis_core::signing::Keypair;
    use aegis_identity::Credential;
    use aegis_jit::{Grant, GrantCatalog, Provider};

    /// A far-future expiry (ms) so a test credential is valid against the real wall clock.
    const FUTURE: u64 = 9_999_999_999_999;

    fn issuer_kp() -> Keypair {
        Keypair::from_seed(&[11u8; 32])
    }

    fn signed_cred(audience: &str, scopes: &[&str], expires_at: u64) -> serde_json::Value {
        let cred = Credential::issue(
            &issuer_kp(),
            "a",
            audience,
            "triage",
            "sess-1",
            "intent-xyz",
            scopes.iter().map(|s| s.to_string()).collect(),
            0,
            expires_at,
        );
        serde_json::to_value(&cred).unwrap()
    }

    fn read_grant() -> Grant {
        Grant {
            id: "db-read".into(),
            audience: "patient-db".into(),
            required_scope: "db.read".into(),
            max_ttl_secs: 300,
            reads_sensitive: true,
            external_effect: false,
            forbid_when_trifecta: true,
            consequence: aegis_core::Consequence::LowReversible,
            provider: Provider::Sts {
                role_arn: "arn:aws:iam::111122223333:role/r".into(),
                resource_arns: vec!["arn:aws:rds-db:us-east-1:111122223333:dbuser/db/reader".into()],
                session_policy_template: "{\"Resource\":\"{resource}\"}".into(),
            },
        }
    }

    fn write_grant() -> Grant {
        Grant {
            id: "db-write".into(),
            audience: "patient-db".into(),
            required_scope: "db.write".into(),
            max_ttl_secs: 60,
            reads_sensitive: false,
            external_effect: true, // leg C
            forbid_when_trifecta: true,
            consequence: aegis_core::Consequence::LowReversible,
            provider: Provider::Secret {
                secret_arn: "arn:aws:secretsmanager:us-east-1:111122223333:secret:k".into(),
                json_key: None,
            },
        }
    }

    fn app_with_grants(grants: Vec<Grant>) -> Router {
        let mut cat = GrantCatalog::empty();
        for g in grants {
            cat.upsert(g);
        }
        router(
            test_broker(),
            GateConfig {
                grants: cat,
                ..Default::default()
            },
        )
    }

    fn issue_body(
        thread: &str,
        grant: &str,
        cred: serde_json::Value,
        ttl: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "agent_id": "a", "run_id": "r", "thread_id": thread,
            "credential": cred, "grant_id": grant, "requested_ttl_secs": ttl
        })
    }

    #[tokio::test]
    async fn issue_unknown_grant_is_denied() {
        let app = app();
        let (status, body) = post(
            app,
            "/credentials/issue",
            issue_body(
                "t1",
                "nope",
                signed_cred("patient-db", &["db.read"], FUTURE),
                60,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["decision"], "deny");
        assert_eq!(body["reason"], "no such grant");
    }

    #[tokio::test]
    async fn issue_expired_credential_is_denied() {
        let app = app_with_grants(vec![read_grant()]);
        let (status, body) = post(
            app,
            "/credentials/issue",
            // credential expired at 500ms; the gate's clock is now, well past it.
            issue_body(
                "t1",
                "db-read",
                signed_cred("patient-db", &["db.read"], 500),
                60,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["decision"], "deny");
        assert_eq!(body["reason"], "credential expired");
    }

    #[tokio::test]
    async fn issue_wrong_audience_is_denied() {
        let app = app_with_grants(vec![read_grant()]);
        // Credential audience "other" ≠ grant audience "patient-db".
        let (status, body) = post(
            app,
            "/credentials/issue",
            issue_body(
                "t1",
                "db-read",
                signed_cred("other", &["db.read"], FUTURE),
                60,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["decision"], "deny");
    }

    #[tokio::test]
    async fn issue_valid_grant_reaches_mint_and_is_gated_off_in_lean_build() {
        // A valid, non-trifecta read grant passes the whole decision path; with the `jit` feature
        // off the mint stub fails closed (502) — proving the decision succeeded and no AWS call is
        // made in a lean build.
        let app = app_with_grants(vec![read_grant()]);
        let (status, body) = post(
            app,
            "/credentials/issue",
            issue_body(
                "t1",
                "db-read",
                signed_cred("patient-db", &["db.read"], FUTURE),
                60,
            ),
        )
        .await;
        if cfg!(feature = "jit") {
            // With the feature on (and AWS creds in the env) this would mint; we don't assert that
            // here since tests run without AWS. Accept either a grant or an upstream mint error.
            assert!(status == StatusCode::OK || status == StatusCode::BAD_GATEWAY);
        } else {
            assert_eq!(status, StatusCode::BAD_GATEWAY);
            assert_eq!(body["reason"], "credential mint failed");
        }
    }

    #[tokio::test]
    async fn issue_completing_the_trifecta_routes_to_human_approval() {
        let app = app_with_grants(vec![write_grant()]);
        // Pre-taint the thread to A+B: an UNTRUSTED read of sensitive data (leg A via provenance,
        // leg B via the tool) — allowed at /mediate (two legs, not the trifecta).
        let (_s, b) = post(
            app.clone(),
            "/mediate",
            call(
                "tX",
                "db.read_patient",
                serde_json::json!({"patient_id": "p1"}),
                "untrusted",
            ),
        )
        .await;
        assert_eq!(b["decision"], "allow");
        assert_eq!(b["capability"]["reads_untrusted"], true);
        assert_eq!(b["capability"]["reads_sensitive"], true);

        // Now a leg-C (external_effect) JIT write grant would complete the trifecta → human approval,
        // and NOTHING is minted (no 502, no secret).
        let (status, body) = post(
            app,
            "/credentials/issue",
            issue_body(
                "tX",
                "db-write",
                signed_cred("patient-db", &["db.write"], FUTURE),
                30,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["decision"], "human_approve");
        assert!(
            body.get("credential").is_none(),
            "no secret on the human-approve path"
        );
    }

    #[tokio::test]
    async fn issue_denied_for_a_quarantined_agent() {
        let app = app_with_grants(vec![read_grant()]);
        // Quarantine agent "a" via the killswitch endpoint (Target = {kind,id}).
        let (_s, b) = post(
            app.clone(),
            "/killswitch/revoke",
            serde_json::json!({ "kind": "agent", "id": "a" }),
        )
        .await;
        assert_eq!(b["revoked_count"], 1);
        let (status, body) = post(
            app,
            "/credentials/issue",
            issue_body(
                "t1",
                "db-read",
                signed_cred("patient-db", &["db.read"], FUTURE),
                60,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["decision"], "deny");
        assert!(body["reason"].as_str().unwrap().contains("quarantined"));
    }

    // ── Typed span emission (Roadmap T0 wiring) ─────────────────────────────────────────────────

    use aegis_trace::InMemoryCollector;

    /// A router wired to an inspectable in-memory collector, plus a clone of the emitter so the test
    /// can flush deterministically.
    fn app_with_trace(collector: InMemoryCollector) -> (Router, SpanEmitter) {
        let (emitter, handle) = SpanEmitter::spawn(collector, 256);
        drop(handle); // detach the drain; emitter clones keep it alive for the test
        let app = router_with_emitter(test_broker(), GateConfig::default(), emitter.clone());
        (app, emitter)
    }

    #[tokio::test]
    async fn mediate_emits_a_typed_broker_span() {
        let collector = InMemoryCollector::new();
        let (app, emitter) = app_with_trace(collector.clone());
        let (_s, b) = post(
            app,
            "/mediate",
            call(
                "t-trace",
                "web.fetch",
                serde_json::json!({"url": "https://x"}),
                "user",
            ),
        )
        .await;
        assert_eq!(b["decision"], "allow");

        emitter.flush(); // deterministic: the span is recorded before we read
        let spans = collector.spans_for(&trace_id_for("t-trace"));
        assert_eq!(spans.len(), 1, "one broker span per mediate call");
        let sp = &spans[0];
        assert_eq!(sp.stage, Stage::BrokerCheck);
        assert!(sp.name.contains("web.fetch"));
        assert!(sp.decision.as_ref().unwrap().is_allow());
        assert!(sp.risks.contains(&Owasp::Llm06));
        assert_eq!(
            sp.attributes.get("tool").unwrap(),
            &serde_json::json!("web.fetch")
        );
        assert_eq!(
            sp.attributes.get("trifecta").unwrap(),
            &serde_json::json!(false)
        );
        assert_eq!(
            sp.attributes.get("tenant").unwrap(),
            &serde_json::json!("default")
        );
    }

    // ── Multi-tenancy (Roadmap T1) ──────────────────────────────────────────────────────────────

    fn mediate_body(thread: &str, tenant: Option<&str>) -> serde_json::Value {
        let mut b = serde_json::json!({
            "agent_id": "a", "run_id": "r", "thread_id": thread,
            "tool": "web.fetch", "args": {"url": "https://x"}, "arg_provenance": "user"
        });
        if let Some(t) = tenant {
            b["tenant"] = serde_json::json!(t);
        }
        b
    }

    #[tokio::test]
    async fn tenant_killswitch_blocks_only_that_tenant() {
        let app = app();
        let (_s, b) = post(
            app.clone(),
            "/killswitch/revoke",
            serde_json::json!({ "kind": "tenant", "id": "acme" }),
        )
        .await;
        assert_eq!(b["revoked_count"], 1);
        let (_s, b) = post(
            app.clone(),
            "/mediate",
            mediate_body("t-acme", Some("acme")),
        )
        .await;
        assert_eq!(b["decision"], "deny");
        assert_eq!(b["tenant"], "acme");
        assert!(b["reason"].as_str().unwrap().contains("tenant revoked"));
        let (_s, b) = post(
            app.clone(),
            "/mediate",
            mediate_body("t-other", Some("other")),
        )
        .await;
        assert_eq!(b["decision"], "allow");
    }

    #[tokio::test]
    async fn global_killswitch_blocks_every_tenant() {
        let app = app();
        post(
            app.clone(),
            "/killswitch/revoke",
            serde_json::json!({ "kind": "global" }),
        )
        .await;
        let (_s, b) = post(app.clone(), "/mediate", mediate_body("t1", None)).await;
        assert_eq!(b["decision"], "deny");
        assert!(b["reason"].as_str().unwrap().contains("global killswitch"));
    }

    #[tokio::test]
    async fn malformed_tenant_is_denied() {
        let (_s, b) = post(app(), "/mediate", mediate_body("t1", Some("Bad Tenant"))).await;
        assert_eq!(b["decision"], "deny");
        assert_eq!(b["reason"], "invalid tenant id");
    }

    #[tokio::test]
    async fn per_tenant_meter_budget_applies() {
        // Tenant "tight" gets max_steps=1; the default tenant keeps the generous default.
        let mut tl = HashMap::new();
        tl.insert(
            TenantId::new("tight").unwrap(),
            Limits {
                max_steps: 1,
                ..Limits::default()
            },
        );
        let app = router(
            test_broker(),
            GateConfig {
                tenant_limits: tl,
                ..Default::default()
            },
        );
        let (_s, b) = post(
            app.clone(),
            "/mediate",
            mediate_body("t-tight", Some("tight")),
        )
        .await;
        assert_eq!(b["decision"], "allow");
        let (_s, b) = post(
            app.clone(),
            "/mediate",
            mediate_body("t-tight", Some("tight")),
        )
        .await;
        assert_eq!(b["decision"], "deny");
        assert!(b["reason"].as_str().unwrap().contains("circuit breaker"));
        // A default-tenant thread is unaffected by the tight budget.
        let (_s, b) = post(app.clone(), "/mediate", mediate_body("t-df", None)).await;
        assert_eq!(b["decision"], "allow");
        let (_s, b) = post(app.clone(), "/mediate", mediate_body("t-df", None)).await;
        assert_eq!(b["decision"], "allow");
    }

    #[tokio::test]
    async fn mediate_span_carries_the_deny_decision() {
        let collector = InMemoryCollector::new();
        let (app, emitter) = app_with_trace(collector.clone());
        // An unknown tool is denied by the broker.
        let (_s, b) = post(
            app,
            "/mediate",
            call("t-deny", "nope", serde_json::json!({}), "user"),
        )
        .await;
        assert_eq!(b["decision"], "deny");
        emitter.flush();
        let spans = collector.spans_for(&trace_id_for("t-deny"));
        assert_eq!(spans.len(), 1);
        let d = spans[0].decision.as_ref().unwrap();
        assert!(d.is_deny());
        assert!(d.reason().unwrap().contains("unknown tool"));
    }

    // ── Output scan (eval on live traffic, Roadmap T3 wiring) ───────────────────────────────────

    #[tokio::test]
    async fn output_scan_allows_clean_and_denies_phi() {
        let app = app();
        // A clean response passes.
        let (status, b) = post(
            app.clone(),
            "/output/scan",
            serde_json::json!({ "thread_id": "t", "response": "the dose is 5mg twice daily" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(b["decision"], "allow");
        // PHI in the response is blocked before it reaches the user.
        let (status, b) = post(
            app.clone(),
            "/output/scan",
            serde_json::json!({ "thread_id": "t", "response": "patient SSN 123-45-6789" }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(b["decision"], "deny");
    }

    #[tokio::test]
    async fn output_scan_emits_a_typed_span() {
        let collector = InMemoryCollector::new();
        let (app, emitter) = app_with_trace(collector.clone());
        post(
            app,
            "/output/scan",
            serde_json::json!({ "thread_id": "t-out", "response": "clean", "tenant": "acme" }),
        )
        .await;
        emitter.flush();
        let spans = collector.spans_for(&trace_id_for("t-out"));
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].stage, Stage::OutputScan);
        assert_eq!(
            spans[0].attributes.get("tenant").unwrap(),
            &serde_json::json!("acme")
        );
    }
}
