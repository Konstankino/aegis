//! # aegis-gateway — the edge gateway core (Roadmap T4)
//!
//! Exposes the Aegis plane to external hosts (MCP clients like Claude Desktop / Cursor, or a REST
//! caller) — but **the security is in the pipeline, not the interface**. This crate is the gateway's
//! deterministic, transport-agnostic core:
//!
//! * [`KeyStore`] — API keys stored as **SHA-256 hashes** (never the secret), each mapped to a
//!   [`TenantId`] and scopes. `authenticate` hashes a presented key and returns the record.
//! * [`RateLimiter`] — a per-key fixed-window **requests/second** limiter with a caller-supplied
//!   clock, so it is deterministic and testable. This layers *over* the meter's tokens/day budget
//!   (which lives in the pipeline): the gateway caps request rate, the meter caps token spend.
//! * [`McpAdapter`] — an **MCP JSON-RPC 2.0** protocol adapter that exposes Aegis capabilities as MCP
//!   tools (`initialize` / `tools/list` / `tools/call`). It is pure: a `tools/call` is *routed* back
//!   to the host to run through the real pipeline, then wrapped as a result — the adapter never runs
//!   a control itself.
//! * [`Gateway`] — the front door: `admit` authenticates + rate-limits one request and returns the
//!   tenant/scopes to attach downstream.
//!
//! No network dependency — the axum/HTTP host that mounts this is a thin outer shell.

use std::collections::HashMap;
use std::sync::Mutex;

use aegis_core::{AegisError, TenantId};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// SHA-256 hex of a secret — how keys are stored and compared (the secret is never retained).
#[must_use]
pub fn hash_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

// ── API-key auth ──────────────────────────────────────────────────────────────────────────────────

/// A registered API key: the hash of the secret, the tenant it authenticates, and its scopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecord {
    /// SHA-256 hex of the key secret (never the secret itself).
    pub key_hash: String,
    /// The tenant this key authenticates as.
    pub tenant: TenantId,
    /// The scopes this key is granted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// Whether the key is disabled (revoked without deleting the record).
    #[serde(default)]
    pub disabled: bool,
}

impl KeyRecord {
    /// Whether this key carries `scope`.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// A store of API keys, keyed by secret hash.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyStore {
    #[serde(default)]
    keys: Vec<KeyRecord>,
}

impl KeyStore {
    /// An empty store — authenticates nothing (deny by default).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse from JSON (`{"keys":[...]}`). Fails closed on malformed input.
    pub fn from_json(src: &str) -> Result<Self, AegisError> {
        serde_json::from_str(src).map_err(|e| AegisError::Config(format!("key store: {e}")))
    }

    /// Serialize to pretty JSON (hashes only — no secrets).
    pub fn to_json(&self) -> Result<String, AegisError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| AegisError::Config(format!("serialize key store: {e}")))
    }

    /// Register a new key from its plaintext secret (hashed on the way in). Returns the stored hash.
    pub fn register(&mut self, secret: &str, tenant: TenantId, scopes: Vec<String>) -> String {
        let key_hash = hash_secret(secret);
        self.keys.push(KeyRecord {
            key_hash: key_hash.clone(),
            tenant,
            scopes,
            disabled: false,
        });
        key_hash
    }

    /// Disable a key by its hash (revoke without deleting). Returns whether one changed.
    pub fn disable(&mut self, key_hash: &str) -> bool {
        if let Some(k) = self.keys.iter_mut().find(|k| k.key_hash == key_hash) {
            let was = k.disabled;
            k.disabled = true;
            !was
        } else {
            false
        }
    }

    /// Authenticate a presented secret: hash it, look it up, and return the record unless it is
    /// disabled. Fails closed (`None`).
    #[must_use]
    pub fn authenticate(&self, presented_secret: &str) -> Option<&KeyRecord> {
        let hash = hash_secret(presented_secret);
        self.keys.iter().find(|k| k.key_hash == hash && !k.disabled)
    }
}

// ── Rate limiting ─────────────────────────────────────────────────────────────────────────────────

/// A rate-limit decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    /// Within budget.
    Allow,
    /// Over budget; retry after this many ms (until the window rolls over).
    Limited { retry_after_ms: u64 },
}

impl RateDecision {
    /// Whether the request may proceed.
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, RateDecision::Allow)
    }
}

/// A per-key fixed-window requests limiter. The clock is caller-supplied (`now_ms`) so it is
/// deterministic and testable. Layers over the pipeline meter's tokens/day: this caps request rate.
#[derive(Debug)]
pub struct RateLimiter {
    max_per_window: u32,
    window_ms: u64,
    state: Mutex<HashMap<String, (u64, u32)>>, // key -> (window_start_ms, count)
}

impl RateLimiter {
    /// A limiter allowing `max_per_window` requests per `window_ms` window, per key.
    #[must_use]
    pub fn new(max_per_window: u32, window_ms: u64) -> Self {
        Self {
            max_per_window,
            window_ms: window_ms.max(1),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// A per-second limiter.
    #[must_use]
    pub fn per_second(max_per_second: u32) -> Self {
        Self::new(max_per_second, 1000)
    }

    /// Count one request for `key` at `now_ms` and decide.
    pub fn check(&self, key: &str, now_ms: u64) -> RateDecision {
        let mut state = self.state.lock().expect("rate limiter poisoned");
        let entry = state.entry(key.to_string()).or_insert((now_ms, 0));
        let (start, count) = *entry;
        if now_ms.saturating_sub(start) >= self.window_ms {
            // New window.
            *entry = (now_ms, 1);
            return RateDecision::Allow;
        }
        if count < self.max_per_window {
            entry.1 = count + 1;
            RateDecision::Allow
        } else {
            let retry_after_ms = self.window_ms - now_ms.saturating_sub(start);
            RateDecision::Limited { retry_after_ms }
        }
    }
}

// ── MCP JSON-RPC 2.0 adapter ────────────────────────────────────────────────────────────────────

/// One MCP tool the gateway advertises (an Aegis capability).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpTool {
    /// The MCP tool name (e.g. `"aegis.mediate"`).
    pub name: String,
    /// A human description.
    pub description: String,
    /// The JSON Schema for the tool's arguments.
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// A parsed JSON-RPC 2.0 request.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    #[serde(default)]
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

/// A JSON-RPC 2.0 response (exactly one of `result` / `error`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }
    fn err(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
            }),
        }
    }
    /// Whether this response is an error.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

/// What the adapter decided for one MCP request.
#[derive(Debug, Clone, PartialEq)]
pub enum McpOutcome {
    /// A complete protocol response (`initialize` / `tools/list` / an error) — send it as-is.
    Respond(JsonRpcResponse),
    /// A `tools/call` the host must run through the real pipeline, then wrap with
    /// [`McpAdapter::tool_result`] / [`McpAdapter::tool_error`].
    Call {
        id: Value,
        name: String,
        arguments: Value,
    },
}

/// The MCP protocol adapter — advertises a tool catalog and routes requests. Pure: it never runs a
/// control, so it is fully testable with JSON fixtures.
#[derive(Debug, Clone)]
pub struct McpAdapter {
    server_name: String,
    tools: Vec<McpTool>,
}

impl McpAdapter {
    /// An adapter advertising `tools`.
    #[must_use]
    pub fn new(server_name: impl Into<String>, tools: Vec<McpTool>) -> Self {
        Self {
            server_name: server_name.into(),
            tools,
        }
    }

    /// The built-in Aegis capability catalog exposed as MCP tools.
    #[must_use]
    pub fn aegis_default() -> Self {
        let obj = |props: Value, required: Value| json!({ "type": "object", "properties": props, "required": required });
        Self::new(
            "aegis-gateway",
            vec![
                McpTool {
                    name: "aegis.mediate".into(),
                    description: "Mediate a tool call through the Aegis broker (Rule of Two)."
                        .into(),
                    input_schema: obj(
                        json!({ "tool": {"type":"string"}, "args": {"type":"object"} }),
                        json!(["tool"]),
                    ),
                },
                McpTool {
                    name: "aegis.credentials_issue".into(),
                    description:
                        "Exchange an identity credential for a short-lived JIT credential.".into(),
                    input_schema: obj(
                        json!({ "grant_id": {"type":"string"}, "requested_ttl_secs": {"type":"integer"} }),
                        json!(["grant_id"]),
                    ),
                },
                McpTool {
                    name: "aegis.sanitize".into(),
                    description: "Run Unicode input hygiene (ingress).".into(),
                    input_schema: obj(json!({ "text": {"type":"string"} }), json!(["text"])),
                },
            ],
        )
    }

    /// The advertised tools.
    #[must_use]
    pub fn tools(&self) -> &[McpTool] {
        &self.tools
    }

    fn has_tool(&self, name: &str) -> bool {
        self.tools.iter().any(|t| t.name == name)
    }

    /// Parse a JSON-RPC body, returning a `-32700` error response on malformed JSON. The error is
    /// boxed (a `JsonRpcResponse` is large — it carries JSON `Value`s).
    pub fn parse(body: &str) -> Result<JsonRpcRequest, Box<JsonRpcResponse>> {
        serde_json::from_str(body).map_err(|e| {
            Box::new(JsonRpcResponse::err(
                Value::Null,
                -32700,
                format!("parse error: {e}"),
            ))
        })
    }

    /// Route one request. Protocol methods produce a `Respond`; a valid `tools/call` produces a
    /// `Call` for the host to execute.
    #[must_use]
    pub fn dispatch(&self, req: &JsonRpcRequest) -> McpOutcome {
        if req.jsonrpc != "2.0" {
            return McpOutcome::Respond(JsonRpcResponse::err(
                req.id.clone(),
                -32600,
                "invalid request: jsonrpc must be \"2.0\"",
            ));
        }
        match req.method.as_str() {
            "initialize" => McpOutcome::Respond(JsonRpcResponse::ok(
                req.id.clone(),
                json!({
                    "protocolVersion": "2024-11-05",
                    "serverInfo": { "name": self.server_name, "version": env!("CARGO_PKG_VERSION") },
                    "capabilities": { "tools": {} }
                }),
            )),
            "tools/list" => McpOutcome::Respond(JsonRpcResponse::ok(
                req.id.clone(),
                json!({ "tools": self.tools }),
            )),
            "tools/call" => {
                let name = req.params.get("name").and_then(Value::as_str);
                let Some(name) = name else {
                    return McpOutcome::Respond(JsonRpcResponse::err(
                        req.id.clone(),
                        -32602,
                        "invalid params: missing tool name",
                    ));
                };
                if !self.has_tool(name) {
                    return McpOutcome::Respond(JsonRpcResponse::err(
                        req.id.clone(),
                        -32602,
                        format!("unknown tool: {name}"),
                    ));
                }
                let arguments = req
                    .params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                McpOutcome::Call {
                    id: req.id.clone(),
                    name: name.to_string(),
                    arguments,
                }
            }
            other => McpOutcome::Respond(JsonRpcResponse::err(
                req.id.clone(),
                -32601,
                format!("method not found: {other}"),
            )),
        }
    }

    /// Wrap a host-produced tool result as an MCP `tools/call` success response.
    #[must_use]
    pub fn tool_result(id: Value, content: Value) -> JsonRpcResponse {
        JsonRpcResponse::ok(
            id,
            json!({ "content": [{ "type": "text", "text": content.to_string() }], "isError": false }),
        )
    }

    /// Wrap a host-side tool failure as an MCP `tools/call` error result (a non-sensitive message).
    #[must_use]
    pub fn tool_error(id: Value, message: impl Into<String>) -> JsonRpcResponse {
        JsonRpcResponse::ok(
            id,
            json!({ "content": [{ "type": "text", "text": message.into() }], "isError": true }),
        )
    }
}

// ── The front door ────────────────────────────────────────────────────────────────────────────────

/// A successfully admitted request: the tenant + scopes to attach to the downstream pipeline call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    pub tenant: TenantId,
    pub scopes: Vec<String>,
    pub key_hash: String,
}

impl Admitted {
    /// Whether the admitted key carries `scope`.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// Why a request was refused at the edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    /// No valid, enabled key.
    Unauthorized,
    /// Over the per-key request-rate budget.
    RateLimited { retry_after_ms: u64 },
}

/// The gateway front door: authenticate + rate-limit, then hand off to the pipeline.
#[derive(Debug)]
pub struct Gateway {
    keys: KeyStore,
    limiter: RateLimiter,
    mcp: McpAdapter,
}

impl Gateway {
    /// Assemble a gateway.
    #[must_use]
    pub fn new(keys: KeyStore, limiter: RateLimiter, mcp: McpAdapter) -> Self {
        Self { keys, limiter, mcp }
    }

    /// Authenticate a presented key and count it against the rate limit. On success returns the
    /// tenant/scopes to attach downstream; on failure a [`Rejection`]. Order matters: an
    /// unauthorized request is refused **before** it can consume rate budget.
    pub fn admit(&self, presented_key: &str, now_ms: u64) -> Result<Admitted, Rejection> {
        let record = self
            .keys
            .authenticate(presented_key)
            .ok_or(Rejection::Unauthorized)?;
        match self.limiter.check(&record.key_hash, now_ms) {
            RateDecision::Allow => Ok(Admitted {
                tenant: record.tenant.clone(),
                scopes: record.scopes.clone(),
                key_hash: record.key_hash.clone(),
            }),
            RateDecision::Limited { retry_after_ms } => {
                Err(Rejection::RateLimited { retry_after_ms })
            }
        }
    }

    /// The MCP adapter (advertise tools, dispatch requests).
    #[must_use]
    pub fn mcp(&self) -> &McpAdapter {
        &self.mcp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> KeyStore {
        let mut s = KeyStore::new();
        s.register(
            "secret-acme",
            TenantId::new("acme").unwrap(),
            vec!["mediate".into()],
        );
        s.register("secret-off", TenantId::default(), vec![]);
        s.disable(&hash_secret("secret-off"));
        s
    }

    #[test]
    fn auth_hashes_keys_and_denies_bad_or_disabled() {
        let s = store();
        let ok = s.authenticate("secret-acme").unwrap();
        assert_eq!(ok.tenant.as_str(), "acme");
        assert!(ok.has_scope("mediate"));
        // The stored record never holds the secret.
        assert!(s.to_json().unwrap().contains(&hash_secret("secret-acme")));
        assert!(!s.to_json().unwrap().contains("secret-acme"));
        // Wrong key and disabled key both fail closed.
        assert!(s.authenticate("wrong").is_none());
        assert!(s.authenticate("secret-off").is_none());
    }

    #[test]
    fn key_store_json_round_trips() {
        let s = store();
        let back = KeyStore::from_json(&s.to_json().unwrap()).unwrap();
        assert!(back.authenticate("secret-acme").is_some());
        assert!(KeyStore::from_json("{}")
            .unwrap()
            .authenticate("x")
            .is_none());
    }

    #[test]
    fn rate_limiter_allows_up_to_the_cap_then_limits_then_resets() {
        let rl = RateLimiter::per_second(2);
        // Two allowed in the window.
        assert!(rl.check("k", 0).is_allow());
        assert!(rl.check("k", 100).is_allow());
        // Third within the same second is limited, with a retry hint.
        match rl.check("k", 200) {
            RateDecision::Limited { retry_after_ms } => assert_eq!(retry_after_ms, 800),
            other => panic!("expected Limited, got {other:?}"),
        }
        // A different key has its own budget.
        assert!(rl.check("other", 200).is_allow());
        // After the window rolls over, the first key is allowed again.
        assert!(rl.check("k", 1000).is_allow());
    }

    #[test]
    fn gateway_admit_orders_auth_before_rate_limit() {
        let gw = Gateway::new(
            store(),
            RateLimiter::per_second(1),
            McpAdapter::aegis_default(),
        );
        // Unauthorized never consumes rate budget.
        assert_eq!(gw.admit("nope", 0), Err(Rejection::Unauthorized));
        // First authorized request is admitted with the tenant/scopes.
        let a = gw.admit("secret-acme", 0).unwrap();
        assert_eq!(a.tenant.as_str(), "acme");
        assert!(a.has_scope("mediate"));
        // Second within the same second is rate-limited.
        match gw.admit("secret-acme", 100) {
            Err(Rejection::RateLimited { retry_after_ms }) => assert_eq!(retry_after_ms, 900),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    fn adapter() -> McpAdapter {
        McpAdapter::aegis_default()
    }

    #[test]
    fn mcp_initialize_and_tools_list() {
        let a = adapter();
        let init = a.dispatch(&JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(1),
            method: "initialize".into(),
            params: json!({}),
        });
        match init {
            McpOutcome::Respond(r) => {
                assert!(!r.is_error());
                let v = serde_json::to_value(&r).unwrap();
                assert_eq!(v["result"]["serverInfo"]["name"], "aegis-gateway");
            }
            other => panic!("expected Respond, got {other:?}"),
        }
        let list = a.dispatch(&JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(2),
            method: "tools/list".into(),
            params: json!({}),
        });
        match list {
            McpOutcome::Respond(r) => {
                let v = serde_json::to_value(&r).unwrap();
                assert_eq!(v["result"]["tools"].as_array().unwrap().len(), 3);
            }
            other => panic!("expected Respond, got {other:?}"),
        }
    }

    #[test]
    fn mcp_tools_call_routes_known_and_rejects_unknown() {
        let a = adapter();
        // A known tool routes to the host for execution.
        let call = a.dispatch(&JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(7),
            method: "tools/call".into(),
            params: json!({ "name": "aegis.mediate", "arguments": { "tool": "web.fetch" } }),
        });
        match call {
            McpOutcome::Call {
                id,
                name,
                arguments,
            } => {
                assert_eq!(id, json!(7));
                assert_eq!(name, "aegis.mediate");
                assert_eq!(arguments["tool"], "web.fetch");
            }
            other => panic!("expected Call, got {other:?}"),
        }
        // An unknown tool is a -32602.
        let bad = a.dispatch(&JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(8),
            method: "tools/call".into(),
            params: json!({ "name": "aegis.destroy" }),
        });
        match bad {
            McpOutcome::Respond(r) => assert_eq!(r.error.unwrap().code, -32602),
            other => panic!("expected error Respond, got {other:?}"),
        }
    }

    #[test]
    fn mcp_rejects_bad_version_and_unknown_method_and_parse_error() {
        let a = adapter();
        // Wrong jsonrpc version -> -32600.
        let bad_ver = a.dispatch(&JsonRpcRequest {
            jsonrpc: "1.0".into(),
            id: json!(1),
            method: "initialize".into(),
            params: json!({}),
        });
        assert!(
            matches!(bad_ver, McpOutcome::Respond(r) if r.error.as_ref().unwrap().code == -32600)
        );
        // Unknown method -> -32601.
        let unknown = a.dispatch(&JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(1),
            method: "nope".into(),
            params: json!({}),
        });
        assert!(
            matches!(unknown, McpOutcome::Respond(r) if r.error.as_ref().unwrap().code == -32601)
        );
        // Malformed JSON -> parse() returns a -32700 response.
        let parse_err = McpAdapter::parse("{not json").unwrap_err();
        assert_eq!(parse_err.error.unwrap().code, -32700);
    }

    #[test]
    fn misc_accessors_and_parse_success() {
        // Gateway exposes its MCP adapter.
        let gw = Gateway::new(
            store(),
            RateLimiter::per_second(1),
            McpAdapter::aegis_default(),
        );
        assert_eq!(gw.mcp().tools().len(), 3);
        // Disabling a missing key reports no change; the predicate on Limited is false.
        let mut s = KeyStore::new();
        assert!(!s.disable("no-such-hash"));
        assert!(!RateDecision::Limited { retry_after_ms: 5 }.is_allow());
        // parse() succeeds on valid JSON-RPC.
        let req = McpAdapter::parse(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).unwrap();
        assert_eq!(req.method, "tools/list");
    }

    #[test]
    fn mcp_tool_result_and_error_wrappers() {
        let ok = McpAdapter::tool_result(json!(1), json!({ "decision": "allow" }));
        let v = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["result"]["isError"], false);
        let err = McpAdapter::tool_error(json!(1), "denied");
        let v = serde_json::to_value(&err).unwrap();
        assert_eq!(v["result"]["isError"], true);
    }
}
