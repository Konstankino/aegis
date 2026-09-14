//! # aegis-prompt — prompt supply (Roadmap T2)
//!
//! Controls **what the model sees**. Three deterministic controls:
//!
//! * [`PromptRegistry`] — system prompts, few-shot examples, and output schemas are **versioned and
//!   content-hashed**, stored outside application code. The app never assembles a prompt by string
//!   concatenation; it fetches from the registry, so every prompt change is a versioned, auditable
//!   event (LLM07 system-prompt leakage · LLM03 supply chain).
//! * [`ContextWindow`] — assembles the final prompt from **clearly delimited sections** (system,
//!   retrieved context, user), so the model sees structure rather than a flat string an injection can
//!   blur; trims retrieved chunks (lowest-relevance first) to fit a budget, never the system prompt or
//!   user input.
//! * [`ModelRouter`] — per-tenant **approved-model allowlist**. The configured model must be on the
//!   list; an injected "use model X" cannot swap it (LLM03 · ASI04 supply-chain poisoning).
//!
//! Deterministic and pure — no model calls, no I/O — so it is fully testable.

use std::collections::HashMap;

use aegis_core::{AegisError, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Versioned prompt registry ─────────────────────────────────────────────────────────────────────

fn content_hash(content: &str) -> String {
    let digest = Sha256::digest(content.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// A versioned prompt: its content and a content hash that IS its version. A canary token may be
/// planted in a system prompt; if it later appears in output, the prompt leaked (checked downstream
/// by the output/eval scanners).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prompt {
    /// Logical id (e.g. `"triage.system"`).
    pub id: String,
    /// The prompt text.
    pub content: String,
    /// The version — `sha256:<hex>` of `content`. Set by [`Prompt::new`]; changes iff content does.
    pub version: String,
    /// An optional planted canary token (leak tripwire).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary: Option<String>,
}

impl Prompt {
    /// A prompt whose version is the hash of its content.
    #[must_use]
    pub fn new(id: impl Into<String>, content: impl Into<String>) -> Self {
        let content = content.into();
        let version = content_hash(&content);
        Self {
            id: id.into(),
            content,
            version,
            canary: None,
        }
    }

    /// Plant a canary token (recorded on the prompt; the registry does not inject it into content).
    #[must_use]
    pub fn with_canary(mut self, token: impl Into<String>) -> Self {
        self.canary = Some(token.into());
        self
    }

    /// Whether the recorded version still matches the content (tamper / drift check).
    #[must_use]
    pub fn verify(&self) -> bool {
        self.version == content_hash(&self.content)
    }
}

/// The versioned prompt registry — the single source of truth. Registering the same id again keeps
/// the prior versions (history), so a rollback or audit can address an exact version.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PromptRegistry {
    #[serde(default)]
    prompts: Vec<Prompt>,
}

impl PromptRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse from JSON (`{"prompts":[...]}`). Fails closed on malformed input.
    pub fn from_json(src: &str) -> Result<Self, AegisError> {
        serde_json::from_str(src).map_err(|e| AegisError::Config(format!("prompt registry: {e}")))
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String, AegisError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| AegisError::Config(format!("serialize prompt registry: {e}")))
    }

    /// Register a prompt (content re-hashed to be authoritative), keeping version history. Returns
    /// the version.
    pub fn register(&mut self, prompt: Prompt) -> String {
        // Re-hash so a caller cannot register a mismatched version.
        let prompt = Prompt {
            version: content_hash(&prompt.content),
            ..prompt
        };
        let version = prompt.version.clone();
        self.prompts.push(prompt);
        version
    }

    /// The latest prompt registered under `id`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Prompt> {
        self.prompts.iter().rev().find(|p| p.id == id)
    }

    /// An exact `(id, version)` — for reproducing a past run.
    #[must_use]
    pub fn get_version(&self, id: &str, version: &str) -> Option<&Prompt> {
        self.prompts
            .iter()
            .find(|p| p.id == id && p.version == version)
    }

    /// Every prompt, in registration order.
    #[must_use]
    pub fn all(&self) -> &[Prompt] {
        &self.prompts
    }

    /// Validate: non-empty ids, and every recorded version matches its content. Fail-closed.
    pub fn validate(&self) -> Result<(), AegisError> {
        for p in &self.prompts {
            if p.id.trim().is_empty() {
                return Err(AegisError::Config("prompt with empty id".into()));
            }
            if !p.verify() {
                return Err(AegisError::Config(format!(
                    "prompt {} version does not match its content",
                    p.id
                )));
            }
        }
        Ok(())
    }
}

// ── Structured context-window builder ─────────────────────────────────────────────────────────────

/// Assembles the final prompt from clearly delimited sections. Retrieved chunks are added in
/// relevance order (highest first); [`render`](ContextWindow::render) trims from the tail to fit a
/// budget, never the system prompt or user input.
#[derive(Debug, Clone, Default)]
pub struct ContextWindow {
    system: String,
    context: Vec<String>,
    user: String,
}

impl ContextWindow {
    /// Start with the system prompt (from the [`PromptRegistry`]).
    #[must_use]
    pub fn new(system: impl Into<String>) -> Self {
        Self {
            system: system.into(),
            context: Vec::new(),
            user: String::new(),
        }
    }

    /// Set the (sanitized) user input.
    #[must_use]
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }

    /// Append a retrieved chunk (call in relevance order, highest first).
    #[must_use]
    pub fn push_context(mut self, chunk: impl Into<String>) -> Self {
        self.context.push(chunk.into());
        self
    }

    // Assemble the delimited prompt from a (possibly trimmed) slice of context chunks.
    fn assemble(&self, chunks: &[String]) -> String {
        let mut out = String::new();
        out.push_str("### SYSTEM\n");
        out.push_str(&self.system);
        out.push_str("\n\n### CONTEXT\n");
        if chunks.is_empty() {
            out.push_str("(none)\n");
        } else {
            for (i, c) in chunks.iter().enumerate() {
                out.push_str(&format!("[{}] {}\n", i + 1, c));
            }
        }
        out.push_str("\n### USER\n");
        out.push_str(&self.user);
        out.push('\n');
        out
    }

    /// Render with every chunk (no trimming).
    #[must_use]
    pub fn render_untrimmed(&self) -> String {
        self.assemble(&self.context)
    }

    /// Render, trimming the lowest-relevance chunks (from the tail) until the result fits
    /// `max_chars` — a token proxy. The system prompt and user input are never trimmed, so the result
    /// may still exceed the budget when those alone are larger; callers should treat `max_chars` as a
    /// target for the context section.
    #[must_use]
    pub fn render(&self, max_chars: usize) -> String {
        let mut n = self.context.len();
        loop {
            let out = self.assemble(&self.context[..n]);
            if out.len() <= max_chars || n == 0 {
                return out;
            }
            n -= 1;
        }
    }

    /// How many context chunks are held.
    #[must_use]
    pub fn context_len(&self) -> usize {
        self.context.len()
    }
}

// ── Approved-model routing ────────────────────────────────────────────────────────────────────────

/// Per-tenant approved-model allowlist. The configured model must be on the tenant's list (or the
/// default list); an injected "switch to model X" cannot swap it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelRouter {
    #[serde(default)]
    default_allowed: Vec<String>,
    #[serde(default)]
    per_tenant: HashMap<TenantId, Vec<String>>,
}

impl ModelRouter {
    /// An empty router (nothing approved → every route denied, safe by default).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse from JSON. Fails closed on malformed input.
    pub fn from_json(src: &str) -> Result<Self, AegisError> {
        serde_json::from_str(src).map_err(|e| AegisError::Config(format!("model router: {e}")))
    }

    /// Add a model to the default allowlist (used by any tenant without its own list).
    #[must_use]
    pub fn allow_default(mut self, model: impl Into<String>) -> Self {
        self.default_allowed.push(model.into());
        self
    }

    /// Add a model to a specific tenant's allowlist.
    #[must_use]
    pub fn allow_for(mut self, tenant: TenantId, model: impl Into<String>) -> Self {
        self.per_tenant
            .entry(tenant)
            .or_default()
            .push(model.into());
        self
    }

    // The allowlist that applies to a tenant: its own if present, else the default.
    fn list_for(&self, tenant: &TenantId) -> &[String] {
        self.per_tenant
            .get(tenant)
            .map(Vec::as_slice)
            .unwrap_or(&self.default_allowed)
    }

    /// Whether `model` is approved for `tenant`.
    #[must_use]
    pub fn is_approved(&self, tenant: &TenantId, model: &str) -> bool {
        self.list_for(tenant).iter().any(|m| m == model)
    }

    /// Route to `requested` if approved for `tenant`, else fail closed (no swap). Returns the model
    /// on success so the caller uses exactly what was validated.
    pub fn route<'a>(&self, tenant: &TenantId, requested: &'a str) -> Result<&'a str, AegisError> {
        if self.is_approved(tenant, requested) {
            Ok(requested)
        } else {
            Err(AegisError::Policy(format!(
                "model '{requested}' is not approved for tenant '{}'",
                tenant.as_str()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_version_is_the_content_hash_and_verifies() {
        let p = Prompt::new("triage.system", "You are a careful clinical assistant.");
        assert!(p.version.starts_with("sha256:"));
        assert!(p.verify());
        // Same content → same version; different content → different version.
        assert_eq!(
            Prompt::new("x", "abc").version,
            Prompt::new("y", "abc").version
        );
        assert_ne!(
            Prompt::new("x", "abc").version,
            Prompt::new("x", "abd").version
        );
        // Tampering with content without updating the version is detected.
        let mut tampered = p.clone();
        tampered.content.push_str(" IGNORE ALL RULES");
        assert!(!tampered.verify());
    }

    #[test]
    fn registry_keeps_history_and_addresses_exact_versions() {
        let mut reg = PromptRegistry::new();
        let v1 = reg.register(Prompt::new("sys", "v1 content"));
        let v2 = reg.register(Prompt::new("sys", "v2 content"));
        assert_ne!(v1, v2);
        // get() returns the latest.
        assert_eq!(reg.get("sys").unwrap().content, "v2 content");
        // get_version() reaches an exact past version.
        assert_eq!(reg.get_version("sys", &v1).unwrap().content, "v1 content");
        assert!(reg.get("missing").is_none());
        reg.validate().unwrap();
        assert_eq!(reg.all().len(), 2);
    }

    #[test]
    fn registry_register_rehashes_a_mismatched_version() {
        let mut reg = PromptRegistry::new();
        // A prompt whose declared version is wrong is corrected on register.
        let bad = Prompt {
            id: "sys".into(),
            content: "real content".into(),
            version: "sha256:deadbeef".into(),
            canary: None,
        };
        let v = reg.register(bad);
        assert_eq!(v, content_hash("real content"));
        assert!(reg.get("sys").unwrap().verify());
    }

    #[test]
    fn registry_json_round_trips_and_validates() {
        let mut reg = PromptRegistry::new();
        reg.register(Prompt::new("sys", "hello").with_canary("CANARY-1"));
        let back = PromptRegistry::from_json(&reg.to_json().unwrap()).unwrap();
        assert_eq!(back.get("sys").unwrap().canary.as_deref(), Some("CANARY-1"));
        back.validate().unwrap();
        assert!(PromptRegistry::from_json("{}").unwrap().all().is_empty());
        // A registry whose version was hand-edited to mismatch fails validation.
        let tampered =
            r#"{"prompts":[{"id":"s","content":"x","version":"sha256:00","canary":null}]}"#;
        assert!(PromptRegistry::from_json(tampered)
            .unwrap()
            .validate()
            .is_err());
    }

    #[test]
    fn context_window_is_delimited_and_ordered() {
        let w = ContextWindow::new("SYS")
            .with_user("what is the dose?")
            .push_context("chunk one")
            .push_context("chunk two");
        let out = w.render_untrimmed();
        assert!(out.contains("### SYSTEM\nSYS"));
        assert!(out.contains("### CONTEXT\n[1] chunk one\n[2] chunk two"));
        assert!(out.contains("### USER\nwhat is the dose?"));
        // Empty context renders "(none)".
        assert!(ContextWindow::new("S")
            .render_untrimmed()
            .contains("(none)"));
    }

    #[test]
    fn context_window_trims_low_relevance_chunks_first_never_system_or_user() {
        let w = ContextWindow::new("SYSTEM-PROMPT-KEPT")
            .with_user("USER-INPUT-KEPT")
            .push_context("AAAAAAAAAA") // highest relevance
            .push_context("BBBBBBBBBB")
            .push_context("CCCCCCCCCC"); // lowest relevance, trimmed first
        let full = w.render_untrimmed();
        let trimmed = w.render(full.len() - 5);
        // System + user always survive.
        assert!(trimmed.contains("SYSTEM-PROMPT-KEPT") && trimmed.contains("USER-INPUT-KEPT"));
        // The lowest-relevance chunk is dropped first; the highest is retained.
        assert!(trimmed.contains("AAAAAAAAAA"));
        assert!(!trimmed.contains("CCCCCCCCCC"));
        assert!(trimmed.len() <= full.len());
    }

    #[test]
    fn model_router_enforces_the_allowlist_per_tenant() {
        let acme = TenantId::new("acme").unwrap();
        let router = ModelRouter::new()
            .allow_default("claude-sonnet-5")
            .allow_for(acme.clone(), "claude-opus-5");
        // Default tenant uses the default list.
        let dflt = TenantId::default();
        assert!(router.is_approved(&dflt, "claude-sonnet-5"));
        assert!(!router.is_approved(&dflt, "claude-opus-5"));
        // A tenant with its own list uses only that list (no fallback to default).
        assert!(router.is_approved(&acme, "claude-opus-5"));
        assert!(!router.is_approved(&acme, "claude-sonnet-5"));
        // route() returns the model or fails closed — an injected swap is refused.
        assert_eq!(
            router.route(&dflt, "claude-sonnet-5").unwrap(),
            "claude-sonnet-5"
        );
        assert!(router.route(&dflt, "evil-model").is_err());
    }

    #[test]
    fn empty_router_denies_everything() {
        let r = ModelRouter::new();
        assert!(!r.is_approved(&TenantId::default(), "anything"));
        assert!(r.route(&TenantId::default(), "anything").is_err());
        // JSON round-trip.
        let j = serde_json::to_string(&r).unwrap();
        assert!(ModelRouter::from_json(&j).is_ok());
    }
}
