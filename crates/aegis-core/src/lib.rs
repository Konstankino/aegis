//! # aegis-core
//!
//! The shared trust vocabulary for the Aegis guardrail plane. Three small types make the
//! trust boundary a **compile-time fact, not a convention** (architecture-considerations.md
//! §2.3):
//!
//! * [`Provenance`] — where content came from, and therefore how much it is trusted.
//! * [`Tagged`] — content is never a bare `String` once it enters Aegis; it carries its origin.
//! * [`Capability`] — the Rule-of-Two bits: every tool call is classified on three axes, and
//!   the [lethal trifecta](Capability::is_trifecta) (all three at once) is the high-impact
//!   condition that must never be auto-approved.
//!
//! Every other Aegis crate depends on this one. It performs no I/O and has no external
//! effects; it only defines the types the deterministic controls reason about.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Where a piece of content originated, and therefore how much it can be trusted.
///
/// Ordered from most to least trusted. When several tagged values are combined, the
/// **least-trusted** origin wins (see [`Provenance::combine`]) — trust never launders upward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// Operator/system-authored content (prompts, policy). Most trusted.
    System,
    /// The authenticated end user of this session.
    User,
    /// First-party but not fully vetted (internal tools, cached derivations).
    SemiTrusted,
    /// Anything a stranger could influence: web pages, documents, tool outputs, peer agents.
    Untrusted,
}

impl Provenance {
    /// Trust rank: lower is more trusted. Used to make "least trusted wins" explicit.
    #[must_use]
    pub const fn trust_rank(self) -> u8 {
        match self {
            Provenance::System => 0,
            Provenance::User => 1,
            Provenance::SemiTrusted => 2,
            Provenance::Untrusted => 3,
        }
    }

    /// True if this origin is untrusted enough to set the Rule-of-Two "reads untrusted" leg.
    ///
    /// `SemiTrusted` and `Untrusted` both count: neither can be assumed free of
    /// attacker-influenced content, so both taint a session's untrusted leg.
    #[must_use]
    pub const fn is_tainting(self) -> bool {
        self.trust_rank() >= Provenance::SemiTrusted.trust_rank()
    }

    /// Combine two origins, keeping the least-trusted (highest-rank) of the two.
    #[must_use]
    pub fn combine(self, other: Provenance) -> Provenance {
        if other.trust_rank() > self.trust_rank() {
            other
        } else {
            self
        }
    }
}

/// A value that carries its [`Provenance`]. Content is never a bare value once it enters
/// Aegis — the origin travels with it so an injection can never lose its "untrusted" label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tagged<T> {
    pub value: T,
    pub origin: Provenance,
}

impl<T> Tagged<T> {
    /// Wrap a value with an explicit origin.
    pub const fn new(value: T, origin: Provenance) -> Self {
        Self { value, origin }
    }

    /// Wrap trusted system-authored content.
    pub const fn system(value: T) -> Self {
        Self::new(value, Provenance::System)
    }

    /// Wrap content originating from the authenticated user.
    pub const fn user(value: T) -> Self {
        Self::new(value, Provenance::User)
    }

    /// Wrap content from an untrusted source (web, document, tool output, peer agent).
    pub const fn untrusted(value: T) -> Self {
        Self::new(value, Provenance::Untrusted)
    }

    /// Transform the inner value while **preserving the origin**. Provenance cannot be
    /// dropped by transforming — that is the whole point of the type.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Tagged<U> {
        Tagged {
            value: f(self.value),
            origin: self.origin,
        }
    }

    /// Borrow the inner value together with its origin.
    pub const fn as_ref(&self) -> Tagged<&T> {
        Tagged {
            value: &self.value,
            origin: self.origin,
        }
    }

    /// True if this value's origin taints the session's untrusted leg.
    pub const fn is_tainting(&self) -> bool {
        self.origin.is_tainting()
    }
}

/// The Rule-of-Two bits (architecture-considerations.md §2.3 / §4).
///
/// Every tool call is classified on three axes. The agent is dangerous only with **all three
/// at once** — the *lethal trifecta*:
///
/// * **(A)** [`reads_untrusted`](Capability::reads_untrusted) — has touched untrusted input
///   this session (a note handed in from the street).
/// * **(B)** [`reads_sensitive`](Capability::reads_sensitive) — can reach private/regulated
///   data (the safe).
/// * **(C)** [`external_effect`](Capability::external_effect) — state change or outbound
///   communication (the door to the outside).
///
/// Within a session capability taint is **monotonic**: it only ever accumulates
/// ([`accumulate`](Capability::accumulate)). An agent that has touched untrusted input cannot
/// later quietly regain trust to reach sensitive data and exfiltrate it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// (A) Touched untrusted (or semi-trusted) input during this session.
    pub reads_untrusted: bool,
    /// (B) Can reach private / regulated / sensitive data.
    pub reads_sensitive: bool,
    /// (C) Produces an external effect: state change or outbound communication.
    pub external_effect: bool,
}

impl Capability {
    /// A capability with no legs set.
    pub const NONE: Capability = Capability {
        reads_untrusted: false,
        reads_sensitive: false,
        external_effect: false,
    };

    /// The lethal trifecta: all three legs at once is the high-impact condition that must
    /// never be auto-approved (Rule of Two → human approval).
    #[must_use]
    pub const fn is_trifecta(&self) -> bool {
        self.reads_untrusted && self.reads_sensitive && self.external_effect
    }

    /// How many of the three legs are currently set (0..=3).
    #[must_use]
    pub const fn active_legs(&self) -> u8 {
        self.reads_untrusted as u8 + self.reads_sensitive as u8 + self.external_effect as u8
    }

    /// True when exactly two legs are set — the [A,B]/[A,C]/[B,C] "residual-risk" band that
    /// the broker may allow but should surface as an explicit decision.
    #[must_use]
    pub const fn is_two_leg(&self) -> bool {
        self.active_legs() == 2
    }

    /// **Monotonically** merge another capability into this one (bitwise OR of every leg).
    /// Taint only ever grows within a session — it can never be cleared here.
    pub fn accumulate(&mut self, other: &Capability) {
        self.reads_untrusted |= other.reads_untrusted;
        self.reads_sensitive |= other.reads_sensitive;
        self.external_effect |= other.external_effect;
    }

    /// The union of two capabilities, without mutating either.
    #[must_use]
    pub fn union(mut self, other: &Capability) -> Capability {
        self.accumulate(other);
        self
    }
}

/// How reversible the consequence of a tool call is (architecture-considerations.md §4 step 5).
///
/// Even when policy and Rule-of-Two allow a call, an irreversible/high-consequence action is
/// routed to a human rather than auto-approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Consequence {
    /// Cheap and reversible (a read, an idempotent write). Safe to auto-approve if policy allows.
    LowReversible,
    /// High-impact or irreversible (send, publish, delete, transfer). Always escalate to a human.
    HighOrIrreversible,
}

/// Shared error type for the Aegis plane.
#[derive(Debug, thiserror::Error)]
pub enum AegisError {
    /// A tool call's arguments did not match the tool's declared schema.
    #[error("argument schema violation: {0}")]
    SchemaViolation(String),
    /// A referenced tool is not present in the registry (fail-closed on ambiguity).
    #[error("unknown tool: {0}")]
    UnknownTool(String),
    /// Failed to parse or load a policy / configuration artifact.
    #[error("policy error: {0}")]
    Policy(String),
    /// Failed to parse or load configuration.
    #[error("configuration error: {0}")]
    Config(String),
    /// An identifier (tenant, etc.) failed validation.
    #[error("invalid identifier: {0}")]
    InvalidId(String),
}

// ── Multi-tenancy (Roadmap T0) ────────────────────────────────────────────────────────────────────

/// A tenant identifier — the multi-tenant dimension threaded through the plane (per-tenant config,
/// ACLs, budgets, kill-switch scope, and audit).
///
/// A stable, operator-assigned **slug**, not a random UUID: tenant ids appear in policy files and
/// audit trails, so they must be human-meaningful and reproducible. Single-tenant deployments use
/// [`TenantId::default`] (`"default"`), so tenancy is opt-in and changes nothing until adopted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TenantId(String);

impl TenantId {
    /// The reserved id for single-tenant deployments.
    pub const DEFAULT: &'static str = "default";

    /// Validate and construct. Ids are lowercase slugs: 1–64 chars of `[a-z0-9._-]`, which keeps
    /// them safe as path segments, config keys, and audit tags. Fails closed on anything else.
    pub fn new(id: impl Into<String>) -> Result<Self, AegisError> {
        let id = id.into();
        let ok = (1..=64).contains(&id.len())
            && id.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            });
        if ok {
            Ok(Self(id))
        } else {
            Err(AegisError::InvalidId(format!(
                "tenant id '{id}' must be 1–64 chars of [a-z0-9._-]"
            )))
        }
    }

    /// The id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the reserved single-tenant default.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.0 == Self::DEFAULT
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self(Self::DEFAULT.to_string())
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for TenantId {
    type Error = AegisError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl From<TenantId> for String {
    fn from(t: TenantId) -> String {
        t.0
    }
}

// ── Unified decision vocabulary (Roadmap T0) ──────────────────────────────────────────────────────

/// The single outcome vocabulary every gate can speak, independent of its domain-specific enum.
///
/// The rich per-domain decisions (`broker::Decision`, `EgressDecision`, `AuthDecision`, …) map
/// **into** this via `From` adapters defined in their own crates. `PolicyDecision` is the lingua
/// franca for spans, the gateway, and audit — it does **not** replace those enums, which stay the
/// authoritative, detailed types each control returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", content = "reason", rename_all = "snake_case")]
pub enum PolicyDecision {
    /// The action is permitted.
    Allow,
    /// The action is refused. Carries a fixed, non-sensitive reason safe to log.
    Deny(Cow<'static, str>),
    /// Permitted in principle but requires a human (the trifecta, or a high/irreversible effect).
    Escalate(Cow<'static, str>),
}

impl PolicyDecision {
    /// A denial with a static reason.
    #[must_use]
    pub fn deny(reason: &'static str) -> Self {
        PolicyDecision::Deny(Cow::Borrowed(reason))
    }
    /// An escalation with a static reason.
    #[must_use]
    pub fn escalate(reason: &'static str) -> Self {
        PolicyDecision::Escalate(Cow::Borrowed(reason))
    }
    /// Whether the action may proceed automatically (neither denied nor escalated).
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }
    /// Whether the action was refused outright.
    #[must_use]
    pub fn is_deny(&self) -> bool {
        matches!(self, PolicyDecision::Deny(_))
    }
    /// Whether the action needs a human.
    #[must_use]
    pub fn is_escalate(&self) -> bool {
        matches!(self, PolicyDecision::Escalate(_))
    }
    /// The reason string for a deny/escalate, if any.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            PolicyDecision::Allow => None,
            PolicyDecision::Deny(r) | PolicyDecision::Escalate(r) => Some(r),
        }
    }
    /// A short, non-sensitive label (`allow` | `deny` | `escalate`) for spans and metrics.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            PolicyDecision::Allow => "allow",
            PolicyDecision::Deny(_) => "deny",
            PolicyDecision::Escalate(_) => "escalate",
        }
    }
}

// ── OWASP risk identifiers (Roadmap T0) ───────────────────────────────────────────────────────────

/// The OWASP risk identifiers the plane maps to — typed, not magic strings, so errors, spans, and
/// the coverage matrix are searchable by risk category. Three separate OWASP GenAI lists:
/// `LLM01..LLM10` (OWASP Top-10 for LLM Applications, 2025), `ASI01..ASI10` (OWASP Top-10 for
/// Agentic Applications / Agentic Security Initiative, 2026), and `AST01..AST10` (OWASP Agentic
/// Skills Top 10, v1.0 2026 — public-review/pre-release at time of mapping). The lists are mapped
/// independently; a control covering a risk in one list does not count for another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Owasp {
    Llm01,
    Llm02,
    Llm03,
    Llm04,
    Llm05,
    Llm06,
    Llm07,
    Llm08,
    Llm09,
    Llm10,
    Asi01,
    Asi02,
    Asi03,
    Asi04,
    Asi05,
    Asi06,
    Asi07,
    Asi08,
    Asi09,
    Asi10,
    Ast01,
    Ast02,
    Ast03,
    Ast04,
    Ast05,
    Ast06,
    Ast07,
    Ast08,
    Ast09,
    Ast10,
}

impl Owasp {
    /// Every risk id, in order — for building the coverage matrix.
    pub const ALL: [Owasp; 30] = [
        Owasp::Llm01,
        Owasp::Llm02,
        Owasp::Llm03,
        Owasp::Llm04,
        Owasp::Llm05,
        Owasp::Llm06,
        Owasp::Llm07,
        Owasp::Llm08,
        Owasp::Llm09,
        Owasp::Llm10,
        Owasp::Asi01,
        Owasp::Asi02,
        Owasp::Asi03,
        Owasp::Asi04,
        Owasp::Asi05,
        Owasp::Asi06,
        Owasp::Asi07,
        Owasp::Asi08,
        Owasp::Asi09,
        Owasp::Asi10,
        Owasp::Ast01,
        Owasp::Ast02,
        Owasp::Ast03,
        Owasp::Ast04,
        Owasp::Ast05,
        Owasp::Ast06,
        Owasp::Ast07,
        Owasp::Ast08,
        Owasp::Ast09,
        Owasp::Ast10,
    ];

    /// The canonical code, e.g. `"LLM06"` or `"ASI03"`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Owasp::Llm01 => "LLM01",
            Owasp::Llm02 => "LLM02",
            Owasp::Llm03 => "LLM03",
            Owasp::Llm04 => "LLM04",
            Owasp::Llm05 => "LLM05",
            Owasp::Llm06 => "LLM06",
            Owasp::Llm07 => "LLM07",
            Owasp::Llm08 => "LLM08",
            Owasp::Llm09 => "LLM09",
            Owasp::Llm10 => "LLM10",
            Owasp::Asi01 => "ASI01",
            Owasp::Asi02 => "ASI02",
            Owasp::Asi03 => "ASI03",
            Owasp::Asi04 => "ASI04",
            Owasp::Asi05 => "ASI05",
            Owasp::Asi06 => "ASI06",
            Owasp::Asi07 => "ASI07",
            Owasp::Asi08 => "ASI08",
            Owasp::Asi09 => "ASI09",
            Owasp::Asi10 => "ASI10",
            Owasp::Ast01 => "AST01",
            Owasp::Ast02 => "AST02",
            Owasp::Ast03 => "AST03",
            Owasp::Ast04 => "AST04",
            Owasp::Ast05 => "AST05",
            Owasp::Ast06 => "AST06",
            Owasp::Ast07 => "AST07",
            Owasp::Ast08 => "AST08",
            Owasp::Ast09 => "AST09",
            Owasp::Ast10 => "AST10",
        }
    }

    /// The short human-readable risk name.
    #[must_use]
    pub fn title(&self) -> &'static str {
        match self {
            Owasp::Llm01 => "Prompt injection",
            Owasp::Llm02 => "Sensitive information disclosure",
            Owasp::Llm03 => "Supply chain",
            Owasp::Llm04 => "Data and model poisoning",
            Owasp::Llm05 => "Improper output handling",
            Owasp::Llm06 => "Excessive agency",
            Owasp::Llm07 => "System prompt leakage",
            Owasp::Llm08 => "Vector and embedding weakness",
            Owasp::Llm09 => "Misinformation",
            Owasp::Llm10 => "Unbounded consumption",
            Owasp::Asi01 => "Agent goal hijack",
            Owasp::Asi02 => "Tool misuse and exploitation",
            Owasp::Asi03 => "Identity and privilege abuse",
            Owasp::Asi04 => "Supply chain poisoning",
            Owasp::Asi05 => "Insecure code execution",
            Owasp::Asi06 => "Memory poisoning",
            Owasp::Asi07 => "Insecure inter-agent communication",
            Owasp::Asi08 => "Cascading failures",
            Owasp::Asi09 => "Human-agent trust exploitation",
            Owasp::Asi10 => "Rogue agents",
            Owasp::Ast01 => "Malicious skills",
            Owasp::Ast02 => "Supply-chain compromise",
            Owasp::Ast03 => "Over-privileged skills",
            Owasp::Ast04 => "Insecure metadata",
            Owasp::Ast05 => "Untrusted external instructions",
            Owasp::Ast06 => "Weak isolation",
            Owasp::Ast07 => "Update drift",
            Owasp::Ast08 => "Poor scanning",
            Owasp::Ast09 => "No governance",
            Owasp::Ast10 => "Cross-platform reuse",
        }
    }
}

impl fmt::Display for Owasp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

#[cfg(test)]
mod t0_tests {
    use super::*;

    #[test]
    fn tenant_id_validates_and_defaults() {
        assert_eq!(TenantId::default().as_str(), "default");
        assert!(TenantId::default().is_default());
        assert_eq!(
            TenantId::new("acme-health.1").unwrap().as_str(),
            "acme-health.1"
        );
        assert!(TenantId::new("").is_err());
        assert!(TenantId::new("Has Space").is_err());
        assert!(TenantId::new("UPPER").is_err());
        assert!(TenantId::new("a".repeat(65)).is_err());
    }

    #[test]
    fn tenant_id_round_trips_through_serde_with_validation() {
        let t = TenantId::new("clinic-7").unwrap();
        let j = serde_json::to_string(&t).unwrap();
        assert_eq!(j, "\"clinic-7\"");
        assert_eq!(serde_json::from_str::<TenantId>(&j).unwrap(), t);
        // Deserialization enforces the same validation (fails closed on a bad id).
        assert!(serde_json::from_str::<TenantId>("\"Bad Id\"").is_err());
    }

    #[test]
    fn policy_decision_predicates_and_serde() {
        assert!(PolicyDecision::Allow.is_allow());
        assert_eq!(PolicyDecision::deny("nope").reason(), Some("nope"));
        assert_eq!(PolicyDecision::escalate("human").label(), "escalate");
        let d = PolicyDecision::deny("blocked");
        let j = serde_json::to_string(&d).unwrap();
        assert_eq!(serde_json::from_str::<PolicyDecision>(&j).unwrap(), d);
    }

    #[test]
    fn owasp_codes_titles_and_serde() {
        assert_eq!(Owasp::Llm06.code(), "LLM06");
        assert_eq!(Owasp::Asi03.to_string(), "ASI03");
        assert_eq!(Owasp::Ast04.code(), "AST04");
        assert_eq!(Owasp::Ast04.title(), "Insecure metadata");
        assert_eq!(Owasp::ALL.len(), 30);
        assert_eq!(serde_json::to_string(&Owasp::Asi10).unwrap(), "\"ASI10\"");
        assert_eq!(serde_json::to_string(&Owasp::Ast01).unwrap(), "\"AST01\"");
        assert_eq!(
            serde_json::from_str::<Owasp>("\"LLM01\"").unwrap(),
            Owasp::Llm01
        );
        assert!(!Owasp::Llm06.title().is_empty());
    }

    #[test]
    fn every_owasp_variant_has_code_title_and_serde_round_trip() {
        for r in Owasp::ALL {
            let code = r.code();
            assert_eq!(code.len(), 5, "{code} should be 5 chars");
            assert!(
                code.starts_with("LLM") || code.starts_with("ASI") || code.starts_with("AST"),
                "{code}"
            );
            assert!(!r.title().is_empty(), "{code} has no title");
            assert_eq!(r.to_string(), code);
            let j = serde_json::to_string(&r).unwrap();
            assert_eq!(j, format!("\"{code}\""));
            assert_eq!(serde_json::from_str::<Owasp>(&j).unwrap(), r);
        }
        let mut codes: Vec<&str> = Owasp::ALL.iter().map(Owasp::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 30, "all OWASP codes are distinct");
    }
}

/// Ed25519 signing primitives (feature `crypto`), shared by the Agentic/ASI crates
/// (mesh/identity/intent) for per-agent PKI. Keys are derived from a 32-byte seed so they are
/// deterministic and reproducible in tests; in production the seed comes from an HSM /
/// orchestrator and is never handed to the agent (architecture-considerations.md §11.2 ASI10).
#[cfg(feature = "crypto")]
pub mod signing {
    use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey, Verifier, VerifyingKey};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// A signing keypair (holds the private key). Never serialized.
    pub struct Keypair(SigningKey);

    /// A public verification key (safe to publish / embed in an agent card).
    #[derive(Clone, PartialEq, Eq)]
    pub struct PublicKey(VerifyingKey);

    /// A detached Ed25519 signature.
    #[derive(Clone, PartialEq, Eq)]
    pub struct Signature(EdSignature);

    impl Keypair {
        /// Deterministically derive a keypair from a 32-byte seed.
        #[must_use]
        pub fn from_seed(seed: &[u8; 32]) -> Self {
            Self(SigningKey::from_bytes(seed))
        }
        /// The public verification key.
        #[must_use]
        pub fn public(&self) -> PublicKey {
            PublicKey(self.0.verifying_key())
        }
        /// Sign a message.
        #[must_use]
        pub fn sign(&self, msg: &[u8]) -> Signature {
            Signature(self.0.sign(msg))
        }
    }

    impl PublicKey {
        /// Verify `sig` over `msg` with this key.
        #[must_use]
        pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
            self.0.verify(msg, &sig.0).is_ok()
        }
        /// Lowercase-hex encoding of the 32-byte key.
        #[must_use]
        pub fn to_hex(&self) -> String {
            hex(&self.0.to_bytes())
        }
        /// Parse a hex-encoded public key.
        #[must_use]
        pub fn from_hex(s: &str) -> Option<Self> {
            let arr: [u8; 32] = unhex(s)?.try_into().ok()?;
            VerifyingKey::from_bytes(&arr).ok().map(PublicKey)
        }
    }

    impl Signature {
        /// Lowercase-hex encoding of the 64-byte signature.
        #[must_use]
        pub fn to_hex(&self) -> String {
            hex(&self.0.to_bytes())
        }
        /// Parse a hex-encoded signature.
        #[must_use]
        pub fn from_hex(s: &str) -> Option<Self> {
            let arr: [u8; 64] = unhex(s)?.try_into().ok()?;
            Some(Signature(EdSignature::from_bytes(&arr)))
        }
    }

    // Public key and signature serialize as hex strings, so they embed cleanly in signed
    // messages / agent cards.
    impl Serialize for PublicKey {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&self.to_hex())
        }
    }
    impl<'de> Deserialize<'de> for PublicKey {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let s = String::deserialize(d)?;
            Self::from_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid public key hex"))
        }
    }
    impl Serialize for Signature {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&self.to_hex())
        }
    }
    impl<'de> Deserialize<'de> for Signature {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let s = String::deserialize(d)?;
            Self::from_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid signature hex"))
        }
    }
    impl std::fmt::Debug for PublicKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "PublicKey({})", self.to_hex())
        }
    }
    impl std::fmt::Debug for Signature {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Signature({}…)", &self.to_hex()[..16])
        }
    }

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
        }
        s
    }

    fn unhex(s: &str) -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            return None;
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn sign_verify_roundtrip_and_reject_tamper() {
            let kp = Keypair::from_seed(&[7u8; 32]);
            let pk = kp.public();
            let sig = kp.sign(b"hello");
            assert!(pk.verify(b"hello", &sig));
            assert!(!pk.verify(b"hell0", &sig)); // tampered message
            let other = Keypair::from_seed(&[8u8; 32]).public();
            assert!(!other.verify(b"hello", &sig)); // wrong key
        }

        #[test]
        fn hex_roundtrip_for_key_and_signature() {
            let kp = Keypair::from_seed(&[3u8; 32]);
            let pk = kp.public();
            let sig = kp.sign(b"x");
            assert_eq!(PublicKey::from_hex(&pk.to_hex()), Some(pk.clone()));
            assert_eq!(Signature::from_hex(&sig.to_hex()), Some(sig));
            assert!(PublicKey::from_hex("zz").is_none());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trifecta_requires_all_three_legs() {
        let mut cap = Capability::NONE;
        assert!(!cap.is_trifecta());
        cap.reads_untrusted = true;
        cap.reads_sensitive = true;
        assert!(!cap.is_trifecta(), "two legs is not the trifecta");
        assert!(cap.is_two_leg());
        cap.external_effect = true;
        assert!(cap.is_trifecta(), "all three legs is the trifecta");
        assert_eq!(cap.active_legs(), 3);
    }

    #[test]
    fn taint_is_monotonic_and_cannot_be_cleared() {
        let mut sess = Capability::NONE;
        sess.accumulate(&Capability {
            reads_untrusted: true,
            ..Capability::NONE
        });
        assert!(sess.reads_untrusted);

        // A later "clean" call cannot lower the untrusted leg back to false.
        sess.accumulate(&Capability::NONE);
        assert!(
            sess.reads_untrusted,
            "accumulate must never clear an already-set leg"
        );
    }

    #[test]
    fn provenance_least_trusted_wins() {
        assert_eq!(
            Provenance::System.combine(Provenance::Untrusted),
            Provenance::Untrusted
        );
        assert_eq!(
            Provenance::Untrusted.combine(Provenance::System),
            Provenance::Untrusted
        );
        assert_eq!(Provenance::User.combine(Provenance::User), Provenance::User);
    }

    #[test]
    fn semi_and_untrusted_both_taint() {
        assert!(Provenance::Untrusted.is_tainting());
        assert!(Provenance::SemiTrusted.is_tainting());
        assert!(!Provenance::User.is_tainting());
        assert!(!Provenance::System.is_tainting());
    }

    #[test]
    fn tagged_map_preserves_origin() {
        let t = Tagged::untrusted("  hi  ".to_string());
        let mapped = t.map(|s| s.trim().to_string());
        assert_eq!(mapped.value, "hi");
        assert_eq!(mapped.origin, Provenance::Untrusted);
        assert!(mapped.is_tainting());
    }

    #[test]
    fn tagged_constructors_and_as_ref() {
        assert_eq!(Tagged::system(1).origin, Provenance::System);
        assert_eq!(Tagged::user(1).origin, Provenance::User);
        assert_eq!(
            Tagged::new(1, Provenance::SemiTrusted).origin,
            Provenance::SemiTrusted
        );
        let t = Tagged::untrusted(String::from("x"));
        let borrowed = t.as_ref();
        assert_eq!(*borrowed.value, "x");
        assert_eq!(borrowed.origin, Provenance::Untrusted);
    }

    #[test]
    fn capability_union_is_the_monotonic_merge_without_mutating_inputs() {
        let a = Capability {
            reads_untrusted: true,
            ..Capability::NONE
        };
        let b = Capability {
            external_effect: true,
            ..Capability::NONE
        };
        let u = a.union(&b);
        assert!(u.reads_untrusted && u.external_effect && !u.reads_sensitive);
        assert_eq!(u.active_legs(), 2);
        assert!(!a.reads_sensitive); // union takes self by value; the original leg set is unchanged
    }

    #[test]
    fn one_leg_is_neither_trifecta_nor_two_leg() {
        let cap = Capability {
            external_effect: true,
            ..Capability::NONE
        };
        assert!(!cap.is_trifecta());
        assert!(!cap.is_two_leg());
        assert_eq!(cap.active_legs(), 1);
    }
}
