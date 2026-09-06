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
