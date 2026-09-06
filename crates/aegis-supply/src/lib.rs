//! # aegis-supply — artifact / supply-chain verifier (LLM04, LLM05)
//!
//! A `● Contain` control that runs in CI/CD and again at model-load time
//! (architecture-considerations.md §3 LLM04, §8). The deterministic core:
//!
//! * **Digest pinning** — an artifact is accepted only if its content digest is on an allowlist
//!   ([`Pinset`]); a mismatch is rejected. (Cryptographic signature verification / Sigstore is a
//!   future feature layered on top; the digest pin is the deterministic backstop.)
//! * **Reject mutable tags** — `latest` and any non-digest reference are refused
//!   ([`require_immutable`]); only immutable digest refs load.
//! * **Namespace-reuse detection** — a name that resolves to a *different* digest than before is
//!   flagged (a re-registered / hijacked dependency).
//! * **SBOM gating** — every component must be pinned to a digest and not on a floating version.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// A content digest (algorithm + lowercase hex), e.g. `sha256:ab12…`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest {
    pub algo: String,
    pub hex: String,
}

impl Digest {
    /// Compute the SHA-256 digest of some bytes.
    #[must_use]
    pub fn sha256(bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(bytes);
        Self {
            algo: "sha256".to_string(),
            hex: hex(&h.finalize()),
        }
    }

    /// Parse a `algo:hex` digest string, validating the hex length for known algorithms.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (algo, hex) = s.split_once(':')?;
        let hex = hex.to_ascii_lowercase();
        if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let ok_len = match algo {
            "sha256" => hex.len() == 64,
            "sha512" => hex.len() == 128,
            _ => return None,
        };
        ok_len.then(|| Self {
            algo: algo.to_string(),
            hex,
        })
    }

    /// Render back to `algo:hex`.
    #[must_use]
    pub fn to_ref(&self) -> String {
        format!("{}:{}", self.algo, self.hex)
    }
}

/// Errors from supply-chain verification.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SupplyError {
    /// The reference is a mutable tag (e.g. `latest`), not an immutable digest.
    #[error("mutable/unpinned reference: {0}")]
    MutableRef(String),
    /// The artifact name is not present in the pinset.
    #[error("artifact not pinned: {0}")]
    NotPinned(String),
    /// The artifact's digest is not among the pinned digests for its name.
    #[error("digest not allowed for {name}")]
    DigestMismatch { name: String },
    /// A name resolved to a different digest than previously seen.
    #[error("namespace reuse for {name}: digest changed")]
    NamespaceReuse { name: String },
    /// An SBOM component lacks a pinned digest.
    #[error("SBOM component {0} is not pinned to a digest")]
    UnpinnedComponent(String),
    /// An SBOM component is on a floating version (e.g. `latest`).
    #[error("SBOM component {0} is on a floating version")]
    FloatingVersion(String),
}

/// True if `reference` immutably pins a content digest (`name@sha256:…` or a bare `sha256:…`),
/// false for a mutable tag.
#[must_use]
pub fn is_immutable_ref(reference: &str) -> bool {
    if let Some((_, after)) = reference.split_once('@') {
        Digest::parse(after).is_some()
    } else {
        Digest::parse(reference).is_some()
    }
}

/// Reject a mutable/unpinned reference; accept only immutable digest refs.
pub fn require_immutable(reference: &str) -> Result<(), SupplyError> {
    if is_immutable_ref(reference) {
        Ok(())
    } else {
        Err(SupplyError::MutableRef(reference.to_string()))
    }
}

/// An allowlist of the digests permitted for each artifact name.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Pinset {
    /// name -> set of permitted `algo:hex` digest strings.
    pub pins: HashMap<String, HashSet<String>>,
}

impl Pinset {
    /// Load a pinset from JSON of the shape `{ "name": ["sha256:…", …], … }`.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let pins: HashMap<String, HashSet<String>> = serde_json::from_str(json)?;
        Ok(Self { pins })
    }

    /// Verify that `digest` is a permitted digest for `name`. Fails closed for unknown names.
    pub fn verify(&self, name: &str, digest: &Digest) -> Result<(), SupplyError> {
        match self.pins.get(name) {
            None => Err(SupplyError::NotPinned(name.to_string())),
            Some(set) if set.contains(&digest.to_ref()) => Ok(()),
            Some(_) => Err(SupplyError::DigestMismatch {
                name: name.to_string(),
            }),
        }
    }
}

/// Detect namespace reuse: a `name` that now resolves to a different digest than `known` recorded.
#[must_use]
pub fn is_namespace_reuse(known: &HashMap<String, Digest>, name: &str, current: &Digest) -> bool {
    known.get(name).is_some_and(|prev| prev != current)
}

/// One component of a Software / AI Bill of Materials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    pub version: String,
    /// Pinned content digest; `None` means the component is not pinned (rejected).
    #[serde(default)]
    pub digest: Option<String>,
}

/// A minimal SBOM/AIBOM: a list of components.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Sbom {
    pub components: Vec<Component>,
}

impl Sbom {
    /// Gate the SBOM: every component must be pinned to a valid digest and not on a floating
    /// version (`latest` / `*`). Returns the first violation.
    pub fn gate(&self) -> Result<(), SupplyError> {
        for c in &self.components {
            if c.version.eq_ignore_ascii_case("latest") || c.version == "*" {
                return Err(SupplyError::FloatingVersion(c.name.clone()));
            }
            match c.digest.as_deref().and_then(Digest::parse) {
                Some(_) => {}
                None => return Err(SupplyError::UnpinnedComponent(c.name.clone())),
            }
        }
        Ok(())
    }
}

/// A kind of capability that can be composed into an agent **at runtime** (§11.1, ASI04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    /// A remote MCP (Model Context Protocol) server.
    McpServer,
    /// An A2A agent card describing a peer agent.
    AgentCard,
    /// A remote prompt template.
    PromptTemplate,
    /// A tool descriptor.
    Tool,
}

/// A dynamically-composed capability presented for activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCapability {
    pub kind: CapabilityKind,
    /// The artifact name (used for the pinset lookup).
    pub name: String,
    /// The full reference, e.g. `registry/x@sha256:…` (must be immutable, not a tag).
    pub reference: String,
    /// The measured content digest of the artifact.
    pub digest: Digest,
}

/// **Runtime capability verification** (§11.1, ASI04): before an agent activates a dynamically
/// loaded MCP server / agent card / prompt template, verify it is (1) referenced immutably,
/// (2) internally consistent (any digest embedded in the reference matches the measured digest),
/// and (3) pinned. Any failure refuses activation — verify-before-activate, fail-closed.
pub fn verify_runtime(cap: &RuntimeCapability, pinset: &Pinset) -> Result<(), SupplyError> {
    // 1. Only immutable digest references may be activated.
    require_immutable(&cap.reference)?;
    // 2. If the reference embeds a digest (`name@sha256:…`), it must match what we measured.
    if let Some((_, after)) = cap.reference.split_once('@') {
        if let Some(embedded) = Digest::parse(after) {
            if embedded != cap.digest {
                return Err(SupplyError::DigestMismatch {
                    name: cap.name.clone(),
                });
            }
        }
    }
    // 3. The measured digest must be on the pinset for this capability name.
    pinset.verify(&cap.name, &cap.digest)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_of_bytes_and_roundtrip() {
        let d = Digest::sha256(b"hello");
        assert_eq!(d.algo, "sha256");
        assert_eq!(d.hex.len(), 64);
        assert_eq!(Digest::parse(&d.to_ref()), Some(d));
    }

    #[test]
    fn digest_parse_rejects_bad_length_or_algo() {
        assert!(Digest::parse("sha256:abcd").is_none()); // too short
        assert!(Digest::parse("md5:abcd").is_none()); // unsupported algo
        assert!(Digest::parse("not-a-digest").is_none());
    }

    #[test]
    fn immutable_refs_recognized_mutable_rejected() {
        assert!(is_immutable_ref(&format!(
            "model@{}",
            Digest::sha256(b"x").to_ref()
        )));
        assert!(is_immutable_ref(&Digest::sha256(b"x").to_ref()));
        assert!(!is_immutable_ref("model:latest"));
        assert!(!is_immutable_ref("model:v1.2.3"));
        assert_eq!(
            require_immutable("model:latest"),
            Err(SupplyError::MutableRef("model:latest".to_string()))
        );
        assert!(require_immutable(&Digest::sha256(b"x").to_ref()).is_ok());
    }

    #[test]
    fn pinset_verifies_and_fails_closed() {
        let d = Digest::sha256(b"weights-v1");
        let json = format!(r#"{{ "model": ["{}"] }}"#, d.to_ref());
        let pins = Pinset::from_json(&json).unwrap();
        assert!(pins.verify("model", &d).is_ok());
        // Unknown name -> NotPinned.
        assert_eq!(
            pins.verify("other", &d),
            Err(SupplyError::NotPinned("other".to_string()))
        );
        // Known name, wrong digest -> DigestMismatch.
        assert_eq!(
            pins.verify("model", &Digest::sha256(b"weights-v2")),
            Err(SupplyError::DigestMismatch {
                name: "model".to_string()
            })
        );
    }

    #[test]
    fn namespace_reuse_detected_on_digest_change() {
        let mut known = HashMap::new();
        known.insert("dep".to_string(), Digest::sha256(b"v1"));
        assert!(is_namespace_reuse(&known, "dep", &Digest::sha256(b"v2")));
        assert!(!is_namespace_reuse(&known, "dep", &Digest::sha256(b"v1")));
        assert!(!is_namespace_reuse(&known, "new", &Digest::sha256(b"v1")));
    }

    #[test]
    fn sbom_gate_requires_pinned_and_fixed_versions() {
        let good = Sbom {
            components: vec![Component {
                name: "torch".into(),
                version: "2.3.0".into(),
                digest: Some(Digest::sha256(b"torch").to_ref()),
            }],
        };
        assert!(good.gate().is_ok());

        let floating = Sbom {
            components: vec![Component {
                name: "torch".into(),
                version: "latest".into(),
                digest: Some(Digest::sha256(b"torch").to_ref()),
            }],
        };
        assert_eq!(
            floating.gate(),
            Err(SupplyError::FloatingVersion("torch".into()))
        );

        let unpinned = Sbom {
            components: vec![Component {
                name: "numpy".into(),
                version: "1.26.0".into(),
                digest: None,
            }],
        };
        assert_eq!(
            unpinned.gate(),
            Err(SupplyError::UnpinnedComponent("numpy".into()))
        );
    }

    #[test]
    fn runtime_capability_verification() {
        let digest = Digest::sha256(b"mcp-server-v1");
        let pinset =
            Pinset::from_json(&format!(r#"{{ "search-mcp": ["{}"] }}"#, digest.to_ref())).unwrap();

        // Immutable ref, matching embedded digest, pinned -> activate.
        let ok = RuntimeCapability {
            kind: CapabilityKind::McpServer,
            name: "search-mcp".into(),
            reference: format!("registry/search-mcp@{}", digest.to_ref()),
            digest: digest.clone(),
        };
        assert!(verify_runtime(&ok, &pinset).is_ok());

        // A mutable :latest reference is refused.
        let mutable = RuntimeCapability {
            reference: "registry/search-mcp:latest".into(),
            ..ok.clone()
        };
        assert!(matches!(
            verify_runtime(&mutable, &pinset),
            Err(SupplyError::MutableRef(_))
        ));

        // Reference embeds a different digest than measured -> refused.
        let swapped = RuntimeCapability {
            reference: format!("registry/search-mcp@{}", Digest::sha256(b"evil").to_ref()),
            ..ok.clone()
        };
        assert_eq!(
            verify_runtime(&swapped, &pinset),
            Err(SupplyError::DigestMismatch {
                name: "search-mcp".into()
            })
        );

        // Not on the pinset -> refused.
        let unpinned = RuntimeCapability {
            name: "unknown-mcp".into(),
            ..ok
        };
        assert!(matches!(
            verify_runtime(&unpinned, &pinset),
            Err(SupplyError::NotPinned(_))
        ));
    }
}
