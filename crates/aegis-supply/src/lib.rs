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
    /// A skill-manifest field carries smuggling/invisible characters (AST04 Insecure Metadata).
    #[error("insecure skill metadata in field {field}")]
    InsecureMetadata { field: String },
    /// A skill was presented for activation without a clean scan attestation (AST08 Poor Scanning).
    #[error("skill {name} is unscanned or the scan attestation does not match the artifact")]
    Unscanned { name: String },
    /// A skill's scan verdict flagged it as unsafe (AST08 Poor Scanning).
    #[error("skill {name} was flagged by its scanner")]
    ScanFlagged { name: String },
    /// A skill is reused on a platform it was not verified for (AST10 Cross-Platform Reuse).
    #[error("skill {name} is not verified for platform {platform}")]
    PlatformUnverified { name: String, platform: String },
    /// A skill declares a permission outside the allowed set (AST03 Over-Privileged Skills).
    #[error("skill {name} declares unpermitted capability {permission}")]
    ExcessivePermission { name: String, permission: String },
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
    /// An agent *skill* — a packaged, dynamically-loaded unit of agent capability
    /// (OWASP Agentic Skills Top 10 / AST). Verified via [`verify_skill`].
    Skill,
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
    verify_pinned_ref(&cap.name, &cap.reference, &cap.digest, pinset)
}

/// The shared immutable-reference + embedded-digest-match + pinset-membership check used by both
/// [`verify_runtime`] and [`verify_skill`]. Fail-closed: (1) only immutable digest references may
/// be activated; (2) if the reference embeds a digest (`name@sha256:…`) it must match the measured
/// digest; (3) the measured digest must be on the pinset for this name.
fn verify_pinned_ref(
    name: &str,
    reference: &str,
    digest: &Digest,
    pinset: &Pinset,
) -> Result<(), SupplyError> {
    require_immutable(reference)?;
    if let Some((_, after)) = reference.split_once('@') {
        if let Some(embedded) = Digest::parse(after) {
            if &embedded != digest {
                return Err(SupplyError::DigestMismatch {
                    name: name.to_string(),
                });
            }
        }
    }
    pinset.verify(name, digest)
}

/// A scanner's verdict on a skill artifact (AST08 Poor Scanning).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanVerdict {
    /// The scanner examined the artifact and found nothing malicious.
    Clean,
    /// The scanner flagged the artifact as malicious or suspicious.
    Flagged,
}

/// An attestation that a skill artifact was scanned before activation (AST08 Poor Scanning).
///
/// The attestation is bound to a content digest: a `Clean` verdict only counts if the scanned
/// digest matches the digest actually being activated, so an attestation for an old/clean build
/// cannot be replayed to admit a swapped-in malicious artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanAttestation {
    /// Identifier of the scanner that produced the verdict.
    pub scanner: String,
    /// The content digest that was scanned.
    pub scanned_digest: Digest,
    /// The scanner's verdict.
    pub verdict: ScanVerdict,
}

/// A dynamically-loaded agent **skill** presented for activation (OWASP Agentic Skills Top 10 / AST).
///
/// Additive to the runtime-capability model: a skill is pinned like any artifact, but also carries
/// the metadata, declared permissions, platform bindings, and scan attestation that the AST list
/// is concerned with. All new fields default via serde, so existing manifests still deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillManifest {
    /// The skill name (used for the pinset lookup).
    pub name: String,
    /// The full reference, e.g. `registry/x@sha256:…` (must be immutable, not a tag).
    pub reference: String,
    /// The measured content digest of the skill artifact.
    pub digest: Digest,
    /// Declared permissions / capabilities the skill requests (AST03 Over-Privileged Skills).
    #[serde(default)]
    pub permissions: std::collections::BTreeSet<String>,
    /// Free-form manifest metadata (description, author, …). Validated for invisible/smuggling
    /// characters (AST04 Insecure Metadata).
    #[serde(default)]
    pub metadata: std::collections::BTreeMap<String, String>,
    /// The platforms this skill has been validated for (AST10 Cross-Platform Reuse).
    #[serde(default)]
    pub platforms: std::collections::BTreeSet<String>,
    /// The scan attestation for the artifact, if any (AST08 Poor Scanning).
    #[serde(default)]
    pub scan: Option<ScanAttestation>,
}

/// The host context a skill is being activated into (AST03/AST10).
#[derive(Debug, Clone)]
pub struct SkillContext<'a> {
    /// The platform the skill is about to run on; it must be among the skill's validated platforms.
    pub host_platform: &'a str,
    /// The permissions the host is willing to grant; a skill may declare only a subset.
    pub allowed_permissions: &'a std::collections::BTreeSet<String>,
}

/// **Skill verification** (OWASP Agentic Skills Top 10 / AST): the deterministic, fail-closed gate
/// a skill must pass before an agent may activate it. It reuses the supply-chain primitives and
/// adds the skill-lifecycle checks the AST list calls for. In order:
///
/// 1. **AST02 Supply-chain compromise / AST01 Malicious skills / AST07 Update drift** — the skill
///    is referenced immutably, its embedded digest matches the measured one, and it is pinned
///    ([`verify_pinned_ref`]). A mutable `:latest` skill, a swapped artifact, or an unpinned name
///    is refused.
/// 2. **AST04 Insecure metadata** — the name and every metadata key/value must be free of the
///    invisible/bidi/tag characters [`aegis_ingress::is_clean`] rejects, so a skill cannot smuggle
///    hidden instructions through its manifest.
/// 3. **AST03 Over-privileged skills** — every declared permission must be within the host's
///    allowed set (least privilege at load time).
/// 4. **AST08 Poor scanning** — a scan attestation is required, its scanned digest must match the
///    artifact, and its verdict must be `Clean`.
/// 5. **AST10 Cross-platform reuse** — the host platform must be among the skill's validated
///    platforms; a skill validated only for platform A is refused on platform B.
pub fn verify_skill(
    manifest: &SkillManifest,
    pinset: &Pinset,
    ctx: &SkillContext<'_>,
) -> Result<(), SupplyError> {
    // 1. Pin / immutability / digest match (shared with verify_runtime).
    verify_pinned_ref(
        &manifest.name,
        &manifest.reference,
        &manifest.digest,
        pinset,
    )?;

    // 2. Metadata hygiene (AST04) — reuse the ingress invisible-character screen, don't duplicate it.
    if !aegis_ingress::is_clean(&manifest.name) {
        return Err(SupplyError::InsecureMetadata {
            field: "name".to_string(),
        });
    }
    for (key, value) in &manifest.metadata {
        if !aegis_ingress::is_clean(key) {
            return Err(SupplyError::InsecureMetadata {
                field: format!("metadata.key:{key}"),
            });
        }
        if !aegis_ingress::is_clean(value) {
            return Err(SupplyError::InsecureMetadata {
                field: format!("metadata.{key}"),
            });
        }
    }

    // 3. Least privilege (AST03) — every declared permission must be host-allowed.
    for permission in &manifest.permissions {
        if !ctx.allowed_permissions.contains(permission) {
            return Err(SupplyError::ExcessivePermission {
                name: manifest.name.clone(),
                permission: permission.clone(),
            });
        }
    }

    // 4. Scan attestation (AST08) — required, bound to this digest, and Clean.
    match &manifest.scan {
        None => {
            return Err(SupplyError::Unscanned {
                name: manifest.name.clone(),
            });
        }
        Some(att) => {
            if att.scanned_digest != manifest.digest {
                return Err(SupplyError::Unscanned {
                    name: manifest.name.clone(),
                });
            }
            if att.verdict != ScanVerdict::Clean {
                return Err(SupplyError::ScanFlagged {
                    name: manifest.name.clone(),
                });
            }
        }
    }

    // 5. Platform binding (AST10) — the skill must be validated for this host platform.
    if !manifest.platforms.contains(ctx.host_platform) {
        return Err(SupplyError::PlatformUnverified {
            name: manifest.name.clone(),
            platform: ctx.host_platform.to_string(),
        });
    }

    Ok(())
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

    // ── Skill verification (OWASP Agentic Skills Top 10 / AST) ──────────────────────────────────

    use std::collections::{BTreeMap, BTreeSet};

    /// A valid, pinned, scanned, single-platform skill with one in-bounds permission.
    fn good_skill() -> (SkillManifest, Pinset) {
        let digest = Digest::sha256(b"summarize-skill-v1");
        let pinset =
            Pinset::from_json(&format!(r#"{{ "summarize": ["{}"] }}"#, digest.to_ref())).unwrap();
        let manifest = SkillManifest {
            name: "summarize".into(),
            reference: format!("registry/summarize@{}", digest.to_ref()),
            digest: digest.clone(),
            permissions: BTreeSet::from(["read_docs".to_string()]),
            metadata: BTreeMap::from([("author".to_string(), "platform-team".to_string())]),
            platforms: BTreeSet::from(["langgraph".to_string()]),
            scan: Some(ScanAttestation {
                scanner: "aegis-scan".into(),
                scanned_digest: digest,
                verdict: ScanVerdict::Clean,
            }),
        };
        (manifest, pinset)
    }

    fn ctx<'a>(platform: &'a str, allowed: &'a BTreeSet<String>) -> SkillContext<'a> {
        SkillContext {
            host_platform: platform,
            allowed_permissions: allowed,
        }
    }

    #[test]
    fn valid_skill_activates() {
        let (m, pinset) = good_skill();
        let allowed = BTreeSet::from(["read_docs".to_string(), "write_docs".to_string()]);
        assert!(verify_skill(&m, &pinset, &ctx("langgraph", &allowed)).is_ok());
    }

    #[test]
    fn mutable_or_unpinned_skill_is_refused() {
        // AST02/AST07: a :latest reference is refused.
        let (mut m, pinset) = good_skill();
        let allowed = BTreeSet::from(["read_docs".to_string()]);
        m.reference = "registry/summarize:latest".into();
        assert!(matches!(
            verify_skill(&m, &pinset, &ctx("langgraph", &allowed)),
            Err(SupplyError::MutableRef(_))
        ));

        // AST02: an unpinned skill name fails closed.
        let (mut m2, pinset2) = good_skill();
        m2.name = "unknown-skill".into();
        m2.reference = format!("registry/unknown-skill@{}", m2.digest.to_ref());
        assert!(matches!(
            verify_skill(&m2, &pinset2, &ctx("langgraph", &allowed)),
            Err(SupplyError::NotPinned(_))
        ));
    }

    #[test]
    fn skill_metadata_with_invisible_chars_is_refused() {
        // AST04: a tag-block smuggling payload in a metadata value is rejected.
        let (mut m, pinset) = good_skill();
        let allowed = BTreeSet::from(["read_docs".to_string()]);
        m.metadata.insert(
            "description".to_string(),
            "harmless\u{E0041}\u{E0042}".to_string(),
        );
        assert_eq!(
            verify_skill(&m, &pinset, &ctx("langgraph", &allowed)),
            Err(SupplyError::InsecureMetadata {
                field: "metadata.description".into()
            })
        );

        // AST04: a bidi-control in the skill name is rejected too. Pin the dirty name so the
        // pin check (step 1) passes and the name-hygiene screen is what fires.
        let (base, _) = good_skill();
        let dirty_name = "sum\u{202E}marize".to_string();
        let mut pins = std::collections::HashMap::new();
        pins.insert(
            dirty_name.clone(),
            std::collections::HashSet::from([base.digest.to_ref()]),
        );
        let dirty = SkillManifest {
            name: dirty_name,
            reference: format!("registry/x@{}", base.digest.to_ref()),
            ..base
        };
        assert_eq!(
            verify_skill(&dirty, &Pinset { pins }, &ctx("langgraph", &allowed)),
            Err(SupplyError::InsecureMetadata {
                field: "name".into()
            })
        );
    }

    #[test]
    fn over_privileged_skill_is_refused() {
        // AST03: a declared permission outside the host's allowed set is refused.
        let (mut m, pinset) = good_skill();
        m.permissions.insert("delete_production_data".to_string());
        let allowed = BTreeSet::from(["read_docs".to_string()]);
        assert_eq!(
            verify_skill(&m, &pinset, &ctx("langgraph", &allowed)),
            Err(SupplyError::ExcessivePermission {
                name: "summarize".into(),
                permission: "delete_production_data".into()
            })
        );
    }

    #[test]
    fn unscanned_or_flagged_or_stale_scan_is_refused() {
        let allowed = BTreeSet::from(["read_docs".to_string()]);

        // AST08: no scan attestation -> refused.
        let (mut m, pinset) = good_skill();
        m.scan = None;
        assert_eq!(
            verify_skill(&m, &pinset, &ctx("langgraph", &allowed)),
            Err(SupplyError::Unscanned {
                name: "summarize".into()
            })
        );

        // AST08: a scan of a *different* digest cannot be replayed to admit this artifact.
        let (mut m2, pinset2) = good_skill();
        if let Some(att) = m2.scan.as_mut() {
            att.scanned_digest = Digest::sha256(b"some-other-build");
        }
        assert_eq!(
            verify_skill(&m2, &pinset2, &ctx("langgraph", &allowed)),
            Err(SupplyError::Unscanned {
                name: "summarize".into()
            })
        );

        // AST08: a Flagged verdict -> refused.
        let (mut m3, pinset3) = good_skill();
        if let Some(att) = m3.scan.as_mut() {
            att.verdict = ScanVerdict::Flagged;
        }
        assert_eq!(
            verify_skill(&m3, &pinset3, &ctx("langgraph", &allowed)),
            Err(SupplyError::ScanFlagged {
                name: "summarize".into()
            })
        );
    }

    #[test]
    fn skill_reused_on_unverified_platform_is_refused() {
        // AST10: a skill validated only for langgraph is refused on a different platform.
        let (m, pinset) = good_skill();
        let allowed = BTreeSet::from(["read_docs".to_string()]);
        assert_eq!(
            verify_skill(&m, &pinset, &ctx("autogen", &allowed)),
            Err(SupplyError::PlatformUnverified {
                name: "summarize".into(),
                platform: "autogen".into()
            })
        );
    }
}
