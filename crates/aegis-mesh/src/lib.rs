//! # aegis-mesh — secure inter-agent communication (ASI07)
//!
//! A `● Contain` control (architecture-considerations.md §11.1/§11.2 ASI07). Peer agent messages
//! are otherwise unauthenticated; this crate makes inter-agent messaging carry **mutual
//! authentication** (signatures against an attested registry), **anti-replay** (nonces + task
//! windows), **protocol pinning** (reject downgrade), **per-message audiences**, and
//! **intent-diffing** (the signed message commits to a digest of its payload, so a payload
//! swapped after signing is rejected).
//!
//! Peer messages are still *untrusted content* — sanitize the payload via `aegis-ingress` before
//! it reaches a model; this crate secures the channel, not the semantics.

use std::collections::{HashMap, HashSet};

use aegis_core::signing::{Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// An attested agent card: the agent's id, public key, and the protocol version it speaks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    pub agent_id: String,
    pub public_key: PublicKey,
    pub protocol_version: u32,
}

/// A registry of attested agent cards — the source of truth for who may speak on the mesh.
#[derive(Debug, Clone, Default)]
pub struct AgentRegistry {
    cards: HashMap<String, AgentCard>,
}

impl AgentRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Register (attest) an agent card.
    pub fn register(&mut self, card: AgentCard) {
        self.cards.insert(card.agent_id.clone(), card);
    }
    /// Look up an agent's card.
    #[must_use]
    pub fn get(&self, agent_id: &str) -> Option<&AgentCard> {
        self.cards.get(agent_id)
    }
}

/// A signed inter-agent message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    pub sender: String,
    /// Recipients permitted to act on this message.
    pub audience: Vec<String>,
    /// The message payload (untrusted until sanitized downstream).
    pub payload: serde_json::Value,
    /// SHA-256 of the canonical payload, committed to by the signature (intent-diffing anchor).
    pub payload_digest: String,
    /// Unique per-message nonce (anti-replay).
    pub nonce: String,
    /// Send time (Unix ms).
    pub timestamp_ms: u64,
    /// The task window `[start, end]` (ms) this message is valid within.
    pub task_window: (u64, u64),
    /// Protocol version (for pinning / downgrade rejection).
    pub protocol_version: u32,
    /// Signature over the canonical body.
    pub signature: Signature,
}

/// Why a message was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MeshError {
    #[error("unknown / unattested sender")]
    UnknownSender,
    #[error("signature invalid")]
    BadSignature,
    #[error("protocol downgrade rejected")]
    ProtocolDowngrade,
    #[error("recipient not in message audience")]
    NotInAudience,
    #[error("replayed message (nonce seen)")]
    Replay,
    #[error("message outside its task window")]
    OutsideTaskWindow,
    #[error("payload does not match its committed digest")]
    IntentMismatch,
}

fn payload_digest(payload: &serde_json::Value) -> String {
    // serde_json's Map is ordered (BTreeMap) by default, so this canonicalization is stable.
    let mut h = Sha256::new();
    h.update(payload.to_string().as_bytes());
    let d = h.finalize();
    let mut s = String::with_capacity(64);
    for b in d {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

fn canonical_body(
    sender: &str,
    audience: &[String],
    payload_digest: &str,
    nonce: &str,
    timestamp_ms: u64,
    task_window: (u64, u64),
    protocol_version: u32,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut field = |bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(bytes);
        out.push(0x1e);
    };
    field(sender.as_bytes());
    for a in audience {
        field(a.as_bytes());
    }
    field(b"|");
    field(payload_digest.as_bytes());
    field(nonce.as_bytes());
    field(&timestamp_ms.to_le_bytes());
    field(&task_window.0.to_le_bytes());
    field(&task_window.1.to_le_bytes());
    field(&protocol_version.to_le_bytes());
    out
}

impl SignedMessage {
    /// Build and sign a message from the sender's keypair.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn sign(
        keypair: &Keypair,
        sender: impl Into<String>,
        audience: Vec<String>,
        payload: serde_json::Value,
        nonce: impl Into<String>,
        timestamp_ms: u64,
        task_window: (u64, u64),
        protocol_version: u32,
    ) -> Self {
        let sender = sender.into();
        let nonce = nonce.into();
        let digest = payload_digest(&payload);
        let body = canonical_body(
            &sender,
            &audience,
            &digest,
            &nonce,
            timestamp_ms,
            task_window,
            protocol_version,
        );
        let signature = keypair.sign(&body);
        Self {
            sender,
            audience,
            payload,
            payload_digest: digest,
            nonce,
            timestamp_ms,
            task_window,
            protocol_version,
            signature,
        }
    }
}

/// Tracks seen `(sender, nonce)` pairs to reject replays.
#[derive(Debug, Clone, Default)]
pub struct ReplayGuard {
    seen: HashSet<(String, String)>,
}

impl ReplayGuard {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    fn already_seen(&self, sender: &str, nonce: &str) -> bool {
        self.seen.contains(&(sender.to_string(), nonce.to_string()))
    }
    fn record(&mut self, sender: &str, nonce: &str) {
        self.seen.insert((sender.to_string(), nonce.to_string()));
    }
}

/// Verify a message end-to-end for `recipient`: attested sender, protocol pin, audience, task
/// window + freshness, signature, payload-digest match, and anti-replay. Records the nonce only
/// when everything else passes.
pub fn verify(
    msg: &SignedMessage,
    recipient: &str,
    registry: &AgentRegistry,
    replay: &mut ReplayGuard,
    now_ms: u64,
    min_protocol: u32,
) -> Result<(), MeshError> {
    let card = registry.get(&msg.sender).ok_or(MeshError::UnknownSender)?;

    if msg.protocol_version < min_protocol {
        return Err(MeshError::ProtocolDowngrade);
    }
    if !msg.audience.iter().any(|a| a == recipient) {
        return Err(MeshError::NotInAudience);
    }
    let (start, end) = msg.task_window;
    if msg.timestamp_ms < start || msg.timestamp_ms > end || now_ms < start || now_ms > end {
        return Err(MeshError::OutsideTaskWindow);
    }
    let body = canonical_body(
        &msg.sender,
        &msg.audience,
        &msg.payload_digest,
        &msg.nonce,
        msg.timestamp_ms,
        msg.task_window,
        msg.protocol_version,
    );
    if !card.public_key.verify(&body, &msg.signature) {
        return Err(MeshError::BadSignature);
    }
    if payload_digest(&msg.payload) != msg.payload_digest {
        return Err(MeshError::IntentMismatch);
    }
    if replay.already_seen(&msg.sender, &msg.nonce) {
        return Err(MeshError::Replay);
    }
    replay.record(&msg.sender, &msg.nonce);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn setup() -> (Keypair, AgentRegistry) {
        let kp = Keypair::from_seed(&[9u8; 32]);
        let mut reg = AgentRegistry::new();
        reg.register(AgentCard {
            agent_id: "planner".into(),
            public_key: kp.public(),
            protocol_version: 2,
        });
        (kp, reg)
    }

    fn msg(kp: &Keypair, nonce: &str, window: (u64, u64), proto: u32) -> SignedMessage {
        SignedMessage::sign(
            kp,
            "planner",
            vec!["executor".into()],
            json!({"task": "summarize", "id": 7}),
            nonce,
            100,
            window,
            proto,
        )
    }

    #[test]
    fn valid_message_verifies_once() {
        let (kp, reg) = setup();
        let mut replay = ReplayGuard::new();
        let m = msg(&kp, "n1", (0, 1000), 2);
        assert!(verify(&m, "executor", &reg, &mut replay, 200, 2).is_ok());
        // Replay of the same nonce is rejected.
        assert_eq!(
            verify(&m, "executor", &reg, &mut replay, 200, 2),
            Err(MeshError::Replay)
        );
    }

    #[test]
    fn unknown_sender_rejected() {
        let (kp, _reg) = setup();
        let empty = AgentRegistry::new();
        let mut replay = ReplayGuard::new();
        assert_eq!(
            verify(
                &msg(&kp, "n", (0, 1000), 2),
                "executor",
                &empty,
                &mut replay,
                200,
                2
            ),
            Err(MeshError::UnknownSender)
        );
    }

    #[test]
    fn protocol_downgrade_rejected() {
        let (kp, reg) = setup();
        let mut replay = ReplayGuard::new();
        let m = msg(&kp, "n", (0, 1000), 1); // speaks v1 while we pin >= 2
        assert_eq!(
            verify(&m, "executor", &reg, &mut replay, 200, 2),
            Err(MeshError::ProtocolDowngrade)
        );
    }

    #[test]
    fn recipient_must_be_in_audience() {
        let (kp, reg) = setup();
        let mut replay = ReplayGuard::new();
        let m = msg(&kp, "n", (0, 1000), 2);
        assert_eq!(
            verify(&m, "intruder", &reg, &mut replay, 200, 2),
            Err(MeshError::NotInAudience)
        );
    }

    #[test]
    fn outside_task_window_rejected() {
        let (kp, reg) = setup();
        let mut replay = ReplayGuard::new();
        let m = msg(&kp, "n", (0, 150), 2);
        // now is past the window end.
        assert_eq!(
            verify(&m, "executor", &reg, &mut replay, 500, 2),
            Err(MeshError::OutsideTaskWindow)
        );
    }

    #[test]
    fn tampered_payload_rejected() {
        let (kp, reg) = setup();
        let mut replay = ReplayGuard::new();
        let mut m = msg(&kp, "n", (0, 1000), 2);
        // Swap the payload after signing -> signature (over the old digest) no longer matches the
        // body once we also fix the digest, and the digest no longer matches the payload if we
        // don't. Either way it must be rejected.
        m.payload = json!({"task": "exfiltrate", "id": 7});
        let res = verify(&m, "executor", &reg, &mut replay, 200, 2);
        assert!(matches!(
            res,
            Err(MeshError::IntentMismatch) | Err(MeshError::BadSignature)
        ));
    }

    #[test]
    fn forged_signature_rejected() {
        let (kp, reg) = setup();
        let mut replay = ReplayGuard::new();
        let attacker = Keypair::from_seed(&[1u8; 32]);
        // Attacker signs a message claiming to be "planner".
        let mut m = msg(&kp, "n", (0, 1000), 2);
        m.signature = attacker.sign(b"whatever");
        assert_eq!(
            verify(&m, "executor", &reg, &mut replay, 200, 2),
            Err(MeshError::BadSignature)
        );
    }
}
