//! # aegis-ledger — tamper-evident audit + memory-write gating (LLM02, LLM03, LLM05)
//!
//! Two `● Contain` controls (architecture-considerations.md §3, §8):
//!
//! * **Tamper-evident audit** — an append-only, **hash-chained** log of decisions, approvals,
//!   and tool calls. Each entry commits to the previous one (`hash = SHA-256(prev_hash ‖
//!   fields)`), so any retroactive edit, reorder, or deletion breaks the chain and is caught by
//!   [`Ledger::verify`]. Entries are keyed by `run_id`/`thread_id` (the same identities as the
//!   checkpointer) and serialize to JSONL for an immutable, write-once sink (S3 Object Lock).
//! * **Memory-write gating** — a long-term memory write is a *privilege* (a poisoned memory
//!   affects every future session), so [`gate_memory_write`] decides deterministically whether a
//!   write is allowed, needs a human, or is refused, from the session taint and content origin.

use aegis_core::{Capability, Provenance};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The genesis hash that the first entry chains from (64 hex zeros).
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What an audit entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// A broker mediation decision.
    Decision,
    /// A human approval / rejection of a paused action.
    Approval,
    /// A tool invocation.
    ToolCall,
    /// A write to long-term memory.
    MemoryWrite,
    /// A meter / circuit-breaker event.
    Meter,
    /// A honeypot tripwire: an agent touched a planted decoy/canary (`aegis-honeypot`). Recorded
    /// immutably because it is high-signal evidence of compromise an attacker would want to erase.
    Tripwire,
}

/// One immutable, hash-chained audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Monotonic sequence number (0 = first).
    pub seq: u64,
    /// Event time (Unix milliseconds).
    pub ts_ms: u64,
    /// The run this belongs to.
    pub run_id: String,
    /// The conversation/thread this belongs to.
    pub thread_id: String,
    /// What kind of event this is.
    pub kind: EntryKind,
    /// A short, **non-sensitive** summary (redact before calling — never raw tool args/PII).
    pub summary: String,
    /// Hash of the previous entry (chain link).
    pub prev_hash: String,
    /// `SHA-256(prev_hash ‖ fields)` for this entry.
    pub hash: String,
}

impl LedgerEntry {
    /// Recompute this entry's hash from its fields and a given previous hash.
    fn compute_hash(
        seq: u64,
        ts_ms: u64,
        run_id: &str,
        thread_id: &str,
        kind: EntryKind,
        summary: &str,
        prev_hash: &str,
    ) -> String {
        // Length-prefixed, record-separated canonical form so no field boundary is ambiguous.
        let kind = serde_json::to_string(&kind).unwrap_or_default();
        let mut hasher = Sha256::new();
        for field in [
            prev_hash,
            &seq.to_string(),
            &ts_ms.to_string(),
            run_id,
            thread_id,
            kind.trim_matches('"'),
            summary,
        ] {
            hasher.update((field.len() as u64).to_le_bytes());
            hasher.update(field.as_bytes());
            hasher.update([0x1e]); // record separator
        }
        hex(&hasher.finalize())
    }
}

/// Errors from ledger verification.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LedgerError {
    /// An entry's recorded hash does not match its recomputed hash (a field was altered).
    #[error("entry {seq} hash mismatch (tampered)")]
    HashMismatch { seq: u64 },
    /// An entry's `prev_hash` does not match the previous entry's `hash` (reorder/deletion).
    #[error("entry {seq} broken chain link")]
    BrokenChain { seq: u64 },
    /// Sequence numbers are not contiguous from 0.
    #[error("entry {seq} out-of-order sequence")]
    BadSequence { seq: u64 },
}

/// An append-only, hash-chained audit ledger held in memory. Entries also serialize to JSONL for
/// an external immutable sink; this type owns the chaining and verification.
///
/// A ledger may be **resumed** from a durable checkpoint ([`Ledger::resume`]) so the chain continues
/// across a cold restart instead of restarting at genesis: `start_seq` / `start_head` are the seq and
/// prev-hash the first in-memory entry chains from. The prior entries live in the immutable sink, not
/// here — [`Ledger::verify`] checks this in-memory segment relative to its checkpoint, and full-history
/// verification walks the sink.
#[derive(Debug, Clone)]
pub struct Ledger {
    entries: Vec<LedgerEntry>,
    start_seq: u64,
    start_head: String,
}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            start_seq: 0,
            start_head: GENESIS_HASH.to_string(),
        }
    }
}

impl Ledger {
    /// A new, empty ledger chaining from genesis.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resume a chain from a durable checkpoint: the next appended entry carries `next_seq` and chains
    /// from `head_hash`. Used on a cold restart so the audit chain is continuous instead of forking a
    /// fresh genesis chain. See the type docs.
    #[must_use]
    pub fn resume(next_seq: u64, head_hash: impl Into<String>) -> Self {
        Self {
            entries: Vec::new(),
            start_seq: next_seq,
            start_head: head_hash.into(),
        }
    }

    /// The current head hash: the last entry's hash, or the checkpoint head ([`GENESIS_HASH`] for a
    /// fresh ledger) when the in-memory segment is empty.
    #[must_use]
    pub fn head(&self) -> &str {
        self.entries
            .last()
            .map_or(self.start_head.as_str(), |e| e.hash.as_str())
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the ledger is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries, in order.
    #[must_use]
    pub fn entries(&self) -> &[LedgerEntry] {
        &self.entries
    }

    /// Append an entry chaining from the current head. Returns the new entry.
    ///
    /// `summary` must already be non-sensitive (redacted). This is the only way to add an entry —
    /// there is no API to mutate or remove existing ones.
    pub fn append(
        &mut self,
        kind: EntryKind,
        run_id: impl Into<String>,
        thread_id: impl Into<String>,
        summary: impl Into<String>,
        ts_ms: u64,
    ) -> &LedgerEntry {
        let seq = self.start_seq + self.entries.len() as u64;
        let prev_hash = self.head().to_string();
        let run_id = run_id.into();
        let thread_id = thread_id.into();
        let summary = summary.into();
        let hash =
            LedgerEntry::compute_hash(seq, ts_ms, &run_id, &thread_id, kind, &summary, &prev_hash);
        self.entries.push(LedgerEntry {
            seq,
            ts_ms,
            run_id,
            thread_id,
            kind,
            summary,
            prev_hash,
            hash,
        });
        self.entries.last().expect("just pushed")
    }

    /// Verify the whole chain: contiguous sequence, intact links, and matching hashes. Any
    /// tampering (edit, reorder, deletion) is detected.
    pub fn verify(&self) -> Result<(), LedgerError> {
        let mut prev = self.start_head.clone();
        for (i, e) in self.entries.iter().enumerate() {
            if e.seq != self.start_seq + i as u64 {
                return Err(LedgerError::BadSequence { seq: e.seq });
            }
            if e.prev_hash != prev {
                return Err(LedgerError::BrokenChain { seq: e.seq });
            }
            let expected = LedgerEntry::compute_hash(
                e.seq,
                e.ts_ms,
                &e.run_id,
                &e.thread_id,
                e.kind,
                &e.summary,
                &e.prev_hash,
            );
            if expected != e.hash {
                return Err(LedgerError::HashMismatch { seq: e.seq });
            }
            prev = e.hash.clone();
        }
        Ok(())
    }

    /// Serialize the ledger as JSON Lines (one entry per line) for an append-only external sink.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        self.entries
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// The decision on a proposed long-term memory write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryDecision {
    /// Safe to persist.
    Allow,
    /// Requires a human (routed to the same approval path as the broker).
    HumanApprove,
    /// Refused — a fixed, non-sensitive reason.
    Deny(&'static str),
}

/// Gate a long-term memory write deterministically.
///
/// Rules (fail-closed): attacker-influenced content is never silently persisted to shared
/// memory, and a session that has ingested untrusted input cannot write without a human.
///
/// * `content_origin == Untrusted` → **Deny** (do not persist attacker-controlled content).
/// * `content_origin == SemiTrusted`, or the session is untrusted-tainted → **HumanApprove**.
/// * otherwise (System/User content, untainted session) → **Allow**.
#[must_use]
pub fn gate_memory_write(session_cap: &Capability, content_origin: Provenance) -> MemoryDecision {
    match content_origin {
        Provenance::Untrusted => {
            MemoryDecision::Deny("untrusted-origin content may not be written to memory")
        }
        Provenance::SemiTrusted => MemoryDecision::HumanApprove,
        Provenance::System | Provenance::User => {
            if session_cap.reads_untrusted {
                MemoryDecision::HumanApprove
            } else {
                MemoryDecision::Allow
            }
        }
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

/// Memory governance (§11.1, ASI06): trust-scoring, decay/expiry of unverified memory, and a
/// hard rule against auto re-ingesting an agent's own outputs. A poisoned long-term memory
/// affects every future session, so unverified entries lose trust over time and must clear a
/// threshold before they are surfaced back into context.
pub mod memory {
    use aegis_core::Provenance;
    use serde::{Deserialize, Serialize};

    /// A trust-scored long-term memory record.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct MemoryRecord {
        /// Stable id.
        pub id: String,
        /// The content and its origin.
        pub content: String,
        /// Where the content came from (drives the base trust).
        pub origin: Provenance,
        /// The agent that wrote it (for the no-self-reingest rule).
        pub author_agent: String,
        /// Write time (Unix ms).
        pub written_at_ms: u64,
        /// Whether the entry has been human/verified (verified memory does not decay).
        pub verified: bool,
    }

    /// The decayed trust of an unverified record: it starts at a base derived from its origin and
    /// **halves every `half_life_ms`**. Verified records keep full trust.
    #[must_use]
    pub fn decayed_trust(record: &MemoryRecord, now_ms: u64, half_life_ms: u64) -> f64 {
        let base = base_trust(record.origin);
        if record.verified || half_life_ms == 0 {
            return base;
        }
        let age = now_ms.saturating_sub(record.written_at_ms) as f64;
        base * 0.5_f64.powf(age / half_life_ms as f64)
    }

    /// The starting trust for a given origin.
    fn base_trust(origin: Provenance) -> f64 {
        match origin {
            Provenance::System => 1.0,
            Provenance::User => 0.9,
            Provenance::SemiTrusted => 0.5,
            Provenance::Untrusted => 0.2,
        }
    }

    /// Governs a long-term memory store: decay/expiry parameters and the surfacing threshold.
    #[derive(Debug, Clone)]
    pub struct MemoryGovernance {
        /// Trust half-life for unverified entries (ms).
        pub half_life_ms: u64,
        /// Minimum decayed trust required to surface an entry back into context.
        pub surface_threshold: f64,
    }

    impl Default for MemoryGovernance {
        fn default() -> Self {
            Self {
                half_life_ms: 7 * 24 * 60 * 60 * 1000, // one week
                surface_threshold: 0.35,
            }
        }
    }

    impl MemoryGovernance {
        /// Whether a record may be surfaced back into context now (decayed trust ≥ threshold).
        #[must_use]
        pub fn may_surface(&self, record: &MemoryRecord, now_ms: u64) -> bool {
            decayed_trust(record, now_ms, self.half_life_ms) >= self.surface_threshold
        }

        /// **No self-reingest** (§11.1): an agent may not re-ingest content it authored itself
        /// (that is how an agent launders its own hallucinations into "fact").
        #[must_use]
        pub fn may_reingest(&self, record: &MemoryRecord, ingesting_agent: &str) -> bool {
            record.author_agent != ingesting_agent
        }

        /// The subset of `records` safe to surface for `ingesting_agent`: above the trust
        /// threshold and not authored by the ingesting agent.
        #[must_use]
        pub fn surfaceable<'a>(
            &self,
            records: &'a [MemoryRecord],
            ingesting_agent: &str,
            now_ms: u64,
        ) -> Vec<&'a MemoryRecord> {
            records
                .iter()
                .filter(|r| self.may_surface(r, now_ms) && self.may_reingest(r, ingesting_agent))
                .collect()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn rec(origin: Provenance, author: &str, written: u64, verified: bool) -> MemoryRecord {
            MemoryRecord {
                id: "m".into(),
                content: "note".into(),
                origin,
                author_agent: author.into(),
                written_at_ms: written,
                verified,
            }
        }

        #[test]
        fn unverified_trust_decays_over_time() {
            let r = rec(Provenance::User, "peer", 0, false);
            // base 0.9; after one half-life it halves.
            assert!((decayed_trust(&r, 0, 1000) - 0.9).abs() < 1e-9);
            assert!((decayed_trust(&r, 1000, 1000) - 0.45).abs() < 1e-9);
        }

        #[test]
        fn verified_memory_does_not_decay() {
            let r = rec(Provenance::User, "peer", 0, true);
            assert!((decayed_trust(&r, 1_000_000, 1000) - 0.9).abs() < 1e-9);
        }

        #[test]
        fn low_trust_memory_is_not_surfaced() {
            let gov = MemoryGovernance {
                half_life_ms: 1000,
                surface_threshold: 0.35,
            };
            // Untrusted base 0.2 is already below threshold.
            assert!(!gov.may_surface(&rec(Provenance::Untrusted, "x", 0, false), 0));
            // User base 0.9 surfaces now, but after enough decay it drops below 0.35.
            let r = rec(Provenance::User, "x", 0, false);
            assert!(gov.may_surface(&r, 0));
            assert!(!gov.may_surface(&r, 2_000)); // 0.9 * 0.25 = 0.225 < 0.35
        }

        #[test]
        fn agent_cannot_reingest_its_own_output() {
            let gov = MemoryGovernance::default();
            let mine = rec(Provenance::User, "agent-a", 0, true);
            assert!(!gov.may_reingest(&mine, "agent-a"));
            assert!(gov.may_reingest(&mine, "agent-b"));
        }

        #[test]
        fn surfaceable_filters_trust_and_self_authorship() {
            let gov = MemoryGovernance {
                half_life_ms: 1000,
                surface_threshold: 0.35,
            };
            let records = vec![
                rec(Provenance::User, "other", 0, true),      // surfaces
                rec(Provenance::User, "agent-a", 0, true),    // self-authored -> dropped
                rec(Provenance::Untrusted, "other", 0, true), // too low trust -> dropped
            ];
            let out = gov.surfaceable(&records, "agent-a", 0);
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].author_agent, "other");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> Ledger {
        let mut l = Ledger::new();
        l.append(EntryKind::Decision, "run1", "t1", "allow db.read", 1);
        l.append(EntryKind::ToolCall, "run1", "t1", "db.read executed", 2);
        l.append(
            EntryKind::Approval,
            "run1",
            "t1",
            "human approved email.send",
            3,
        );
        l
    }

    #[test]
    fn empty_ledger_head_is_genesis() {
        let l = Ledger::new();
        assert!(l.is_empty());
        assert_eq!(l.head(), GENESIS_HASH);
        assert!(l.verify().is_ok());
    }

    #[test]
    fn append_chains_and_verifies() {
        let l = seed();
        assert_eq!(l.len(), 3);
        assert_eq!(l.entries()[1].prev_hash, l.entries()[0].hash);
        assert_eq!(l.entries()[2].prev_hash, l.entries()[1].hash);
        assert_eq!(l.head(), l.entries()[2].hash);
        assert!(l.verify().is_ok());
    }

    #[test]
    fn hashes_are_deterministic_across_ledgers() {
        assert_eq!(seed().head(), seed().head());
    }

    #[test]
    fn resume_continues_the_chain_from_a_checkpoint() {
        // Pretend seq 0..2 already exist in the durable sink; the last one's (seq, hash) is the head.
        let prior = seed();
        let head = prior.head().to_string();
        let next_seq = prior.len() as u64; // 3

        // A cold environment resumes from that checkpoint rather than restarting at genesis.
        let mut resumed = Ledger::resume(next_seq, head.clone());
        assert_eq!(
            resumed.head(),
            head,
            "empty resumed ledger heads at the checkpoint"
        );
        let e = resumed.append(EntryKind::Decision, "run1", "t1", "allow after resume", 4);
        assert_eq!(e.seq, 3, "seq continues from the checkpoint, not 0");
        assert_eq!(
            e.prev_hash, head,
            "chains from the durable head, not genesis"
        );
        let first_hash = e.hash.clone();

        let e2 = resumed.append(EntryKind::ToolCall, "run1", "t1", "next", 5);
        assert_eq!(e2.seq, 4);
        assert_eq!(e2.prev_hash, first_hash);

        // The in-memory segment verifies relative to its checkpoint.
        assert!(resumed.verify().is_ok());
    }

    #[test]
    fn chain_is_byte_identical_across_multiple_resumes() {
        // The whole point of anchoring: a chain rebuilt across N cold restarts (a fresh `resume` from
        // the persisted head each time) is IDENTICAL to the same chain built in one process.
        let events = [
            (EntryKind::Decision, "allow db.read", 1u64),
            (EntryKind::ToolCall, "db.read executed", 2),
            (EntryKind::Decision, "allow web.fetch", 3),
            (EntryKind::Approval, "human approved", 4),
            (EntryKind::Meter, "step 5", 5),
            (EntryKind::Tripwire, "decoy touched", 6),
        ];

        // (a) One continuous process.
        let mut single = Ledger::new();
        for &(kind, summary, ts) in &events {
            single.append(kind, "run1", "t1", summary, ts);
        }
        assert!(single.verify().is_ok());
        let single_hashes: Vec<_> = single.entries().iter().map(|e| e.hash.clone()).collect();

        // (b) Rebuilt as three 2-entry segments, each a cold restart resuming from the persisted head.
        let mut head = GENESIS_HASH.to_string();
        let mut next_seq = 0u64;
        let mut rebuilt: Vec<String> = Vec::new();
        for chunk in events.chunks(2) {
            let mut seg = Ledger::resume(next_seq, head.clone());
            for &(kind, summary, ts) in chunk {
                seg.append(kind, "run1", "t1", summary, ts);
            }
            assert!(seg.verify().is_ok(), "each resumed segment verifies");
            assert_eq!(
                seg.entries()[0].prev_hash,
                head,
                "segment chains from the persisted head"
            );
            head = seg.head().to_string();
            next_seq += chunk.len() as u64;
            rebuilt.extend(seg.entries().iter().map(|e| e.hash.clone()));
        }

        assert_eq!(
            rebuilt, single_hashes,
            "segmented restarts reproduce the exact chain"
        );
        assert_eq!(head, single.head(), "final heads match");
    }

    #[test]
    fn tampering_a_resumed_segment_is_detected() {
        let mut l = Ledger::resume(7, "deadbeef");
        l.append(EntryKind::Decision, "r", "t", "ok", 1); // seq 7, prev deadbeef
        l.append(EntryKind::ToolCall, "r", "t", "next", 2); // seq 8
        assert!(l.verify().is_ok());
        // Edit a summary after the fact -> hash mismatch on that entry.
        l.entries[0].summary = "ok (edited)".into();
        assert_eq!(l.verify(), Err(LedgerError::HashMismatch { seq: 7 }));
    }

    #[test]
    fn resume_from_genesis_behaves_like_a_fresh_ledger() {
        let mut r = Ledger::resume(0, GENESIS_HASH);
        let mut n = Ledger::new();
        for i in 0..3 {
            r.append(EntryKind::Decision, "run", "t", "x", i);
            n.append(EntryKind::Decision, "run", "t", "x", i);
        }
        assert_eq!(r.head(), n.head());
        assert!(r.verify().is_ok());
    }

    #[test]
    fn a_resumed_segment_that_starts_at_the_wrong_seq_fails_verify() {
        // A segment whose first entry does not sit at start_seq is a broken/forged resume.
        let mut l = Ledger::resume(5, GENESIS_HASH);
        l.append(EntryKind::Decision, "r", "t", "x", 1); // seq 5
        assert!(l.verify().is_ok());
        l.entries[0].seq = 6; // tamper: not the expected start_seq
        assert_eq!(l.verify(), Err(LedgerError::BadSequence { seq: 6 }));
    }

    #[test]
    fn tampering_with_a_summary_is_detected() {
        let mut l = seed();
        l.entries[1].summary = "db.read executed (edited)".to_string();
        assert_eq!(l.verify(), Err(LedgerError::HashMismatch { seq: 1 }));
    }

    #[test]
    fn deleting_an_entry_breaks_the_chain() {
        let mut l = seed();
        l.entries.remove(1); // seq 2 now sits where seq 1 was
                             // Sequence check fires first (the entry formerly at index 2 has seq 2, not 1).
        assert_eq!(l.verify(), Err(LedgerError::BadSequence { seq: 2 }));
    }

    #[test]
    fn reordering_breaks_the_chain_link() {
        let mut l = seed();
        l.entries.swap(0, 1);
        assert!(l.verify().is_err());
    }

    #[test]
    fn jsonl_has_one_line_per_entry() {
        let l = seed();
        assert_eq!(l.to_jsonl().lines().count(), 3);
    }

    #[test]
    fn memory_gate_denies_untrusted_content() {
        assert_eq!(
            gate_memory_write(&Capability::NONE, Provenance::Untrusted),
            MemoryDecision::Deny("untrusted-origin content may not be written to memory")
        );
    }

    #[test]
    fn memory_gate_requires_human_for_semitrusted_or_tainted_session() {
        assert_eq!(
            gate_memory_write(&Capability::NONE, Provenance::SemiTrusted),
            MemoryDecision::HumanApprove
        );
        let tainted = Capability {
            reads_untrusted: true,
            ..Capability::NONE
        };
        assert_eq!(
            gate_memory_write(&tainted, Provenance::User),
            MemoryDecision::HumanApprove
        );
    }

    #[test]
    fn tripwire_entry_appends_verifies_and_serializes() {
        let mut l = Ledger::new();
        l.append(EntryKind::Decision, "run1", "t1", "allow db.read", 1);
        // A honeypot trip is recorded like any other entry; the summary stays non-sensitive.
        let e = l.append(
            EntryKind::Tripwire,
            "run1",
            "t1",
            "honeypot decoy touched: 169.254.169.254",
            2,
        );
        assert_eq!(e.kind, EntryKind::Tripwire);
        assert!(l.verify().is_ok());
        // The kind round-trips through the JSONL serialization used for the immutable sink.
        assert!(l.to_jsonl().contains("\"tripwire\""));
    }

    #[test]
    fn memory_gate_allows_trusted_content_in_untainted_session() {
        assert_eq!(
            gate_memory_write(&Capability::NONE, Provenance::User),
            MemoryDecision::Allow
        );
        assert_eq!(
            gate_memory_write(&Capability::NONE, Provenance::System),
            MemoryDecision::Allow
        );
    }
}
