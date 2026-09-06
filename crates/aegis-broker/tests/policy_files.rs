//! Integration test: the broker loaded from the *reference* policy artifacts
//! (`policies/tools.example.json` + `policies/broker.example.cedar`) enforces the intended
//! decisions. The plain `policies/tools.json` / `broker.cedar` are intentionally blank starters
//! (default-deny); this gate validates the populated example set teams copy from.
//!
//! This is the acceptance gate for the keystone against real configuration, not just inline
//! test fixtures.

use aegis_broker::registry::ToolCall;
use aegis_broker::{Broker, Decision, Session};
use aegis_core::Provenance;
use serde_json::json;

fn policy_path(name: &str) -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR = crates/aegis-broker; policies live at ../../policies.
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../policies")
        .join(name)
}

fn shipped_broker() -> Broker {
    let tools = std::fs::read_to_string(policy_path("tools.example.json")).unwrap();
    let cedar = std::fs::read_to_string(policy_path("broker.example.cedar")).unwrap();
    Broker::from_sources(&tools, &cedar).unwrap()
}

#[test]
fn shipped_policies_load() {
    let broker = shipped_broker();
    assert!(broker.registry().len() >= 5);
    assert!(broker.engine().len() >= 3);
}

#[test]
fn benign_reversible_read_is_allowed() {
    let broker = shipped_broker();
    let mut s = Session::new("care-assistant", "run-1", "thread-1");
    // A clean (user-provenance) patient read: sensitive but reversible, single leg.
    let call = ToolCall::new(
        "db.read_patient",
        json!({"patient_id": "abc-123"}),
        Provenance::User,
    );
    assert_eq!(broker.mediate(&mut s, &call), Decision::Allow);
}

#[test]
fn untrusted_argument_read_of_sensitive_is_denied_by_policy() {
    let broker = shipped_broker();
    let mut s = Session::new("care-assistant", "run-1", "thread-1");
    // Untrusted-provenance args reaching sensitive data -> the shipped forbid denies it.
    let call = ToolCall::new(
        "db.read_patient",
        json!({"patient_id": "abc-123"}),
        Provenance::Untrusted,
    );
    assert_eq!(
        broker.mediate(&mut s, &call),
        Decision::deny("policy denies this")
    );
}

#[test]
fn non_system_agent_cannot_rotate_keys() {
    let broker = shipped_broker();
    let mut s = Session::new("care-assistant", "run-1", "thread-1");
    let call = ToolCall::new(
        "admin.rotate_keys",
        json!({"key_id": "k1"}),
        Provenance::User,
    );
    assert_eq!(
        broker.mediate(&mut s, &call),
        Decision::deny("policy denies this")
    );
}

#[test]
fn system_agent_rotate_keys_escalates_to_human() {
    let broker = shipped_broker();
    let mut s = Session::new("system", "run-1", "thread-1");
    // Allowed by policy; irreversible + trifecta-capable tool -> human approval, never silent.
    let call = ToolCall::new(
        "admin.rotate_keys",
        json!({"key_id": "k1"}),
        Provenance::User,
    );
    assert_eq!(broker.mediate(&mut s, &call), Decision::HumanApprove);
}

#[test]
fn tainted_session_cannot_shell_out() {
    let broker = shipped_broker();
    let mut s = Session::new("care-assistant", "run-1", "thread-1");
    // Ingest untrusted web content first.
    let fetch = ToolCall::new(
        "web.fetch",
        json!({"url": "https://example.com/x"}),
        Provenance::Untrusted,
    );
    broker.mediate(&mut s, &fetch);
    let shell = ToolCall::new("os.shell_exec", json!({"cmd": "id"}), Provenance::User);
    assert_eq!(
        broker.mediate(&mut s, &shell),
        Decision::deny("policy denies this")
    );
}
