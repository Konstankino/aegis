//! Acceptance test for the editorial-pipeline scenario policy set
//! (`pipelines/editorial/policies/`): a three-agent chain A → B → C where each agent may
//! invoke ONLY its own transform plus the single handoff it is allowed. Proves the least-privilege
//! Cedar policy holds, and gates it in CI.

use aegis_broker::{Broker, Decision, Session, ToolCall};
use aegis_core::Provenance;
use serde_json::{json, Value};

const TOOLS: &str = include_str!("../../../pipelines/editorial/policies/tools.json");
const CEDAR: &str = include_str!("../../../pipelines/editorial/policies/broker.cedar");

fn broker() -> Broker {
    Broker::from_sources(TOOLS, CEDAR).expect("scenario policies compile together")
}

/// Whether `agent` is allowed to invoke `tool` (a fresh session per call — pure authorization).
fn allows(agent: &str, tool: &str, args: Value) -> bool {
    let broker = broker();
    let mut session = Session::new(agent, "run", "thread");
    matches!(
        broker.mediate(&mut session, &ToolCall::new(tool, args, Provenance::User)),
        Decision::Allow
    )
}

#[test]
fn each_agent_may_call_only_its_own_lane() {
    // Agent A — grammar + the handoff to B; nothing else.
    assert!(allows(
        "agent-a",
        "grammar.correct",
        json!({"text": "he go"})
    ));
    assert!(allows(
        "agent-a",
        "send.to_agent_b",
        json!({"text": "He goes."})
    ));
    assert!(!allows("agent-a", "enrich.add_facts", json!({"text": "x"})));
    assert!(!allows(
        "agent-a",
        "referee.select",
        json!({"candidates": ["x"]})
    ));
    assert!(!allows(
        "agent-a",
        "send.to_agent_c",
        json!({"candidates": ["x"]})
    ));
    assert!(!allows("agent-a", "publish.final", json!({"text": "x"})));

    // Agent B — enrichment + the handoff to C; may not re-run grammar, re-send to B, or publish.
    assert!(allows(
        "agent-b",
        "enrich.add_facts",
        json!({"text": "He goes."})
    ));
    assert!(allows(
        "agent-b",
        "send.to_agent_c",
        json!({"candidates": ["v1", "v2"]})
    ));
    assert!(!allows("agent-b", "grammar.correct", json!({"text": "x"})));
    assert!(!allows("agent-b", "send.to_agent_b", json!({"text": "x"})));
    assert!(!allows("agent-b", "publish.final", json!({"text": "x"})));

    // Agent C — referee + publish; may not enrich or reach back into an earlier lane.
    assert!(allows(
        "agent-c",
        "referee.select",
        json!({"candidates": ["v1", "v2"]})
    ));
    assert!(allows("agent-c", "publish.final", json!({"text": "v2"})));
    assert!(!allows("agent-c", "enrich.add_facts", json!({"text": "x"})));
    assert!(!allows("agent-c", "send.to_agent_b", json!({"text": "x"})));
    assert!(!allows("agent-c", "grammar.correct", json!({"text": "x"})));
}

#[test]
fn ingest_principal_may_only_read_the_source() {
    // agent-ingest exists solely to fetch the dropped *.txt with a short-lived, object-scoped
    // credential; it may invoke source.read and NOTHING else.
    assert!(allows(
        "agent-ingest",
        "source.read",
        json!({"bucket": "b", "key": "incoming/x.txt"})
    ));
    // The version/etag pin (TOCTOU) is part of the schema and passes mediation.
    assert!(allows(
        "agent-ingest",
        "source.read",
        json!({"bucket": "b", "key": "incoming/x.txt", "version_id": "v3", "etag": "e1"})
    ));
    for (tool, args) in [
        ("grammar.correct", json!({"text": "x"})),
        ("send.to_agent_b", json!({"text": "x"})),
        ("enrich.add_facts", json!({"text": "x"})),
        ("send.to_agent_c", json!({"candidates": ["x"]})),
        ("referee.select", json!({"candidates": ["x"]})),
        ("publish.final", json!({"text": "x"})),
    ] {
        assert!(
            !allows("agent-ingest", tool, args),
            "agent-ingest must not be able to call {tool}"
        );
    }
    // Conversely, no editorial agent may read the source — only the ingest principal can.
    for agent in ["agent-a", "agent-b", "agent-c"] {
        assert!(
            !allows(
                agent,
                "source.read",
                json!({"bucket": "b", "key": "incoming/x.txt"})
            ),
            "{agent} must not be able to read the S3 source"
        );
    }
}

#[test]
fn a_cannot_skip_the_chain_and_go_straight_to_c() {
    // The chain is enforced by which handoff each agent holds: A has only send.to_agent_b.
    assert!(!allows(
        "agent-a",
        "send.to_agent_c",
        json!({"candidates": ["x"]})
    ));
    assert!(!allows("agent-a", "publish.final", json!({"text": "x"})));
}

#[test]
fn unknown_agent_or_tool_is_denied() {
    // An unregistered agent principal matches no permit -> default-deny.
    assert!(!allows("agent-x", "grammar.correct", json!({"text": "x"})));
    // An unknown tool fails closed before policy even runs.
    let broker = broker();
    let mut session = Session::new("agent-a", "run", "thread");
    assert!(matches!(
        broker.mediate(
            &mut session,
            &ToolCall::new("hack.exfil", json!({}), Provenance::User)
        ),
        Decision::Deny(_)
    ));
}

#[test]
fn a_malformed_argument_is_refused_by_the_schema() {
    // grammar.correct requires a string `text`; a wrong-typed arg is a structural deny.
    assert!(!allows("agent-a", "grammar.correct", json!({"text": 42})));
    assert!(!allows(
        "agent-a",
        "grammar.correct",
        json!({"wrong": "field"})
    ));
}

const ASL: &str = include_str!("../../../pipelines/editorial/asl/pipeline.asl.json");

#[test]
fn asl_orchestration_is_a_linear_a_b_c_chain_over_one_lambda() {
    // The deployable Step Functions definition parses (the `${agent_lambda_arn}` placeholders are
    // valid JSON strings) and encodes the same A -> B -> C order as the policy.
    let d: Value = serde_json::from_str(ASL).expect("editorial ASL is valid JSON");
    // S3-ingestion-only: the run starts at the agent-ingest stage (there is no HTTP seed path).
    assert_eq!(d["StartAt"], "Ingest");
    let states = &d["States"];

    // Three agent stages, in order, each invoking the SAME agent Lambda with a distinct agent_id —
    // proving agents are principals, not separate functions.
    for (state, agent, next) in [
        ("AgentA_Grammar", "agent-a", "AgentB_Enrich"),
        ("AgentB_Enrich", "agent-b", "AgentC_Referee"),
        ("AgentC_Referee", "agent-c", "Respond"),
    ] {
        let s = &states[state];
        assert_eq!(s["Type"], "Task", "{state} is a Task");
        assert_eq!(
            s["Parameters"]["FunctionName"], "${agent_lambda_arn}",
            "{state} invokes the one shared agent function"
        );
        assert_eq!(
            s["Parameters"]["Payload"]["agent_id"], agent,
            "{state} runs as principal {agent}"
        );
        assert_eq!(s["Next"], next, "{state} advances to {next}");
    }
    // The agent_ids in the ASL are exactly the broker.cedar principals — so the deployed chain is
    // governed by the least-privilege policy this test also verifies.
    assert!(CEDAR.contains("agent-a") && CEDAR.contains("agent-b") && CEDAR.contains("agent-c"));

    // Terminal shape.
    assert_eq!(states["Respond"]["End"], true);
    assert_eq!(states["Failed"]["Type"], "Fail");
}

#[test]
fn asl_entry_is_s3_ingestion_only() {
    // The pipeline's ONLY entry is the S3 file-drop: the state machine starts at the agent-ingest
    // stage, which fetches the dropped object and hands its text into AgentA. There is no HTTP seed
    // path (no Init/Route/SeedText states) — a run is started only by the EventBridge trigger.
    let d: Value = serde_json::from_str(ASL).expect("editorial ASL is valid JSON");
    let states = &d["States"];
    assert_eq!(d["StartAt"], "Ingest", "the run starts at the ingest stage");
    let ingest = &states["Ingest"];
    assert_eq!(ingest["Type"], "Task", "Ingest is a Task");
    assert_eq!(
        ingest["Parameters"]["FunctionName"], "${agent_lambda_arn}",
        "Ingest invokes the one shared agent function"
    );
    assert_eq!(
        ingest["Parameters"]["Payload"]["agent_id"], "agent-ingest",
        "Ingest runs as principal agent-ingest"
    );
    assert_eq!(
        ingest["Next"], "AgentA_Grammar",
        "Ingest hands off into the A->B->C chain"
    );
    // No leftover HTTP-entry states.
    assert!(states["Route"].is_null() && states["SeedText"].is_null() && states["Init"].is_null());
    // The ingest principal is governed by the same least-privilege policy set.
    assert!(CEDAR.contains("agent-ingest"));
}

#[test]
fn the_happy_chain_flows_end_to_end() {
    let chain = [
        (
            "agent-a",
            "grammar.correct",
            json!({"text": "he go to store"}),
        ),
        (
            "agent-a",
            "send.to_agent_b",
            json!({"text": "He goes to the store."}),
        ),
        (
            "agent-b",
            "enrich.add_facts",
            json!({"text": "He goes to the store."}),
        ),
        (
            "agent-b",
            "send.to_agent_c",
            json!({"candidates": ["v1", "v2"]}),
        ),
        (
            "agent-c",
            "referee.select",
            json!({"candidates": ["v1", "v2"]}),
        ),
        ("agent-c", "publish.final", json!({"text": "v2"})),
    ];
    for (agent, tool, args) in chain {
        assert!(
            allows(agent, tool, args),
            "{agent} should be allowed {tool}"
        );
    }
}
