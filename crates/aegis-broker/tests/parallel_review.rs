//! Acceptance test for the parallel-review pipeline policy set (`pipelines/parallel-review/`): a
//! fan-out/fan-in chain A -> (B || C) -> D. Agent A dispatches; peer writers B and C improve the
//! text concurrently and each may invoke ONLY its own transform + its submit handoff; referee D is
//! the only principal that may publish. Proves the least-privilege Cedar policy holds and gates it in
//! CI, and that the deployable ASL encodes the parallel structure keyed on the same principals.

use aegis_broker::{Broker, Decision, Session, ToolCall};
use aegis_core::Provenance;
use serde_json::{json, Value};

const TOOLS: &str = include_str!("../../../pipelines/parallel-review/policies/tools.json");
const CEDAR: &str = include_str!("../../../pipelines/parallel-review/policies/broker.cedar");
const ASL: &str = include_str!("../../../pipelines/parallel-review/asl/pipeline.asl.json");

fn broker() -> Broker {
    Broker::from_sources(TOOLS, CEDAR).expect("scenario policies compile together")
}

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
    // Agent A — intake: grammar + dispatch; nothing else.
    assert!(allows(
        "agent-a",
        "grammar.correct",
        json!({"text": "he go"})
    ));
    assert!(allows(
        "agent-a",
        "dispatch.to_workers",
        json!({"text": "He goes."})
    ));
    assert!(!allows("agent-a", "improve.text", json!({"text": "x"})));
    assert!(!allows("agent-a", "publish.final", json!({"text": "x"})));

    // Agent D — referee: select + publish; may not improve or dispatch.
    assert!(allows(
        "agent-d",
        "referee.select",
        json!({"candidates": ["v1", "v2"]})
    ));
    assert!(allows("agent-d", "publish.final", json!({"text": "v2"})));
    assert!(!allows("agent-d", "improve.text", json!({"text": "x"})));
    assert!(!allows(
        "agent-d",
        "dispatch.to_workers",
        json!({"text": "x"})
    ));
}

#[test]
fn b_and_c_are_peers_with_identical_least_privilege() {
    for writer in ["agent-b", "agent-c"] {
        // The writer's lane: improve + submit.
        assert!(allows(writer, "improve.text", json!({"text": "He goes."})));
        assert!(allows(
            writer,
            "submit.candidate",
            json!({"text": "He goes to the shop."})
        ));
        // A peer writer is not the referee and cannot reach the intake/publish lanes.
        assert!(!allows(
            writer,
            "referee.select",
            json!({"candidates": ["x"]})
        ));
        assert!(!allows(writer, "publish.final", json!({"text": "x"})));
        assert!(!allows(writer, "dispatch.to_workers", json!({"text": "x"})));
        assert!(!allows(writer, "grammar.correct", json!({"text": "x"})));
    }
}

#[test]
fn unknown_agent_or_tool_is_denied() {
    assert!(!allows("agent-x", "improve.text", json!({"text": "x"})));
    let broker = broker();
    let mut session = Session::new("agent-b", "run", "thread");
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
    assert!(!allows("agent-b", "improve.text", json!({"text": 42})));
    assert!(!allows(
        "agent-b",
        "improve.text",
        json!({"wrong": "field"})
    ));
}

#[test]
fn asl_fans_out_to_b_and_c_in_parallel_over_one_lambda() {
    let d: Value = serde_json::from_str(ASL).expect("parallel-review ASL is valid JSON");
    assert_eq!(d["StartAt"], "Init");
    let states = &d["States"];

    // A prepares, then a Parallel state, then D referees.
    assert_eq!(
        states["AgentA_Prepare"]["Parameters"]["Payload"]["agent_id"],
        "agent-a"
    );
    assert_eq!(states["AgentA_Prepare"]["Next"], "Improve");

    let improve = &states["Improve"];
    assert_eq!(improve["Type"], "Parallel");
    let branches = improve["Branches"].as_array().expect("Branches array");
    assert_eq!(
        branches.len(),
        2,
        "exactly two peer writers run in parallel"
    );

    let mut agents: Vec<String> = branches
        .iter()
        .map(|b| {
            let start = b["StartAt"].as_str().unwrap();
            let task = &b["States"][start];
            assert_eq!(task["Type"], "Task");
            assert_eq!(
                task["Parameters"]["FunctionName"], "${agent_lambda_arn}",
                "every branch invokes the one shared agent function"
            );
            task["Parameters"]["Payload"]["agent_id"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    agents.sort();
    assert_eq!(agents, vec!["agent-b", "agent-c"]);

    // Fan-in: the two candidates are collected and handed to the referee.
    assert_eq!(improve["ResultSelector"]["candidates.$"], "$[*].text");
    assert_eq!(improve["Next"], "AgentD_Referee");
    assert_eq!(
        states["AgentD_Referee"]["Parameters"]["Payload"]["agent_id"],
        "agent-d"
    );
    assert_eq!(
        states["AgentD_Referee"]["Parameters"]["Payload"]["candidates.$"],
        "$.improve.candidates"
    );

    // The ASL principals are exactly the broker.cedar principals.
    for a in ["agent-a", "agent-b", "agent-c", "agent-d"] {
        assert!(CEDAR.contains(a), "{a} must be a broker.cedar principal");
    }
}

#[test]
fn the_happy_path_flows_end_to_end() {
    let chain = [
        (
            "agent-a",
            "grammar.correct",
            json!({"text": "he go to store"}),
        ),
        (
            "agent-a",
            "dispatch.to_workers",
            json!({"text": "He goes to the store."}),
        ),
        (
            "agent-b",
            "improve.text",
            json!({"text": "He goes to the store."}),
        ),
        (
            "agent-b",
            "submit.candidate",
            json!({"text": "He heads to the store."}),
        ),
        (
            "agent-c",
            "improve.text",
            json!({"text": "He goes to the store."}),
        ),
        (
            "agent-c",
            "submit.candidate",
            json!({"text": "He walks to the store."}),
        ),
        (
            "agent-d",
            "referee.select",
            json!({"candidates": ["v1", "v2"]}),
        ),
        (
            "agent-d",
            "publish.final",
            json!({"text": "He heads to the store."}),
        ),
    ];
    for (agent, tool, args) in chain {
        assert!(
            allows(agent, tool, args),
            "{agent} should be allowed {tool}"
        );
    }
}
