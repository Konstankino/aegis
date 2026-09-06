"""Aegis multi-agent supervisor (planner).

Given the user's request, it asks the LLM to decompose it into independent sub-tasks, each routed
to a named worker role. Step Functions then fans out to a worker agent per sub-task (the same
turn-engine as the single-agent scaffold, `agent.py`), each of which mediates its own tool calls
through the Aegis gate and pauses for human approval independently.

The supervisor itself calls no tools — it only plans — so there is nothing to mediate here; the
containment happens in each worker. Inter-agent coordination is carried by the Step Functions
state (the trust boundary). If you run a Rust supervisor instead, wrap each sub-task in a signed
`aegis-intent` capsule and have workers validate it via the gate's `/intent/validate`.

Standard library + boto3 only. Model access is Amazon Bedrock (Converse).
"""

import json
import os

import boto3

MODEL_ID = os.environ["MODEL_ID"]
MAX_SUBTASKS = int(os.environ.get("AEGIS_MAX_SUBTASKS", "4"))
# Comma-separated worker roles this supervisor may route to (mirror your deployed workers).
WORKER_ROLES = [r.strip() for r in os.environ.get("AEGIS_WORKER_ROLES", "researcher,writer").split(",")]

bedrock = boto3.client("bedrock-runtime")

# A single tool the model uses to emit its plan as structured data (so we never parse free text).
PLAN_TOOL = [{
    "toolSpec": {
        "name": "emit_plan",
        "description": "Emit the plan as a list of independent sub-tasks for worker agents.",
        "inputSchema": {"json": {
            "type": "object",
            "properties": {
                "subtasks": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "worker_role": {"type": "string", "enum": WORKER_ROLES},
                            "task": {"type": "string"},
                        },
                        "required": ["worker_role", "task"],
                    },
                }
            },
            "required": ["subtasks"],
        }},
    }
}]


def handler(event, context):
    user_input = event["input"]
    thread_id = event["thread_id"]

    system = (
        "You are a supervisor that breaks a user request into a small number of independent "
        f"sub-tasks. Route each to one of these worker roles: {', '.join(WORKER_ROLES)}. "
        "Call emit_plan exactly once with the sub-tasks."
    )
    resp = bedrock.converse(
        modelId=MODEL_ID,
        system=[{"text": system}],
        messages=[{"role": "user", "content": [{"text": user_input}]}],
        toolConfig={"tools": PLAN_TOOL, "toolChoice": {"tool": {"name": "emit_plan"}}},
    )
    out = resp["output"]["message"]
    plan = next((c["toolUse"]["input"] for c in out["content"] if "toolUse" in c), {"subtasks": []})

    # Clamp fan-out (the meter also enforces a hard fan-out cap server-side).
    subtasks = plan.get("subtasks", [])[:MAX_SUBTASKS]
    # Give each sub-task its own thread id so worker sessions/taint don't bleed together.
    enriched = [
        {
            "index": i,
            "worker_role": st["worker_role"],
            "task": st["task"],
            "thread_id": f"{thread_id}#{st['worker_role']}#{i}",
        }
        for i, st in enumerate(subtasks)
    ]
    return {"thread_id": thread_id, "subtasks": enriched}
