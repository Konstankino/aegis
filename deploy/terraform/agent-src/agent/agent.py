"""Aegis agent loop (one "turn engine" invoked by Step Functions).

Per invocation it runs the LLM + tool loop IN-PROCESS until it either:
  * produces a final answer                 -> returns {"status": "done", "answer": ...}
  * hits a tool the broker sends to a human -> returns {"status": "needs_approval", "pending": ...}

Step Functions owns the durable pause (waitForTaskToken) and loops back into this Lambda on
approval. Every proposed tool call is mediated through the Aegis inline-plane gate on loopback,
so a fooled model reaches nothing important. Conversation state is checkpointed in DynamoDB
(KMS-encrypted), keyed by thread_id, so it survives the pause.

Standard library + boto3 only (both are in the Lambda runtime). Model access is Amazon Bedrock
(Converse API) — credentials come from the execution role; no keys, no direct internet egress.

This is a SCAFFOLD: the tool implementations in `run_tool` are stubs to replace with your real
side effects; TOOL_SPECS should mirror your project's policies/tools.json.
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

import boto3

GATE = "http://" + os.environ.get("AEGIS_GATE_ADDR", "127.0.0.1:8080")
MODEL_ID = os.environ["MODEL_ID"]
AGENT_ID = os.environ.get("AEGIS_AGENT_ID", "agent")
TABLE = os.environ.get("AEGIS_CHECKPOINT_TABLE")
# The isolated code-runner Lambda (ASI05). Empty = code execution is disabled for this agent.
RUNNER_FUNCTION = os.environ.get("AEGIS_RUNNER_FUNCTION")
MAX_TURNS = int(os.environ.get("AEGIS_MAX_TURNS", "12"))
SYSTEM_PROMPT = os.environ.get(
    "AEGIS_SYSTEM_PROMPT",
    "You are a careful assistant. Use tools only when needed. Your tool requests are mediated by "
    "a security plane; if one is denied, explain and continue without it.",
)

bedrock = boto3.client("bedrock-runtime")
_lambda = boto3.client("lambda")
_ddb = boto3.resource("dynamodb").Table(TABLE) if TABLE else None


# ── The tool registry the model sees (Bedrock Converse toolConfig). Mirror policies/tools.json. ─
TOOL_SPECS = [
    {
        "toolSpec": {
            "name": "db_read_patient",  # Converse tool names can't contain '.'; map to db.read_patient below
            "description": "Read a patient record by id (sensitive data).",
            "inputSchema": {"json": {
                "type": "object",
                "properties": {"patient_id": {"type": "string"}},
                "required": ["patient_id"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "web_fetch",
            "description": "Fetch a URL (subject to the egress allowlist).",
            "inputSchema": {"json": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "email_send",
            "description": "Send an email (high-consequence; may require human approval).",
            "inputSchema": {"json": {
                "type": "object",
                "properties": {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}},
                "required": ["to", "subject", "body"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "code_run",
            "description": "Run a short Python snippet in an isolated sandbox (no network, /tmp only, "
                           "short timeout). Returns stdout/stderr. Use for calculation or data wrangling.",
            "inputSchema": {"json": {
                "type": "object",
                "properties": {"code": {"type": "string"}},
                "required": ["code"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "log_write",
            "description": "Write an audit/log line. Any PII/secrets in the message are auto-redacted "
                           "before it is stored — safe for outcomes like 'file could not be fixed'.",
            "inputSchema": {"json": {
                "type": "object",
                "properties": {"level": {"type": "string", "enum": ["info", "warn", "error"]},
                               "message": {"type": "string"}},
                "required": ["level", "message"],
            }},
        }
    },
]

# Converse tool name (no dots) -> the fully-qualified name the broker/policies use.
TOOL_NAME_MAP = {
    "db_read_patient": "db.read_patient",
    "web_fetch": "web.fetch",
    "email_send": "email.send",
    "code_run": "code.run",
    "log_write": "log.write",
}


# ── Gate helpers (loopback to the aegis-extension) ──────────────────────────────────────────────
def _gate_post(path, body):
    req = urllib.request.Request(
        GATE + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _gate_get(path):
    try:
        with urllib.request.urlopen(GATE + path, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _wait_for_gate(attempts=30, delay=0.1):
    for _ in range(attempts):
        try:
            if _gate_get("/healthz")[0] == 200:
                return True
        except Exception:
            pass
        time.sleep(delay)
    return False


def mediate(thread_id, run_id, fq_tool, args):
    """Run a proposed tool call through the Aegis broker. Returns the decision dict."""
    _, body = _gate_post("/mediate", {
        "agent_id": AGENT_ID, "run_id": run_id, "thread_id": thread_id,
        "tool": fq_tool, "args": args, "arg_provenance": "untrusted",
    })
    return body


def preflight(thread_id, est_tokens):
    """Enforce the token/cost budget before paying for inference."""
    _, body = _gate_post("/meter/preflight", {"thread_id": thread_id, "est_tokens": est_tokens})
    return body


def redact_text(text):
    """Scrub PII/secrets (email/SSN/cards/AWS-keys/API-tokens/IP/phone) via aegis-redact before the
    text is logged or persisted. Returns (clean_text, redaction_count).

    Fail-closed on DISCLOSURE: if the gate cannot redact (unexpected — the gate was health-checked at
    turn start), omit the content rather than risk leaking a raw secret into logs."""
    if not text:
        return "", 0
    try:
        status, body = _gate_post("/redact", {"text": text})
        if status == 200:
            return body.get("text", ""), body.get("total", 0)
    except Exception:  # noqa: BLE001 — never let a redaction failure surface raw content
        pass
    return "[redaction unavailable — content omitted]", 0


# ── Checkpoint (DynamoDB, KMS-encrypted) ────────────────────────────────────────────────────────
def load_messages(thread_id):
    if not _ddb:
        return None
    item = _ddb.get_item(Key={"PK": f"thread#{thread_id}", "SK": "messages"}).get("Item")
    return json.loads(item["value"]) if item else None


def save_messages(thread_id, messages):
    if _ddb:
        _ddb.put_item(Item={"PK": f"thread#{thread_id}", "SK": "messages", "value": json.dumps(messages)})


# ── Tool execution (SCAFFOLD stubs — replace with your real side effects) ───────────────────────
def run_tool(fq_tool, args, thread_id=""):
    if fq_tool == "web.fetch":
        # Route every outbound URL through the egress allowlist first.
        status, body = _gate_get("/decide?url=" + urllib.parse.quote(args.get("url", ""), safe=""))
        if status != 200:
            return {"error": f"egress denied: {body.get('reason')}"}
        # TODO: actually fetch body['url'] (needs a route/endpoint to the allowed host).
        return {"fetched": body.get("url"), "note": "stub — implement the real fetch"}
    if fq_tool == "db.read_patient":
        # TODO: read from your datastore.
        return {"patient_id": args.get("patient_id"), "record": "stub record"}
    if fq_tool == "email.send":
        # TODO: send via SES. Reached only after human approval (high-consequence).
        return {"sent": True, "to": args.get("to")}
    if fq_tool == "code.run":
        return run_code(args.get("code", ""), thread_id)
    if fq_tool == "log.write":
        # Redact BEFORE the line reaches CloudWatch — traces/logs are first-class output (LLM02),
        # so a raw message (e.g. echoing the rejected file's contents) must never be logged verbatim.
        clean, n = redact_text(args.get("message", ""))
        print(json.dumps({"aegis_log": True, "level": args.get("level", "info"),
                          "message": clean, "redactions": n}))
        return {"logged": True, "redactions": n}
    return {"error": f"no implementation for {fq_tool}"}


def run_code(code, thread_id=""):
    """Execute agent-generated code (ASI05): the deterministic /sandbox/validate gate first, then —
    only on allow — invoke the isolated runner Lambda. The broker has already allowed this tool
    call (we are past mediate), so `approved` is true; the sandbox gate is the code-specific check
    (root / network / path / destructive patterns) in front of the real container isolation.

    agent_id/thread_id are sent so a honeypot decoy hit (e.g. the code reads the planted
    ~/.aws/credentials canary) is attributed as a tripwire: an immutable ledger entry keyed by
    thread and a killswitch quarantine of this agent."""
    if not code.strip():
        return {"error": "empty code"}
    # 1) Deterministic policy gate (aegis-sandbox) + honeypot tripwire, via the loopback plane.
    status, body = _gate_post("/sandbox/validate", {
        "command": code, "approved": True, "agent_id": AGENT_ID, "thread_id": thread_id,
    })
    if status != 200 or not body.get("allow"):
        if body.get("tripwire"):
            # A decoy was touched: the agent is now quarantined; surface it plainly.
            return {"error": "sandbox tripwire: honeypot decoy touched (agent quarantined)"}
        return {"error": f"sandbox denied: {body.get('reason', 'policy')}"}
    # 2) Enforcement: hand the code to the locked-down runner (separate function, no network, /tmp).
    if not RUNNER_FUNCTION:
        return {"error": "code execution not configured (no runner)"}
    try:
        resp = _lambda.invoke(
            FunctionName=RUNNER_FUNCTION,
            InvocationType="RequestResponse",
            Payload=json.dumps({"code": code, "timeout_ms": 5000}).encode(),
        )
    except Exception as e:  # noqa: BLE001 — surface any invoke failure to the model as a tool error
        return {"error": f"runner invoke failed: {e}"}
    payload = json.loads(resp["Payload"].read() or b"{}")
    if resp.get("FunctionError"):
        return {"error": "runner crashed", "detail": payload}
    return payload


# ── Message helpers (Bedrock Converse format) ──────────────────────────────────────────────────
def text_of(message):
    return "".join(c.get("text", "") for c in message.get("content", []))


def tool_result_msg(tool_use_id, result):
    return {"role": "user", "content": [{"toolResult": {
        "toolUseId": tool_use_id, "content": [{"json": result}],
    }}]}


def estimate_tokens(messages):
    # Cheap heuristic; the meter also enforces hard caps server-side.
    return max(1, len(json.dumps(messages)) // 4)


# ── The turn engine ─────────────────────────────────────────────────────────────────────────────
def handler(event, context):
    if not _wait_for_gate():
        return {"status": "error", "error": "aegis gate unavailable"}

    thread_id = event["thread_id"]
    run_id = getattr(context, "aws_request_id", "local")
    messages = load_messages(thread_id) or []

    # Resume path: Step Functions is re-invoking us after a human approved a paused action.
    if event.get("resume") and event.get("pending"):
        pending = event["pending"]
        fq = TOOL_NAME_MAP.get(pending["name"], pending["name"])
        result = run_tool(fq, pending["input"], thread_id)  # already mediated + human-approved
        messages.append(tool_result_msg(pending["toolUseId"], result))
    elif event.get("input"):
        messages.append({"role": "user", "content": [{"text": event["input"]}]})

    for _ in range(MAX_TURNS):
        # 1) Budget pre-flight before the model call.
        pf = preflight(thread_id, estimate_tokens(messages))
        if pf.get("decision") == "reject":
            save_messages(thread_id, messages)
            return {"status": "done", "answer": f"stopped (budget): {pf.get('reason')}", "thread_id": thread_id}

        # 2) LLM turn.
        resp = bedrock.converse(
            modelId=MODEL_ID,
            system=[{"text": SYSTEM_PROMPT}],
            messages=messages,
            toolConfig={"tools": TOOL_SPECS},
        )
        out = resp["output"]["message"]
        messages.append(out)

        # 3) Tool call, or final answer?
        tool_use = next((c["toolUse"] for c in out["content"] if "toolUse" in c), None)
        if not tool_use:
            save_messages(thread_id, messages)
            return {"status": "done", "answer": text_of(out), "thread_id": thread_id}

        fq = TOOL_NAME_MAP.get(tool_use["name"], tool_use["name"])

        # 4) Mediate the proposed tool call through Aegis.
        decision = mediate(thread_id, run_id, fq, tool_use["input"])
        verdict = decision.get("decision")

        if verdict == "deny":
            messages.append(tool_result_msg(tool_use["toolUseId"], {"error": decision.get("reason")}))
            continue  # let the model re-plan without the denied tool
        if verdict == "human_approve":
            save_messages(thread_id, messages)  # persist state across the pause
            return {
                "status": "needs_approval",
                "thread_id": thread_id,
                "pending": {"toolUseId": tool_use["toolUseId"], "name": tool_use["name"], "input": tool_use["input"]},
                "capability": decision.get("capability"),
                "ledger": decision.get("ledger"),
            }
        # 5) allow -> execute the tool and feed the result back to the model.
        result = run_tool(fq, tool_use["input"], thread_id)
        messages.append(tool_result_msg(tool_use["toolUseId"], result))

    save_messages(thread_id, messages)
    return {"status": "done", "answer": "stopped (turn budget reached)", "thread_id": thread_id}
