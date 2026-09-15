"""Aegis agent engine — one generic "turn engine" invoked by Step Functions.

It is **pipeline-agnostic**. Everything specific to a pipeline is data + a small plugin, loaded from
the Lambda bundle at start-up (see `pipelines/<name>/` in the repo, staged into the zip by
`modules/aegis-pipeline`):

  * `tools.json`   — the tool SCHEMAS (the same policy artifact the broker enforces). The Converse
                     `toolConfig` is built from these; there are NO tool schemas hard-coded here.
  * `pipeline.json`— the manifest: for each stage/principal, its system prompt, which tools it may
                     see, and the terminal handoff that ends the stage. Absent ⇒ a generic
                     single-agent profile (all tools, returns `{"answer": …}`).
  * `pipeline.py`  — the pipeline's tool implementations: `run_tool(fq, args, agent_id, thread_id)`.
                     Returns None for tools it does not own, so the engine's platform tools apply.

Per invocation it runs the LLM + tool loop IN-PROCESS until it either produces a final answer, hits a
tool the broker sends to a human, or (in a pipeline) invokes its terminal handoff — whose args become
the stage output in the shape the state machine's ResultSelector expects. Every proposed tool call is
mediated through the Aegis inline-plane gate on loopback as the invocation's `agent_id`, so a fooled
model reaches nothing important. Conversation state is checkpointed in DynamoDB (KMS-encrypted), keyed
by thread_id, so it survives the durable pause Step Functions owns.

Standard library + boto3 only. Model access is Amazon Bedrock (Converse) via the execution role.
The engine's own tools are PLATFORM capabilities only (web.fetch via the egress gate, code.run via the
isolated runner, log.write via the redaction gate); domain tools belong to a pipeline plugin.
"""

import importlib.util
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

import boto3

GATE = "http://" + os.environ.get("AEGIS_GATE_ADDR", "127.0.0.1:8080")
MODEL_ID = os.environ["MODEL_ID"]
# Fallback principal when Step Functions does not pass one in the event. In a pipeline the SAME
# function is invoked per stage with a different `agent_id` in the payload, so the per-invocation id
# always wins over this default.
DEFAULT_AGENT_ID = os.environ.get("AEGIS_AGENT_ID", "agent")
TABLE = os.environ.get("AEGIS_CHECKPOINT_TABLE")
# The isolated code-runner Lambda (ASI05). Empty = code execution is disabled for this agent.
RUNNER_FUNCTION = os.environ.get("AEGIS_RUNNER_FUNCTION")
MAX_TURNS = int(os.environ.get("AEGIS_MAX_TURNS", "12"))
# Where the bundle (tools.json / pipeline.json / pipeline.py) sits — the Lambda task root by default.
BUNDLE_DIR = os.environ.get("AEGIS_BUNDLE_DIR", os.path.dirname(os.path.abspath(__file__)))
# System prompt for the generic single-agent profile (used only when there is no pipeline manifest).
DEFAULT_SYSTEM_PROMPT = os.environ.get(
    "AEGIS_SYSTEM_PROMPT",
    "You are a careful assistant. Use tools only when needed. Your tool requests are mediated by "
    "a security plane; if one is denied, explain and continue without it.",
)

bedrock = boto3.client("bedrock-runtime")
_lambda = boto3.client("lambda")
_ddb = boto3.resource("dynamodb").Table(TABLE) if TABLE else None


# ── Bundle loading: tools.json (schemas) + pipeline.json (manifest) + pipeline.py (plugin) ───────
def _load_json(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def load_tool_schemas(bundle_dir):
    """{fully-qualified tool name -> JSON schema} from the pipeline's tools.json (the policy artifact)."""
    tools = _load_json(os.path.join(bundle_dir, "tools.json"), [])
    return {
        t["name"]: t.get("schema", {"type": "object", "additionalProperties": True})
        for t in tools if isinstance(t, dict) and "name" in t
    }


def load_manifest(bundle_dir):
    """The pipeline manifest (stages/principals), or None for a generic single-agent deployment."""
    return _load_json(os.path.join(bundle_dir, "pipeline.json"), None)


def load_plugin(bundle_dir):
    """Import the pipeline's tool implementations from pipeline.py in the bundle, if present."""
    path = os.path.join(bundle_dir, "pipeline.py")
    if not os.path.exists(path):
        return None
    spec = importlib.util.spec_from_file_location("aegis_pipeline_plugin", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def converse_name(fq_tool):
    """Bedrock Converse tool names cannot contain '.', so map `grammar.correct` <-> `grammar_correct`."""
    return fq_tool.replace(".", "_")


def build_tool_spec(fq_tool, schema, description):
    return {"toolSpec": {
        "name": converse_name(fq_tool),
        "description": description or fq_tool,
        "inputSchema": {"json": schema},
    }}


def _profile_from_tools(system, tool_entries, schemas, terminal_spec):
    """Assemble a profile (Converse specs + name map + terminal) from manifest tool entries."""
    tools, name_map = [], {}
    for entry in tool_entries:
        fq = entry["name"] if isinstance(entry, dict) else entry
        desc = entry.get("description") if isinstance(entry, dict) else None
        schema = schemas.get(fq, {"type": "object", "additionalProperties": True})
        tools.append(build_tool_spec(fq, schema, desc))
        name_map[converse_name(fq)] = fq
    terminal = {}
    if terminal_spec:
        terminal = {terminal_spec["tool"]: (terminal_spec["output_key"], terminal_spec["arg_key"])}
    return {"system": system, "tools": tools, "name_map": name_map, "terminal": terminal}


def build_profiles(schemas, manifest):
    """{agent_id -> profile} derived from the manifest. Empty when there is no manifest."""
    if not manifest:
        return {}
    profiles = {}
    for stage in manifest.get("stages", []):
        profiles[stage["agent_id"]] = _profile_from_tools(
            stage.get("system", ""), stage.get("tools", []), schemas, stage.get("terminal"),
        )
    return profiles


def default_profile(schemas):
    """Generic single-agent profile: every tool in tools.json, no terminal (returns an answer)."""
    return _profile_from_tools(DEFAULT_SYSTEM_PROMPT, list(schemas.keys()), schemas, None)


# A pipeline principal with no matching stage gets nothing — the broker would deny it anyway.
LOCKED_PROFILE = {"system": "No tools are available for this principal.", "tools": [],
                  "name_map": {}, "terminal": {}}

TOOL_SCHEMAS = load_tool_schemas(BUNDLE_DIR)
MANIFEST = load_manifest(BUNDLE_DIR)
PLUGIN = load_plugin(BUNDLE_DIR)
PROFILES = build_profiles(TOOL_SCHEMAS, MANIFEST)
DEFAULT_PROFILE = default_profile(TOOL_SCHEMAS)


def profile_for(agent_id):
    """The tool profile shown to this principal. Pipeline mode is keyed by agent_id; without a
    manifest, every principal gets the generic single-agent profile."""
    if agent_id in PROFILES:
        return PROFILES[agent_id]
    if PROFILES:  # pipeline mode, but an unrecognised principal -> no tools
        return LOCKED_PROFILE
    return DEFAULT_PROFILE


def reload_bundle(bundle_dir):
    """Re-read the bundle from `bundle_dir` and rebuild the derived registries. Test seam; also lets a
    warm container pick up a hot-swapped bundle."""
    global TOOL_SCHEMAS, MANIFEST, PLUGIN, PROFILES, DEFAULT_PROFILE  # noqa: PLW0603
    TOOL_SCHEMAS = load_tool_schemas(bundle_dir)
    MANIFEST = load_manifest(bundle_dir)
    PLUGIN = load_plugin(bundle_dir)
    PROFILES = build_profiles(TOOL_SCHEMAS, MANIFEST)
    DEFAULT_PROFILE = default_profile(TOOL_SCHEMAS)


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


def mediate(agent_id, thread_id, run_id, fq_tool, args):
    """Run a proposed tool call through the Aegis broker as `agent_id`. Returns the decision dict."""
    _, body = _gate_post("/mediate", {
        "agent_id": agent_id, "run_id": run_id, "thread_id": thread_id,
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


# ── Output scanning (LLM02/LLM07) ───────────────────────────────────────────────────────────────
SAFE_BLOCK = "[blocked: output failed a safety scan]"


def scan_output(thread_id, text):
    """Scan outgoing model text through the plane's `/output/scan` (PHI/PII leak + canary /
    system-prompt-leak) before it leaves this stage. Returns True to allow.

    Fail-closed: a deny (422) OR an unreachable gate returns False — the gate was health-checked at
    turn start, so a failure here is treated as 'do not emit', never as a pass."""
    if not text:
        return True
    try:
        status, _ = _gate_post("/output/scan", {"thread_id": thread_id, "response": text})
        return status == 200
    except Exception:  # noqa: BLE001 — never let a scan failure leak unscanned output
        return False


def guarded_output(thread_id, value):
    """Scan an outgoing value before it is returned (a final answer, or a stage handoff to the next
    agent). Accepts a string or a list of candidate strings; returns a safe placeholder in place of
    any content that fails the scan, so nothing unsafe moves downstream."""
    if isinstance(value, list):
        joined = "\n".join(str(v) for v in value)
        return value if scan_output(thread_id, joined) else [SAFE_BLOCK]
    return value if scan_output(thread_id, value or "") else SAFE_BLOCK


# ── Checkpoint (DynamoDB, KMS-encrypted) ────────────────────────────────────────────────────────
def load_messages(thread_id):
    if not _ddb:
        return None
    item = _ddb.get_item(Key={"PK": f"thread#{thread_id}", "SK": "messages"}).get("Item")
    return json.loads(item["value"]) if item else None


def save_messages(thread_id, messages):
    if _ddb:
        _ddb.put_item(Item={"PK": f"thread#{thread_id}", "SK": "messages", "value": json.dumps(messages)})


# ── Tool execution ──────────────────────────────────────────────────────────────────────────────
def run_tool(fq_tool, args, agent_id="", thread_id=""):
    """Execute a broker-allowed tool. The pipeline plugin handles its own (domain) tools first; the
    engine provides only PLATFORM tools that are cross-cutting capabilities of the guardrail plane."""
    if PLUGIN is not None and hasattr(PLUGIN, "run_tool"):
        result = PLUGIN.run_tool(fq_tool, args, agent_id, thread_id)
        if result is not None:
            return result

    if fq_tool == "web.fetch":
        # Route every outbound URL through the egress allowlist first.
        status, body = _gate_get("/decide?url=" + urllib.parse.quote(args.get("url", ""), safe=""))
        if status != 200:
            return {"error": f"egress denied: {body.get('reason')}"}
        # TODO: actually fetch body['url'] (needs a route/endpoint to the allowed host).
        return {"fetched": body.get("url"), "note": "stub — implement the real fetch"}
    if fq_tool == "code.run":
        return run_code(args.get("code", ""), agent_id, thread_id)
    if fq_tool == "log.write":
        # Redact BEFORE the line reaches CloudWatch — traces/logs are first-class output (LLM02),
        # so a raw message (e.g. echoing rejected content) must never be logged verbatim.
        clean, n = redact_text(args.get("message", ""))
        print(json.dumps({"aegis_log": True, "level": args.get("level", "info"),
                          "message": clean, "redactions": n}))
        return {"logged": True, "redactions": n}
    return {"error": f"no implementation for {fq_tool}"}


def run_code(code, agent_id="", thread_id=""):
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
        "command": code, "approved": True, "agent_id": agent_id, "thread_id": thread_id,
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


def seed_input(event):
    """Turn the stage input into the first user message. A referee stage receives `candidates`
    (a list) rather than a single `input` text."""
    if event.get("input") is not None:
        return {"role": "user", "content": [{"text": event["input"]}]}
    if event.get("candidates") is not None:
        listing = "\n".join(f"[{i}] {c}" for i, c in enumerate(event["candidates"]))
        return {"role": "user", "content": [{"text": "Candidate versions:\n" + listing}]}
    return None


# ── The turn engine ─────────────────────────────────────────────────────────────────────────────
def handler(event, context):
    if not _wait_for_gate():
        return {"status": "error", "error": "aegis gate unavailable"}

    thread_id = event["thread_id"]
    run_id = getattr(context, "aws_request_id", "local")
    # The principal for THIS invocation: Step Functions passes it per pipeline stage; env is only a
    # fallback. Every mediate call and the tool profile below key off this id.
    agent_id = event.get("agent_id") or DEFAULT_AGENT_ID
    profile = profile_for(agent_id)
    messages = load_messages(thread_id) or []

    # Resume path: Step Functions is re-invoking us after a human approved a paused action.
    if event.get("resume") and event.get("pending"):
        pending = event["pending"]
        fq = profile["name_map"].get(pending["name"], pending["name"])
        result = run_tool(fq, pending["input"], agent_id, thread_id)  # already mediated + approved
        messages.append(tool_result_msg(pending["toolUseId"], result))
    else:
        seeded = seed_input(event)
        if seeded:
            messages.append(seeded)

    for _ in range(MAX_TURNS):
        # 1) Budget pre-flight before the model call.
        pf = preflight(thread_id, estimate_tokens(messages))
        if pf.get("decision") == "reject":
            save_messages(thread_id, messages)
            return {"status": "done", "answer": f"stopped (budget): {pf.get('reason')}", "thread_id": thread_id}

        # 2) LLM turn — the profile decides which tools this principal is shown.
        resp = bedrock.converse(
            modelId=MODEL_ID,
            system=[{"text": profile["system"]}],
            messages=messages,
            toolConfig={"tools": profile["tools"]},
        )
        out = resp["output"]["message"]
        messages.append(out)

        # 3) Tool call, or final answer?
        tool_use = next((c["toolUse"] for c in out["content"] if "toolUse" in c), None)
        if not tool_use:
            # Final answer: scan it before it reaches the user (LLM02) — never emit unscanned model
            # output.
            answer = guarded_output(thread_id, text_of(out))
            save_messages(thread_id, messages)
            return {"status": "done", "answer": answer, "thread_id": thread_id}

        fq = profile["name_map"].get(tool_use["name"], tool_use["name"])

        # 4) Mediate the proposed tool call through Aegis as this principal.
        decision = mediate(agent_id, thread_id, run_id, fq, tool_use["input"])
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
        # 5) allow -> execute the governed side effect.
        result = run_tool(fq, tool_use["input"], agent_id, thread_id)

        # A terminal handoff ends this stage: its args ARE the stage output, shaped for the state
        # machine's ResultSelector ({output: ...} or {candidates: [...]}).
        terminal = profile["terminal"].get(fq)
        if terminal:
            result_key, arg_key = terminal
            # Scan the handoff BEFORE it moves to the next stage — a compromised agent must not pass
            # leaked/unsafe content down the chain.
            payload = guarded_output(thread_id, tool_use["input"].get(arg_key))
            save_messages(thread_id, messages)
            return {"status": "done", result_key: payload, "thread_id": thread_id}

        messages.append(tool_result_msg(tool_use["toolUseId"], result))

    save_messages(thread_id, messages)
    return {"status": "done", "answer": "stopped (turn budget reached)", "thread_id": thread_id}
