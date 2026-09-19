#!/usr/bin/env python3
"""Amazon Bedrock Converse API **tool use** for the editorial pipeline (A → B → C) — runnable locally.

This is a self-contained reference that drives the SAME editorial flow the deployed plane runs, but in
one process, so you can watch real Bedrock Converse tool use end to end. It reads the SAME source of
truth as production:

  * policies/tools.json   — tool schemas → the Bedrock Converse `toolConfig`
  * policies/broker.cedar — least-privilege authorization (parsed into an allow-map for mediation)
  * pipeline.json         — per-stage system prompt + which tools each principal may see + terminal
  * code/pipeline.py      — the tool implementations (run_tool)

Each stage runs the Converse tool-use loop: send messages + toolConfig → the model returns a
`toolUse` → we **mediate** it against broker.cedar → run the tool → return a `toolResult` → repeat,
until the stage's *terminal* handoff, whose args become the stage output (exactly as the ASL's
ResultSelector expects). Output threads into the next stage: A → B → C.

Usage:
    python3 run_local.py "he go to the stor yesterday"            # offline scripted mock model
    python3 run_local.py --live "he go to the stor yesterday"     # real Bedrock (needs AWS + access)
    python3 run_local.py --live --model anthropic.claude-... --region us-east-1 "..."

    # Mediate + output-scan through the REAL Aegis gate (start it first, see the README):
    python3 run_local.py --gate 127.0.0.1:8785 "he go to the stor yesterday"
"""
import argparse
import importlib.util
import json
import os
import re
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MODEL = os.environ.get("AEGIS_MODEL_ID", "anthropic.claude-sonnet-4-5-20250929-v1:0")
MAX_TURNS = 8


# ── Load the bundle (same files as production) ──────────────────────────────────────────────────
def load_json(*parts):
    with open(os.path.join(HERE, *parts), encoding="utf-8") as fh:
        return json.load(fh)


def load_plugin():
    path = os.path.join(HERE, "code", "pipeline.py")
    spec = importlib.util.spec_from_file_location("editorial_plugin", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_allow_map():
    """Parse broker.cedar into {agent_id: {tool, ...}} so mediation reflects the REAL policy."""
    text = open(os.path.join(HERE, "policies", "broker.cedar"), encoding="utf-8").read()
    allow = {}
    pat = re.compile(
        r'permit\s*\(\s*principal\s*==\s*Agent::"([^"]+)"\s*,\s*action\s*==\s*Action::"invoke"\s*,'
        r'\s*resource\s*==\s*Tool::"([^"]+)"\s*\)',
        re.DOTALL,
    )
    for agent, tool in pat.findall(text):
        allow.setdefault(agent, set()).add(tool)
    return allow


TOOL_SCHEMAS = {t["name"]: t.get("schema", {}) for t in load_json("policies", "tools.json")}
MANIFEST = load_json("pipeline.json")
PLUGIN = load_plugin()
ALLOW = load_allow_map()


# ── Build the per-stage profile (Converse toolConfig + name map + terminal) ─────────────────────
def converse_name(fq):
    """Converse tool names cannot contain '.', so map grammar.correct <-> grammar_correct."""
    return fq.replace(".", "_")


def build_profile(stage):
    tools, name_map = [], {}
    for entry in stage["tools"]:
        fq = entry["name"]
        tools.append({"toolSpec": {
            "name": converse_name(fq),
            "description": entry.get("description", fq),
            "inputSchema": {"json": TOOL_SCHEMAS.get(fq, {"type": "object"})},
        }})
        name_map[converse_name(fq)] = fq
    t = stage["terminal"]
    return {
        "agent_id": stage["agent_id"],
        "system": stage["system"],
        "tools": tools,
        "name_map": name_map,
        "terminal": {t["tool"]: (t["output_key"], t["arg_key"])},
    }


PROFILES = {s["agent_id"]: build_profile(s) for s in MANIFEST["stages"]}


# ── Mediation: mirror the broker's order (unknown tool → schema → policy) ────────────────────────
def mediate(agent_id, fq, args):
    """Deterministic allow/deny for a proposed tool call. Returns (ok: bool, reason: str)."""
    if fq not in TOOL_SCHEMAS:
        return False, "unknown tool"
    schema = TOOL_SCHEMAS[fq]
    for key in schema.get("required", []):
        if key not in args:
            return False, "argument schema violation (missing %s)" % key
    props = schema.get("properties", {})
    for key, val in args.items():
        if schema.get("additionalProperties") is False and key not in props:
            return False, "argument schema violation (unexpected %s)" % key
        want = props.get(key, {}).get("type")
        if want and not _type_ok(want, val):
            return False, "argument schema violation (%s not %s)" % (key, want)
    if fq not in ALLOW.get(agent_id, set()):
        return False, "policy denies this"
    return True, "allow"


def _type_ok(want, val):
    return {
        "string": isinstance(val, str),
        "array": isinstance(val, list),
        "object": isinstance(val, dict),
        "number": isinstance(val, (int, float)) and not isinstance(val, bool),
        "boolean": isinstance(val, bool),
    }.get(want, True)


# ── Plane: where mediation + output scanning happen ─────────────────────────────────────────────
SAFE_BLOCK = "[blocked: output failed a safety scan]"


def _guard_join(value):
    """The text handed to /output/scan for a stage output (a string, or joined candidates)."""
    return "\n".join(str(v) for v in value) if isinstance(value, list) else (value or "")


class LocalPlane:
    """In-process reference: mediation from the parsed broker.cedar; no output scanning (offline)."""

    kind = "local (broker.cedar parsed in-process)"

    def mediate(self, agent_id, fq, args, thread_id):
        return mediate(agent_id, fq, args)

    def guard_output(self, value, thread_id):
        return value  # no scanner offline


class GatePlane:
    """The REAL Aegis inline-plane gate over loopback HTTP: /mediate and /output/scan, exactly the
    endpoints the deployed engine (agent.py) calls. Run the gate locally first (see the README):

        AEGIS_GATE_ADDR=127.0.0.1:8080 \\
        AEGIS_POLICY_DIR=pipelines/editorial/policies \\
        cargo run -p aegis-extension
    """

    def __init__(self, addr):
        self.base = "http://" + addr
        self.kind = "gate @ " + self.base
        self._healthcheck()

    def _post(self, path, body):
        req = urllib.request.Request(
            self.base + path, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def _healthcheck(self):
        try:
            with urllib.request.urlopen(self.base + "/healthz", timeout=5) as r:
                if r.status != 200:
                    raise RuntimeError("gate /healthz returned %d" % r.status)
        except Exception as e:  # noqa: BLE001 — a clear message beats a stack trace here
            raise SystemExit(
                "cannot reach the Aegis gate at %s (%s).\nStart it first, e.g.:\n"
                "  CARGO_TARGET_DIR=$HOME/.aegis-target AEGIS_GATE_ADDR=%s \\\n"
                "  AEGIS_POLICY_DIR=%s cargo run -p aegis-extension"
                % (self.base, e, self.base.replace("http://", ""),
                   os.path.join(HERE, "policies")))

    def mediate(self, agent_id, fq, args, thread_id):
        # The same request shape the engine posts; the gate loads THIS pipeline's tools.json +
        # broker.cedar and applies Cedar keyed on agent_id, accumulating Rule-of-Two taint per thread.
        status, body = self._post("/mediate", {
            "agent_id": agent_id, "run_id": "run-local", "thread_id": thread_id,
            "tool": fq, "args": args, "arg_provenance": "untrusted"})
        decision = body.get("decision", "deny")
        return decision == "allow", body.get("reason") or decision

    def guard_output(self, value, thread_id):
        # /output/scan: PHI/PII + canary/system-prompt-leak; 200 allow, 422 deny -> fail-closed.
        status, _ = self._post("/output/scan", {"thread_id": thread_id, "response": _guard_join(value)})
        if status == 200:
            return value
        return [SAFE_BLOCK] if isinstance(value, list) else SAFE_BLOCK


# ── Bedrock Converse clients ────────────────────────────────────────────────────────────────────
class LiveConverse:
    """The real Amazon Bedrock Converse API."""

    def __init__(self, model, region):
        import boto3  # imported lazily so the offline/mock path needs no AWS SDK
        self.model = model
        self.client = boto3.client("bedrock-runtime", region_name=region)

    def converse(self, system, messages, tools):
        return self.client.converse(
            modelId=self.model,
            system=[{"text": system}],
            messages=messages,
            toolConfig={"tools": tools},
        )


class MockConverse:
    """A scripted stand-in so the flow runs offline (and in tests): it inspects the offered tools to
    know the stage, and the message history to know whether to emit the internal transform or the
    terminal handoff. It does a tiny, believable transform on the seed text."""

    def converse(self, system, messages, tools):
        names = {t["toolSpec"]["name"] for t in tools}
        turns = sum(1 for m in messages if m["role"] == "assistant"
                    for c in m["content"] if "toolUse" in c)
        if "send_to_agent_b" in names:      # Agent A — grammar
            text = _first_user_text(messages)
            fixed = _naive_grammar(text)
            move = ("grammar_correct", {"text": fixed}) if turns == 0 \
                else ("send_to_agent_b", {"text": fixed})
        elif "send_to_agent_c" in names:    # Agent B — enrichment
            text = _first_user_text(messages)
            enriched = text.rstrip(".") + ". (Fun fact: the phrase dates back centuries.)"
            move = ("enrich_add_facts", {"text": text}) if turns == 0 \
                else ("send_to_agent_c", {"candidates": [text, enriched]})
        elif "publish_final" in names:      # Agent C — referee
            cands = _first_user_candidates(messages)
            best = max(cands, key=len) if cands else ""
            move = ("referee_select", {"candidates": cands}) if turns == 0 \
                else ("publish_final", {"text": best})
        else:
            return {"stopReason": "end_turn",
                    "output": {"message": {"role": "assistant", "content": [{"text": "(no tools)"}]}}}
        name, inp = move
        return {"stopReason": "tool_use", "output": {"message": {"role": "assistant", "content": [
            {"toolUse": {"toolUseId": "tu-%s-%d" % (name, turns), "name": name, "input": inp}}]}}}


def _first_user_text(messages):
    for m in messages:
        if m["role"] == "user":
            return "".join(c.get("text", "") for c in m["content"] if "text" in c)
    return ""


def _first_user_candidates(messages):
    listing = _first_user_text(messages)
    return re.findall(r"^\[\d+\]\s*(.+)$", listing, re.MULTILINE) or [listing]


def _naive_grammar(text):
    t = text.strip()
    if t and t[0].islower():
        t = t[0].upper() + t[1:]
    if t and t[-1] not in ".!?":
        t += "."
    return t


# ── Converse tool-use loop for one stage ────────────────────────────────────────────────────────
def tool_result_msg(tool_use_id, result):
    """The Bedrock Converse tool-result turn (a user message carrying the tool output)."""
    return {"role": "user", "content": [{"toolResult": {
        "toolUseId": tool_use_id, "content": [{"json": result}]}}]}


def seed_message(event):
    if "input" in event:
        return {"role": "user", "content": [{"text": event["input"]}]}
    listing = "\n".join("[%d] %s" % (i, c) for i, c in enumerate(event["candidates"]))
    return {"role": "user", "content": [{"text": "Candidate versions:\n" + listing}]}


def run_stage(client, plane, agent_id, event, trace, thread_id="thread-local"):
    """Drive one stage's Converse tool-use loop; return the stage output dict ({output}|{candidates}).
    Mediation and output scanning go through `plane` (in-process, or the real Aegis gate)."""
    profile = PROFILES[agent_id]
    messages = [seed_message(event)]
    for _ in range(MAX_TURNS):
        resp = client.converse(profile["system"], messages, profile["tools"])
        out = resp["output"]["message"]
        messages.append(out)
        tool_uses = [c["toolUse"] for c in out["content"] if "toolUse" in c]
        if not tool_uses:  # the model answered without a handoff — not expected in this pipeline
            return {"output": "".join(c.get("text", "") for c in out["content"])}
        for tu in tool_uses:
            fq = profile["name_map"].get(tu["name"], tu["name"])
            ok, reason = plane.mediate(agent_id, fq, tu["input"], thread_id)
            trace.append((agent_id, fq, "allow" if ok else "DENY", reason))
            if not ok:
                messages.append(tool_result_msg(tu["toolUseId"], {"error": reason}))
                continue
            result = PLUGIN.run_tool(fq, tu["input"], agent_id, thread_id)
            terminal = profile["terminal"].get(fq)
            if terminal:  # the handoff ends the stage; its args ARE the output (scanned before it moves)
                output_key, arg_key = terminal
                payload = plane.guard_output(tu["input"].get(arg_key), thread_id)
                return {output_key: payload}
            messages.append(tool_result_msg(tu["toolUseId"], result if result is not None else {}))
    raise RuntimeError("stage %s did not reach its terminal handoff within %d turns"
                       % (agent_id, MAX_TURNS))


def run_editorial(client, text, plane=None):
    """Drive A → B → C, threading each stage's output into the next (as the ASL does). One thread_id
    for the whole run, so the gate accumulates Rule-of-Two taint across the chain like production."""
    plane = plane or LocalPlane()
    trace, thread = [], "run-local-thread"
    a = run_stage(client, plane, "agent-a", {"input": text}, trace, thread)
    b = run_stage(client, plane, "agent-b", {"input": a["output"]}, trace, thread)
    c = run_stage(client, plane, "agent-c", {"candidates": b["candidates"]}, trace, thread)
    return c["output"], {"a": a, "b": b, "c": c}, trace


# ── CLI ─────────────────────────────────────────────────────────────────────────────────────────
def main(argv=None):
    ap = argparse.ArgumentParser(description="Bedrock Converse tool use for the editorial pipeline.")
    ap.add_argument("text", nargs="?", default="he go to the stor yesterday",
                    help="the raw text to run through A -> B -> C")
    ap.add_argument("--live", action="store_true", help="call real Bedrock (needs AWS + model access)")
    ap.add_argument("--model", default=DEFAULT_MODEL, help="Bedrock model id (with --live)")
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    ap.add_argument("--gate", metavar="ADDR", default=None,
                    help="mediate + output-scan through the REAL Aegis gate at ADDR "
                         "(e.g. 127.0.0.1:8080); default is in-process mediation")
    args = ap.parse_args(argv)

    client = LiveConverse(args.model, args.region) if args.live else MockConverse()
    plane = GatePlane(args.gate) if args.gate else LocalPlane()
    print("model: %s\nplane: %s\n"
          % (args.model if args.live else "MockConverse (offline)", plane.kind))

    final, stages, trace = run_editorial(client, args.text, plane)

    print("=== mediated tool calls (%s) ===" % ("Aegis gate" if args.gate else "broker.cedar"))
    for agent, tool, verdict, reason in trace:
        mark = "  ok " if verdict == "allow" else "DENY "
        print("  %s %-8s %-18s %s" % (mark, agent, tool, "" if verdict == "allow" else "(%s)" % reason))
    print("\n=== stage outputs ===")
    print("  A (grammar)   ->", stages["a"]["output"])
    print("  B (candidates)->", stages["b"]["candidates"])
    print("  C (final)     ->", stages["c"]["output"])
    print("\nINPUT : %s\nFINAL : %s" % (args.text, final))
    return 0


if __name__ == "__main__":
    sys.exit(main())
