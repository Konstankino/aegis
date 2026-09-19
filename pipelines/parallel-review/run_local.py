#!/usr/bin/env python3
"""Amazon Bedrock Converse API **tool use** for the parallel-review pipeline (A → B ∥ C → D).

A fan-out/fan-in run, driven locally so you can watch real Converse tool use end to end: Agent A
dispatches, Agents B and C improve the text CONCURRENTLY (two threads, one shared thread_id), and Agent
D referees the two candidates. Reads the SAME source of truth as production — policies/tools.json (→ the
Converse `toolConfig`), policies/broker.cedar (→ least-privilege mediation), pipeline.json (per-stage
prompt + tools + terminal), code/pipeline.py (tool implementations).

Usage:
    python3 run_local.py "he go to the stor yesterday"                 # offline scripted mock
    python3 run_local.py --live "..."                                  # real Bedrock (AWS + access)
    python3 run_local.py --gate 127.0.0.1:8785 "..."                   # mediate via the real gate

Start the gate first for --gate (dev mode, over THIS pipeline's policies):
    AEGIS_GATE_ADDR=127.0.0.1:8785 AEGIS_POLICY_DIR="$PWD/pipelines/parallel-review/policies" \\
        cargo run -p aegis-extension
"""
import argparse
import concurrent.futures
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
SAFE_BLOCK = "[blocked: output failed a safety scan]"


# ── Bundle (same files as production) ───────────────────────────────────────────────────────────
def load_json(*parts):
    with open(os.path.join(HERE, *parts), encoding="utf-8") as fh:
        return json.load(fh)


def load_plugin():
    path = os.path.join(HERE, "code", "pipeline.py")
    spec = importlib.util.spec_from_file_location("parallel_review_plugin", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_allow_map():
    text = open(os.path.join(HERE, "policies", "broker.cedar"), encoding="utf-8").read()
    pat = re.compile(
        r'permit\s*\(\s*principal\s*==\s*Agent::"([^"]+)"\s*,\s*action\s*==\s*Action::"invoke"\s*,'
        r'\s*resource\s*==\s*Tool::"([^"]+)"\s*\)', re.DOTALL)
    allow = {}
    for agent, tool in pat.findall(text):
        allow.setdefault(agent, set()).add(tool)
    return allow


TOOL_SCHEMAS = {t["name"]: t.get("schema", {}) for t in load_json("policies", "tools.json")}
MANIFEST = load_json("pipeline.json")
PLUGIN = load_plugin()
ALLOW = load_allow_map()


def converse_name(fq):
    return fq.replace(".", "_")


def build_profile(stage):
    tools, name_map = [], {}
    for entry in stage["tools"]:
        fq = entry["name"]
        tools.append({"toolSpec": {
            "name": converse_name(fq), "description": entry.get("description", fq),
            "inputSchema": {"json": TOOL_SCHEMAS.get(fq, {"type": "object"})}}})
        name_map[converse_name(fq)] = fq
    t = stage["terminal"]
    return {"agent_id": stage["agent_id"], "system": stage["system"], "tools": tools,
            "name_map": name_map, "terminal": {t["tool"]: (t["output_key"], t["arg_key"])}}


PROFILES = {s["agent_id"]: build_profile(s) for s in MANIFEST["stages"]}


# ── Mediation (mirror the broker order: unknown tool → schema → policy) ──────────────────────────
def mediate(agent_id, fq, args):
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
    return {"string": isinstance(val, str), "array": isinstance(val, list),
            "object": isinstance(val, dict), "boolean": isinstance(val, bool),
            "number": isinstance(val, (int, float)) and not isinstance(val, bool)}.get(want, True)


def _guard_join(value):
    return "\n".join(str(v) for v in value) if isinstance(value, list) else (value or "")


class LocalPlane:
    kind = "local (broker.cedar parsed in-process)"

    def mediate(self, agent_id, fq, args, thread_id):
        return mediate(agent_id, fq, args)

    def guard_output(self, value, thread_id):
        return value


class GatePlane:
    """The REAL Aegis gate over loopback HTTP (/mediate, /output/scan)."""

    def __init__(self, addr):
        self.base = "http://" + addr
        self.kind = "gate @ " + self.base
        self._healthcheck()

    def _post(self, path, body):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(),
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
        except Exception as e:  # noqa: BLE001
            raise SystemExit(
                "cannot reach the Aegis gate at %s (%s).\nStart it first, e.g.:\n"
                "  CARGO_TARGET_DIR=$HOME/.aegis-target AEGIS_GATE_ADDR=%s \\\n"
                "  AEGIS_POLICY_DIR=%s cargo run -p aegis-extension"
                % (self.base, e, self.base.replace("http://", ""), os.path.join(HERE, "policies")))

    def mediate(self, agent_id, fq, args, thread_id):
        _, body = self._post("/mediate", {
            "agent_id": agent_id, "run_id": "run-local", "thread_id": thread_id,
            "tool": fq, "args": args, "arg_provenance": "untrusted"})
        decision = body.get("decision", "deny")
        return decision == "allow", body.get("reason") or decision

    def guard_output(self, value, thread_id):
        status, _ = self._post("/output/scan", {"thread_id": thread_id, "response": _guard_join(value)})
        if status == 200:
            return value
        return [SAFE_BLOCK] if isinstance(value, list) else SAFE_BLOCK


# ── Bedrock Converse clients ────────────────────────────────────────────────────────────────────
class LiveConverse:
    def __init__(self, model, region):
        import boto3
        self.model, self.client = model, boto3.client("bedrock-runtime", region_name=region)

    def converse(self, system, messages, tools):
        return self.client.converse(modelId=self.model, system=[{"text": system}],
                                    messages=messages, toolConfig={"tools": tools})


class MockConverse:
    """Scripted offline model: A grammar→dispatch, B/C improve→submit, D referee→publish."""

    def converse(self, system, messages, tools):
        names = {t["toolSpec"]["name"] for t in tools}
        turns = sum(1 for m in messages if m["role"] == "assistant"
                    for c in m["content"] if "toolUse" in c)
        if "dispatch_to_workers" in names:      # Agent A
            fixed = _naive_grammar(_first_user_text(messages))
            move = ("grammar_correct", {"text": fixed}) if turns == 0 \
                else ("dispatch_to_workers", {"text": fixed})
        elif "submit_candidate" in names:       # Agents B and C (peers, identical tools)
            text = _first_user_text(messages)
            improved = text.rstrip(".") + " — a clearer, sharper rewrite."
            move = ("improve_text", {"text": text}) if turns == 0 \
                else ("submit_candidate", {"text": improved})
        elif "publish_final" in names:          # Agent D
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
    return {"role": "user", "content": [{"toolResult": {
        "toolUseId": tool_use_id, "content": [{"json": result}]}}]}


def seed_message(event):
    if "input" in event:
        return {"role": "user", "content": [{"text": event["input"]}]}
    listing = "\n".join("[%d] %s" % (i, c) for i, c in enumerate(event["candidates"]))
    return {"role": "user", "content": [{"text": "Candidate versions:\n" + listing}]}


def run_stage(client, plane, agent_id, event, trace, thread_id):
    profile = PROFILES[agent_id]
    messages = [seed_message(event)]
    for _ in range(MAX_TURNS):
        out = client.converse(profile["system"], messages, profile["tools"])["output"]["message"]
        messages.append(out)
        tool_uses = [c["toolUse"] for c in out["content"] if "toolUse" in c]
        if not tool_uses:
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
            if terminal:
                output_key, arg_key = terminal
                return {output_key: plane.guard_output(tu["input"].get(arg_key), thread_id)}
            messages.append(tool_result_msg(tu["toolUseId"], result if result is not None else {}))
    raise RuntimeError("stage %s did not reach its terminal handoff within %d turns"
                       % (agent_id, MAX_TURNS))


def run_parallel(client, text, plane=None):
    """A → (B ∥ C, concurrently on ONE shared thread_id) → D, as the ASL Parallel state does."""
    plane = plane or LocalPlane()
    trace, thread = [], "run-local-thread"
    a = run_stage(client, plane, "agent-a", {"input": text}, trace, thread)

    # Fan-out: B and C run CONCURRENTLY, both taking A's output, both on the shared thread. This
    # exercises the gate under concurrent multi-principal writes to one thread.
    def worker(agent):
        local = []
        out = run_stage(client, plane, agent, {"input": a["output"]}, local, thread)
        return agent, out, local

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        results = {agent: (out, tr) for agent, out, tr in
                   ex.map(worker, ["agent-b", "agent-c"])}
    for agent in ("agent-b", "agent-c"):
        trace.extend(results[agent][1])
    candidates = [results["agent-b"][0]["output"], results["agent-c"][0]["output"]]

    # Fan-in: the referee.
    d = run_stage(client, plane, "agent-d", {"candidates": candidates}, trace, thread)
    return d["output"], {"a": a, "b": results["agent-b"][0], "c": results["agent-c"][0], "d": d}, trace


# ── CLI ─────────────────────────────────────────────────────────────────────────────────────────
def main(argv=None):
    ap = argparse.ArgumentParser(description="Bedrock Converse tool use for the parallel-review pipeline.")
    ap.add_argument("text", nargs="?", default="he go to the stor yesterday")
    ap.add_argument("--live", action="store_true", help="call real Bedrock (needs AWS + model access)")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    ap.add_argument("--gate", metavar="ADDR", default=None,
                    help="mediate + output-scan through the REAL Aegis gate at ADDR (e.g. 127.0.0.1:8785)")
    args = ap.parse_args(argv)

    client = LiveConverse(args.model, args.region) if args.live else MockConverse()
    plane = GatePlane(args.gate) if args.gate else LocalPlane()
    print("model: %s\nplane: %s\n"
          % (args.model if args.live else "MockConverse (offline)", plane.kind))

    final, stages, trace = run_parallel(client, args.text, plane)

    print("=== mediated tool calls (%s) ===" % ("Aegis gate" if args.gate else "broker.cedar"))
    for agent, tool, verdict, reason in trace:
        mark = "  ok " if verdict == "allow" else "DENY "
        print("  %s %-8s %-20s %s" % (mark, agent, tool, "" if verdict == "allow" else "(%s)" % reason))
    print("\n=== stage outputs ===")
    print("  A (prepared) ->", stages["a"]["output"])
    print("  B (candidate)->", stages["b"]["output"])
    print("  C (candidate)->", stages["c"]["output"])
    print("  D (final)    ->", stages["d"]["output"])
    print("\nINPUT : %s\nFINAL : %s" % (args.text, final))
    return 0


if __name__ == "__main__":
    sys.exit(main())
