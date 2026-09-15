"""Unit tests for the generic agent engine (`agent.py`).

No AWS, no network: `boto3` is stubbed in `sys.modules` before import, the gate is replaced with an
in-process broker, and Bedrock is a scripted stand-in. The engine is exercised against a SYNTHETIC
pipeline bundle written to a temp dir (tools.json + pipeline.json + pipeline.py) and loaded via
`agent.reload_bundle()` — so these tests prove the engine is data-driven and pipeline-agnostic, with
no editorial (or any other) pipeline baked in. The editorial pipeline has its own tests under
`pipelines/editorial/code/test_pipeline.py`.

Run: `python3 -m unittest -v` from this directory.
"""

import json
import os
import sys
import tempfile
import types
import unittest

# ── Stub boto3 BEFORE importing agent.py (it calls boto3.client/resource at import time) ─────────
_fake_boto3 = types.ModuleType("boto3")
_fake_boto3.client = lambda *a, **k: types.SimpleNamespace(name=(a[0] if a else "client"))
_fake_boto3.resource = lambda *a, **k: types.SimpleNamespace(Table=lambda *_a, **_k: None)
sys.modules["boto3"] = _fake_boto3

os.environ.setdefault("MODEL_ID", "test-model")
os.environ.setdefault("AEGIS_AGENT_ID", "agent")  # the env default; the event id must override it
os.environ.pop("AEGIS_CHECKPOINT_TABLE", None)     # -> no DynamoDB checkpoint in tests

import agent  # noqa: E402  (import after the stubs/env above, by design)


# A synthetic two-stage pipeline: a text stage (terminal -> {output}) and a collect stage
# (terminal -> {candidates}). Tool SCHEMAS live in tools.json; the engine must build the Converse
# specs from them — nothing about these tools is hard-coded in agent.py.
FIXTURE_TOOLS = [
    {"name": "t.echo", "schema": {"type": "object", "properties": {"text": {"type": "string"}},
                                  "required": ["text"], "additionalProperties": False}},
    {"name": "t.hand", "schema": {"type": "object", "properties": {"text": {"type": "string"}},
                                  "required": ["text"], "additionalProperties": False}},
    {"name": "t.collect", "schema": {"type": "object",
                                     "properties": {"items": {"type": "array", "items": {"type": "string"}}},
                                     "required": ["items"], "additionalProperties": False}},
]
FIXTURE_MANIFEST = {
    "name": "fixture",
    "stages": [
        {"agent_id": "p-a", "state": "A", "system": "stage A",
         "tools": [{"name": "t.echo", "description": "echo the text"}, {"name": "t.hand"}],
         "terminal": {"tool": "t.hand", "output_key": "output", "arg_key": "text"}},
        {"agent_id": "p-b", "state": "B", "system": "stage B",
         "tools": [{"name": "t.collect"}],
         "terminal": {"tool": "t.collect", "output_key": "candidates", "arg_key": "items"}},
    ],
}
FIXTURE_PLUGIN = (
    "def run_tool(fq, args, agent_id='', thread_id=''):\n"
    "    if fq == 't.echo':\n"
    "        return {'echoed': args.get('text', '')}\n"
    "    if fq in ('t.hand', 't.collect'):\n"
    "        return {'ok': True}\n"
    "    return None\n"
)

_ALLOWED = {"p-a": {"t.echo", "t.hand"}, "p-b": {"t.collect"}}


def _write_bundle(dir_path, tools=FIXTURE_TOOLS, manifest=FIXTURE_MANIFEST, plugin=FIXTURE_PLUGIN):
    with open(os.path.join(dir_path, "tools.json"), "w") as fh:
        json.dump(tools, fh)
    if manifest is not None:
        with open(os.path.join(dir_path, "pipeline.json"), "w") as fh:
            json.dump(manifest, fh)
    if plugin is not None:
        with open(os.path.join(dir_path, "pipeline.py"), "w") as fh:
            fh.write(plugin)


def _msg(content):
    return {"output": {"message": {"role": "assistant", "content": content}}}


def _tool_use(name, inp):
    return _msg([{"toolUse": {"toolUseId": f"tu-{name}", "name": name, "input": inp}}])


class _ScriptedModel:
    """Chooses its move from the tools it is shown, so it also proves each principal got the right
    (and only the right) tool profile."""

    def __init__(self):
        self.turns = {}
        self.tools_seen = []

    def converse(self, modelId, system, messages, toolConfig):
        names = {t["toolSpec"]["name"] for t in toolConfig["tools"]}
        self.tools_seen.append(names)
        if "t_hand" in names:      # stage p-a: echo then hand off text
            stage, internal, terminal = "a", ("t_echo", {"text": "hi"}), ("t_hand", {"text": "HELLO"})
        elif "t_collect" in names:  # stage p-b: collect items
            stage, internal, terminal = "b", None, ("t_collect", {"items": ["x", "y"]})
        else:                       # default/locked: nothing to call
            return _msg([{"text": "final answer"}])
        n = self.turns.get(stage, 0)
        self.turns[stage] = n + 1
        if internal and n == 0:
            return _tool_use(*internal)
        return _tool_use(*terminal)


class EngineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        _write_bundle(cls._tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        agent.reload_bundle(self._tmp.name)
        self.mediate_calls = []
        self.model = _ScriptedModel()

        def fake_mediate(agent_id, thread_id, run_id, fq, args):
            self.mediate_calls.append((agent_id, fq))
            allow = fq in _ALLOWED.get(agent_id, set())
            return {"decision": "allow"} if allow else {"decision": "deny", "reason": "policy denies this"}

        self._orig = (agent.bedrock, agent.mediate, agent._wait_for_gate, agent.preflight,
                      agent.save_messages, agent.load_messages, agent.scan_output)
        agent.bedrock = self.model
        agent.mediate = fake_mediate
        agent._wait_for_gate = lambda *a, **k: True
        agent.preflight = lambda *a, **k: {"decision": "allow"}
        agent.save_messages = lambda *a, **k: None
        agent.load_messages = lambda *a, **k: None
        agent.scan_output = lambda *a, **k: True  # output scan allows unless a test overrides

    def tearDown(self):
        (agent.bedrock, agent.mediate, agent._wait_for_gate, agent.preflight,
         agent.save_messages, agent.load_messages, agent.scan_output) = self._orig

    # ── Converse specs are built from tools.json, not hard-coded ────────────────────────────────
    def test_specs_are_derived_from_tools_json(self):
        prof = agent.profile_for("p-a")
        by_name = {t["toolSpec"]["name"]: t["toolSpec"] for t in prof["tools"]}
        self.assertEqual(set(by_name), {"t_echo", "t_hand"})
        # schema comes straight from tools.json; description from the manifest.
        self.assertEqual(by_name["t_echo"]["inputSchema"]["json"], FIXTURE_TOOLS[0]["schema"])
        self.assertEqual(by_name["t_echo"]["description"], "echo the text")
        # dotted<->underscore name mapping is generated, not hand-written.
        self.assertEqual(prof["name_map"], {"t_echo": "t.echo", "t_hand": "t.hand"})

    # ── agent_id is sourced from the event, not the env ─────────────────────────────────────────
    def test_agent_id_comes_from_event(self):
        agent.handler({"agent_id": "p-a", "thread_id": "t", "input": "hi"}, None)
        self.assertTrue(all(aid == "p-a" for aid, _ in self.mediate_calls))
        self.assertNotIn("agent", {aid for aid, _ in self.mediate_calls})

    # ── terminal handoff -> the stage output shape declared in the manifest ─────────────────────
    def test_text_stage_returns_output(self):
        out = agent.handler({"agent_id": "p-a", "thread_id": "t", "input": "hi"}, None)
        self.assertEqual(out, {"status": "done", "output": "HELLO", "thread_id": "t"})
        self.assertEqual([fq for _, fq in self.mediate_calls], ["t.echo", "t.hand"])

    def test_collect_stage_returns_candidates(self):
        out = agent.handler({"agent_id": "p-b", "thread_id": "t", "input": "hi"}, None)
        self.assertEqual(out, {"status": "done", "candidates": ["x", "y"], "thread_id": "t"})

    # ── profile isolation: a principal is shown only its own tools ──────────────────────────────
    def test_profile_isolation(self):
        agent.handler({"agent_id": "p-a", "thread_id": "t", "input": "hi"}, None)
        offered = set().union(*self.model.tools_seen)
        self.assertEqual(offered, {"t_echo", "t_hand"})
        self.assertNotIn("t_collect", offered)

    # ── the pipeline plugin implements its own tools; the engine falls through otherwise ────────
    def test_plugin_run_tool_is_used(self):
        self.assertEqual(agent.run_tool("t.echo", {"text": "abc"}), {"echoed": "abc"})
        # A tool the plugin does not own and the engine does not implement -> explicit no-op error.
        self.assertEqual(agent.run_tool("nope.x", {}), {"error": "no implementation for nope.x"})

    # ── an unknown principal in pipeline mode is locked down (no tools) ─────────────────────────
    def test_unknown_principal_is_locked(self):
        self.assertEqual(agent.profile_for("p-x")["tools"], [])

    # ── with no manifest, every principal gets the generic single-agent profile (all tools) ─────
    def test_default_profile_without_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            _write_bundle(d, manifest=None, plugin=None)
            agent.reload_bundle(d)
            prof = agent.profile_for("whoever")
            self.assertEqual({t["toolSpec"]["name"] for t in prof["tools"]},
                             {"t_echo", "t_hand", "t_collect"})
            self.assertEqual(prof["terminal"], {})  # no terminal -> returns an answer
        agent.reload_bundle(self._tmp.name)

    # ── output scanning (LLM02): a failing scan blocks the outgoing text, fail-closed ────────────
    def test_output_scan_blocks_a_failing_final_answer(self):
        # A single-tool bundle whose model just answers (no tool call), with the scan denying.
        with tempfile.TemporaryDirectory() as d:
            _write_bundle(d, manifest=None, plugin=None)
            agent.reload_bundle(d)
            agent.bedrock = type("M", (), {"converse": staticmethod(
                lambda **_k: _msg([{"text": "patient SSN 123-45-6789"}]))})()
            agent.scan_output = lambda *_a, **_k: False  # scan denies
            out = agent.handler({"agent_id": "x", "thread_id": "t", "input": "hi"}, None)
            self.assertEqual(out["answer"], agent.SAFE_BLOCK)
            self.assertNotIn("123-45-6789", out["answer"])
        agent.reload_bundle(self._tmp.name)

    def test_output_scan_blocks_a_failing_handoff(self):
        # A terminal handoff whose payload fails the scan is replaced before it moves downstream.
        agent.scan_output = lambda *_a, **_k: False
        out = agent.handler({"agent_id": "p-a", "thread_id": "t", "input": "hi"}, None)
        self.assertEqual(out["output"], agent.SAFE_BLOCK)


if __name__ == "__main__":
    unittest.main()
