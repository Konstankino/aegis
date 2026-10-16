"""Tests for the parallel-review pipeline (fan-out/fan-in: A -> (B || C) -> D).

Three kinds of check, none needing AWS:
  1. the plugin transforms in `pipeline.py`;
  2. consistency — the manifest, tools.json, broker.cedar and the (Parallel) state machine agree on
     the same principals and tools; and
  3. an END-TO-END run of every stage through the REAL generic engine (staged bundle + scripted
     model + in-process broker), proving the engine serves this fan-out topology from data alone,
     with no engine change — the parallelism lives only in the ASL.

Run: `python3 -m unittest -v` from this directory.
"""

import json
import os
import sys
import tempfile
import types
import unittest

import pipeline  # the plugin under test (same directory)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                     # pipelines/parallel-review
REPO = os.path.dirname(os.path.dirname(ROOT))    # repo root
AGENT_DIR = os.path.join(REPO, "deploy", "terraform", "agent-src", "agent")


def _load(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return json.load(fh)


# ── 1. Plugin ────────────────────────────────────────────────────────────────────────────────────
class PluginTest(unittest.TestCase):
    def test_transforms(self):
        self.assertEqual(pipeline.run_tool("grammar.correct", {"text": "he go"}), {"corrected": "he go"})
        self.assertEqual(pipeline.run_tool("improve.text", {"text": "x"}), {"improved": "x"})
        self.assertEqual(pipeline.run_tool("referee.select", {"candidates": ["b", "c"]}),
                         {"selected": "b", "index": 0})

    def test_handoffs(self):
        for tool in ("dispatch.to_workers", "submit.candidate", "publish.final"):
            self.assertEqual(pipeline.run_tool(tool, {"text": "x"}), {"handoff": tool, "ok": True})

    def test_foreign_tools_fall_through(self):
        self.assertIsNone(pipeline.run_tool("web.fetch", {"url": "https://x"}))


# ── 2. Consistency (navigates the Parallel branches) ─────────────────────────────────────────────
class ConsistencyTest(unittest.TestCase):
    def setUp(self):
        self.manifest = _load("pipeline.json")
        self.tool_names = {t["name"] for t in _load("policies", "tools.json")}
        self.asl = _load("asl", "pipeline.asl.json")
        with open(os.path.join(ROOT, "policies", "broker.cedar"), encoding="utf-8") as fh:
            self.cedar = fh.read()

    def _find_state(self, name):
        """Locate a state by name at the top level or inside any Parallel branch."""
        states = self.asl["States"]
        if name in states:
            return states[name]
        for st in states.values():
            for branch in st.get("Branches", []):
                if name in branch["States"]:
                    return branch["States"][name]
        return None

    def test_tools_exist_and_are_implemented(self):
        for stage in self.manifest["stages"]:
            for entry in stage["tools"]:
                self.assertIn(entry["name"], self.tool_names, f"{entry['name']} missing from tools.json")
                self.assertIsNotNone(pipeline.run_tool(entry["name"], {}), f"{entry['name']} not in pipeline.py")
            self.assertIn(stage["terminal"]["tool"], self.tool_names)

    def test_principals_match_cedar_and_asl(self):
        for stage in self.manifest["stages"]:
            self.assertIn(stage["agent_id"], self.cedar, f"{stage['agent_id']} not in broker.cedar")
            st = self._find_state(stage["state"])
            self.assertIsNotNone(st, f"{stage['state']} not found in the ASL")
            self.assertEqual(st["Type"], "Task")
            self.assertEqual(st["Parameters"]["FunctionName"], "${agent_lambda_arn}")
            self.assertEqual(st["Parameters"]["Payload"]["agent_id"], stage["agent_id"])

    def test_b_and_c_run_in_parallel_as_peers(self):
        improve = self.asl["States"]["Improve"]
        self.assertEqual(improve["Type"], "Parallel")
        branch_agents = {
            b["States"][b["StartAt"]]["Parameters"]["Payload"]["agent_id"] for b in improve["Branches"]
        }
        self.assertEqual(branch_agents, {"agent-b", "agent-c"})
        # Peers = identical tool sets in the manifest.
        by_id = {s["agent_id"]: {t["name"] for t in s["tools"]} for s in self.manifest["stages"]}
        self.assertEqual(by_id["agent-b"], by_id["agent-c"])
        # Fan-in: the referee consumes the collected candidates.
        self.assertEqual(improve["ResultSelector"]["candidates.$"], "$[*].text")
        self.assertEqual(
            self.asl["States"]["AgentD_Referee"]["Parameters"]["Payload"]["candidates.$"],
            "$.improve.candidates",
        )

    def test_top_level_flow(self):
        s = self.asl["States"]
        self.assertEqual(self.asl["StartAt"], "Init")
        self.assertEqual(s["Init"]["Next"], "AgentA_Prepare")
        self.assertEqual(s["AgentA_Prepare"]["Next"], "Improve")
        self.assertEqual(s["Improve"]["Next"], "AgentD_Referee")
        self.assertEqual(s["AgentD_Referee"]["Next"], "Respond")


# ── 3. End-to-end through the real engine (staged bundle, scripted model, in-process broker) ──────
_ALLOWED = {
    "agent-a": {"grammar.correct", "dispatch.to_workers"},
    "agent-b": {"improve.text", "submit.candidate"},
    "agent-c": {"improve.text", "submit.candidate"},
    "agent-d": {"referee.select", "publish.final"},
}


def _msg(content):
    return {"output": {"message": {"role": "assistant", "content": content}}}


def _tool_use(name, inp):
    return _msg([{"toolUse": {"toolUseId": f"tu-{name}", "name": name, "input": inp}}])


class _ScriptedModel:
    """Chooses its move from the tools it is shown (also proving each principal's profile)."""

    def __init__(self):
        self.turns = {}

    def converse(self, modelId, system, messages, toolConfig):
        names = {t["toolSpec"]["name"] for t in toolConfig["tools"]}
        if "dispatch_to_workers" in names:      # agent-a
            plan = ("a", ("grammar_correct", {"text": "he go"}), ("dispatch_to_workers", {"text": "He goes."}))
        elif "submit_candidate" in names:       # agent-b / agent-c (peers)
            plan = ("bc", ("improve_text", {"text": "He goes."}),
                    ("submit_candidate", {"text": "He goes to the shop."}))
        elif "publish_final" in names:          # agent-d
            plan = ("d", ("referee_select", {"candidates": ["v1", "v2"]}),
                    ("publish_final", {"text": "He goes to the shop."}))
        else:
            return _msg([{"text": "final answer"}])
        stage, internal, terminal = plan
        n = self.turns.get(stage, 0)
        self.turns[stage] = n + 1
        return _tool_use(*(internal if n == 0 else terminal))


class EngineEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Stage the bundle the way modules/aegis-pipeline does: engine + tools.json + pipeline.json +
        # pipeline.py flattened into one dir.
        cls._tmp = tempfile.TemporaryDirectory()
        d = cls._tmp.name
        for src, dst in [
            (os.path.join(ROOT, "policies", "tools.json"), "tools.json"),
            (os.path.join(ROOT, "pipeline.json"), "pipeline.json"),
            (os.path.join(ROOT, "code", "pipeline.py"), "pipeline.py"),
        ]:
            with open(src, encoding="utf-8") as fh:
                data = fh.read()
            with open(os.path.join(d, dst), "w", encoding="utf-8") as fh:
                fh.write(data)

        # Import the engine with boto3 stubbed and the bundle pointed at the staged dir.
        fake = types.ModuleType("boto3")
        fake.client = lambda *a, **k: types.SimpleNamespace()
        fake.resource = lambda *a, **k: types.SimpleNamespace(Table=lambda *_a, **_k: None)
        sys.modules["boto3"] = fake
        os.environ["MODEL_ID"] = "test-model"
        os.environ["AEGIS_BUNDLE_DIR"] = d
        os.environ.pop("AEGIS_CHECKPOINT_TABLE", None)
        sys.path.insert(0, AGENT_DIR)
        import agent  # noqa: E402
        cls.agent = agent
        agent.reload_bundle(d)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        agent = self.agent
        self.mediate_calls = []

        def fake_mediate(agent_id, thread_id, run_id, fq, args):
            self.mediate_calls.append((agent_id, fq))
            ok = fq in _ALLOWED.get(agent_id, set())
            return {"decision": "allow"} if ok else {"decision": "deny", "reason": "policy denies this"}

        self._orig = (agent.bedrock, agent.mediate, agent._wait_for_gate, agent.preflight,
                      agent.save_messages, agent.load_messages, agent.scan_output)
        agent.bedrock = _ScriptedModel()
        agent.mediate = fake_mediate
        agent._wait_for_gate = lambda *a, **k: True
        agent.preflight = lambda *a, **k: {"decision": "allow"}
        agent.save_messages = lambda *a, **k: None
        agent.load_messages = lambda *a, **k: None
        agent.scan_output = lambda *a, **k: True  # output scan allows in these E2E tests

    def tearDown(self):
        a = self.agent
        (a.bedrock, a.mediate, a._wait_for_gate, a.preflight, a.save_messages, a.load_messages,
         a.scan_output) = self._orig

    def test_agent_a_dispatches_prepared_text(self):
        out = self.agent.handler({"agent_id": "agent-a", "thread_id": "t", "input": "he go"}, None)
        self.assertEqual(out, {"status": "done", "output": "He goes.", "thread_id": "t"})

    def test_peers_b_and_c_each_submit_a_candidate(self):
        # B and C are separate invocations (parallel in the ASL); each returns its own {output}.
        for aid in ("agent-b", "agent-c"):
            self.agent.bedrock = _ScriptedModel()  # a fresh conversation per (parallel) invocation
            out = self.agent.handler({"agent_id": aid, "thread_id": "t", "input": "He goes."}, None)
            self.assertEqual(out["output"], "He goes to the shop.")
            self.assertEqual([fq for a, fq in self.mediate_calls if a == aid],
                             ["improve.text", "submit.candidate"])

    def test_referee_consumes_candidates_and_publishes(self):
        out = self.agent.handler({"agent_id": "agent-d", "thread_id": "t",
                                  "candidates": ["v1", "v2"]}, None)
        self.assertEqual(out, {"status": "done", "output": "He goes to the shop.", "thread_id": "t"})

    def test_a_worker_may_not_publish(self):
        # A peer writer is not the referee: the broker denies publish.final even if the model tries.
        # The terminal tuple carries (output_key, arg_key, source); "args" is the default source.
        self.assertEqual(self.agent.profile_for("agent-b")["terminal"],
                         {"submit.candidate": ("output", "text", "args")})
        self.assertNotIn("publish_final",
                         {t["toolSpec"]["name"] for t in self.agent.profile_for("agent-b")["tools"]})


if __name__ == "__main__":
    unittest.main()
