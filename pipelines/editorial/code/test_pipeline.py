"""Tests for the editorial pipeline definition.

Two kinds of check, neither of which needs AWS:
  1. the plugin transforms in `pipeline.py` behave; and
  2. the pipeline is internally consistent — the manifest (`pipeline.json`), the policy tool set
     (`policies/tools.json`), the Cedar policy (`policies/broker.cedar`) and the state machine
     (`asl/pipeline.asl.json`) all agree on the same principals and tools. This is what lets the ONE
     generic engine serve A/B/C from data alone.

Run: `python3 -m unittest -v` from this directory.
"""

import json
import os
import unittest

import pipeline  # the plugin under test (same directory)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # pipelines/editorial


def _load(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return json.load(fh)


class PluginTest(unittest.TestCase):
    def test_transforms(self):
        self.assertEqual(pipeline.run_tool("grammar.correct", {"text": "he go"}), {"corrected": "he go"})
        self.assertEqual(pipeline.run_tool("referee.select", {"candidates": ["v1", "v2"]}),
                         {"selected": "v1", "index": 0})
        self.assertEqual(pipeline.run_tool("referee.select", {"candidates": []}),
                         {"selected": "", "index": -1})
        enr = pipeline.run_tool("enrich.add_facts", {"text": "x"})
        self.assertEqual(enr["enriched"], "x")

    def test_handoffs_are_acknowledged(self):
        for tool in ("send.to_agent_b", "send.to_agent_c", "publish.final"):
            self.assertEqual(pipeline.run_tool(tool, {"text": "x"}), {"handoff": tool, "ok": True})

    def test_returns_none_for_foreign_tools(self):
        # Anything this pipeline does not own must fall through to the engine.
        self.assertIsNone(pipeline.run_tool("web.fetch", {"url": "https://x"}))
        self.assertIsNone(pipeline.run_tool("code.run", {"code": "1"}))


class ConsistencyTest(unittest.TestCase):
    def setUp(self):
        self.manifest = _load("pipeline.json")
        self.tool_names = {t["name"] for t in _load("policies", "tools.json")}
        self.asl = _load("asl", "pipeline.asl.json")
        with open(os.path.join(ROOT, "policies", "broker.cedar"), encoding="utf-8") as fh:
            self.cedar = fh.read()

    def test_every_manifest_tool_exists_in_policy(self):
        for stage in self.manifest["stages"]:
            for entry in stage["tools"]:
                name = entry["name"] if isinstance(entry, dict) else entry
                self.assertIn(name, self.tool_names, f"{name} missing from tools.json")
            self.assertIn(stage["terminal"]["tool"], self.tool_names)

    # Platform tools are cross-cutting capabilities of the guardrail plane, implemented by the ENGINE
    # (agent.py), not by a pipeline plugin — the plugin returns None for them so the engine takes over.
    PLATFORM_TOOLS = {"source.read", "web.fetch", "code.run", "log.write"}

    def test_every_manifest_tool_is_implemented_by_the_plugin_or_is_a_platform_tool(self):
        for stage in self.manifest["stages"]:
            for entry in stage["tools"]:
                name = entry["name"] if isinstance(entry, dict) else entry
                if name in self.PLATFORM_TOOLS:
                    # Engine-provided: the plugin must NOT own it (falls through to the platform).
                    self.assertIsNone(pipeline.run_tool(name, {}),
                                      f"{name} is a platform tool; the plugin must not implement it")
                else:
                    self.assertIsNotNone(pipeline.run_tool(name, {}),
                                         f"{name} not implemented in pipeline.py")

    def test_ingest_stage_reads_the_source_with_a_platform_tool(self):
        # The optional first stage fetches the dropped file; it is a distinct principal that may use
        # ONLY source.read, and its terminal draws the stage output from the tool RESULT (the fetched
        # text), not the call args — so the document is not rewritten by the model.
        ingest = next((s for s in self.manifest["stages"] if s["agent_id"] == "agent-ingest"), None)
        self.assertIsNotNone(ingest, "manifest must define the agent-ingest stage")
        self.assertEqual([t["name"] for t in ingest["tools"]], ["source.read"])
        self.assertEqual(ingest["terminal"],
                         {"tool": "source.read", "output_key": "output", "arg_key": "text", "from": "result"})
        # S3-ingestion-only: the ingest stage is the sole entry (StartAt), and hands off into A->B->C.
        self.assertEqual(self.asl["StartAt"], "Ingest")
        self.assertEqual(self.asl["States"]["Ingest"]["Next"], "AgentA_Grammar")
        self.assertNotIn("Route", self.asl["States"])   # no HTTP router
        self.assertNotIn("SeedText", self.asl["States"])

    def test_manifest_principals_match_cedar_and_asl(self):
        agent_ids = [s["agent_id"] for s in self.manifest["stages"]]
        for aid in agent_ids:
            self.assertIn(aid, self.cedar, f"{aid} not a principal in broker.cedar")
        # Each stage's ASL Task runs as that principal, in the same order, on one shared function.
        states = self.asl["States"]
        for stage in self.manifest["stages"]:
            st = states[stage["state"]]
            self.assertEqual(st["Type"], "Task")
            self.assertEqual(st["Parameters"]["FunctionName"], "${agent_lambda_arn}")
            self.assertEqual(st["Parameters"]["Payload"]["agent_id"], stage["agent_id"])

    def test_asl_chain_order_follows_the_manifest(self):
        states = self.asl["States"]
        stages = self.manifest["stages"]
        for cur, nxt in zip(stages, stages[1:]):
            self.assertEqual(states[cur["state"]]["Next"], nxt["state"])


if __name__ == "__main__":
    unittest.main()
