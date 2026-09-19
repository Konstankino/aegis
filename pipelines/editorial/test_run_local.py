"""Tests for run_local.py — the Bedrock Converse tool-use driver for the editorial pipeline.

No AWS: the real Bedrock client is never constructed; we drive the loop with the scripted MockConverse
(and a deliberately rogue client for the deny path). Run: `python3 -m unittest test_run_local`.
"""
import unittest

import run_local as R


class ProfileAndMediationTest(unittest.TestCase):
    def test_toolconfig_is_built_from_tools_json(self):
        prof = R.PROFILES["agent-a"]
        names = {t["toolSpec"]["name"] for t in prof["tools"]}
        self.assertEqual(names, {"grammar_correct", "send_to_agent_b"})  # dotted -> underscore
        # schema comes straight from tools.json
        spec = next(t for t in prof["tools"] if t["toolSpec"]["name"] == "grammar_correct")
        self.assertEqual(spec["toolSpec"]["inputSchema"]["json"], R.TOOL_SCHEMAS["grammar.correct"])
        # terminal is derived from the manifest
        self.assertEqual(prof["terminal"], {"send.to_agent_b": ("output", "text")})

    def test_allow_map_parsed_from_broker_cedar(self):
        self.assertEqual(R.ALLOW["agent-a"], {"grammar.correct", "send.to_agent_b"})
        self.assertEqual(R.ALLOW["agent-b"], {"enrich.add_facts", "send.to_agent_c"})
        self.assertEqual(R.ALLOW["agent-c"], {"referee.select", "publish.final"})

    def test_mediate_allow_deny_unknown_and_schema(self):
        self.assertEqual(R.mediate("agent-a", "grammar.correct", {"text": "x"}), (True, "allow"))
        # off-lane, but a known tool -> policy denies
        ok, why = R.mediate("agent-a", "publish.final", {"text": "x"})
        self.assertFalse(ok)
        self.assertEqual(why, "policy denies this")
        # unknown tool (e.g. an unmapped Converse name) -> fail closed before policy
        self.assertEqual(R.mediate("agent-a", "publish_final", {"text": "x"}),
                         (False, "unknown tool"))
        # schema violations
        self.assertFalse(R.mediate("agent-a", "grammar.correct", {"text": 42})[0])
        self.assertFalse(R.mediate("agent-a", "grammar.correct", {"wrong": "field"})[0])


class HappyPathTest(unittest.TestCase):
    def test_full_a_b_c_flow_over_the_mock(self):
        final, stages, trace = R.run_editorial(R.MockConverse(), "he go to the stor")
        # Six mediated calls, all allowed, in order.
        self.assertEqual(
            [(a, t, v) for a, t, v, _ in trace],
            [("agent-a", "grammar.correct", "allow"),
             ("agent-a", "send.to_agent_b", "allow"),
             ("agent-b", "enrich.add_facts", "allow"),
             ("agent-b", "send.to_agent_c", "allow"),
             ("agent-c", "referee.select", "allow"),
             ("agent-c", "publish.final", "allow")],
        )
        # Stage output shapes: A/C -> {output}, B -> {candidates}.
        self.assertIn("output", stages["a"])
        self.assertEqual(len(stages["b"]["candidates"]), 2)
        # The referee published the enriched (longer) candidate.
        self.assertEqual(final, stages["c"]["output"])
        self.assertIn("Fun fact", final)


class DenyPathTest(unittest.TestCase):
    def test_broker_denies_an_off_lane_call_and_the_stage_recovers(self):
        # A rogue "model" for agent-a first proposes publish_final (off its lane), then the legit
        # send_to_agent_b. The broker must DENY the first and the stage must still finish.
        class RogueA:
            def converse(self, system, messages, tools):
                names = {t["toolSpec"]["name"] for t in tools}
                turns = sum(1 for m in messages if m["role"] == "assistant"
                            for c in m["content"] if "toolUse" in c)
                move = ("publish_final", {"text": "leak"}) if turns == 0 \
                    else ("send_to_agent_b", {"text": "He goes to the store."})
                name, inp = move
                return {"stopReason": "tool_use", "output": {"message": {
                    "role": "assistant", "content": [{"toolUse": {
                        "toolUseId": "tu", "name": name, "input": inp}}]}}}

        trace = []
        out = R.run_stage(RogueA(), R.LocalPlane(), "agent-a", {"input": "he go"}, trace)
        verdicts = [(t, v) for _, t, v, _ in trace]
        self.assertIn(("publish_final", "DENY"), verdicts)          # off-lane refused
        self.assertIn(("send.to_agent_b", "allow"), verdicts)       # legit handoff allowed
        self.assertEqual(out, {"output": "He goes to the store."})  # stage still completed


if __name__ == "__main__":
    unittest.main()
