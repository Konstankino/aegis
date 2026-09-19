"""Tests for run_local.py — Bedrock Converse tool use for the parallel-review pipeline (A → B∥C → D).

No AWS: the loop is driven by the scripted MockConverse (and a rogue client for the deny path). B and
C run concurrently via a thread pool; the mock is stateless (reads messages), so it is thread-safe.
Run: `python3 -m unittest test_run_local`.
"""
import unittest

import run_local as R


class ProfileAndMediationTest(unittest.TestCase):
    def test_toolconfig_and_terminals(self):
        self.assertEqual({t["toolSpec"]["name"] for t in R.PROFILES["agent-a"]["tools"]},
                         {"grammar_correct", "dispatch_to_workers"})
        # B and C are peers: identical visible tools + identical terminal.
        self.assertEqual(R.PROFILES["agent-b"]["terminal"], {"submit.candidate": ("output", "text")})
        self.assertEqual(R.PROFILES["agent-c"]["terminal"], R.PROFILES["agent-b"]["terminal"])
        self.assertEqual(R.PROFILES["agent-d"]["terminal"], {"publish.final": ("output", "text")})

    def test_allow_map(self):
        self.assertEqual(R.ALLOW["agent-a"], {"grammar.correct", "dispatch.to_workers"})
        self.assertEqual(R.ALLOW["agent-b"], {"improve.text", "submit.candidate"})
        self.assertEqual(R.ALLOW["agent-c"], R.ALLOW["agent-b"])  # peers
        self.assertEqual(R.ALLOW["agent-d"], {"referee.select", "publish.final"})

    def test_mediate(self):
        self.assertEqual(R.mediate("agent-b", "improve.text", {"text": "x"}), (True, "allow"))
        self.assertEqual(R.mediate("agent-b", "publish.final", {"text": "x"}),
                         (False, "policy denies this"))          # writer may not publish
        self.assertEqual(R.mediate("agent-c", "dispatch.to_workers", {"text": "x"}),
                         (False, "policy denies this"))          # only A dispatches
        self.assertEqual(R.mediate("agent-a", "publish_final", {"text": "x"}),
                         (False, "unknown tool"))                # unmapped converse name


class FanOutFlowTest(unittest.TestCase):
    def test_full_a_bc_d_flow(self):
        final, stages, trace = R.run_parallel(R.MockConverse(), "he go to the stor")
        # A (2) then B (2) then C (2) then D (2), all allowed (B/C order is fixed by run_parallel).
        self.assertEqual(
            [(a, t) for a, t, v, _ in trace if v == "allow"],
            [("agent-a", "grammar.correct"), ("agent-a", "dispatch.to_workers"),
             ("agent-b", "improve.text"), ("agent-b", "submit.candidate"),
             ("agent-c", "improve.text"), ("agent-c", "submit.candidate"),
             ("agent-d", "referee.select"), ("agent-d", "publish.final")],
        )
        self.assertTrue(all(v == "allow" for _, _, v, _ in trace))
        # Fan-in: exactly two candidates from B and C, and D published one of them.
        self.assertEqual(stages["b"]["output"], stages["c"]["output"])  # peers, same mock transform
        self.assertIn(final, {stages["b"]["output"], stages["c"]["output"]})


class DenyPathTest(unittest.TestCase):
    def test_broker_denies_a_worker_trying_to_publish(self):
        # A rogue "model" for agent-b first proposes publish_final (referee-only), then the legit
        # submit_candidate. The broker must DENY the first; the stage must still complete.
        class RogueB:
            def converse(self, system, messages, tools):
                turns = sum(1 for m in messages if m["role"] == "assistant"
                            for c in m["content"] if "toolUse" in c)
                name, inp = ("publish_final", {"text": "leak"}) if turns == 0 \
                    else ("submit_candidate", {"text": "improved."})
                return {"stopReason": "tool_use", "output": {"message": {"role": "assistant",
                        "content": [{"toolUse": {"toolUseId": "tu", "name": name, "input": inp}}]}}}

        trace = []
        out = R.run_stage(RogueB(), R.LocalPlane(), "agent-b", {"input": "x"}, trace, "t")
        verdicts = [(t, v) for _, t, v, _ in trace]
        self.assertIn(("publish_final", "DENY"), verdicts)
        self.assertIn(("submit.candidate", "allow"), verdicts)
        self.assertEqual(out, {"output": "improved."})


if __name__ == "__main__":
    unittest.main()
