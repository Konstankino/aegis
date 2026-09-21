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


class TerminalFromResultTest(unittest.TestCase):
    """A terminal handoff with `"from": "result"` takes the stage output from the tool's RESULT, not
    its call args — so a fetched document flows out verbatim without the model rewriting it."""

    TOOLS = [{"name": "src.read",
              "schema": {"type": "object",
                         "properties": {"bucket": {"type": "string"}, "key": {"type": "string"}},
                         "required": ["bucket", "key"], "additionalProperties": False}}]
    MANIFEST = {"name": "fx", "stages": [
        {"agent_id": "p-i", "state": "I", "system": "load it",
         "tools": [{"name": "src.read"}],
         "terminal": {"tool": "src.read", "output_key": "output", "arg_key": "text", "from": "result"}}]}
    PLUGIN = ("def run_tool(fq, args, agent_id='', thread_id=''):\n"
              "    if fq == 'src.read':\n"
              "        return {'text': 'FILE CONTENT'}\n"
              "    return None\n")

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        _write_bundle(self._tmp.name, tools=self.TOOLS, manifest=self.MANIFEST, plugin=self.PLUGIN)
        agent.reload_bundle(self._tmp.name)
        self._orig = (agent.bedrock, agent.mediate, agent._wait_for_gate, agent.preflight,
                      agent.save_messages, agent.load_messages, agent.scan_output)
        agent.bedrock = type("M", (), {"converse": staticmethod(
            lambda **_k: _tool_use("src_read", {"bucket": "b", "key": "incoming/x.txt"}))})()
        agent.mediate = lambda *a, **k: {"decision": "allow"}
        agent._wait_for_gate = lambda *a, **k: True
        agent.preflight = lambda *a, **k: {"decision": "allow"}
        agent.save_messages = lambda *a, **k: None
        agent.load_messages = lambda *a, **k: None
        agent.scan_output = lambda *a, **k: True

    def tearDown(self):
        (agent.bedrock, agent.mediate, agent._wait_for_gate, agent.preflight,
         agent.save_messages, agent.load_messages, agent.scan_output) = self._orig
        agent.reload_bundle(EngineTest._tmp.name)
        self._tmp.cleanup()

    def test_output_comes_from_the_tool_result(self):
        out = agent.handler({"agent_id": "p-i", "thread_id": "t",
                             "source_bucket": "b", "source_key": "incoming/x.txt"}, None)
        self.assertEqual(out, {"status": "done", "output": "FILE CONTENT", "thread_id": "t"})


class SourceReadTest(unittest.TestCase):
    """`source.read` fetches an S3 object with a SHORT-LIVED, object-scoped credential minted by the
    JIT broker: /identity/self (sign) -> /credentials/issue (exchange) -> GetObject. Fail-closed."""

    def setUp(self):
        self.posts = []
        self._orig_post = agent._gate_post
        self._orig_boto = agent.boto3

        def fake_post(path, body):
            self.posts.append((path, body))
            if path == "/identity/self":
                if getattr(self, "identity_fail", False):
                    return 503, {"error": "unavailable"}
                return 200, {"credential": {"subject": body["agent_id"], "sig": "x"}}
            if path == "/credentials/issue":
                if getattr(self, "deny", False):
                    return 403, {"decision": "deny", "reason": "policy denies this"}
                return 200, {"decision": "grant", "credential": {
                    "kind": "sts", "access_key_id": "AK", "secret_access_key": "SK",
                    "session_token": "TOK", "expires_at_ms": 1}}
            return 200, {}

        class _Body:
            def __init__(self, data): self._d = data
            def read(self): return self._d

        class _S3:
            def __init__(self, outer, **kw): self.kw = kw; outer.s3_kwargs = kw
            def get_object(self_inner, Bucket, Key, **kw):
                self.get_calls.append((Bucket, Key))
                self.get_kwargs = kw
                if getattr(self, "s3_raise", False):
                    raise RuntimeError("AccessDenied")
                return {"Body": _Body(b"hello from s3")}

        self.get_calls = []
        self.s3_kwargs = None
        agent._gate_post = fake_post
        agent.boto3 = types.SimpleNamespace(client=lambda svc, **kw: _S3(self, **kw))

    def tearDown(self):
        agent._gate_post = self._orig_post
        agent.boto3 = self._orig_boto

    def test_mints_short_lived_creds_then_reads(self):
        out = agent.run_tool("source.read", {"bucket": "b", "key": "incoming/x.txt"},
                             "agent-ingest", "thread-1")
        self.assertEqual(out, {"text": "hello from s3"})
        paths = [p for p, _ in self.posts]
        self.assertEqual(paths, ["/identity/self", "/credentials/issue"])
        # The exchange presents the signed credential and names the editorial source grant + scope.
        issue_body = dict(self.posts[1][1])
        self.assertIn("credential", issue_body)
        self.assertTrue(issue_body["grant_id"])         # a concrete grant id, not empty
        self.assertLessEqual(issue_body["requested_ttl_secs"], 300)
        # The object is read with the MINTED short-lived session, never a standing role.
        self.assertEqual(self.s3_kwargs["aws_access_key_id"], "AK")
        self.assertEqual(self.s3_kwargs["aws_session_token"], "TOK")
        self.assertEqual(self.get_calls, [("b", "incoming/x.txt")])

    def test_fail_closed_when_credential_denied(self):
        self.deny = True
        out = agent.run_tool("source.read", {"bucket": "b", "key": "incoming/x.txt"},
                             "agent-ingest", "thread-1")
        self.assertIn("error", out)
        self.assertEqual(self.get_calls, [])  # denied -> NO object read

    def test_missing_bucket_or_key_is_rejected_before_any_call(self):
        out = agent.run_tool("source.read", {"bucket": "b"}, "agent-ingest", "t")
        self.assertIn("error", out)
        self.assertEqual(self.posts, [])  # no identity/credential hops for a malformed request

    def test_fail_closed_when_identity_issue_fails(self):
        self.identity_fail = True
        out = agent.run_tool("source.read", {"bucket": "b", "key": "incoming/x.txt"},
                             "agent-ingest", "t")
        self.assertIn("error", out)
        self.assertEqual([p for p, _ in self.posts], ["/identity/self"])  # stopped before exchange
        self.assertEqual(self.get_calls, [])

    def test_s3_read_error_is_surfaced(self):
        self.s3_raise = True
        out = agent.run_tool("source.read", {"bucket": "b", "key": "incoming/x.txt"},
                             "agent-ingest", "t")
        self.assertIn("error", out)
        self.assertIn("get_object", out["error"])

    # ── TOCTOU: pin the read to the exact object version/etag from the event ─────────────────────
    def test_pins_to_version_id(self):
        agent.run_tool("source.read",
                       {"bucket": "b", "key": "incoming/x.txt", "version_id": "V3"},
                       "agent-ingest", "t")
        self.assertEqual(self.get_kwargs, {"VersionId": "V3"})  # exact version, not "latest"

    def test_uses_ifmatch_when_only_etag(self):
        agent.run_tool("source.read",
                       {"bucket": "b", "key": "incoming/x.txt", "etag": "E1"},
                       "agent-ingest", "t")
        self.assertEqual(self.get_kwargs, {"IfMatch": "E1"})  # 412 if overwritten -> fail closed

    def test_version_id_preferred_over_etag(self):
        agent.run_tool("source.read",
                       {"bucket": "b", "key": "incoming/x.txt", "version_id": "V3", "etag": "E1"},
                       "agent-ingest", "t")
        self.assertEqual(self.get_kwargs, {"VersionId": "V3"})

    def test_no_pin_reads_current_object(self):
        agent.run_tool("source.read", {"bucket": "b", "key": "incoming/x.txt"}, "agent-ingest", "t")
        self.assertEqual(self.get_kwargs, {})  # unversioned bucket, no etag: plain read


class IngestAuthoritativeSourceTest(unittest.TestCase):
    """TOCTOU + tamper defence: the bucket/key/version/etag the ingest stage reads are taken from the
    S3 event (via the ASL), NOT from the model's tool call. The handler overwrites the source.read
    args before mediation, so a tampered or stale model call can't change which object/version is read,
    and every (cold) re-invocation re-applies the same authoritative pin from the event."""

    TOOLS = [{"name": "source.read",
              "schema": {"type": "object",
                         "properties": {"bucket": {"type": "string"}, "key": {"type": "string"},
                                        "version_id": {"type": "string"}, "etag": {"type": "string"}},
                         "required": ["bucket", "key"], "additionalProperties": False}}]
    MANIFEST = {"name": "fx", "stages": [
        {"agent_id": "agent-ingest", "state": "Ingest", "system": "load it",
         "tools": [{"name": "source.read"}],
         "terminal": {"tool": "source.read", "output_key": "output", "arg_key": "text", "from": "result"}}]}
    PLUGIN = "def run_tool(fq, args, agent_id='', thread_id=''):\n    return None\n"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        _write_bundle(self._tmp.name, tools=self.TOOLS, manifest=self.MANIFEST, plugin=self.PLUGIN)
        agent.reload_bundle(self._tmp.name)
        self.mediated = []
        self.get_calls = []

        # The model tries to read a DIFFERENT object and an OLD version — this must be ignored.
        tampered = {"bucket": "attacker", "key": "secret.txt", "version_id": "OLD"}
        self._orig = (agent.bedrock, agent.mediate, agent._wait_for_gate, agent.preflight,
                      agent.save_messages, agent.load_messages, agent.scan_output,
                      agent._gate_post, agent.boto3)
        agent.bedrock = type("M", (), {"converse": staticmethod(
            lambda **_k: _tool_use("source_read", tampered))})()

        def fake_mediate(agent_id, thread_id, run_id, fq, args):
            self.mediated.append((fq, dict(args)))
            return {"decision": "allow"}

        agent.mediate = fake_mediate
        agent._wait_for_gate = lambda *a, **k: True
        agent.preflight = lambda *a, **k: {"decision": "allow"}
        agent.save_messages = lambda *a, **k: None
        agent.load_messages = lambda *a, **k: None
        agent.scan_output = lambda *a, **k: True

        def fake_post(path, body):
            if path == "/identity/self":
                return 200, {"credential": {"x": 1}}
            if path == "/credentials/issue":
                return 200, {"decision": "grant", "credential": {
                    "access_key_id": "AK", "secret_access_key": "SK", "session_token": "TOK"}}
            return 200, {}

        outer = self

        class _S3:
            def get_object(self_inner, Bucket, Key, **kw):
                outer.get_calls.append((Bucket, Key, kw))
                return {"Body": type("B", (), {"read": staticmethod(lambda: b"authoritative text")})()}

        agent._gate_post = fake_post
        agent.boto3 = types.SimpleNamespace(client=lambda *a, **k: _S3())

    def tearDown(self):
        (agent.bedrock, agent.mediate, agent._wait_for_gate, agent.preflight,
         agent.save_messages, agent.load_messages, agent.scan_output,
         agent._gate_post, agent.boto3) = self._orig
        agent.reload_bundle(EngineTest._tmp.name)
        self._tmp.cleanup()

    def test_event_source_overrides_a_tampered_model_call(self):
        out = agent.handler({
            "agent_id": "agent-ingest", "thread_id": "t",
            "source_bucket": "trusted-bucket", "source_key": "incoming/x.txt",
            "source_version_id": "V-EVENT", "source_etag": "E-EVENT",
        }, None)
        # Mediation saw the AUTHORITATIVE args from the event, never the tampered ones.
        self.assertEqual(self.mediated, [("source.read",
                         {"bucket": "trusted-bucket", "key": "incoming/x.txt",
                          "version_id": "V-EVENT", "etag": "E-EVENT"})])
        # The object read is pinned to the event's bucket/key/version — TOCTOU window closed.
        self.assertEqual(self.get_calls, [("trusted-bucket", "incoming/x.txt", {"VersionId": "V-EVENT"})])
        self.assertEqual(out, {"status": "done", "output": "authoritative text", "thread_id": "t"})


class SeedSourceTest(unittest.TestCase):
    def test_seed_input_names_the_s3_coordinates(self):
        msg = agent.seed_input({"source_bucket": "b", "source_key": "incoming/x.txt"})
        self.assertEqual(msg["role"], "user")
        text = "".join(c.get("text", "") for c in msg["content"])
        self.assertIn("b", text)
        self.assertIn("incoming/x.txt", text)


if __name__ == "__main__":
    unittest.main()
