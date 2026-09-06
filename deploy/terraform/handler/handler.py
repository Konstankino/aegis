"""Aegis Phase-0 demo agent handler (standard library only).

This function does NOT call a real model. It plays the role of the agent loop: it takes a
scripted sequence of *tool-call requests* (as a hijacked or honest model would emit) and runs
each one through the Aegis inline-plane gate served by the aegis-extension on loopback. It
returns the gate's decisions so you can see the broker, output encoder, and egress firewall
enforcing policy end to end.

The gate endpoints (see the extension):
  POST /mediate  -> broker decision (allow | human_approve | deny), taint kept server-side
  POST /encode   -> context-aware sink encoding
  GET  /decide   -> egress allowlist check
  GET  /healthz  -> liveness
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

GATE = "http://" + os.environ.get("AEGIS_GATE_ADDR", "127.0.0.1:8080")


def _post(path, body):
    req = urllib.request.Request(
        GATE + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:  # 4xx/5xx still carry a JSON body
        return e.code, json.loads(e.read() or b"{}")


def _get(path):
    try:
        with urllib.request.urlopen(GATE + path, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _wait_for_gate(attempts=30, delay=0.1):
    """The extension binds the gate before it registers, but retry to be safe on cold start."""
    for _ in range(attempts):
        try:
            status, _ = _get("/healthz")
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(delay)
    return False


def _mediate(agent_id, run_id, thread_id, tool, args, provenance):
    _, body = _post(
        "/mediate",
        {
            "agent_id": agent_id,
            "run_id": run_id,
            "thread_id": thread_id,
            "tool": tool,
            "args": args,
            "arg_provenance": provenance,
        },
    )
    return body


def _mediate_one(event, run_id):
    """Single-call mediation — the shape Step Functions' Map invokes.

    The event IS one tool-call item: {agent_id, thread_id, tool, args, arg_provenance, label}.
    Returns {decision, capability, tool_call} so the state machine can branch on `decision`.
    """
    result = _mediate(
        event.get("agent_id", "care-assistant"),
        event.get("run_id", run_id),
        event["thread_id"],
        event["tool"],
        event.get("args", {}),
        event.get("arg_provenance", "untrusted"),
    )
    return {
        "decision": result.get("decision", "deny"),
        "capability": result.get("capability", {}),
        "reason": result.get("reason"),
        "tool_call": {"tool": event["tool"], "label": event.get("label", event["tool"])},
    }


def handler(event, context):
    run_id = getattr(context, "aws_request_id", "local-run")
    gate_ok = _wait_for_gate()

    # Step Functions invokes the function with a single tool-call item; return just its decision.
    # Fail closed to a valid decision shape if the gate never came up, so the state machine's
    # ResultSelector ($.Payload.decision) always resolves.
    if isinstance(event, dict) and "tool" in event:
        if not gate_ok:
            return {
                "decision": "deny",
                "reason": "aegis gate unavailable",
                "capability": {},
                "tool_call": {"tool": event.get("tool"), "label": event.get("label", event.get("tool"))},
            }
        return _mediate_one(event, run_id)

    if not gate_ok:
        return {"ok": False, "error": "aegis gate did not become healthy", "gate": GATE}

    # Otherwise (e.g. {"demo": true} or a direct console test) return the full scripted trace.
    broker_steps = []

    # ── Scenario 1: the lethal trifecta accumulates within ONE conversation (thread) ──────────
    # 1a) The model fetches attacker-controlled web content -> allowed (untrusted + external).
    broker_steps.append({
        "scenario": "trifecta",
        "label": "fetch untrusted web content",
        "result": _mediate("care-assistant", run_id, "t-trifecta",
                            "web.fetch", {"url": "https://attacker.example/notes"}, "untrusted"),
    })
    # 1b) The SAME clean patient read that is fine on its own now completes A+B+C -> human.
    broker_steps.append({
        "scenario": "trifecta",
        "label": "then read sensitive patient data (same thread)",
        "result": _mediate("care-assistant", run_id, "t-trifecta",
                            "db.read_patient", {"patient_id": "abc-123"}, "user"),
    })

    # ── Scenario 2: the identical read in a CLEAN thread is allowed (single leg) ───────────────
    broker_steps.append({
        "scenario": "clean",
        "label": "read sensitive patient data (fresh thread)",
        "result": _mediate("care-assistant", run_id, "t-clean",
                            "db.read_patient", {"patient_id": "abc-123"}, "user"),
    })

    # ── Scenario 3: least-privilege policy denies (Cedar) ────────────────────────────────────
    broker_steps.append({
        "scenario": "least-privilege",
        "label": "care-assistant tries to rotate KMS keys",
        "result": _mediate("care-assistant", run_id, "t-priv",
                            "admin.rotate_keys", {"key_id": "k-1"}, "user"),
    })
    broker_steps.append({
        "scenario": "least-privilege",
        "label": "the system agent rotates KMS keys (allowed, but irreversible -> human)",
        "result": _mediate("system", run_id, "t-sys",
                            "admin.rotate_keys", {"key_id": "k-1"}, "user"),
    })

    # ── Scenario 4: structural denials (schema + unknown tool + untrusted->sensitive) ────────
    broker_steps.append({
        "scenario": "structural",
        "label": "web.fetch with schema-invalid args",
        "result": _mediate("care-assistant", run_id, "t-bad",
                            "web.fetch", {"not_a_url": 1}, "user"),
    })
    broker_steps.append({
        "scenario": "structural",
        "label": "untrusted-provenance args reaching sensitive data",
        "result": _mediate("care-assistant", run_id, "t-inj",
                            "db.read_patient", {"patient_id": "x"}, "untrusted"),
    })

    # ── Output handling: context-aware sink encoding ─────────────────────────────────────────
    encode_steps = []
    for sink, value in [
        ("html", "<script>steal()</script>"),
        ("shell", "$(rm -rf /)"),
        ("path", "../../etc/passwd"),
    ]:
        status, body = _post("/encode", {"sink": sink, "value": value})
        encode_steps.append({"sink": sink, "input": value, "status": status, "result": body})

    # ── Egress firewall: default-deny allowlist + query stripping ────────────────────────────
    egress_steps = []
    for url in [
        "https://api.internal.example/v1?page=2&leak=PHI_SECRET",
        "https://evil.example/collect?data=PHI_SECRET",
    ]:
        status, body = _get("/decide?url=" + urllib.parse.quote(url, safe=""))
        egress_steps.append({"url": url, "status": status, "result": body})

    return {
        "ok": True,
        "gate": GATE,
        "egress_contained_vpc": os.environ.get("AEGIS_POLICY_DIR") == "/opt/policies",
        "broker": broker_steps,
        "encode": encode_steps,
        "egress": egress_steps,
        "note": "A fooled model can only *request*; the broker/output/egress decide.",
    }
