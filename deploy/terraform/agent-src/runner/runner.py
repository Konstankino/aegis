"""Aegis code runner (ASI05) — the isolated executor for agent-generated code.

This Lambda is the ENFORCEMENT half of the sandbox. The agent never runs model-authored code
in-process; on an `allow` from the Aegis `/sandbox/validate` gate it invokes THIS function, which
is deliberately a bare executor:

  * its own minimal IAM role — CloudWatch Logs only (no Bedrock, S3, DynamoDB, KMS, or ledger);
  * no network egress — it runs in the no-default-route VPC behind a deny-all security group, so
    a breakout reaches nothing (set `enable_vpc = true`; see the note at the bottom);
  * `/tmp` as the only writable, ephemeral working dir (wiped between execution environments);
  * a short wall-clock timeout plus per-process resource limits (CPU / address space / file size
    / no forking), applied to the child before it runs.

Because Lambda is itself a Firecracker microVM, that microVM boundary IS the container here; this
handler adds process-level limits and a stripped environment on top of it.

Contract (invoked with RequestResponse):
    event  = {"code": "<python source>", "timeout_ms": 5000}
    return = {"exit_code", "stdout", "stderr", "timed_out", "duration_ms"}

Standard library only (runs with the stock Lambda Python runtime).
"""

import json
import os
import resource
import shutil
import subprocess
import sys
import time

# The single writable, ephemeral working directory. Mirrors SandboxPolicy::working_dir so the
# deterministic policy gate and this executor agree on where code may touch the filesystem.
WORKING_DIR = os.environ.get("AEGIS_SANDBOX_DIR", "/tmp/aegis-sandbox")

# Honeypot canary (§11, ASI08): a unique per-project secret. It is planted as a decoy credential
# file in the working dir — a legitimate task never reads it, but code that exfiltrates its contents
# carries the token out, tripping the Aegis canary tripwire at /mediate (tool args) or egress (URL).
# The child process runs with a stripped env and cannot read this var directly; it can only obtain
# the token by reading the planted file, which is exactly the exfiltration we want to detect.
CANARY = os.environ.get("AEGIS_CANARY", "")

# Ceilings. The wall-clock timeout is the outer kill; the rlimits bound a single process before it
# even starts. Kept conservative; tune via env to match your SandboxPolicy.
DEFAULT_TIMEOUT_MS = int(os.environ.get("AEGIS_SANDBOX_TIMEOUT_MS", "5000"))
MAX_TIMEOUT_MS = int(os.environ.get("AEGIS_SANDBOX_MAX_TIMEOUT_MS", "15000"))
RLIMIT_CPU_SECONDS = int(os.environ.get("AEGIS_SANDBOX_CPU_SECONDS", "10"))
RLIMIT_AS_BYTES = int(os.environ.get("AEGIS_SANDBOX_AS_BYTES", str(256 * 1024 * 1024)))
RLIMIT_FSIZE_BYTES = int(os.environ.get("AEGIS_SANDBOX_FSIZE_BYTES", str(8 * 1024 * 1024)))
MAX_OUTPUT_BYTES = 64 * 1024  # truncate stdout/stderr so a chatty program can't blow up the reply


def _apply_limits():
    """preexec_fn: clamp the child process before exec. POSIX only (Lambda is Linux)."""
    # CPU seconds (SIGXCPU then SIGKILL), virtual memory, and max file size.
    resource.setrlimit(resource.RLIMIT_CPU, (RLIMIT_CPU_SECONDS, RLIMIT_CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (RLIMIT_AS_BYTES, RLIMIT_AS_BYTES))
    resource.setrlimit(resource.RLIMIT_FSIZE, (RLIMIT_FSIZE_BYTES, RLIMIT_FSIZE_BYTES))
    # No new processes: block fork()/subprocess from the executed code.
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
    except (ValueError, OSError):
        pass  # not enforceable everywhere; best-effort
    # New session so a kill hits the whole process group, not just the leader.
    os.setsid()


def _plant_canary():
    """Plant the canary as a decoy AWS credentials file in the ephemeral working dir. No-op when
    no canary is configured. Reading this file is never part of a legitimate task; exfiltrating it
    trips the tripwire."""
    if not CANARY:
        return
    creds_dir = os.path.join(WORKING_DIR, ".aws")
    os.makedirs(creds_dir, exist_ok=True)
    with open(os.path.join(creds_dir, "credentials"), "w", encoding="utf-8") as f:
        f.write("[default]\naws_access_key_id=AKIAEXAMPLE\naws_secret_access_key=%s\n" % CANARY)


def _clean_working_dir():
    shutil.rmtree(WORKING_DIR, ignore_errors=True)
    os.makedirs(WORKING_DIR, exist_ok=True)
    _plant_canary()


def _truncate(b):
    if len(b) > MAX_OUTPUT_BYTES:
        return b[:MAX_OUTPUT_BYTES].decode("utf-8", "replace") + "\n...[truncated]"
    return b.decode("utf-8", "replace")


def handler(event, context):
    code = event.get("code")
    if not isinstance(code, str) or not code.strip():
        return {"exit_code": None, "stdout": "", "stderr": "no code provided",
                "timed_out": False, "duration_ms": 0}

    timeout_ms = min(int(event.get("timeout_ms", DEFAULT_TIMEOUT_MS)), MAX_TIMEOUT_MS)

    _clean_working_dir()
    script = os.path.join(WORKING_DIR, "main.py")
    with open(script, "w", encoding="utf-8") as f:
        f.write(code)

    # A stripped environment: the child sees nothing from the runner's context.
    child_env = {"PATH": "/usr/bin:/bin", "HOME": WORKING_DIR, "TMPDIR": WORKING_DIR,
                 "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}

    started = time.time()
    timed_out = False
    try:
        # -I = isolated mode (ignore env vars & user site), -B = no .pyc. cwd is the ephemeral dir.
        proc = subprocess.run(
            [sys.executable, "-I", "-B", script],
            cwd=WORKING_DIR,
            env=child_env,
            capture_output=True,
            timeout=timeout_ms / 1000.0,
            preexec_fn=_apply_limits,
            check=False,
        )
        exit_code, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        timed_out = True
        exit_code = None
        out = e.stdout or b""
        err = (e.stderr or b"") + b"\n[killed: wall-clock timeout]"
    finally:
        _clean_working_dir()

    return {
        "exit_code": exit_code,
        "stdout": _truncate(out),
        "stderr": _truncate(err),
        "timed_out": timed_out,
        "duration_ms": int((time.time() - started) * 1000),
    }

# ── Network isolation note ──────────────────────────────────────────────────────────────────────
# This handler does not (and cannot portably) block sockets from inside the process. Egress
# containment is ARCHITECTURAL: deploy the runner in the no-default-route VPC with the deny-all
# security group (enable_vpc = true). Without a VPC, a Lambda has internet egress by default — so
# for real code execution, run this function in the VPC.
