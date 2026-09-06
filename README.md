# Aegis — Phases 0–3

Aegis is a deterministic Rust guardrail plane that wraps LangGraph agents and maps to the
OWASP GenAI/LLM & Agentic Top 10 (2026). Its thesis: **stop trying to build a model that
cannot be fooled; build the system around it so that when the model is fooled — and it will
be — nothing important breaks.** Aegis owns the *consequence side* deterministically, so a
fooled model is harmless. See `../architecture-considerations.md` for the full design.

This workspace implements the full LLM roadmap (§5) — **Phase 0** (consequence-side backbone),
**Phase 1** (budget, evidence, hygiene), **Phase 2** (data-plane guards), **Phase 3**
(validation as a gate) — **plus the Agentic/ASI Top-10 crates (§11)**.

> **Phase 0 done when** (§5): no path from model output to a side effect or outbound byte
> bypasses the broker/egress, and every sink receives only validated, encoded output.
>
> **Phase 1 done when** (§5): every run has a hard cost ceiling + an immutable audit trail, and
> no invisible-character payload survives ingest.
>
> **Phase 2 done when** (§5): the model can never be handed an unauthorized chunk, no
> unsigned/mutable-tagged artifact loads, and traces/args are redacted before logging.
>
> **Phase 3 done when** (§5): nothing ships on a static benchmark alone — the adaptive red-team
> suite gates CI and must contain every attack.

## Crates

| Crate | Role | OWASP | Tier | Phase |
|---|---|---|---|---|
| [`aegis-core`](crates/aegis-core) | Shared trust vocabulary: `Provenance`, `Tagged<T>`, `Capability` (Rule of Two) | — | — | 0 |
| [`aegis-broker`](crates/aegis-broker) | **Keystone (priority #1).** Deterministic tool-call mediation with a Cedar policy core | LLM03 | ● | 0 |
| [`aegis-output`](crates/aegis-output) | Strict schema validation + context-aware sink encoding + exfil neutralization | LLM10 | ● | 0 |
| [`aegis-egress`](crates/aegis-egress) | Default-deny egress allowlist + query stripping, with an axum proxy | LLM02/06 | ● | 0 |
| [`aegis-meter`](crates/aegis-meter) | Token/cost governor: pre-flight estimation, hard spend caps, agentic circuit breakers | LLM06 | ● | 1 |
| [`aegis-ledger`](crates/aegis-ledger) | Tamper-evident hash-chained audit + memory-write gating | LLM02/03/05 | ● | 1 |
| [`aegis-ingress`](crates/aegis-ingress) | Deterministic Unicode hygiene (strip invisible/bidi/tag chars) + provenance wrapping | LLM01/09 | ◐/● | 1 |
| [`aegis-retrieval`](crates/aegis-retrieval) | Authorization inside the vector query + trust-tier segregation + score withholding | LLM09/05/02 | ●/◐ | 2 |
| [`aegis-supply`](crates/aegis-supply) | Artifact digest pinning, mutable-tag rejection, namespace-reuse + SBOM gating | LLM04/05 | ● | 2 |
| [`aegis-redact`](crates/aegis-redact) | PII/secret redaction of outputs, reasoning traces, and tool-call args | LLM02/08 | ◐/● | 2 |
| [`aegis-redteam`](crates/aegis-redteam) | Adaptive attack harness that runs the whole defense and gates CI | LLM01–10, ASI | ○ | 3 |
| [`aegis-mesh`](crates/aegis-mesh) | Secure inter-agent comms: signing, anti-replay, protocol pinning, attested registry | ASI07 | ● | §11 |
| [`aegis-identity`](crates/aegis-identity) | Per-agent identity + JIT scoped credentials + delegation control | ASI03 | ● | §11 |
| [`aegis-intent`](crates/aegis-intent) | Signed goal/intent envelope bound per cycle + goal-drift | ASI01 | ● | §11 |
| [`aegis-sandbox`](crates/aegis-sandbox) | Isolated code-execution policy (non-root, ephemeral, gate-before-exec) | ASI05 | ● | §11 |
| [`aegis-killswitch`](crates/aegis-killswitch) | Emergency revocation + quarantine + gated reintegration | ASI08/10 | ● | §11 |
| [`aegis-extension`](crates/aegis-extension) | Lambda external extension that hosts the inline plane | — | — | all |

`●` = *Contain* (deterministic): the threat's consequence is bounded by code that behaves the
same every time and does not degrade under adaptive attack. `◐` = *Reduce*: ingress byte-hygiene
lowers attack success but is never the last line — the `●` trio sits behind it.

## Agentic / ASI Top-10 (§11)

The LLM Top-10 covers the model as a *component*; the Agentic (ASI) list covers the moment it
becomes an *actor* — with tools, memory across sessions, peers it talks to, and consequences it
sets in motion. Five deterministic crates cover the new surfaces (per-agent PKI signing uses
Ed25519 via `aegis-core`'s `crypto` feature):

- **`aegis-mesh`** (ASI07) — peer messages carry mutual auth (signatures against an **attested
  registry**), **anti-replay** (nonces + task windows), **protocol pinning** (reject downgrade),
  per-message audiences, and intent-diffing (the signature commits to a payload digest).
- **`aegis-identity`** (ASI03) — JIT, short-lived, **scoped credentials** bound to
  subject/audience/purpose/session and the original user intent; delegation can only *narrow*
  scope and must preserve the intent binding (the **confused-deputy** defense).
- **`aegis-intent`** (ASI01) — a signed **goal/scope capsule** per execution cycle; an action
  outside the declared scope is a deviation, and a stable goal id drives drift detection.
- **`aegis-sandbox`** (ASI05) — the deterministic policy for isolated code execution: non-root,
  no direct network, ephemeral working dir, and **code runs only after passing the
  generation→execution gate**.
- **`aegis-killswitch`** (ASI08/10) — **instant revocation** of a tool/agent/prompt/connection
  (consulted by `/mediate` on every call) + quarantine; reintegration needs fresh attestation
  **and** human approval.

The honest note from the doc holds: the ASI list skews more `◐ Reduce` / `○ Process` because
rogue-agent *emergence* and human persuasion are not code-fixable — Aegis bounds the
*consequence* so even a hijacked agent breaks nothing important, and adds deterministic crypto
containment for the new channels.

### Existing-crate agentic extensions (§11.1)

The Phase 0–2 crates also gained agentic hardening:

- **broker** — semantic tool validation: a call may pin a tool **version**
  (`ToolCall::with_expected_version`), and the broker fails closed on a mismatch or a version
  pinned against an unversioned tool (ASI02).
- **meter** — an inter-agent **fan-out cap** (`observe_fanout`, `max_fanout`) bounds how many
  sub-agents a session may spawn (ASI08 blast radius).
- **ledger** — memory governance (`memory::MemoryGovernance`): unverified memory **trust decays**
  over a half-life and must clear a threshold to be surfaced, and an agent **may not re-ingest
  its own output** (ASI06).
- **retrieval** — **two-factor surfacing** (`guard_two_factor`): high-impact (Sensitive/Restricted)
  chunks are withheld unless a second factor is present (ASI06).
- **supply** — **runtime capability verification** (`verify_runtime`): a dynamically-composed MCP
  server / agent card / prompt template is verified immutable + digest-consistent + pinned before
  activation (ASI04).
- **redteam** — **digital-twin replay** (`replay`, `default_twin`): a recorded golden run is
  replayed as a pre-deployment gate, so a change can't silently regress a known-good trajectory
  (ASI08).

## Phase 3 — the red-team gate

A static benchmark lies: adaptive attack success has exceeded 90% against defenses whose static
success was near zero. So `aegis-redteam` runs the **whole deterministic defense** against
attacks written *with knowledge of it* — invisible-character smuggling, trifecta exploitation,
network + query-string exfiltration, PII-in-trace, budget loops, XSS output, mutable-tag and
digest-swap supply attacks, unauthorized/cross-tenant retrieval, ledger tampering, memory
poisoning — and asserts each is contained. It exits non-zero if any attack breaches, so it gates
CI (`.github/workflows/ci.yml`):

```bash
cargo run -p aegis-redteam            # human-readable; exit 1 on any breach
cargo run -p aegis-redteam -- --json  # machine-readable report
```

What the harness **cannot** prove is the `○ Process` residual — model factual accuracy,
memorization, human-approval fatigue — which lives in evals, data governance, and staffing, not
in deterministic code.

## Phase 2 in one glance

Three data-plane guards, callable in-process or via the gate:

- **Retrieval** (`aegis-retrieval`) — a client-supplied scope is a *suggestion, not a control*:
  `authorize_query` intersects it with the caller's entitlement and fails closed; chunks carry a
  trust tier and an untrusted-tainted session is capped, so the model can never be handed an
  unauthorized or too-sensitive chunk. Chunk text is sanitized at ingest, raw similarity scores
  are bucketed (never leaked), and a deterministic heuristic flags retrieval-hijack attempts.
- **Supply** (`aegis-supply`) — artifacts load only when their content **digest is pinned**;
  `latest`/mutable tags are refused, a name resolving to a new digest is flagged
  (namespace reuse), and an SBOM must have every component pinned to a fixed version.
- **Redact** (`aegis-redact`) — one deterministic classify-and-redact path for the *whole*
  disclosure surface (final answer, reasoning traces, tool-call args): emails, SSNs, Luhn-valid
  cards, AWS keys, API tokens, IPs, phones → `[REDACTED:<KIND>]`, before anything is logged.

## Phase 1 in one glance

Three deterministic controls, wired into the gate and keyed per `thread_id`:

- **Meter** (`aegis-meter`) — a per-session budget with a circuit breaker. Pre-flight token/cost
  estimation rejects *before* inference; a **hard spend cap halts** the run (it trips, not just
  alarms); step / recursion / wall-clock ceilings and state-hash loop detection stop runaway
  agent loops.
- **Ledger** (`aegis-ledger`) — an append-only, **hash-chained** audit log
  (`hash = SHA-256(prev ‖ fields)`); any edit, reorder, or deletion breaks the chain and
  `verify()` catches it. Plus memory-write gating (a poisoned long-term memory affects every
  future session, so writes from tainted/untrusted context need a human or are refused).
- **Ingress** (`aegis-ingress`) — strips the invisible-character channels that hide injections
  (tag block, zero-width, variation selectors, bidi controls) and NFC-normalizes, then
  provenance-wraps. A `◐ Reduce` control with the `●` trio behind it (§5 sequencing rule).

## The broker in one glance

Your agent code never calls a tool directly — only through the broker, which decides in code,
never by asking the model:

```rust
match broker.mediate(&mut session, &call) {
    Decision::Allow        => run_tool(&call),         // execute
    Decision::HumanApprove => pause_for_human(&call),  // -> Step Functions task-token pause
    Decision::Deny(reason) => reject(&reason),         // refuse and log
}
```

`mediate` implements §4 exactly: schema-validate → accumulate Rule-of-Two taint (monotonic) →
authorize with Cedar → the lethal trifecta always needs a human → high/irreversible effects
escalate to a human.

## Build & test

```bash
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --check
```

### Coverage

The deterministic security logic is covered at **~99% of lines** (`cargo llvm-cov`). The
measurement excludes the irreducible runtime entrypoints that cannot run outside a live AWS
Lambda environment: `aegis-extension/src/main.rs` (async extension registration + socket
serving), `aegis-egress/src/bin/proxy.rs` (the proxy `main`), `aegis-extension/src/s3.rs` (S3
fetch, behind the `s3` feature), and `aegis-extension/src/otel.rs` (OTLP exporter setup, behind
the `otel` feature). The `InlinePlane` loading logic was factored into
`aegis-extension/src/plane.rs` precisely so it is testable without that glue.

```bash
cargo install cargo-llvm-cov   # one time
cargo llvm-cov --workspace --summary-only \
  --ignore-filename-regex '(aegis-extension/src/main\.rs|bin/proxy\.rs|aegis-extension/src/s3\.rs|aegis-extension/src/otel\.rs)'
```

Every library file (`aegis-core`, `aegis-broker` lib/registry/policy, `aegis-output`,
`aegis-egress` lib, the gate, and the plane loader) sits at 97–100% line coverage.

## Run the egress proxy locally

```bash
AEGIS_EGRESS_ALLOWLIST=policies/egress-allowlist.toml \
AEGIS_EGRESS_ADDR=127.0.0.1:8080 \
  cargo run -p aegis-egress --bin aegis-egress
```

Then, from another shell:

```bash
# allowlisted host -> 200, data-bearing params stripped
curl -s 'http://127.0.0.1:8080/decide?url=https%3A%2F%2Fapi.internal.example%2Fv1%3Fpage%3D2%26leak%3Dsecret'
# unlisted host -> 403
curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8080/decide?url=https%3A%2F%2Fevil.example%2Fx'
```

## The inline-plane gate (`aegis-extension`)

The extension hosts a loopback HTTP **gate** so a non-Rust handler can use the same
deterministic gates a Rust handler would call in-process:

| Endpoint | Crate | Purpose |
|---|---|---|
| `POST /mediate` | broker + meter + ledger | Mediate a tool call. Taint, meter budget, and audit ledger are all **server-side, keyed by `thread_id`** — the client can't reset or forge them. The meter circuit breaker runs in front; a ledger entry is appended after. |
| `POST /encode` | output | Context-aware sink-encode a string (`html`/`sql`/`shell`/`path`/`email`/`terminal_log`). |
| `POST /sanitize` | ingress | Strip invisible/bidi/tag Unicode + NFC-normalize; returns `{text, removed, had_bidi, normalized}`. |
| `POST /redact` | redact | PII/secret-redact text; returns `{text, findings, total}`. |
| `POST /meter/preflight` | meter | Token/cost pre-flight before a model call; returns `proceed`/`reject` + tripped state. |
| `POST /meter/record` | meter | Record actual token/cost usage after a model call. |
| `POST /memory/gate` | ledger | Gate a long-term memory write (`allow`/`human_approve`/`deny`) from session taint + content origin. |
| `POST /retrieval/authorize` | retrieval | Authorize a retrieval query in-scope; returns the effective `{namespaces, max_tier}` or `403`. |
| `POST /supply/verify` | supply | Verify an artifact `{name, digest}` against the pinset; `200` or `422`. |
| `GET  /ledger/verify` | ledger | Verify a thread's tamper-evident chain (`?thread_id=...`). |
| `POST /killswitch/revoke`, `GET /killswitch/status` | killswitch | Emergency-revoke a target; `/mediate` consults it on every call. |
| `POST /sandbox/validate` | sandbox | Gate a proposed code execution against the sandbox policy. |
| `POST /intent/validate` | intent | Validate an action against a signed intent capsule. |
| `GET  /decide` | egress | Egress allowlist check (`?url=...`). |
| `GET  /healthz` | — | Liveness. |

Serve it locally (no AWS needed):

```bash
AEGIS_POLICY_DIR=policies AEGIS_GATE_ADDR=127.0.0.1:8080 cargo run -p aegis-extension
```
```bash
curl -s -XPOST 127.0.0.1:8080/encode  -d '{"sink":"html","value":"<script>x</script>"}'
curl -s -XPOST 127.0.0.1:8080/mediate -d '{"agent_id":"a","run_id":"r","thread_id":"t1","tool":"web.fetch","args":{"url":"https://x"},"arg_provenance":"untrusted"}'
# repeat /mediate on the SAME thread_id with a sensitive tool -> "human_approve" (trifecta)
```

With neither `AEGIS_GATE_ADDR` nor `AWS_LAMBDA_RUNTIME_API` set it just loads, self-checks the
artifacts, prints a readiness summary, and exits.

Using `/mediate` from Python:

```python
import requests
GATE = "http://127.0.0.1:8080"
r = requests.post(f"{GATE}/mediate", json={
    "agent_id": "care-assistant", "run_id": run_id, "thread_id": thread_id,
    "tool": "db.read_patient", "args": {"patient_id": pid}, "arg_provenance": "user",
}).json()
if   r["decision"] == "allow":         run_tool()
elif r["decision"] == "human_approve": pause_for_step_functions_task_token()
else:                                  reject(r["reason"])
```

## Runnable examples

```bash
cargo run -p aegis-extension --example agent_loop     # end-to-end: broker + output + egress, catches a trifecta
cargo run -p aegis-output   --example output_sinks    # every sink encoder + exfil neutralization
cargo run -p aegis-egress   --example egress_firewall # allowlist decisions incl. query stripping
```

## Observability (OpenTelemetry)

The extension instruments every gate request with `tracing` (an HTTP span per request plus
`aegis.mediate` / `aegis.encode` spans; broker decisions recorded as span fields), so you get
structured logs out of the box with zero configuration. Build with the **`otel`** feature to
also export **OTLP traces + metrics** — it activates automatically when
`OTEL_EXPORTER_OTLP_ENDPOINT` is set, and stays quiet (logs only, no connection errors) when it
is not:

```bash
# run against any OTLP collector (Jaeger, Grafana Alloy, the OTel Collector, ADOT…)
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 \
OTEL_SERVICE_NAME=aegis \
AEGIS_POLICY_DIR=policies AEGIS_GATE_ADDR=127.0.0.1:8080 \
  cargo run -p aegis-extension --features otel
```

Signals: a span per gate request with `tool` / `thread_id` / `decision` / `trifecta` fields
(never tool arguments — no PII), and an `aegis.broker.decisions` counter with `decision` and
`trifecta` attributes. Only the non-sensitive verdict and flags are recorded. Transport is
gRPC/tonic (plaintext localhost, no OpenSSL). On Lambda, set `otel_collector_layer_arn` in the
Terraform to attach the ADOT collector layer and export to X-Ray + CloudWatch.

## Deploy on AWS Lambda

Aegis composes with Architecture A (Step Functions → Lambda → LangGraph → DynamoDB/KMS); it
sits between the model and every capability. Two deployment shapes:

**A) Rust agent function — broker/output in-process.** Depend on `aegis-broker` and
`aegis-output` directly in your handler crate and call `broker.mediate(...)` in the tool loop
(true no-network-hop, §2.4). Ship `aegis-extension` as a layer for the egress proxy + config.

**B) Python/other agent function — the extension as an external-extension layer.** Build the
extension and publish it as a Lambda layer; it boots at cold start, validates the guardrail
artifacts (failing the sandbox if they are broken), and serves the inline-plane gate
(`/mediate`, `/encode`, `/decide`) on a loopback port your handler calls — so a Python handler
gets the broker and output gates without a Rust handler.

```bash
# One-time: the standard tool for Rust Lambda artifacts.
cargo install cargo-lambda

# Build the extension for the function's architecture (arm64/Graviton shown).
cargo lambda build -p aegis-extension --extension --release --arm64
# -> target/lambda/extensions/aegis-extension  (the required layer layout)

# Publish as a layer and attach it to your agent function.
cargo lambda deploy --extension --name aegis-inline-plane
aws lambda update-function-configuration \
  --function-name my-agent \
  --layers <aegis-inline-plane layer ARN>
```

Function configuration:
- `AEGIS_POLICY_DIR` → where the layer syncs `tools.json` / `broker.cedar` /
  `egress-allowlist.toml` (bake them into the layer, or pull from a versioned S3 prefix at boot).
- `AEGIS_GATE_ADDR` → loopback bind for the gate (default `127.0.0.1:8080`; `AEGIS_EGRESS_ADDR`
  is accepted as a fallback name); point the handler's HTTP client at it, and give the function
  a VPC subnet with **no default route** so the gate's egress check is the only way out (§2.4).
- IAM (least privilege): the checkpointer's DynamoDB actions + `kms:Decrypt`/`GenerateDataKey`/
  `DescribeKey` scoped `kms:ViaService = dynamodb.<region>.amazonaws.com`, and S3 read for the
  policy prefix.

`Decision::HumanApprove` is the Step Functions integration point: return it from the handler
and let the state machine pause on `waitForTaskToken` until a human approves (§4).

## Configuration artifacts (`policies/`)

- `tools.json` — the tool registry: each tool's JSON schema plus its Rule-of-Two
  classification (`reaches_sensitive_data`, `has_external_effect`) and `consequence`.
- `broker.cedar` — the Cedar policy set (default-deny; least-privilege `forbid`s).
- `egress-allowlist.toml` — permitted hosts/suffixes and per-host permitted query params.
- `meter.toml` — Phase-1 budget limits: token/cost ceilings, hard spend cap, and the agentic
  circuit-breaker thresholds (steps / recursion / wall-clock / loop). Absent → sane defaults.
- `pins.json` — Phase-2 supply-chain pinset: artifact name → allowed content digests. Absent or
  empty → fails closed (nothing verifies until pins are provided).

In production these are synced from a versioned S3 prefix; the broker, egress, meter, and supply
verifier evaluate them locally with no per-decision network call.
