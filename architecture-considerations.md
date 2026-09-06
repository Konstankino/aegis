# Architecture Considerations

> Consolidated outcomes, findings, decisions, and reasoning from the working thread.
> Scope: durable multi-agent stacks on AWS (LangGraph + Step Functions + Lambda), the
> **Aegis** Rust security plane mapped to the OWASP GenAI/LLM Top 10 (2026), its
> coexistence with **Amazon Bedrock Guardrails**, and all supporting deliverables.
> Audience: the engineer building multi-agent monitoring/observability infrastructure
> for healthcare-SaaS clients on AWS.

---

## 0. TL;DR — the load-bearing conclusions

1. **Step Functions and LangGraph are not interchangeable.** They live at different
   layers and *compose*. Step Functions = a general-purpose durable workflow/state-machine
   engine. LangGraph = an in-process agent framework (typed state, cycles, checkpointing,
   streaming). "Both orchestrate steps" is a surface resemblance only.
2. **One durability owner per boundary.** On any boundary where work can be retried or
   resumed, exactly one system answers "how far did we get?" Never stack multiple
   checkpointing systems over the same work.
3. **Canonical AWS pattern (Architecture A):** Step Functions orchestrates **stateless**
   Lambda; LangGraph runs the agent loop *inside* the Lambda; **DynamoDB (KMS-encrypted)**
   is the checkpointer. Each invocation runs once, no replay.
4. **Security posture (OWASP 2026 thesis):** stop trying to build a model that cannot be
   fooled; build the system *around* it so that when the model is fooled — and it will be —
   nothing important breaks. Prompt injection is intrinsic and not reliably preventable.
5. **Aegis** is the deterministic **Rust guardrail plane** that enforces that posture. It
   cannot stop the model being fooled; it owns the **consequence side** deterministically so
   a fooled model is harmless.
6. **The single highest-leverage control is the capability broker** (Rule of Two / lethal
   trifecta). Build it first.
7. **Aegis and Bedrock Guardrails reinforce each other** (they are not competitors):
   Guardrails = probabilistic ML screen (◐ reduce, model-facing); Aegis = deterministic
   containment (● contain, system-facing). A Guardrails *pass is never an authorization*.

---

## 1. Step Functions vs LangGraph vs Durable Functions

### 1.1 The core distinction

The original question was whether AWS Step Functions and LangGraph are "the same thing from
different providers." **No** — the resemblance is superficial (both express sequencing,
branching, parallel fan-out, so diagrams look alike). The real differences:

| Dimension | AWS Step Functions | LangGraph |
|---|---|---|
| What it is | General-purpose **distributed state-machine service** (microservices, ETL, business processes) | Purpose-built **stateful agent-graph framework** |
| LLM-native concepts | None | Message state, tool-calling loops, checkpointed memory, HITL interrupts, token streaming |
| Execution model | External, durable, managed state transitions declared in **ASL JSON** | In-process Python/JS objects; persistence optional via checkpointers |
| Control flow | Limited declarative primitives; awkward, capped looping | Explicitly **cyclic** graph, natural for agent iteration |
| State size | **256 KB** cap between states → forces S3 claim-check for large data | Arbitrary-size state in memory |
| Cost/latency | Bills **per state transition**; ~50–100 ms/transition overhead | Near-instant function-call transitions; chatty loops far cheaper |
| Duration | Year-long executions supported | Bounded by its host (e.g. Lambda's 900 s) |
| Streaming | No native token streaming; needs WebSocket/AppSync | Native multi-mode streaming |
| Long pauses / HITL | `waitForTaskToken` is excellent for durable multi-hour/day pauses | `interrupt()` + checkpointer; durability left to the developer |
| Observability | CloudWatch / X-Ray | LangSmith |
| Integrations | Native Bedrock + 200+ AWS services without Lambda glue | LangChain model abstractions + prebuilt agent patterns |

**They compose.** Step Functions as the durable *outer* orchestrator (document ingestion,
parallel processing, human approval via task tokens); LangGraph running the *inner* agent
loop inside a Lambda or ECS task. (AWS's newer managed direction here is **Bedrock
AgentCore**; noted, not required for the patterns below.)

### 1.2 The governing principle — "one durability owner per boundary"

On any boundary where work can be retried or resumed, exactly one system is responsible for
"how far did we get?" Step Functions owns orchestration progress; each agent's checkpointer
owns its loop progress; the Lambda in between owns nothing durable.

**Antipattern:** Step Functions + durable-Lambda + LangGraph checkpointer = **three
checkpointing systems over the same work** → idempotency/reconciliation hell.

### 1.3 The two clean architectures

- **Architecture A** — Step Functions orchestrates **stateless** Lambda; LangGraph runs the
  agent; **DynamoDB (KMS-encrypted)** is the checkpointer. Each Lambda invocation runs once,
  no replay. **This is the recommended default** whenever there is real orchestration or
  agent complexity.
- **Architecture B** — **Durable Functions own durability end-to-end**; LangGraph runs
  in-memory. Two sub-variants:
  - **B-proper:** the whole graph runs in one atomic durable step.
  - **B-handrolled:** the agent loop runs on durable steps, no LangGraph engine.
  - Use B for a single-agent system with long, cheap waits and little surrounding
    orchestration.

**Verdict:** A is the robust default; B for single-agent/long-cheap-waits; set the
atomic-vs-handrolled dial deliberately.

### 1.4 Hard limits and mechanics that shaped the decisions

- **Lambda single-invocation ceiling: 900 s (15 min).** Nothing configurable raises it.
- **DynamoDB item cap 400 KB** → `DynamoDBSaver` (`langgraph-checkpoint-aws`) offloads
  checkpoints larger than ~350 KB to S3. Enable this early.
- **Step Functions inter-state payload cap: 256 KB** → pass **S3 references** for large
  payloads; never push whole documents through the state machine.
- **AWS-official DynamoDB checkpoint schema** = composite PK/SK. Minimum IAM for the
  checkpointer: `GetItem`, `PutItem`, `Query`, `BatchGetItem`, `BatchWriteItem`.
- **KMS-with-DynamoDB least privilege:** `kms:Decrypt` + `kms:GenerateDataKey` +
  `kms:DescribeKey` with condition `kms:ViaService = dynamodb.<REGION>.amazonaws.com`.
- **"Fan-out"** clarified = parallel independent branches (SF `Parallel`/`Map`, LangGraph
  `Send` API) + a fan-in join. Only valid when branches are independent.

### 1.5 Verified current LangGraph/AWS APIs (as of the thread; version-sensitive)

- `create_supervisor` — `langgraph-supervisor`
- `create_swarm` / `create_handoff_tool` — `langgraph-swarm`
- Handoff mechanism: `Command(goto=..., graph=Command.PARENT)`
- HITL: `interrupt()` / `Command(resume=...)` — **requires a checkpointer + `thread_id`**.
- **Key gotcha:** on resume, the interrupted node **re-runs from the top** — put
  side-effects *after* `interrupt()` or make them idempotent.
- Bedrock model access: `ChatBedrockConverse` (`langchain-aws`), Converse API, credentials
  from the Lambda execution role (never hard-coded).

> **Version caution:** concepts are stable; import paths, constructor args, package names,
> and Bedrock model/inference-profile IDs drift between releases — pin and verify.

---

## 2. The Aegis security plane (Rust) — mapped to OWASP GenAI/LLM Top 10 (2026)

**Name status:** *Aegis is the confirmed, approved name* (no longer a working title).

### 2.1 Strategy and the honesty frame

Aegis is a small **Cargo workspace of composable crates** wrapping the LangGraph agents.
Rust is chosen because the guardrail plane must never itself be the weak point: memory-safe
(no parser-level RCE in the thing meant to stop RCE), fast enough to sit inline, one static
binary that runs as a **Lambda extension** or **Fargate sidecar**, and — most importantly —
the highest-value OWASP controls are **deterministic** (policy eval, schema validation,
encoding, byte-stripping, allowlists), which belong in compiled, testable code, not
delegated back to a model.

Every control is tagged with one of three **honesty tiers**:

| Tier | Meaning | Rust's role |
|---|---|---|
| **● Contain** (deterministic) | The threat's *consequence* is bounded by code that behaves the same every time and does not degrade under adaptive attack. | Rust owns this outright — most of the value is here. |
| **◐ Reduce** (probabilistic) | Lowers attack success, but an adaptive attacker who has read the defense can still get through. Never the last line. | Rust helps, always paired with a Contain control behind it. |
| **○ Process** (not code-fixable) | Residual lives in data governance, model training/retraining, or human process. | Rust can measure and gate, not solve. |

**Consequence of the frame:** prompt injection (LLM01) is **◐ at the input** and **● at the
consequence**. Aegis spends almost no budget on *detecting* injections and almost all of it
ensuring a successful injection reaches nothing worth reaching. That IS the OWASP posture,
made executable.

### 2.2 The workspace (crates)

| Crate | Concern | Primary OWASP entries | Tier |
|---|---|---|---|
| `aegis-core` | Trust tiers, provenance labels, capability tags, shared types | — | — |
| `aegis-broker` | Capability mediator / deterministic policy engine (Cedar) | LLM03, LLM01, LLM07 | ● |
| `aegis-output` | Output schema validation + sink-specific encoding | LLM10, LLM02 | ● |
| `aegis-egress` | Network egress firewall / exfiltration broker | LLM02, LLM06, LLM01 | ● |
| `aegis-meter` | Token-aware cost governor + agentic circuit breakers | LLM06 | ● |
| `aegis-ingress` | Input normalization / prompt firewall | LLM01, LLM09 | ◐/● |
| `aegis-retrieval` | Retrieval + vector authorization guard | LLM09, LLM05, LLM02 | ●/◐ |
| `aegis-supply` | Artifact / supply-chain verifier (sign, pin, scan) | LLM04, LLM05 | ● |
| `aegis-redact` | Disclosure / redaction filter for outputs and traces | LLM02, LLM08 | ◐/● |
| `aegis-ledger` | Tamper-evident audit + memory-write gating | LLM02, LLM03, LLM05 | ● |
| `aegis-redteam` | Adaptive attack harness (release gate) | LLM01 (all) | ○ |
| `aegis-mesh` *(new, §11)* | Secure inter-agent communication (mTLS, signing, anti-replay, attested registry) | ASI07, ASI03, ASI04, ASI10 | ● |
| `aegis-identity` *(new, §11)* | Per-agent identity + delegation control + JIT scoped credentials | ASI03, ASI10 | ● |
| `aegis-intent` *(new, §11)* | Signed goal/intent envelope bound per execution cycle + goal-drift | ASI01 | ● |
| `aegis-sandbox` *(new, §11)* | Isolated, non-root, ephemeral code-execution environment | ASI05 | ● |
| `aegis-killswitch` *(new, §11)* | Emergency revocation + quarantine + recovery/reintegration | ASI04, ASI08, ASI10 | ● |
| `aegis-honeypot` *(new, §11)* | Deception tripwires — decoy probes + planted canary tokens → quarantine | ASI05, ASI08 | ●/◐ |

### 2.3 The trust vocabulary (`aegis-core`)

Three small types make the trust boundary a **compile-time fact**, not a convention:

```rust
// Where content came from, and therefore how much it is trusted.
pub enum Provenance { System, User, SemiTrusted, Untrusted }

// Content is never a bare String once it enters Aegis: it carries its origin.
pub struct Tagged<T> { pub value: T, pub origin: Provenance }

// The Rule-of-Two bits. Every tool call is classified on these three axes.
pub struct Capability {
    pub reads_untrusted: bool,  // (A) touched untrusted input this session
    pub reads_sensitive: bool,  // (B) can reach private/regulated data
    pub external_effect: bool,  // (C) state change or outbound communication
}
impl Capability {
    // The lethal trifecta: all three at once is the high-impact condition.
    pub fn is_trifecta(&self) -> bool {
        self.reads_untrusted && self.reads_sensitive && self.external_effect
    }
}
```

### 2.4 Deployment on AWS

- **Inline plane** (ingress, output, egress, meter, retrieval, redact, broker): a single
  Rust binary as a **Lambda extension** co-located with each agent Lambda (in-process, no
  network hop), or a **Fargate sidecar** behind an internal ALB when the agent runs on ECS.
  Latency-sensitive and partly stateful (rate limits, breakers) → co-location beats a remote
  service.
- **Egress containment is architectural, not just code:** run the agent in a **private
  subnet with no default route**; force all outbound through the `aegis-egress` proxy. A
  fooled model cannot exfiltrate to an endpoint the VPC cannot reach.
- **Policies (Cedar)** live versioned in S3; the broker evaluates locally (no per-decision
  network call).
- **`aegis-supply`** runs in CI/CD (GitHub Actions) and again at model-load time.
- **`aegis-ledger`** appends to DynamoDB or S3 with **Object Lock** for immutability,
  correlated to CloudTrail by `run_id`/`thread_id` (the same keys as the LangGraph
  checkpointer).
- **Composes with, does not replace, Architecture A:** Step Functions still own orchestration
  and the durable human-approval pause; LangGraph still runs the loop; DynamoDB + KMS still
  hold state. Aegis sits *between* the model and every capability it wants to exercise.

### 2.5 Request path (the "1.1" pipeline)

```
UNTRUSTED INPUT
  → aegis-ingress (normalize · strip Unicode/tags · provenance wrap)   ◐/●
  → [ MODEL ]  (produces an untrusted REQUEST, not a command)
  → aegis-output (schema validate + sink-encode)                        ●
  → aegis-broker (POLICY ENGINE · Rule of Two)                          ●
  → aegis-egress (allowlist; external effect gated here)                ●
  → TOOLS · NETWORK · SINKS  (allowed only)

cross-cutting the whole pipeline:
  aegis-meter (cost · breakers) · aegis-retrieval (authz-in-query) ·
  aegis-supply (sign · pin) · aegis-redact (traces · PII) ·
  aegis-ledger (audit · memory) · aegis-redteam (adaptive gate)
```

The three consequence-side boxes (output, broker, egress) are the load-bearing ones; the
ingress guard is valuable but explicitly **not** trusted to be sufficient on its own.

---

## 3. Threat-by-threat plan (LLM01–LLM10)

For each entry: what OWASP considers achievable, the Aegis controls, the honest
contain/reduce/process split, and priority.

### LLM01 — Prompt Injection
- **OWASP:** intrinsic; no reliable prevention exists.
- **Aegis:** ◐ at input (`aegis-ingress` deterministic Unicode hygiene = strip tag-block
  U+E0000–E007F, variation selectors U+FE00–FE0F & U+E0100–E01EF, zero-width U+200B/C/D &
  U+2060, neutralize bidi; provenance wrapping; encoding/low-resource heuristics), ● at
  consequence (broker + egress + output).
- **Contained:** invisible-character channels + the whole consequence surface. **Reduced
  only:** steering by visible-text/cross-modal payloads. **Residual ○:** a wrong *answer*.
- **Priority:** build the containment trio (broker, output, egress) first. Do **not** build
  an injection detector as a primary control.

### LLM02 — Sensitive Information Disclosure
- Surfaces are broader than the final answer: tool-call args, reasoning traces, retrieved
  chunks, logs, embeddings, timing/length side channels.
- **Aegis:** `aegis-redact` treats traces & tool-args as first-class output (●) + layered
  PII/PHI/secret detection (◐); `aegis-broker` keeps secrets out of the prompt entirely (●);
  `aegis-egress` blocks image-URL beacons / hidden-Unicode exfil / covert channels (●);
  `aegis-retrieval` authorizes before retrieval (●).
- **Residual ○:** side channels (padding/batching helps ◐) and memorization/inversion
  (DP-SGD, dedup, unlearning, encoder vetting — pipeline, not Rust).

### LLM03 — Excessive Agency (the keystone)
- Root causes: excessive functionality, permissions, autonomy — all deterministic to fix.
- **`aegis-broker` (●):** complete mediation (no path from model output to a side effect
  skips it; authorization decided in code, never by asking the model); least privilege per
  operation (schema-validated args, re-checked at execution); Rule-of-Two gating (any [A,B,C]
  → human approval via SF task token; [A,B] or [A,C] → explicit residual-risk decision);
  graduated enforcement (audit→warn→block→escalate; reviewer sees the *exact* rendered
  action); idempotency + dual control; **open-ended tools banned**.
- **Implementation:** **Cedar** (Amazon's Rust-native policy language) as the evaluation
  core; policies versioned in S3, evaluated locally.
- **Priority: #1. Build first.**

### LLM04 — Supply Chain
- **`aegis-supply` (●):** sign + hash verify (Sigstore); pin to immutable digests (reject
  `latest`; detect namespace reuse); SBOM/AIBOM (CycloneDX ML-BOM) gating; serialization
  scanning + AI-suggested-dependency verification (defeats slopsquatting).
- **Residual ○:** behavioral backdoors that survive signing → red-teaming + evaluation.

### LLM05 — Data and Model Poisoning
- **Aegis:** `aegis-supply` artifact integrity (weights, adapters, chat templates, tokenizer
  configs) ●; `aegis-retrieval` RAG-corpus containment (provenance tags, trust-tier
  segregation, retrieval-hijack detection) ●/◐; `aegis-ledger` memory-write gating ●.
- **Residual ○:** training-data poisoning (~250 poisoned docs can backdoor a model
  regardless of dataset size; alignment does not remove backdoors) → data governance, lineage
  (DVC), curation, post-alignment trigger-probing.

### LLM06 — Unbounded Consumption
- **`aegis-meter` (●):** token-aware limits (tokens/min, tokens/day, est-cost/request) with
  pre-flight token estimation (HF `tokenizers`, Rust-native) that rejects before inference;
  **hard spending caps** (non-overridable, halt inference — not just alarms); agentic circuit
  breakers (step/recursion/wall-clock/cost ceilings; state-hashing loop detection);
  growing-context guard (per-session cumulative cost); extraction throttling (◐).

### LLM07 — Misinformation
- **Aegis:** `aegis-broker` claim-check-act — separate generation from execution; re-validate
  args/authorization/preconditions/state before high-impact tool calls (●); `aegis-output`
  mandatory structured fields (●).
- **Residual ○:** factual accuracy / grounding is model/RAG quality — Aegis limits blast
  radius, doesn't raise accuracy.

### LLM08 — Hidden Context Exposure
- Fix is almost entirely **architectural** (● by design): no secrets in the prompt/hidden
  context (`aegis-broker`/`aegis-redact`); authorization enforced deterministically by the
  broker, never delegated to system-prompt instructions; hidden context treated as
  non-secret by policy so disclosure has little direct impact.

### LLM09 — Vector and Embedding Weaknesses
- Frame: poisoning makes it wrong, inversion makes it leak, jamming makes it silent,
  access-control failure makes it indiscriminate.
- **`aegis-retrieval`:** authorization **inside** the index query (● — a client-supplied
  scope is a suggestion, not a control); ingest normalization (strip zero-width/homoglyphs)
  ●; provenance + trust-tier index segregation ●; withhold raw similarity scores + detect
  retrieval-hijack ◐; **treat embeddings as source-equivalent** (encrypt, treat backups at
  source sensitivity, classify an "embeddings-only" leak as a source-document breach because
  inversion recovers text) ●/○.

### LLM10 — Improper Output Handling
- Textbook **● Contain** and one of Rust's strongest fits.
- **`aegis-output`:** strict schema validation in trusted code (never a second LLM call);
  context-aware sink encoding (HTML/SQL/shell/path/email); control-char/ANSI/OSC/BEL
  stripping for terminal/log/IDE sinks; render-time exfil neutralization (disable auto-fetch
  of markdown images/link previews/iframes; allowlist or server-side fetch that strips
  data-bearing query params); no auto-exec of generated code.

### Coverage matrix (● contain / ◐ reduce / ○ process residual)

| OWASP 2026 | Primary crate(s) | Tier |
|---|---|---|
| LLM01 Prompt Injection | broker, egress, output (contain); ingress (reduce) | ●/◐ |
| LLM02 Sensitive Info Disclosure | redact, egress, broker, retrieval | ●/◐/○ |
| LLM03 Excessive Agency | broker | ● |
| LLM04 Supply Chain | supply | ● |
| LLM05 Data & Model Poisoning | supply, retrieval, ledger | ●/○ |
| LLM06 Unbounded Consumption | meter, egress | ● |
| LLM07 Misinformation | broker, output | ●/○ |
| LLM08 Hidden Context Exposure | broker, redact | ● |
| LLM09 Vector & Embedding | retrieval, ingress | ●/◐ |
| LLM10 Improper Output Handling | output | ● |

**Read-off:** the entries Aegis contains outright (LLM03, 04, 06, 08, 10) are the
consequence- and infrastructure-side ones, and they make the reduce-tier and process-tier
residuals survivable. **Build the ● column first.**

---

## 4. The capability model in depth (the keystone)

The broker sits between the agent and every tool. It never asks the model whether an action
is allowed; it decides deterministically from the session's accumulated capability state and
a Cedar policy.

```rust
pub enum Decision { Allow, HumanApprove, Deny(&'static str) }
pub struct Session { pub cap: Capability, pub run_id: String }

pub fn mediate(sess: &mut Session, call: &ToolCall, policy: &cedar::PolicySet) -> Decision {
    // 1. Structural: arguments must match the tool's strict schema.
    if !call.schema_valid() { return Decision::Deny("argument schema violation"); }
    // 2. Update this session's Rule-of-Two taint from THIS call.
    sess.cap.reads_untrusted |= call.touches(Provenance::Untrusted);
    sess.cap.reads_sensitive |= call.reaches_sensitive_data();
    sess.cap.external_effect |= call.has_external_effect();
    // 3. Deterministic authorization in code (Cedar), never via the model.
    if !cedar_authorized(policy, sess, call) { return Decision::Deny("policy denies this"); }
    // 4. Rule of Two: the trifecta is never auto-approved.
    if sess.cap.is_trifecta() { return Decision::HumanApprove; }  // -> SF task-token pause
    // 5. Graduated enforcement: irreversible/high-consequence -> human.
    match call.consequence() {
        Consequence::LowReversible      => Decision::Allow,
        Consequence::HighOrIrreversible => Decision::HumanApprove,
    }
}
```

Three properties make it load-bearing:
- **Deterministic** — same call, same decision; does not degrade when an attacker reads it.
- **Monotonic** — capability taint only *accumulates* within a session, so an agent that has
  touched untrusted input cannot later quietly regain trust to reach sensitive data and
  exfiltrate.
- **Outside the model** — no injected prompt can talk the broker out of a Cedar policy,
  because the broker never consults the model for the decision.

**Concrete meaning of "a fooled model breaks nothing important":** the injection may fully
control the model's output; that output can only ever *request* a tool call; the broker
grants requests by policy and capability, not by persuasion — so the worst a compromised
model achieves is a denied request and a ledger entry.

### Rule of Two / lethal trifecta — the intuition (plain-language)

Think of the agent as an intern with keys to three rooms: **A** the street (untrusted input
— strangers hand it notes), **B** the safe (sensitive data), **C** the door to the outside
(external effect: send/change/delete). The intern is dangerous only with **all three keys at
once**: a note from the street says "carry the safe's contents outside and drop them in the
mailbox," and B+C make it possible. Remove any one leg and high-impact exploitation
collapses. **Rule of Two:** allow at most two of the three simultaneously; the [A,B,C]
combination always needs human approval. The decision is made by *code that can't be talked
into it* (the broker + Cedar), not by the model.

---

## 5. Implementation roadmap (leverage-ordered, deterministic-first)

- **Phase 0 — consequence-side backbone (wk 1–3):** `aegis-broker`, `aegis-output`,
  `aegis-egress`. *Done when* no path from model output to a side effect or outbound byte
  bypasses the broker/egress, and every sink receives only validated, encoded output.
- **Phase 1 — budget, evidence, hygiene (wk 3–5):** `aegis-meter`, `aegis-ledger`,
  `aegis-ingress` (deterministic parts). *Done when* every run has a hard cost ceiling + an
  immutable audit trail, and no invisible-character payload survives ingest.
- **Phase 2 — data-plane guards (wk 5–8):** `aegis-retrieval`, `aegis-supply`,
  `aegis-redact`. *Done when* the model can never be handed an unauthorized chunk, no
  unsigned/mutable-tagged artifact loads, and traces/args are redacted before logging.
- **Phase 3 — validation as a gate (ongoing):** `aegis-redteam` adaptive harness in CI;
  routing-accuracy + misinformation evals on every change; post-alignment trigger-probing.
  *Done when* nothing ships on a static benchmark alone.

**Sequencing rule (important, often misread):** never let a **◐ Reduce** control
(ingress detection) ship as if it were a **● Contain** control. Phase 0 must land *before*
ingress heuristics, so the probabilistic layer always has deterministic containment behind
it.
- *Plain-language:* a probabilistic screen "guesses"; a deterministic control "guarantees."
  Put the real locks (Phase 0) in place first, then add the guesser (ingress). If the guesser
  is wrong, the locks still hold. The rule uses "must land" = "must already be in place";
  "behind it" = the deterministic backstop sits behind the probabilistic front line.

---

## 6. What Rust cannot fix — the honest boundary (○ residuals)

- The model can still be fooled (LLM01) — Aegis makes it harmless, not impossible.
- Training-data memorization/poisoning (LLM02, LLM05) — DP-SGD, dedup, lineage, curation,
  unlearning, trigger-probing.
- Factual accuracy (LLM07) — grounding/RAG quality is model-side.
- Behavioral backdoors that survive signing (LLM04, LLM05) — only behavioral eval + red-team.
- Embedding inversion / encoder backdoors (LLM09) — geometry is a model property.
- **Human-approval fatigue** — the Rule-of-Two gate depends on humans reviewing [A,B,C]
  actions; at volume, review quality degrades. A process/staffing problem, not a code one.

The point is not that Aegis is weak — its power is *precisely located*: it owns the
consequence side completely and is honest about the input and model sides. That division is
the OWASP posture and what makes the plan trustworthy.

---

## 7. Coexistence with Amazon Bedrock Guardrails (mutually reinforcing)

**They reinforce each other; they do not compete.** Guardrails = almost entirely **◐ Reduce**
(model-facing, probabilistic ML judgments). Aegis = almost entirely **● Contain**
(system-facing, deterministic). **One coherence rule: a Guardrails *pass* is never an
authorization.**

### 7.1 Correct ordering (this is the correlation that makes them reinforce)

```
UNTRUSTED INPUT
  → aegis-ingress (normalize + strip invisible chars, deterministic ●)
        → hands Guardrails CLEAN text, so its classifiers can't be evaded by
          Unicode smuggling            (Aegis strengthens Guardrails)
  → BEDROCK GUARDRAILS (input): prompt-attack · content · PII   ◐
        → cuts VOLUME + emits grounding/PII signals   (Guardrails strengthens Aegis)
  → [ MODEL ]
  → BEDROCK GUARDRAILS (output): content · PII · grounding score   ◐
  → AEGIS deterministic backstop: output · broker · egress · ...   ●
        (a Guardrails pass is NOT an authorization)
  → TOOLS · NETWORK · SINKS (allowed only)

feedback: aegis-ledger + aegis-redteam → tune Guardrails policies over time
```

`aegis-ingress` runs **first** so Guardrails classify clean, de-smuggled text — an attacker
can no longer slip invisible-character/homoglyph payloads past the Guardrails classifier.

### 7.2 How they reinforce each other (both directions)

- **Aegis → Guardrails:** ingress normalization before Guardrails raises the Guardrails
  classifiers' hit rate; and because Aegis contains consequences deterministically, you can
  tune Guardrails for **signal rather than as the sole gate** — fewer conservative hard
  blocks and false positives, because a miss is caught downstream.
- **Guardrails → Aegis:** they cut the volume of hostile content reaching the deterministic
  layer, and their grounding/PII/attack scores become inputs Aegis acts on deterministically
  (e.g. `aegis-broker` refuses a high-impact tool call when the grounding score is low).
- **Feedback loop:** `aegis-ledger` records which Guardrails *passes* later became broker
  denials, and `aegis-redteam` finds adaptive bypasses; both feed back into tightening
  Guardrails policies. The deterministic layer tells you where the probabilistic layer leaks.

### 7.3 Let Guardrails own what Aegis structurally cannot

Prompt-attack/jailbreak classification, content/toxicity/word/image filters,
contextual-grounding scoring, PII detection in prompts/responses, automated-reasoning checks
— ML judgments where Bedrock's classifiers beat any hand-rolled Rust heuristic. Guardrails
hold those ◐ slots; `aegis-ingress` shrinks to the deterministic byte work classifiers don't
do.

### 7.4 Keep Aegis for the deterministic consequence surface Guardrails don't reach

- **Capability model:** Guardrails offer "Get user confirmation" and "Return Control" hooks
  but no Rule-of-Two accounting, least-privilege-per-operation, complete mediation,
  idempotency, or Cedar authz. **Those hooks are the integration point:** `aegis-broker`
  decides `HumanApprove`, enacted via Bedrock's user-confirmation / Return Control.
- **Output handling:** Guardrails filter harmful content but don't do context-aware sink
  encoding, control-char/ANSI stripping, schema validation, or markdown-image exfil
  neutralization. A clean, non-toxic response can still carry a malicious SQL string or an
  exfil URL → `aegis-output` stays essential.
- **No Guardrails equivalent at all:** token/cost metering (`aegis-meter`),
  artifact signing/pinning (`aegis-supply`), authorization inside the vector query
  (`aegis-retrieval`), network-egress allowlisting (`aegis-egress`).

### 7.5 Overlap wiring + cost sequencing

- LLM01: Guardrails classifier first (◐), Aegis containment behind (●) — don't build a
  second injection classifier.
- LLM07: Guardrails produce the grounding score (◐); `aegis-broker` turns "grounding below
  threshold" into a deterministic refusal (●).
- LLM02: Guardrails redact prompt/response (◐); `aegis-redact` covers surfaces Guardrails
  never see — reasoning traces, tool-call args, embeddings (●).
- **Cost:** Guardrails add per-call latency/spend; Aegis's deterministic checks are nearly
  free. Run the cheap deterministic gates (schema, egress, capability) first so they can
  short-circuit before you pay for a Guardrails call; reserve Guardrails' expensive checks for
  untrusted content and grounding, not every internal hop.

### 7.6 Division of responsibility

| Concern | Bedrock Guardrails (◐ reduce) | Aegis (● contain) |
|---|---|---|
| Prompt injection / jailbreak (LLM01) | Prompt-attack filter, input tagging | broker/egress/output backstop; ingress byte-hygiene |
| Content safety / toxicity | Content, word, image filters | — (defers to Guardrails) |
| Misinformation (LLM07) | Contextual-grounding score, automated reasoning | broker gates the tool call on the score |
| Sensitive info (LLM02) | PII filters in prompt/response | redact traces, tool args, embeddings; no-secrets-in-prompt |
| Excessive agency (LLM03) | Get-user-confirmation, Return Control (hooks) | Rule of Two, least privilege, complete mediation, Cedar |
| Output handling (LLM10) | — | schema validation, sink encoding, control-char, exfil |
| Consumption (LLM06) | — | meter: caps, circuit breakers |
| Supply chain (LLM04) | VPC/PrivateLink for imports (infra) | supply: sign, pin, SBOM, scan |
| Vector/embeddings (LLM09) | — | retrieval: authz-in-query, segregation |
| Network egress | — | egress: default-deny allowlist proxy |

> **OWASP numbering note:** the older pre-2026 list labelled Sensitive Information Disclosure
> as LLM06 and Excessive Agency as LLM07/LLM08. In the 2026 list these are **LLM02** and
> **LLM03**; the underlying Bedrock features are the same — only the numbers moved. (This
> correction was needed because an uploaded Bedrock summary used the old numbering.)

---

## 8. Per-crate integration reference (beginner-oriented)

**Mental model:** an agent is a *loop*, not magic. The model reads context and either answers
or **asks to call a tool** (a tool call is structured text like "call `send_email` with these
args"). The model executes nothing — your code decides whether to run the request. **The
model's output is an untrusted *request*, not a command.** Multi-agent = several such loops
handing work to each other → more places where untrusted text can set something in motion.
Aegis = deterministic checkpoints on the loop's boundaries. Deployment words: a **Lambda
extension** runs beside your function in the same environment (in-process); a **Fargate
sidecar** is a helper container next to your app container.

For each crate: what it does · where it plugs in · why it sits there · the beginner mistake
it removes.

- **`aegis-core`** — shared trust vocabulary (`Provenance`, `Capability`). Every crate
  depends on it. Makes "untrusted" a *type-level* fact, not a comment. *Removes:* passing
  bare `String`s around and losing provenance — where injections hide.
- **`aegis-ingress`** — cleans/labels everything entering the model (strip invisible Unicode,
  normalize, provenance-wrap). At the entrance, the one point where input is still clean of
  the model's influence. Byte hygiene is deterministic and complete. *Removes:* believing an
  input filter "solves" injection — it only **reduces**; real defense is downstream.
- **`aegis-output`** — validates output against a strict schema and sink-encodes it (HTML/
  SQL/shell), strips control chars, neutralizes exfil. Between the model and every downstream
  sink. Encoding must happen where output leaves your control (the sink). *Removes:* dropping
  the model's answer straight into SQL/HTML/terminal.
- **`aegis-broker`** — decides Allow/HumanApprove/Deny for every tool call. The boundary
  where "requesting text" becomes "an action." The decision is made by *code* (Cedar +
  Rule-of-Two), not the model. *Removes:* trusting the model to decide when to call a
  powerful tool. Your agent code never calls a tool directly — only through the broker:
  ```rust
  match broker.mediate(&mut session, &call, &policy) {
      Decision::Allow        => run_tool(&call),        // execute
      Decision::HumanApprove => pause_for_human(&call), // -> Step Functions pause
      Decision::Deny(reason) => reject(reason),         // refuse and log
  }
  ```
- **`aegis-egress`** — controls where the agent can reach on the network (allowlist + strip
  data-bearing query params). Agent lives in a private subnet with no default route; all
  outbound goes through this proxy. Architectural containment — the most reliable kind.
  *Removes:* giving a Lambda full internet egress "just to make it work."
- **`aegis-meter`** — counts tokens/cost and breaks runaway loops (pre-flight estimation;
  step/recursion/cost ceilings). Wraps the model calls and the whole run. An agent loop won't
  limit itself → the breaker must be *outside* the loop. *Removes:* two agents handing control
  back and forth forever while the token bill climbs.
- **`aegis-retrieval`** — (RAG = put docs in a vector DB, fetch most-similar chunks into
  context; similarity search knows nothing about access rights.) Authorizes search *inside*
  the index query, segregates by trust tier, normalizes at ingest. In front of the vector DB.
  Filter *after* the search and the model has already seen the chunk — you can't recall it.
  *Removes:* one shared index for all tenants with a permission filter "somewhere in the app."
- **`aegis-supply`** — verifies artifact provenance (sign + hash, pin to immutable digest,
  scan). In CI/CD and at model-load, not the hot path. A poisoned artifact must be stopped
  *before* production. *Removes:* pulling a model by name or `latest` tag (re-registerable to
  a malicious version).
- **`aegis-redact`** — redacts sensitive content in the final answer *and* in reasoning
  traces and tool-call args. A shared classify-and-redact path before logging/returning. It's
  not only the final answer that leaks. *Removes:* logging raw reasoning traces to shared
  observability "for debugging."
- **`aegis-ledger`** — immutable log of calls/decisions/approvals + gates writes to long-term
  memory. Appends to immutable storage keyed by `run_id`/`thread_id` (`thread_id` = the
  identity of one run/conversation). Without a trail you debug blind; a memory write is a
  privilege (a poisoned memory affects all future sessions). *Removes:* letting an agent
  freely write to its own memory → a "sleeper agent."
- **`aegis-redteam`** — runs the whole defense against **adaptive** attacks (written after
  reading the defense). In CI as a release gate; testers get the full defense spec. A static
  benchmark lies. *Removes:* seeing "near-zero success" on a static set and declaring the
  defense done — adaptive success can exceed 90%.

**One request, end to end:** (1) ingress cleans+labels → (2) meter budgets → (3) retrieval
fetches only allowed chunks → (4) model *asks* for a tool call → (5) output validates+encodes
→ (6) broker decides Allow/HumanApprove/Deny → (7) egress allows only allowlisted
destinations → (8) ledger records immutably (redact having cleaned sensitive spans first).
`aegis-supply` did its work earlier (build/load); `aegis-redteam` continuously checks the
whole chain holds under adaptive attack.

---

## 9. Deliverables produced in the thread

All are polished PDFs generated via a Python content-module + renderer pattern (Pygments for
syntax highlighting, `wkhtmltopdf`; DejaVu Sans for Cyrillic; **light backgrounds throughout
to save printer toner** — the one dark diagram was later flipped to light).

| Deliverable | Notes |
|---|---|
| `Editorial_Arbiter_Reference.pdf` | 16pp. Worked Architecture-A example: 3 LangGraph subagents (Grammar → Engage → Arbiter) on Step Functions; per-agent DynamoDB checkpoint tables; one customer-managed KMS CMK; least-privilege IAM per agent; SF ASL (JSONata). |
| `A_vs_B_Architecture_Comparison.pdf` | 7pp. 11-dimension traffic-light scorecard across A / B-proper / B-handrolled. |
| `LangGraph_on_Lambda_Study_Guide.pdf` | 22pp English curriculum, Parts 0–11 + appendices, incl. worked real-world examples. |
| `LangGraph_на_AWS_Lambda_Посібник.pdf` | 23pp Ukrainian translation of the study guide (prose UK; code identifiers/API English; comments UK). AWS-specific. |
| `Aegis_OWASP_Rust_Mitigation_Plan.pdf` | English Aegis plan (this document's PDF form). Sections 0–8 + coverage matrix; **image** request-path diagram. |
| `Aegis_OWASP_Rust_План_Захисту.pdf` | Ukrainian Aegis plan, structurally identical (same block count). |

**Aegis PDF section map:** 0 Strategy · 1 Architecture (image request-path diagram + workspace
table) · 2 Threat-by-threat (LLM01–10) · 3 Capability model · 4 Roadmap · 5 Rust ecosystem
cheat-sheet · 6 What Rust cannot fix · 7 Coexistence with Bedrock Guardrails · 8 Per-crate
beginner primer · Appendix coverage matrix.

**Rust ecosystem cheat-sheet (candidate crates — pin & verify versions):** `cedar-policy`
(broker), `serde` + `jsonschema` (output), `tokenizers` (meter/ingress),
`unicode-normalization` + `unicode-security` (ingress/retrieval), `aho-corasick` + `regex`
(redact), `sigstore` (supply), `axum`/`tower` + `hyper` (egress/gateway), `aws-sdk-*` +
`lambda_runtime` + `lambda-extension` (all), `tracing` + OTel exporter (ledger).

---

## 10. Stated preferences and constraints (for continuity)

- Deliver a bot/project build as a **single zip named after the project** (e.g. `aegis`).
- Plain-text chat with **emoji markers** for structure; no markdown/bold/headers in chat
  replies (PDF/document deliverables use full formatting — accepted).
- **Benchmark-grounded** recommendations with **honest tradeoff analysis**.
- Works across **Ukrainian and English**.
- **Light backgrounds** in printable deliverables (toner).
- **Adaptive-testing rule:** reject static-only attack-success claims; red-team with the
  defense disclosed (adaptive success has exceeded 90% against most defenses while static
  success was near zero — Nasr et al., cited by OWASP).

---

## 11. OWASP Agentic AI Top 10 (ASI 2026) — coverage and Aegis adaptation

### 11.0 Why this is a second, companion list

The LLM Top 10 covers the model **as a component**; the Agentic (ASI) Top 10 covers the moment
the model **becomes an actor** — with tools it can call, memory it carries across sessions, peers
it talks to, and consequences it sets in motion. OWASP itself says to pair the two lists. Aegis
was already built for the consequence surface, so much of the ASI list maps onto existing crates
— but ASI opens genuinely new surfaces (inter-agent communication, agent identity, rogue-agent
emergence, human-agent trust) that require **new Aegis components**.

Honest note: the ASI list skews more **◐ Reduce / ○ Process** than the LLM list, because agentic
risks include *emergent behavioral* phenomena (rogue agents, cascading failures, human persuasion)
that deterministic code cannot fully prevent. Aegis's value stays where it always was — bounding
the **consequence** so that even a hijacked or rogue agent breaks nothing important — plus new
deterministic controls (crypto inter-agent auth, per-agent identity, kill-switch, sandbox, deception
tripwires) that contain the new surfaces. Many ASI entries overlap the LLM list (e.g. ASI02↔LLM03/06,
ASI05↔LLM05/01, ASI06↔LLM05/09); the LLM-side controls already do double duty, and this section
adds only the agentic deltas.

### 11.1 New Aegis components (the adaptation)

Six new crates augment the §2.2 workspace:

- **`aegis-mesh`** — secure inter-agent communication: mutual auth (mTLS + per-agent PKI), message
  signing (payload+context hash) + intent-diffing, anti-replay (nonces/session-ids/timestamps tied
  to task windows), protocol pinning (reject downgrade), attested agent registry + signed agent
  cards, typed message schemas with per-message audiences, metadata-inference reduction (padded
  messages). *Primary for ASI07; supports ASI03/04/10.*
- **`aegis-identity`** — per-agent non-human identity + delegation control: JIT short-lived scoped
  credentials (mTLS/scoped tokens) bound to subject/audience/purpose/session/duration; delegation
  that re-validates the **original user intent** (confused-deputy defense) and forbids privilege
  inheritance without re-validated intent; re-auth on context switch; per-session sandboxes that
  wipe memory between tasks/users. *Primary for ASI03; supports ASI10.*
- **`aegis-intent`** — a signed **goal/intent envelope** bound per execution cycle ("intent
  capsule"): the broker validates each action against the current declared task/scope and
  pauses/blocks on deviation; a stable goal identifier drives drift alerting. *Primary for ASI01;
  supports ASI10.*
- **`aegis-sandbox`** — isolated code-execution environment: non-root, ephemeral, network-restricted
  (via egress) and syscall-limited container with a dedicated working dir; separates code
  generation from execution behind a broker validation gate. *Primary for ASI05.*
- **`aegis-killswitch`** — emergency revocation: instantly disable a specific tool, prompt, agent
  connection, or agent across all deployments; quarantine suspicious agents; require fresh
  attestation + human approval before reintegration. *Primary for ASI08/ASI10; supports ASI04.*
- **`aegis-honeypot`** — deception tripwires. **Decoys** are patterns a legitimate flow would never
  touch (probe paths, the cloud metadata IP `169.254.169.254`, credential-file names, sentinel
  command markers), matched at policy time (`/sandbox/validate`) *before* execution. **Canaries** are
  unique tokens planted out-of-band (a fake secret in the ephemeral working dir, a seeded memory
  chunk) whose appearance in outbound content — a `/mediate` tool-call argument or an egress URL —
  is proof data was read and is being exfiltrated. The crate owns only deterministic **detection**
  (case-insensitive substring matching, no I/O, no policy decision of its own); the gate orchestrates
  the response, so a hit is escalated at the *agent* level — an immutable `EntryKind::Tripwire`
  ledger entry **+ quarantine via `aegis-killswitch`** — rather than swallowed as a routine `Deny`,
  and the base containment (the sandbox/egress `Deny`) is never weakened. An empty set is inert (zero
  false positives until decoys/canaries are configured); each project ships its own
  `policies/honeypots.json` plus a unique per-deployment runtime canary (`AEGIS_CANARY`). *Primary
  for ASI05/ASI08; supports ASI10.*

Existing crates also gain agentic extensions: **broker** adds semantic/identity tool validation
(fully-qualified names + version pins, fail-closed on ambiguity) and blast-radius guardrails
(quotas, progress caps, planner↔executor breakers); **meter** adds inter-agent fan-out caps;
**ledger** adds behavioral-integrity baselines, plan-divergence detection, a watchdog layer, memory
trust-scoring + decay/expiry, and a rule against auto re-ingesting the agent's own outputs;
**retrieval** adds two-factor surfacing of high-impact memory; **supply** adds runtime verification
of dynamically-composed capabilities (MCP servers, agent cards, remote prompt templates);
**redteam** adds digital-twin replay as a pre-deployment cascade gate.

### 11.2 Threat-by-threat (ASI01–ASI10)

**ASI01 Agent Goal Hijack** — *Risk:* attacker redirects the agent's goals/task-selection/decision
pathways (prompt injection, deceptive tool outputs, forged agent messages, poisoned data).
*Existing:* ingress (◐), broker gates goal-changing/high-impact actions (●), retrieval (poisoned
RAG), ledger (goal audit). *Adaptation:* **aegis-intent** binds the declared goal per cycle and the
broker refuses actions deviating from the declared scope; sanitize all connected sources
(ingress/retrieval/mesh) before they touch goals. *Tier:* ◐ input, ● consequence.

**ASI02 Tool Misuse & Exploitation** — *Risk:* agent misuses legitimate tools (over-privileged/
over-scoped, unvalidated forwarding to shell, loop amplification, tool poisoning, typosquatting,
EDR-bypass tool-chaining, approved-ping→DNS-exfil). *Existing:* broker (● least privilege, complete
mediation, Rule of Two, idempotency), egress (● ping→DNS / allowlist), meter (◐ loop/DoS), output
(◐ unvalidated forwarding), supply (○ descriptor/typosquat). *Key:* the broker's **monotonic
Rule-of-Two taint** is the exact defense for "internal query → external exfiltration" — once
`reads_sensitive` is set, any `external_effect` request becomes the trifecta → human approval.
*Adaptation:* broker adds semantic/identity tool validation (fully-qualified names, version pins,
fail-closed) and dry-run/diff preview for high-impact actions; ledger adds tool-chaining anomaly
detection. *Tier:* ●.

**ASI03 Identity & Privilege Abuse** — *Risk:* delegation-chain/role-inheritance abuse, confused
deputy, TOCTOU, synthetic identity, memory-based privilege retention, forged agent persona.
*Existing:* broker Cedar least-privilege + **execution-time re-check = TOCTOU fix** (◐), ledger
memory-write gating, session isolation. *Adaptation:* **aegis-identity** (per-agent identity, JIT
scoped creds, delegation that re-validates original user intent, intent-bound tokens, re-auth on
context switch, memory wipe between users) + **aegis-mesh** cryptographic agent attestation
(forged-persona defense). *Tier:* ●.

**ASI04 Agentic Supply Chain** — *Risk:* runtime-composed capabilities may be malicious — poisoned
remote prompt templates, tool-descriptor injection, typosquatting, compromised MCP/registry,
agent-in-the-middle via agent cards. *Existing:* supply (● sign/attest/SBOM/AIBOM/pin/verify-
before-activate). *Adaptation:* extend supply to **runtime verification** of dynamically-loaded MCP
servers/agent cards/prompt templates; **aegis-killswitch** for emergency revocation; **aegis-mesh**
attested registry (agent-in-the-middle). *Tier:* ●.

**ASI05 Unexpected Code Execution (RCE)** — *Risk:* agent generates+executes code → RCE (shell
injection, unsafe deserialization, `eval()` in memory, multi-tool chain, unverified package
installs, lockfile poisoning). *Existing:* output (● no auto-exec, shell/path escaping), broker
(● open-ended tools banned, generation-vs-execution gate, ban eval), egress (sandbox egress), supply
(◐ package/lockfile pinning). *Adaptation:* **aegis-sandbox** — non-root, ephemeral,
network/syscall-limited exec with a dedicated working dir; **aegis-honeypot** plants decoy credential
files + a metadata-IP tripwire in that working dir, so generated code that probes for an escape
(reads `.aws/credentials`, curls `169.254.169.254`) trips a **quarantine before it can act** —
turning a blind RCE attempt into a high-confidence detection instead of a silent deny. *Tier:* ●
(consequence); bad-code generation ◐/○.

**ASI06 Memory & Context Poisoning** — *Risk:* persistent corruption of stored/retrievable context
(RAG/embedding poisoning, shared-memory poisoning, long-term drift, context-window manipulation,
cross-agent propagation, bootstrap poisoning). *Existing:* retrieval (● authz-in-query, per-tenant
namespaces, cross-tenant bleed prevention), ledger (● memory-write gating), redact (scan writes).
*Adaptation:* memory governance — **expire/decay unverified memory**, **trust-scored entries +
two-factor to surface high-impact memory**, snapshots/rollback/quarantine, and a hard rule
**against auto re-ingesting the agent's own outputs**. *Tier:* ●/◐.

**ASI07 Insecure Inter-Agent Communication** — *Risk:* real-time agent messages lack
auth/integrity/confidentiality (MITM, tampering, replay, protocol downgrade, descriptor forgery,
A2A registration spoofing, metadata profiling, semantics split-brain). *Existing:* **gap** — Aegis
had no inter-agent channel security. *Adaptation:* **aegis-mesh** (new, major) — mutual auth,
message signing + intent-diffing, anti-replay, protocol pinning, attested registry/signed agent
cards, typed schemas with per-message audiences, metadata padding; treat peer messages as untrusted
→ route through ingress. *Tier:* ● (crypto auth/integrity/anti-replay); semantic split-brain ◐/○.

**ASI08 Cascading Failures** — *Risk:* a single fault propagates across agents/workflows into
system-wide harm (fan-out, cross-tenant spread, feedback loops, auto-deployment cascade, governance
drift). *Existing:* meter (● circuit breakers + loop detection), broker (◐ planner↔executor
separation, human gates), ledger (◐ non-repudiation/lineage), egress/sandbox (contain propagation).
*Adaptation:* blast-radius guardrails across meter+broker+mesh (quotas, progress caps, fan-out caps,
rate-limit fast-spreading commands); **aegis-killswitch** emergency revocation; **aegis-honeypot**
canary tokens whose appearance in outbound content trips an immediate quarantine — cutting a
compromised agent out of the mesh *before* a leak or a hijacked command cascades; **digital-twin
replay** as a pre-deployment gate in redteam; drift detection in ledger. *Tier:* ● (breakers/
kill-switch); speed-vs-human ○.

**ASI09 Human-Agent Trust Exploitation** — *Risk:* agent exploits human trust (anthropomorphism,
authority bias, fake explainability, missing confirmation, consent-laundering via read-only
previews, weaponized explainability). *Existing:* broker HITL (● mandatory confirmation for
sensitive actions), output (◐ separate preview from effect), ledger (plan-divergence detection).
*Adaptation:* human-factors safeguards at the output/broker boundary — deterministic **plain-
language risk summaries with provenance** substituted for model-generated rationales (a hijacked
agent fabricates rationales), risk badges, a report-suspicious channel that can trigger capability
lockdown, adaptive trust-calibration cues; block side-effects during any "preview" context.
*Tier:* ●/◐ (deterministic controls); persuasion itself ○.

**ASI10 Rogue Agents** — *Risk:* an agent deviates from its intended function/scope after drift
begins (goal drift/scheming, workflow hijacking, collusion/self-replication, reward hacking,
impersonated observer agent). *Existing:* broker (● least privilege bounds a rogue agent's reach;
reward-hacking-deletes-backups → HITL; self-replication → approval + rate limits), ledger (◐
behavioral baselines, watchdog, anomaly/plan-divergence detection), identity/mesh (crypto
attestation; impersonated-observer defense), killswitch/sandbox (● instantly disable + quarantine).
*Adaptation:* **behavioral attestation** — signed behavioral manifests (identity+intent) validated
before each action, with a watchdog layer (ledger); killswitch + recovery/reintegration on fresh
attestation; keys never directly available to agents (orchestrator/HSM mediates signing).
*Tier:* rogue *emergence* ○; *consequences* ●-contained; *detection* ◐.

### 11.3 ASI coverage matrix (threat → primary crates)

| ASI (2026) | Primary Aegis components | Tier |
|---|---|---|
| ASI01 Agent Goal Hijack | intent, broker, ingress, retrieval, ledger | ●/◐ |
| ASI02 Tool Misuse & Exploitation | broker, egress, meter, supply, output | ● |
| ASI03 Identity & Privilege Abuse | identity, broker, mesh, ledger | ● |
| ASI04 Agentic Supply Chain | supply, killswitch, mesh | ● |
| ASI05 Unexpected Code Execution (RCE) | sandbox, honeypot, output, broker, egress, supply | ● |
| ASI06 Memory & Context Poisoning | retrieval, ledger, redact | ●/◐ |
| ASI07 Insecure Inter-Agent Communication | mesh, ingress | ●/◐ |
| ASI08 Cascading Failures | meter, killswitch, honeypot, broker, ledger, redteam | ●/○ |
| ASI09 Human-Agent Trust Exploitation | broker, output, ledger | ●/◐/○ |
| ASI10 Rogue Agents | broker, identity, ledger, killswitch, sandbox | ●/◐/○ |

The per-crate view of this mapping (which crate mitigates which LLM **and** ASI entries, fully or
partially) is maintained in the companion file **`crate-coverage-matrix.md`**.

### 11.4 Agentic-specific residuals (○)

- **Rogue-agent emergence / autonomous misalignment** — code bounds consequences and detects drift,
  but cannot prevent an aligned-looking agent from drifting; behavioral evals, red-team, governance.
- **Human persuasion (ASI09)** — Aegis enforces confirmation, preview-effect separation, and
  provenance, but cannot stop social-engineering of a human who clicks approve; training +
  human-factors.
- **Semantic split-brain across agents (ASI07)** — crypto integrity is deterministic, but divergent
  parsing of one instruction is semantic; typed contracts + intent-diffing reduce, not eliminate.
- **Speed/scale vs human oversight in cascades (ASI08)** — breakers/kill-switch bound blast radius,
  but fault propagation can outrun humans; the residual must sit in the org's risk budget.

---

## 12. Open next step (proposed, not yet done)

Scaffold the actual **`aegis` Rust workspace** as a single zip: `aegis-core` types, a working
`aegis-broker` skeleton with Cedar wired in, and stubs for the remaining crates — matching the
zip-per-project preference.
