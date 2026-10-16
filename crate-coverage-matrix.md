# Aegis crate coverage matrix

The **per-crate** (crate → threats) companion to `architecture-considerations.md`. That document
holds the *threat → crates* view (§3 LLM matrix, §11.3 ASI matrix, §12.2 AST matrix); this file
inverts it, so you can read a single crate and see every OWASP **LLM Top-10 (2025)**, **Agentic ASI
Top-10 (2026)**, and **Agentic Skills AST Top-10 (v1.0 2026)** entry it mitigates, fully or partially.
The two files are kept in sync — when a crate's mapping changes in `architecture-considerations.md`,
update the corresponding row here.

> **Source of truth.** The authoritative, test-enforced risk→crate mapping is the generated
> `docs/owasp-coverage-matrix.md` (built from the `aegis_core::Owasp` enum + `aegis_redteam::coverage`,
> with a red-team test asserting every risk has a covering crate). This per-crate table is a
> hand-maintained *inverse, supporting-role* view. Its LLM/ASI codes predate the §3 numbering
> reconciliation and are indicative of supporting roles rather than the canonical single-primary
> mapping; when the two disagree on a specific cell, the generated matrix wins.

## How to read it

- **Tier** — the honesty tier of the crate's *primary* contribution:
  **● Contain** (deterministic, code-enforced) · **◐ Reduce** (deterministic control over a partly
  behavioral risk) · **○ Process** (evals / red-team / governance; not a runtime guarantee).
- In the LLM / ASI / AST columns, a **bold** code is an entry for which the crate is a *primary*
  control; a plain code is a *supporting* role (the crate appears in that threat's matrix row but is
  not the lead). `—` means the crate maps to no entry in that family. The three lists are mapped
  **independently** — a crate's AST role is its skill-lifecycle contribution, not a reuse of its
  LLM/ASI mapping (overlaps are noted in `architecture-considerations.md` §12.1).

## Per-crate coverage

| Crate | Primary role | LLM Top-10 (2025) | Agentic ASI Top-10 (2026) | Agentic Skills AST Top-10 (2026) | Tier |
|---|---|---|---|---|---|
| `aegis-core` | Trust vocabulary — provenance labels, capability/Rule-of-Two tags, shared types (+ `TenantId`, `PolicyDecision`, `Owasp`) | — | — | — | — |
| `aegis-trace` *(T0)* | Observability spine — typed `Trace`/`Span`, pluggable `TraceCollector`, non-blocking `SpanEmitter` | — | — | — | — |
| `aegis-broker` | Capability mediator / deterministic policy engine (Cedar) | **LLM01**, **LLM03**, **LLM07**, LLM02, LLM08 | **ASI02**, ASI01, ASI03, ASI05, ASI08, ASI09, ASI10 | AST03, AST05 | ● |
| `aegis-output` | Output schema validation + sink-specific encoding | **LLM02**, **LLM10**, LLM01, LLM07 | ASI02, ASI05, ASI09 | — | ● |
| `aegis-egress` | Network egress firewall / exfiltration broker | **LLM01**, **LLM02**, **LLM06** | ASI02, ASI05 | — | ● |
| `aegis-meter` | Token-aware cost governor + agentic circuit breakers | **LLM06** | ASI02, **ASI08** | — | ● |
| `aegis-ingress` | Input normalization / prompt firewall | **LLM01**, **LLM09** | ASI01, ASI07 | **AST05**, AST04 | ◐/● |
| `aegis-retrieval` | Retrieval + vector authorization guard | **LLM02**, **LLM05**, **LLM09** | ASI01, ASI06 | AST05 | ●/◐ |
| `aegis-supply` | Artifact / supply-chain verifier (sign, pin, scan, skills) | **LLM04**, **LLM05** | **ASI04**, ASI02, ASI05 | **AST01**, **AST02**, **AST03**, **AST04**, **AST07**, **AST08**, **AST10** | ● |
| `aegis-redact` | Disclosure / redaction filter for outputs and traces | **LLM02**, **LLM08** | ASI06 | — | ◐/● |
| `aegis-ledger` | Tamper-evident audit + memory-write gating | **LLM02**, **LLM03**, **LLM05** | ASI01, ASI03, ASI06, ASI08, ASI09, ASI10 | **AST09** | ● |
| `aegis-redteam` | Adaptive attack harness (release gate) | **LLM01** (all, as a gate) | ASI08 (digital-twin replay gate) | AST08 (skill-gate attacks) | ○ |
| `aegis-eval` *(T3)* | Evaluation harness — `Evaluator` trait, deterministic `PhiLeakEvaluator`, threshold aggregation, golden sets | **LLM02** (PHI leak, measured), LLM07, LLM09 | — | — | ● |
| `aegis-gateway` *(T4)* | Edge gateway core — hashed API-key auth, per-key rate limiter, MCP JSON-RPC 2.0 adapter. Transport only; security stays in the pipeline | — | — | — | — |
| `aegis-mesh` *(§11)* | Secure inter-agent communication (mTLS, signing, anti-replay, attested registry) | — | **ASI07**, ASI03, ASI04, ASI10 | AST10 | ● |
| `aegis-identity` *(§11)* | Per-agent identity + delegation control + JIT scoped credentials | — | **ASI03**, ASI10 | AST03 | ● |
| `aegis-jit` *(§11)* | JIT credential broker: exchange a validated identity credential for a short-lived, scoped STS session / just-in-time secret | — | **ASI03**, **ASI06** | — | ● |
| `aegis-prompt` *(T2)* | Prompt supply: versioned/hashed `PromptRegistry`, delimited `ContextWindow` builder, per-tenant approved-`ModelRouter` | **LLM07**, LLM03 | **ASI04** | — | ● |
| `aegis-intent` *(§11)* | Signed goal/intent envelope per execution cycle + goal-drift | — | **ASI01** | — | ● |
| `aegis-sandbox` *(§11)* | Isolated, non-root, ephemeral code-execution environment | — | **ASI05**, ASI10 | **AST06**, AST01 | ● |
| `aegis-killswitch` *(§11)* | Emergency revocation + quarantine + gated reintegration | — | **ASI04**, **ASI08**, **ASI10** | AST09 | ● |
| `aegis-honeypot` *(§11)* | Deception tripwires — decoy probes + planted canary tokens → quarantine | LLM02 (canary exfil detection, supporting) | **ASI05**, **ASI08**, ASI10 | AST01 | ●/◐ |

## `aegis-honeypot` — coverage detail

Added after the initial §11 crate set; a **detection-only** deception layer (deterministic
case-insensitive substring matching, no I/O, no policy decision of its own). The gate
(`aegis-extension`) orchestrates the response; the base containment (the sandbox/egress `Deny`) is
never weakened.

| Entry | Fully / Partially | How `aegis-honeypot` contributes |
|---|---|---|
| **ASI05** Unexpected Code Execution | ● / ◐ | **Decoys** (`match_exec`) — probe paths, the cloud metadata IP `169.254.169.254`, credential-file names, sentinel command markers — are matched at policy time (`/sandbox/validate`) *before* execution. Generated code that probes for an escape trips a **quarantine before it can act**, turning a blind RCE attempt into a high-confidence detection. |
| **ASI08** Cascading Failures | ● / ◐ | **Canaries** (`scan`) — unique tokens planted in the ephemeral working dir / memory. Their appearance in outbound content (a `/mediate` tool-call argument or an egress URL) proves exfiltration and trips an immediate quarantine — cutting a compromised agent out of the mesh *before* a leak or hijacked command cascades. |
| ASI10 Rogue Agents | ◐ (supports) | Interaction with any planted decoy/canary is a high-confidence signal that an agent has gone rogue; the tripwire drives quarantine + reintegration-on-attestation via `aegis-killswitch`. |
| LLM02 Sensitive Info Disclosure | ◐ (supports) | The canary chokepoint at `/mediate`/egress is a direct exfiltration tripwire, reinforcing the disclosure controls (`redact`, `egress`). |

**Escalation contract:** a hit is escalated at the *agent* level, not swallowed as a routine
`Deny` — an immutable `EntryKind::Tripwire` entry in `aegis-ledger` **+** agent quarantine via
`aegis-killswitch` (reintegration requires fresh attestation + a human). **Fail-safe:** an empty
`policies/honeypots.json` is inert (zero false positives until decoys/canaries are deliberately
configured); each project ships its own decoy/canary set plus a unique per-deployment runtime canary
(`AEGIS_CANARY`).

## Notes

- **Honesty tiers, not a scorecard.** A ● means the *consequence* is deterministically contained,
  not that the risk is eliminated — several entries remain ◐/○ because the underlying phenomenon
  (rogue-agent emergence, human persuasion, misinformation) is partly behavioral. See
  `architecture-considerations.md` §11.4 for the agentic residuals.
- **Cross-family double-duty.** Many ASI entries overlap the LLM list (e.g. ASI02↔LLM03/06,
  ASI05↔LLM05/01, ASI06↔LLM05/09), so a crate's LLM-side control often carries its agentic role too;
  the ASI column records only the agentic delta beyond the LLM mapping.
- **Source of truth.** The threat→crate matrices live in `architecture-considerations.md` (§3 for
  LLM, §11.3 for ASI, §12.2 for AST); the generated, test-enforced artifact is
  `docs/owasp-coverage-matrix.md`. This file is the hand-maintained inverse view; keep all consistent.
- **AST overlaps.** The Agentic Skills list reuses the artifact-integrity, isolation, and taint
  machinery that already serves LLM/ASI, but applied to the skill lifecycle — so a crate's AST codes
  are deliberately a separate column, not a copy of its LLM/ASI codes (see §12.1 for the per-item
  overlap callouts). `aegis-supply::verify_skill` (`SkillManifest`/`SkillContext`) is the new
  skill-lifecycle home that carries most AST entries.
