// Editorial pipeline — least-privilege per-agent tool authorization (ASI02/ASI03/ASI07).
//
// Default-deny: an agent may invoke ONLY the tools permitted below. Everything else — a wrong-lane
// call (Agent A invoking the referee), a skipped step (Agent A sending straight to C), or an unknown
// agent — is refused by the broker deterministically, before any effect.
//
// The chain is enforced by which HANDOFF tool each agent may call:
//   A ──send.to_agent_b──▶ B ──send.to_agent_c──▶ C ──publish.final──▶ out

// ── Agent A — grammar: correct the text, then hand off to Agent B. ────────────────────────────────
permit ( principal == Agent::"agent-a", action == Action::"invoke", resource == Tool::"grammar.correct" );
permit ( principal == Agent::"agent-a", action == Action::"invoke", resource == Tool::"send.to_agent_b" );

// ── Agent B — enrichment: add interesting, sound facts, then hand off to Agent C. ─────────────────
permit ( principal == Agent::"agent-b", action == Action::"invoke", resource == Tool::"enrich.add_facts" );
permit ( principal == Agent::"agent-b", action == Action::"invoke", resource == Tool::"send.to_agent_c" );

// ── Agent C — referee: choose the best version and publish the final text. ────────────────────────
permit ( principal == Agent::"agent-c", action == Action::"invoke", resource == Tool::"referee.select" );
permit ( principal == Agent::"agent-c", action == Action::"invoke", resource == Tool::"publish.final" );
