// Parallel-review pipeline — least-privilege per-agent tool authorization (ASI02/ASI03/ASI07).
//
// Default-deny: an agent may invoke ONLY the tools permitted below. A fan-out/fan-in topology:
//
//              ┌─▶ Agent B ─submit.candidate─┐
//   Agent A ───┤                             ├──▶ Agent D ─publish.final─▶ out
//   dispatch   └─▶ Agent C ─submit.candidate─┘   referee
//
// Agents B and C are PEER principals: identical permissions (improve.text + submit.candidate), run
// concurrently, and cannot reach each other or the referee's tools. The referee (D) is the only
// principal that may publish.

// ── Agent A — intake: light grammar, then dispatch to the parallel workers. ──────────────────────
permit ( principal == Agent::"agent-a", action == Action::"invoke", resource == Tool::"grammar.correct" );
permit ( principal == Agent::"agent-a", action == Action::"invoke", resource == Tool::"dispatch.to_workers" );

// ── Agent B — writer (peer): improve the text, then submit its candidate. ────────────────────────
permit ( principal == Agent::"agent-b", action == Action::"invoke", resource == Tool::"improve.text" );
permit ( principal == Agent::"agent-b", action == Action::"invoke", resource == Tool::"submit.candidate" );

// ── Agent C — writer (peer): improve the text, then submit its candidate. ────────────────────────
permit ( principal == Agent::"agent-c", action == Action::"invoke", resource == Tool::"improve.text" );
permit ( principal == Agent::"agent-c", action == Action::"invoke", resource == Tool::"submit.candidate" );

// ── Agent D — referee: choose the best candidate and publish the final text. ─────────────────────
permit ( principal == Agent::"agent-d", action == Action::"invoke", resource == Tool::"referee.select" );
permit ( principal == Agent::"agent-d", action == Action::"invoke", resource == Tool::"publish.final" );
