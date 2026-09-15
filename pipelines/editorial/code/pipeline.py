"""Editorial pipeline plugin — the pipeline-specific tool implementations.

The generic engine ([deploy/terraform/agent-src/agent/agent.py]) discovers this module in the Lambda
bundle and calls `run_tool` for every tool the broker allows. It contains **no tool schemas or profile
data** — those are data: schemas live in `../policies/tools.json`, and which principal sees which tool
(plus prompts and the terminal handoff) lives in `../pipeline.json`. This file is only the transforms.

These are SCAFFOLD stubs: in production the model does the actual grammar/enrichment/referee work and
these functions are the governed side effects (e.g. `enrich.add_facts` would call the
egress-allowlisted facts service). The handoff tools (`send.to_agent_b` / `send.to_agent_c` /
`publish.final`) are *terminal*: the engine captures their args as the stage output, so here they need
only be ledgered.

Contract: `run_tool(fq_tool, args, agent_id, thread_id) -> dict | None`. Return a dict to handle the
tool; return `None` for anything this pipeline does not own, so the engine's platform tools
(web.fetch / code.run / log.write) still apply.
"""

# The fully-qualified tool names this pipeline implements (must match ../policies/tools.json).
GRAMMAR = "grammar.correct"
ENRICH = "enrich.add_facts"
REFEREE = "referee.select"
HANDOFFS = ("send.to_agent_b", "send.to_agent_c", "publish.final")


def run_tool(fq_tool, args, agent_id="", thread_id=""):
    if fq_tool == GRAMMAR:
        return {"corrected": args.get("text", "")}
    if fq_tool == ENRICH:
        # External effect (leg C): in production this calls the egress-allowlisted facts service.
        return {"enriched": args.get("text", ""), "facts_added": 0, "note": "stub — call the facts service"}
    if fq_tool == REFEREE:
        candidates = args.get("candidates") or []
        return {"selected": candidates[0] if candidates else "", "index": 0 if candidates else -1}
    if fq_tool in HANDOFFS:
        # Terminal handoff — the engine turns its args into the stage output; nothing else to do.
        return {"handoff": fq_tool, "ok": True}
    return None  # not ours -> the engine handles it (or fails closed)
