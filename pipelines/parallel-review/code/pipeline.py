"""Parallel-review pipeline plugin — the pipeline-specific tool implementations.

Fan-out/fan-in: Agent A dispatches; Agents B and C improve the text concurrently; Agent D referees.
Like every pipeline, this file holds ONLY the transforms — schemas live in `../policies/tools.json`
and the per-principal profiles/handoffs in `../pipeline.json`. The parallelism itself is expressed in
`../asl/pipeline.asl.json` (a Step Functions `Parallel` state); the engine is unchanged — it just runs
one principal per invocation, and the terminal handoff produces that stage's output.

These are SCAFFOLD stubs: in production the model does the real grammar/improve/referee work and these
functions are the governed side effects. `dispatch.to_workers`, `submit.candidate` and `publish.final`
are terminal handoffs — the engine captures their args as the stage output.

Contract: `run_tool(fq_tool, args, agent_id, thread_id) -> dict | None` (None ⇒ not ours).
"""

GRAMMAR = "grammar.correct"
IMPROVE = "improve.text"
REFEREE = "referee.select"
HANDOFFS = ("dispatch.to_workers", "submit.candidate", "publish.final")


def run_tool(fq_tool, args, agent_id="", thread_id=""):
    if fq_tool == GRAMMAR:
        return {"corrected": args.get("text", "")}
    if fq_tool == IMPROVE:
        # Each writer produces its own improved version; a real impl would call the model.
        return {"improved": args.get("text", "")}
    if fq_tool == REFEREE:
        candidates = args.get("candidates") or []
        return {"selected": candidates[0] if candidates else "", "index": 0 if candidates else -1}
    if fq_tool in HANDOFFS:
        # Terminal handoff — the engine turns its args into the stage output; nothing else to do.
        return {"handoff": fq_tool, "ok": True}
    return None  # not ours -> the engine handles it (or fails closed)
