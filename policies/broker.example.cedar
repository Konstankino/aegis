// Aegis broker — example Cedar policy set (architecture-considerations.md §3 LLM03 / §4).
//
// Authorization is DEFAULT-DENY: a request is authorized only if a `permit` matches and no
// `forbid` overrides it. The broker (Rust) owns the Rule-of-Two human-approval path and the
// graduated-enforcement escalation AFTER this authorization step, so these policies express
// *least privilege* — which agent may reach which tool under which conditions — and leave the
// trifecta/consequence handling to code.
//
// Request shape built by aegis-broker::policy:
//   principal : Agent::"<agent_id>"
//   action    : Action::"invoke"
//   resource  : Tool::"<fully-qualified tool name>"
//   context   : { reads_untrusted, reads_sensitive, external_effect, call_reaches_sensitive,
//                 call_external_effect, is_trifecta, active_legs, consequence, arg_provenance }

// Baseline: an agent may request any registered tool. The registry already bounds which tools
// exist; capability and consequence gates are enforced deterministically by the broker.
permit (
    principal,
    action == Action::"invoke",
    resource
);

// Least privilege: only the dedicated `system` agent may rotate keys, regardless of session.
forbid (
    principal,
    action == Action::"invoke",
    resource == Tool::"admin.rotate_keys"
)
unless { principal == Agent::"system" };

// Defense in depth: a session that has ingested untrusted input may not invoke the raw shell
// at all — even before the Rule-of-Two human-approval path would apply.
forbid (
    principal,
    action == Action::"invoke",
    resource == Tool::"os.shell_exec"
)
when { context.reads_untrusted };

// A tool call whose own arguments are untrusted may not directly reach sensitive data: force
// the read to happen on a clean, non-attacker-controlled argument path.
forbid (
    principal,
    action == Action::"invoke",
    resource
)
when { context.arg_provenance == "untrusted" && context.call_reaches_sensitive };
