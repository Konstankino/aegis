//! The tool registry: the deterministic table that turns "what does this call touch?" into a
//! lookup instead of a question for the model.
//!
//! In the §4 pseudocode the broker asks `call.reaches_sensitive_data()`,
//! `call.has_external_effect()`, `call.consequence()`. Those are **not** judgments made by the
//! model — they are static properties declared for each tool when it is registered, and
//! validated arguments are checked against the tool's JSON schema. The registry is loaded from
//! a signed/versioned artifact (`policies/tools.json`), never assembled from model output.

use std::collections::HashMap;

use aegis_core::{AegisError, Consequence, Provenance};
use jsonschema::Validator;
use serde::{Deserialize, Serialize};

/// The static classification of a single tool, plus its argument schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    /// Fully-qualified tool name (used verbatim as the Cedar resource id).
    pub name: String,
    /// Optional pinned version (§11.1, ASI02). When a call pins a version, it must match this
    /// exactly; a call that pins a version against an unversioned tool is refused (fail-closed).
    #[serde(default)]
    pub version: Option<String>,
    /// Whether invoking this tool can reach private/regulated data (Rule-of-Two leg B).
    #[serde(default)]
    pub reaches_sensitive_data: bool,
    /// Whether this tool produces an external effect: state change or outbound comms (leg C).
    #[serde(default)]
    pub has_external_effect: bool,
    /// How reversible the tool's effect is (drives graduated enforcement).
    pub consequence: Consequence,
    /// JSON Schema (draft 2020-12 compatible) the tool's arguments must satisfy.
    pub schema: serde_json::Value,
}

/// A compiled tool spec: the spec plus its pre-built JSON-schema validator.
struct CompiledTool {
    spec: ToolSpec,
    validator: Validator,
}

/// The set of tools an agent is permitted to request, keyed by fully-qualified name.
///
/// Lookups fail closed: a call naming a tool not in the registry is rejected, never guessed.
pub struct ToolRegistry {
    tools: HashMap<String, CompiledTool>,
}

/// A request from the model to invoke a tool. The model's output is an untrusted **request**,
/// not a command (architecture-considerations.md §4/§8): it can only ever *ask*.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Fully-qualified name of the tool the model is asking to invoke.
    pub tool: String,
    /// Arguments the model produced. Untrusted until schema-validated.
    pub args: serde_json::Value,
    /// The trust level of the context that produced this call. If the session has ingested
    /// untrusted content, that taint is already tracked on the session; this field lets an
    /// individual call raise the untrusted leg as well.
    #[serde(default = "default_untrusted")]
    pub arg_provenance: Provenance,
    /// Optional version the caller pins for this tool (§11.1, ASI02). When set, the broker
    /// refuses the call unless the registered tool declares exactly this version.
    #[serde(default)]
    pub expected_version: Option<String>,
}

const fn default_untrusted() -> Provenance {
    // Model-authored tool arguments are untrusted by default — the safe assumption.
    Provenance::Untrusted
}

impl ToolCall {
    /// Construct a tool call with explicit argument provenance.
    pub fn new(
        tool: impl Into<String>,
        args: serde_json::Value,
        arg_provenance: Provenance,
    ) -> Self {
        Self {
            tool: tool.into(),
            args,
            arg_provenance,
            expected_version: None,
        }
    }

    /// Pin the tool version this call requires (§11.1, ASI02). Builder style.
    #[must_use]
    pub fn with_expected_version(mut self, version: impl Into<String>) -> Self {
        self.expected_version = Some(version.into());
        self
    }
}

impl ToolRegistry {
    /// Build a registry from a list of tool specs, compiling each schema once.
    pub fn new(specs: impl IntoIterator<Item = ToolSpec>) -> Result<Self, AegisError> {
        let mut tools = HashMap::new();
        for spec in specs {
            let validator = jsonschema::validator_for(&spec.schema).map_err(|e| {
                AegisError::Config(format!("invalid schema for tool '{}': {e}", spec.name))
            })?;
            tools.insert(spec.name.clone(), CompiledTool { spec, validator });
        }
        Ok(Self { tools })
    }

    /// Load a registry from `tools.json` content (a JSON array of [`ToolSpec`]).
    pub fn from_json(json: &str) -> Result<Self, AegisError> {
        let specs: Vec<ToolSpec> = serde_json::from_str(json)
            .map_err(|e| AegisError::Config(format!("cannot parse tool registry: {e}")))?;
        Self::new(specs)
    }

    /// Look up a tool's static spec, failing closed if it is unknown.
    pub fn spec(&self, tool: &str) -> Result<&ToolSpec, AegisError> {
        self.tools
            .get(tool)
            .map(|c| &c.spec)
            .ok_or_else(|| AegisError::UnknownTool(tool.to_string()))
    }

    /// Validate a call's arguments against the tool's declared schema. This is Aegis's own
    /// schema check in trusted code — never a second LLM call.
    pub fn schema_valid(&self, call: &ToolCall) -> Result<(), AegisError> {
        let compiled = self
            .tools
            .get(&call.tool)
            .ok_or_else(|| AegisError::UnknownTool(call.tool.clone()))?;
        if compiled.validator.is_valid(&call.args) {
            Ok(())
        } else {
            let detail = compiled
                .validator
                .iter_errors(&call.args)
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            Err(AegisError::SchemaViolation(format!(
                "{}: {detail}",
                call.tool
            )))
        }
    }

    /// Number of registered tools.
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tool_call_arg_provenance_defaults_to_untrusted() {
        // Deserialized without arg_provenance -> the safe default (exercises default_untrusted).
        let call: ToolCall = serde_json::from_value(json!({"tool": "t", "args": {}})).unwrap();
        assert_eq!(call.arg_provenance, Provenance::Untrusted);
    }

    #[test]
    fn from_json_rejects_malformed_json_and_invalid_schema() {
        assert!(ToolRegistry::from_json("not json").is_err());
        // A pattern that is not a valid regex fails to compile in ToolRegistry::new.
        let bad_schema = json!([{
            "name": "t", "consequence": "low_reversible",
            "schema": { "type": "string", "pattern": "(" }
        }])
        .to_string();
        assert!(ToolRegistry::from_json(&bad_schema).is_err());
    }

    #[test]
    fn empty_registry_len_is_empty_and_lookups_fail_closed() {
        let reg = ToolRegistry::new(std::iter::empty()).unwrap();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(reg.spec("nope").is_err());
        let call = ToolCall::new("nope", json!({}), Provenance::User);
        assert!(reg.schema_valid(&call).is_err());
    }
}
