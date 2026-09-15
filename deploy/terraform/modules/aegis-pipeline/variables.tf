# Generic, reusable per-PIPELINE module. Instantiated once per pipeline by a stack root. The heavy,
# shared infrastructure (extension layer, KMS key, policy S3 bucket, optional VPC) is created once by
# the root and passed in here; this module creates the per-pipeline agent + orchestration resources.
#
# A pipeline is a linear chain of Cedar principals over ONE agent function: Step Functions invokes it
# per stage with a different agent_id. Everything pipeline-specific lives in pipelines/<name>/
# (policies + pipeline.json manifest + code/pipeline.py + asl/pipeline.asl.json); nothing is baked
# into this module.

variable "project_name" {
  description = "Unique name for this pipeline's stack (prefixes all resources)."
  type        = string
}

variable "region" {
  description = "AWS region."
  type        = string
}

variable "pipeline_name" {
  description = "Human-readable pipeline name (tags only, e.g. \"editorial\")."
  type        = string
  default     = ""
}

variable "pipeline_dir" {
  description = "Path to this pipeline's directory (pipelines/<name>): holds pipeline.json and code/pipeline.py, staged into the agent bundle."
  type        = string
}

# ── Shared infrastructure passed in from the root ───────────────────────────────────────────────
variable "extension_layer_arn" {
  description = "ARN of the shared aegis-extension Lambda layer (built once, with s3+otel)."
  type        = string
}

variable "kms_key_arn" {
  description = "Shared customer-managed CMK ARN (encrypts tables, queues, logs, env)."
  type        = string
}

variable "policy_bucket" {
  description = "Shared S3 bucket that holds each project's policy artifacts under its own prefix."
  type        = string
}

variable "agent_source_dir" {
  description = "Path to deploy/terraform/agent-src (the shared Lambda source)."
  type        = string
}

variable "asl_dir" {
  description = "Path to this pipeline's asl/ directory (must contain pipeline.asl.json)."
  type        = string
}

variable "policy_dir" {
  description = "Path to this pipeline's policy artifacts (tools.json, broker.cedar, egress-allowlist.toml, meter.toml, pins.json, sandbox.toml, grants.toml, honeypots.json)."
  type        = string
}

# ── Behaviour ───────────────────────────────────────────────────────────────────────────────────
variable "model_id" {
  description = "Amazon Bedrock model id the agent calls (Converse API)."
  type        = string
  default     = "anthropic.claude-sonnet-4-5-20250929-v1:0"
}

variable "python_runtime" {
  type    = string
  default = "python3.12"
}

variable "architecture" {
  type    = string
  default = "arm64"
}

variable "auto_approve" {
  description = "Deploy an auto-approver Lambda so approvals resume automatically (demo)."
  type        = bool
  default     = true
}

variable "otel_collector_layer_arn" {
  description = <<-EOT
    ARN of an OpenTelemetry (ADOT) collector Lambda layer. When set, it is attached to the agent
    function, the extension is pointed at it (OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317),
    and the role is granted X-Ray + CloudWatch-metrics permissions. Empty = structured logs only.
  EOT
  type        = string
  default     = ""
}

variable "log_retention_days" {
  type    = number
  default = 14
}

# Optional VPC (no-default-route egress containment). Pass shared subnet/sg from the root.
variable "vpc_subnet_ids" {
  type    = list(string)
  default = []
}

variable "vpc_security_group_ids" {
  type    = list(string)
  default = []
}

# Dedicated deny-all-egress SG for the code runner (from the shared module). Falls back to the
# agent SG when empty. In-VPC only (harmless when enable_vpc = false).
variable "runner_security_group_ids" {
  type    = list(string)
  default = []
}

# ── Code runner (ASI05) ─────────────────────────────────────────────────────────────────────────
variable "enable_code_runner" {
  description = "Deploy the isolated code-runner Lambda and grant the agent lambda:InvokeFunction on it."
  type        = bool
  default     = true
}

variable "runner_timeout_seconds" {
  description = "Wall-clock ceiling for a single code execution."
  type        = number
  default     = 10
}

variable "runner_memory_mb" {
  description = "Memory for the runner (also caps the executed process)."
  type        = number
  default     = 512
}
