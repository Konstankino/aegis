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

# ── Entry points ──────────────────────────────────────────────────────────────────────────────────
# The synchronous HTTP front door (API Gateway: POST /chat, GET /status → start Lambda). Optional so a
# pipeline can be made event-driven only (e.g. the editorial pipeline is S3-ingestion-only). When off,
# no API Gateway, start Lambda, or its IAM role are created; the pipeline is triggered only by whatever
# other entry it defines (e.g. the S3 file-drop EventBridge rule).
variable "enable_http_entry" {
  description = "Create the HTTP API front door (POST /chat, GET /status). Set false for an event-driven-only pipeline."
  type        = bool
  default     = true
}

# ── S3 file-drop ingestion (optional) ────────────────────────────────────────────────────────────
# When source_bucket is set, an EventBridge rule fires on every *.txt dropped under source_prefix and
# starts an execution; the agent-ingest principal then reads that object with a SHORT-LIVED,
# object-scoped credential minted by the JIT broker (never a standing role). Empty = feature off, no
# EventBridge/JIT resources are created and existing deployments are unchanged.
variable "source_bucket" {
  description = "Name of an EXISTING S3 bucket to watch for dropped *.txt files. Empty disables the feature."
  type        = string
  default     = ""
}

variable "source_prefix" {
  description = "Key prefix under source_bucket to watch and to scope the JIT read credential to (least-privilege)."
  type        = string
  default     = "incoming/"
}

variable "source_kms_key_arn" {
  description = "CMK ARN that encrypts objects in source_bucket, if any. Empty = SSE-S3 (no extra kms:Decrypt granted)."
  type        = string
  default     = ""
}

variable "manage_source_bucket_notifications" {
  description = "When true, this module enables EventBridge notifications on source_bucket. Set false if the bucket's notification config is managed elsewhere (it must already have EventBridge enabled)."
  type        = bool
  default     = true
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
