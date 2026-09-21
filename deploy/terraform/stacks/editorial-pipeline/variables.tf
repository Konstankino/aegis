variable "region" {
  type    = string
  default = "us-east-1"
}

variable "architecture" {
  type    = string
  default = "arm64"
}

variable "auto_approve" {
  type    = bool
  default = true
}

variable "default_model_id" {
  type    = string
  default = "anthropic.claude-sonnet-4-5-20250929-v1:0"
}

variable "enable_vpc" {
  description = "Run agents in a shared no-default-route VPC (S3/DynamoDB/Bedrock endpoints)."
  type        = bool
  default     = false
}

variable "otel_collector_layer_arn" {
  description = "ADOT collector layer ARN to export traces/metrics; empty = structured logs only."
  type        = string
  default     = ""
}

# Pipelines to deploy. key = stack/project name (prefixes resources); value.pipeline_dir = path to
# that pipeline's directory (pipelines/<name>). Leave empty to deploy the built-in editorial pipeline.
variable "pipelines" {
  type = map(object({
    pipeline_dir  = string
    pipeline_name = optional(string)
    model_id      = optional(string)
    # HTTP front door (POST /chat, GET /status). Default on; set false for an event-driven-only
    # pipeline (the editorial pipeline is S3-ingestion-only and defaults this off below).
    enable_http_entry = optional(bool, true)
    # Optional S3 file-drop ingestion: watch an existing bucket for *.txt and read each with a
    # short-lived, object-scoped JIT credential. Omit source_bucket to leave the feature off.
    source_bucket                      = optional(string, "")
    source_prefix                      = optional(string, "incoming/")
    source_kms_key_arn                 = optional(string, "")
    manage_source_bucket_notifications = optional(bool, true)
  }))
  default = {}
}

variable "enable_rag" {
  description = "Deploy the separate RAG engine module (modules/rag). Requires enable_vpc = true."
  type        = bool
  default     = false
}

variable "enable_phoenix" {
  description = "Deploy the separate Arize Phoenix dashboard module (modules/phoenix). Requires enable_vpc = true."
  type        = bool
  default     = false
}

variable "phoenix_ui_cidrs" {
  description = "CIDRs allowed to reach the internal Phoenix UI (used only when enable_phoenix = true)."
  type        = list(string)
  default     = []
}
