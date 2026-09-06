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

# Each project gets its own single-agent stack (Lambda + SFN + API + tables + policies).
# key = project name; value.policy_dir = path to that project's policy artifacts.
variable "projects" {
  type = map(object({
    policy_dir = string
    model_id   = optional(string)
  }))
}
