# Arize Phoenix dashboard module — inputs.
#
# A SEPARATE, optional L5 (observability) module: runs Arize Phoenix as the trace/eval dashboard.
# Consumes the network (L1) and foundation (L0) layers and, optionally, the L2 traces Postgres for
# persistence. The core guardrail plane never references it; the extension just points its OTLP
# exporter at the endpoint this module outputs.

variable "project_name" {
  description = "Name prefix for all created resources (foundation layer)."
  type        = string
}

variable "tags" {
  description = "Common resource tags (foundation layer)."
  type        = map(string)
  default     = {}
}

# ── Network layer (L1) ──────────────────────────────────────────────────────────────────────────
# The VPC is derived from the subnets, so callers pass only what aegis-shared outputs.
variable "subnet_ids" {
  description = "Private subnet ids for the Fargate service and the internal load balancer (≥1)."
  type        = list(string)
}

variable "client_security_group_id" {
  description = "Security group allowed to send OTLP traces to Phoenix (the agent/extension app tier)."
  type        = string
}

variable "ui_ingress_cidrs" {
  description = "CIDRs allowed to reach the Phoenix UI through the internal LB (e.g. a VPN/bastion range)."
  type        = list(string)
  default     = []
}

# ── Foundation layer (L0) ───────────────────────────────────────────────────────────────────────
variable "kms_key_arn" {
  description = "Customer-managed KMS key ARN for the log group."
  type        = string
}

# ── Data layer (L2), optional ─────────────────────────────────────────────────────────────────────
variable "database_url_secret_arn" {
  description = <<-EOT
    Optional Secrets Manager ARN holding a `PHOENIX_SQL_DATABASE_URL` (a postgres:// URL) so Phoenix
    persists traces in the L2 traces Postgres. When empty, Phoenix uses ephemeral local storage
    (fine for a demo, not for production).
  EOT
  type        = string
  default     = ""
}

# ── Phoenix service config (module-local) ─────────────────────────────────────────────────────────
variable "image" {
  description = "The Arize Phoenix container image (pin a digest/tag in production)."
  type        = string
  default     = "arizephoenix/phoenix:latest"
}

variable "cpu" {
  description = "Fargate task CPU units."
  type        = number
  default     = 512
}

variable "memory" {
  description = "Fargate task memory (MiB)."
  type        = number
  default     = 1024
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the Phoenix service."
  type        = number
  default     = 14
}
