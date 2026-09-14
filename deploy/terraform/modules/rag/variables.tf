# RAG engine module — inputs.
#
# A SEPARATE, optional module: the vector store + its network/secret plumbing that the Aegis
# `RetrievalBackend` adapter connects to. Consumes the network (L1) and foundation (L0) layers and
# exposes an endpoint + secret the application layer (L3) reads. The core guardrail plane never
# references this module.

variable "project_name" {
  description = "Name prefix for all created resources (from the foundation layer)."
  type        = string
}

variable "tags" {
  description = "Common resource tags (from the foundation layer)."
  type        = map(string)
  default     = {}
}

# ── Network layer (L1) ──────────────────────────────────────────────────────────────────────────
# The VPC is derived from the subnets, so callers pass only what aegis-shared outputs.
variable "subnet_ids" {
  description = "Private subnet ids for the DB subnet group (no default route). Requires ≥1 subnet."
  type        = list(string)
}

variable "app_security_group_id" {
  description = "The security group of the app tier (agent Lambda) allowed to reach the DB on 5432."
  type        = string
}

# ── Foundation layer (L0) ───────────────────────────────────────────────────────────────────────
variable "kms_key_arn" {
  description = "Customer-managed KMS key ARN for encrypting the DB storage and the credentials secret."
  type        = string
}

# ── RAG sizing / config (module-local) ──────────────────────────────────────────────────────────
variable "engine_version" {
  description = "PostgreSQL engine version. Must support the pgvector extension (>= 15 recommended)."
  type        = string
  default     = "16.4"
}

variable "instance_class" {
  description = "RDS instance class for the vector DB."
  type        = string
  default     = "db.t4g.medium"
}

variable "allocated_storage_gb" {
  description = "Initial storage (GB) for the vector DB."
  type        = number
  default     = 50
}

variable "db_name" {
  description = "The database name that holds the embeddings (pgvector) table."
  type        = string
  default     = "aegis_rag"
}

variable "master_username" {
  description = "Master username for the vector DB."
  type        = string
  default     = "aegis"
}
