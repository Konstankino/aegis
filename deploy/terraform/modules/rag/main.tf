# RAG engine module — the vector store and its plumbing.
#
# A pgvector-capable PostgreSQL instance in the private subnets, reachable only from the app tier,
# with a KMS-encrypted credentials secret. The Aegis `RetrievalBackend` adapter (application layer)
# reads the outputs to connect. The embedding/ingestion pipeline (which runs documents through
# `aegis_retrieval::ingest` before upsert) is application code that also consumes these outputs.
#
# NOTE: pgvector is enabled per-database with `CREATE EXTENSION vector;` after the instance is up
# (run once by a migration / bootstrap step) — RDS ships the extension for supported versions.

terraform {
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.80" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

# Derive the VPC from the subnets, so callers pass only what aegis-shared already outputs.
data "aws_subnet" "first" {
  id = var.subnet_ids[0]
}

locals {
  vpc_id = data.aws_subnet.first.vpc_id
}

# ── Network: reachable only from the app tier, on 5432 ─────────────────────────────────────────────
resource "aws_security_group" "db" {
  name        = "${var.project_name}-rag-db"
  description = "Aegis RAG vector DB — ingress from the app tier only."
  vpc_id      = local.vpc_id
  tags        = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "from_app" {
  security_group_id            = aws_security_group.db.id
  description                  = "PostgreSQL from the Aegis agent app tier."
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.app_security_group_id
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.project_name}-rag"
  subnet_ids = var.subnet_ids
  tags       = var.tags
}

# ── Credentials: generated, stored KMS-encrypted in Secrets Manager (never in plaintext state use) ─
resource "random_password" "master" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "db" {
  name       = "${var.project_name}/rag/db-credentials"
  kms_key_id = var.kms_key_arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id = aws_secretsmanager_secret.db.id
  secret_string = jsonencode({
    username = var.master_username
    password = random_password.master.result
    dbname   = var.db_name
    host     = aws_db_instance.this.address
    port     = aws_db_instance.this.port
  })
}

# ── The vector database ───────────────────────────────────────────────────────────────────────────
resource "aws_db_instance" "this" {
  identifier     = "${var.project_name}-rag"
  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  db_name  = var.db_name
  username = var.master_username
  password = random_password.master.result

  allocated_storage = var.allocated_storage_gb
  storage_encrypted = true
  kms_key_id        = var.kms_key_arn

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false

  # Demo-friendly; harden for production (backups, deletion protection, multi-AZ).
  skip_final_snapshot = true
  apply_immediately   = true

  tags = var.tags
}
