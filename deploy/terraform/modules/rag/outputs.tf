# RAG engine module — outputs (the interface the application layer reads).
#
# Only what L3 (the agent function + its RetrievalBackend adapter and ingestion pipeline) needs to
# connect — nothing more.

output "db_endpoint" {
  description = "host:port of the vector DB, for the RetrievalBackend adapter."
  value       = "${aws_db_instance.this.address}:${aws_db_instance.this.port}"
}

output "db_name" {
  description = "The database holding the pgvector embeddings table."
  value       = aws_db_instance.this.db_name
}

output "credentials_secret_arn" {
  description = "Secrets Manager ARN holding the DB credentials (username/password/host/port/dbname)."
  value       = aws_secretsmanager_secret.db.arn
}

output "security_group_id" {
  description = "The DB security group id (ingress from the app tier only)."
  value       = aws_security_group.db.id
}
