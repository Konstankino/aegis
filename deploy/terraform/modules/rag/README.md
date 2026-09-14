# RAG engine module (separate, optional)

The RAG **engine** Aegis governs — deliberately kept out of the core guardrail plane. Aegis provides
the security guards (`aegis-retrieval`) and the `RetrievalBackend` seam; this module provisions the
vector store the adapter connects to.

## Layer contract

- **Consumes** — L1 network (`vpc_id`, `subnet_ids`, `app_security_group_id`), L0 foundation
  (`kms_key_arn`, `project_name`, `tags`).
- **Exposes** — `db_endpoint`, `db_name`, `credentials_secret_arn`, `security_group_id` for the
  application layer.
- **Never** references the core plane; the core never hard-references it. Toggle with
  `var.enable_rag` (default off) in the root.

## What it creates

A pgvector-capable PostgreSQL instance in the private subnets, reachable **only** from the app tier on
5432, KMS-encrypted, with generated credentials in Secrets Manager.

## Wiring it up

1. `enable_rag = true` (requires `enable_vpc = true`).
2. After apply, enable the extension once: `CREATE EXTENSION IF NOT EXISTS vector;` and create the
   embeddings table (namespace, tier, `embedding_version`, embedding vector, text).
3. Point the agent function at `credentials_secret_arn`; implement a `RetrievalBackend` that runs the
   pgvector similarity query, and run ingested documents through `aegis_retrieval::ingest` before upsert.

## Swap instead of deploy

A client with an existing vector store skips this module entirely and points the `RetrievalBackend`
adapter at their store — the security plane is unchanged.

> Conventional resources; set engine version / instance class per account and run `terraform validate`
> + `plan` before apply. Harden for production (backups, deletion protection, multi-AZ).
