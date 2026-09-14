# 0014 — Layered infrastructure + separate RAG and Phoenix modules

- **Date:** 2026-09-14
- **Status:** Done (docs + Terraform scaffolding)
- **Type:** Infrastructure structure (Terraform + docs)

## What & why

The user asked to (1) keep the RAG infra in **separate templates**, (2) **layer** the infra properly
(network / application / …), and (3) add **Arize Phoenix** as the dashboard, also separately layered.

## Layering

- **[`docs/infrastructure-layers.md`](../docs/infrastructure-layers.md)** — defines the layers
  (L0 foundation · L1 network · L2 data · L3 application · L4 edge · L5 observability), the
  **downward-only** dependency rule, and how today's Terraform maps onto them. **Correction:** the repo
  already has a proper modular structure — `modules/aegis-shared` (L0/L1/L2, built once) +
  `modules/aegis-agent` (L3) composed by `stacks/single-agent` and `stacks/multi-agent`; the flat root
  is the Phase-0 demo. Both consumption modes are documented.

## Separate modules (peers, not layers)

- **`deploy/terraform/modules/rag/`** — the RAG *engine* Aegis governs (pgvector on RDS in the private
  subnets, KMS-encrypted, ingress from the app tier only, credentials in Secrets Manager). Consumes L1
  subnets + L0 KMS (derives the VPC from the subnets, so it takes only what `aegis-shared` outputs);
  exposes `db_endpoint` / `credentials_secret_arn` for the app layer. Optional/swappable.
- **`deploy/terraform/modules/phoenix/`** — **Arize Phoenix** as the L5 dashboard (Fargate behind an
  internal ALB on 6006 = UI + OTLP-over-HTTP; least-privilege SGs; optional persistence to the L2 traces
  Postgres). Exposes `otlp_endpoint` the extension points `OTEL_EXPORTER_OTLP_ENDPOINT` at. Swappable
  for Langfuse/Grafana.

## Wiring

- Both modules are toggled by **`enable_rag` / `enable_phoenix`** (default off; require `enable_vpc`).
- Wired into **both** consumption modes: the flat demo (`rag.tf` / `phoenix.tf`, root outputs +
  `terraform.tfvars.example`) and the layered **stacks** (a `module "rag"` / `module "phoenix"` block in
  each `stacks/*/main.tf`, sourcing `module.shared` outputs; toggles added to each stack's variables).
- The core guardrail plane never references either module; they are purely additive.

## Note / verification

Terraform is not installed in this environment, so `terraform validate` / `plan` were **not** run — the
HCL follows the existing files' conventions (provider `~> 5.80`, KMS, tags, count-gated optionals) and
each module's README says to validate before apply. Resource bodies are conventional; per-account
choices (engine version, instance class, image digest) are left as variables.
