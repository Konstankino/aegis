# Arize Phoenix dashboard module (separate, optional — L5 observability)

Runs [Arize Phoenix](https://github.com/Arize-ai/phoenix) as the trace/eval dashboard for the plane —
kept in its own module so it can be omitted, replaced (Langfuse/Grafana), or pointed at a client's
existing observability stack without touching the core.

## Layer contract

- **Consumes** — L1 network (`vpc_id`, `subnet_ids`, `client_security_group_id`, `ui_ingress_cidrs`),
  L0 foundation (`kms_key_arn`, `project_name`, `tags`), and **optionally** L2 data
  (`database_url_secret_arn` — the traces Postgres, for persistence).
- **Exposes** — `endpoint` / `otlp_endpoint` (the internal URL) for the application layer.
- **Never** references the core plane. The extension just sets `OTEL_EXPORTER_OTLP_ENDPOINT` to the
  `otlp_endpoint`. Toggle with `var.enable_phoenix` (default off) in the root.

## What it creates

An internal Fargate service behind an internal ALB on port 6006 (UI **and** OTLP-over-HTTP), with a
CloudWatch log group and least-privilege security groups (OTLP from the app tier; UI from
`ui_ingress_cidrs` only). Optionally persists traces to the L2 Postgres.

## Wiring it up

1. `enable_phoenix = true` (requires `enable_vpc = true`).
2. Point the extension at it: `OTEL_EXPORTER_OTLP_ENDPOINT = module.phoenix.otlp_endpoint`.
3. For durable traces, pass `database_url_secret_arn` (a `postgres://…` URL in Secrets Manager on the
   L2 traces DB). Otherwise Phoenix uses ephemeral storage (demo only).
4. Reach the UI over the VPN/bastion whose CIDR is in `ui_ingress_cidrs` (the LB is internal by design).

## Swap instead of deploy

Prefer Langfuse or Grafana? Omit this module and deploy that stack against the same OTLP export /
traces DB — the security plane is unchanged.

> Conventional resources; pin the image digest and run `terraform validate` + `plan` before apply.
