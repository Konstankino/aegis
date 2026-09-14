# Arize Phoenix dashboard — a SEPARATE, optional module at the observability layer (L5). Off by
# default; toggle with `enable_phoenix`. See modules/phoenix/ and docs/infrastructure-layers.md.
#
# Consumes network (L1) + foundation (L0) and exposes an OTLP endpoint the extension points its OTEL
# exporter at. Kept a module so it can be swapped for Langfuse/Grafana without touching the core.

module "phoenix" {
  count  = var.enable_phoenix ? 1 : 0
  source = "./modules/phoenix"

  project_name             = var.project_name
  tags                     = local.tags
  subnet_ids               = aws_subnet.private[*].id
  client_security_group_id = one(aws_security_group.lambda[*].id)
  ui_ingress_cidrs         = var.phoenix_ui_cidrs
  kms_key_arn              = aws_kms_key.cmk.arn
  # Optional durable persistence to the L2 traces Postgres — wire once that store exists:
  # database_url_secret_arn = module.rag[0].credentials_secret_arn  # or a dedicated traces DB
}

# Phoenix runs in the private subnets, so it needs the network layer.
check "phoenix_requires_vpc" {
  assert {
    condition     = !var.enable_phoenix || var.enable_vpc
    error_message = "enable_phoenix requires enable_vpc = true (Phoenix runs in the private subnets)."
  }
}
