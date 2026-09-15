# Pipeline stack: shared infra built once, then one aegis-pipeline module per pipeline.
#
# This stack is generic. To deploy another pipeline, add an entry to `var.pipelines` pointing at its
# pipelines/<name>/ directory — no change to any module or shared code. By default it deploys the
# editorial pipeline (pipelines/editorial).

locals {
  # Default to the editorial pipeline when no pipelines are supplied (variable defaults cannot use
  # path.module, so the fallback is expressed here).
  pipelines = length(var.pipelines) > 0 ? var.pipelines : {
    editorial = {
      pipeline_dir  = abspath("${path.module}/../../../../pipelines/editorial")
      pipeline_name = "editorial"
      model_id      = null
    }
  }
}

module "shared" {
  source                = "../../modules/aegis-shared"
  name_prefix           = "aegis-pipe"
  region                = var.region
  architecture          = var.architecture
  workspace_dir         = abspath("${path.module}/../../../..") # the aegis Cargo workspace root
  build_script          = abspath("${path.module}/../../build.sh")
  enable_vpc            = var.enable_vpc
  enable_otel_endpoints = var.enable_vpc && var.otel_collector_layer_arn != ""
}

module "pipeline" {
  source   = "../../modules/aegis-pipeline"
  for_each = local.pipelines

  project_name  = each.key
  pipeline_name = coalesce(each.value.pipeline_name, each.key)
  region        = var.region
  architecture  = var.architecture
  auto_approve  = var.auto_approve
  model_id      = coalesce(each.value.model_id, var.default_model_id)

  # Shared infra.
  extension_layer_arn = module.shared.extension_layer_arn
  kms_key_arn         = module.shared.kms_key_arn
  policy_bucket       = module.shared.policy_bucket

  # Shared engine source + this pipeline's own directory (policies + manifest + code + asl).
  agent_source_dir = abspath("${path.module}/../../agent-src")
  pipeline_dir     = each.value.pipeline_dir
  asl_dir          = "${each.value.pipeline_dir}/asl"
  policy_dir       = "${each.value.pipeline_dir}/policies"

  # Optional shared VPC + OTel.
  vpc_subnet_ids            = module.shared.vpc_subnet_ids
  vpc_security_group_ids    = module.shared.lambda_security_group_ids
  runner_security_group_ids = module.shared.runner_security_group_ids
  otel_collector_layer_arn  = var.otel_collector_layer_arn
}

# ── Optional, separate modules (properly layered — see docs/infrastructure-layers.md) ──────────────
# The RAG engine Aegis governs, and the Arize Phoenix dashboard. Both consume the shared network + KMS
# outputs, are toggled off by default, and require enable_vpc = true.
module "rag" {
  count  = var.enable_rag ? 1 : 0
  source = "../../modules/rag"

  project_name          = "aegis-pipe"
  subnet_ids            = module.shared.vpc_subnet_ids
  app_security_group_id = one(module.shared.lambda_security_group_ids)
  kms_key_arn           = module.shared.kms_key_arn
}

module "phoenix" {
  count  = var.enable_phoenix ? 1 : 0
  source = "../../modules/phoenix"

  project_name             = "aegis-pipe"
  subnet_ids               = module.shared.vpc_subnet_ids
  client_security_group_id = one(module.shared.lambda_security_group_ids)
  ui_ingress_cidrs         = var.phoenix_ui_cidrs
  kms_key_arn              = module.shared.kms_key_arn
}
