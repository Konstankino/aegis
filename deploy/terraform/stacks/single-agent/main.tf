# Single-agent stack: shared infra built once, then one single-agent module per project.

module "shared" {
  source                = "../../modules/aegis-shared"
  name_prefix           = "aegis-single"
  region                = var.region
  architecture          = var.architecture
  workspace_dir         = abspath("${path.module}/../../../..") # the aegis Cargo workspace root
  build_script          = abspath("${path.module}/../../build.sh")
  enable_vpc            = var.enable_vpc
  enable_otel_endpoints = var.enable_vpc && var.otel_collector_layer_arn != ""
}

module "agent" {
  source   = "../../modules/aegis-agent"
  for_each = var.projects

  project_name = each.key
  topology     = "single"
  region       = var.region
  architecture = var.architecture
  auto_approve = var.auto_approve
  model_id     = coalesce(each.value.model_id, var.default_model_id)

  # Shared infra.
  extension_layer_arn = module.shared.extension_layer_arn
  kms_key_arn         = module.shared.kms_key_arn
  policy_bucket       = module.shared.policy_bucket

  # Shared source + this project's policies.
  agent_source_dir = abspath("${path.module}/../../agent-src")
  asl_dir          = abspath("${path.module}/../../asl")
  policy_dir       = each.value.policy_dir

  # Optional shared VPC + OTel.
  vpc_subnet_ids            = module.shared.vpc_subnet_ids
  vpc_security_group_ids    = module.shared.lambda_security_group_ids
  runner_security_group_ids = module.shared.runner_security_group_ids
  otel_collector_layer_arn  = var.otel_collector_layer_arn
}
