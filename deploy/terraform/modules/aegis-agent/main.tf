data "aws_caller_identity" "current" {}

locals {
  name          = var.project_name
  is_multi      = var.topology == "multi"
  in_vpc        = length(var.vpc_subnet_ids) > 0
  policy_prefix = var.project_name
  # The agent function serves as the single agent, or as the worker in the multi topology.
  agent_name = local.is_multi ? "${var.project_name}-worker" : "${var.project_name}-agent"
  # The isolated code-runner (ASI05), one per project.
  runner_name = "${var.project_name}-runner"
  # The runner's SG: its own deny-all group when provided, else the shared agent SG.
  runner_sg = length(var.runner_security_group_ids) > 0 ? var.runner_security_group_ids : var.vpc_security_group_ids

  # Policy artifacts uploaded to the shared bucket under this project's prefix; the extension
  # fetches them at cold start (AEGIS_POLICY_S3_PREFIX).
  policy_files = {
    "tools.json"            = "${var.policy_dir}/tools.json"
    "broker.cedar"          = "${var.policy_dir}/broker.cedar"
    "egress-allowlist.toml" = "${var.policy_dir}/egress-allowlist.toml"
    "meter.toml"            = "${var.policy_dir}/meter.toml"
    "pins.json"             = "${var.policy_dir}/pins.json"
    # Per-project honeypot decoys/canaries (ASI05/ASI08). Fetched from S3 at cold start so each
    # project has its own set; the layer-baked honeypots.json is the shared fallback.
    "honeypots.json" = "${var.policy_dir}/honeypots.json"
  }

  tags = {
    Project   = var.project_name
    ManagedBy = "terraform"
    Component = "aegis-agent"
    Topology  = var.topology
  }
}

# ── Lambda packages (shared source, packaged per project) ──────────────────────────────────────
data "archive_file" "agent" {
  type        = "zip"
  source_dir  = "${var.agent_source_dir}/agent"
  output_path = "${path.module}/build/${var.project_name}-agent.zip"
}

data "archive_file" "supervisor" {
  count       = local.is_multi ? 1 : 0
  type        = "zip"
  source_dir  = "${var.agent_source_dir}/supervisor"
  output_path = "${path.module}/build/${var.project_name}-supervisor.zip"
}

data "archive_file" "start" {
  type        = "zip"
  source_dir  = "${var.agent_source_dir}/start"
  output_path = "${path.module}/build/${var.project_name}-start.zip"
}

data "archive_file" "runner" {
  count       = var.enable_code_runner ? 1 : 0
  type        = "zip"
  source_dir  = "${var.agent_source_dir}/runner"
  output_path = "${path.module}/build/${var.project_name}-runner.zip"
}

data "archive_file" "approver" {
  count       = var.auto_approve ? 1 : 0
  type        = "zip"
  source_dir  = "${var.agent_source_dir}/approver"
  output_path = "${path.module}/build/${var.project_name}-approver.zip"
}

# ── Per-project policy artifacts in the shared bucket ──────────────────────────────────────────
resource "aws_s3_object" "policy" {
  for_each = local.policy_files
  bucket   = var.policy_bucket
  key      = "${local.policy_prefix}/${each.key}"
  source   = each.value
  etag     = filemd5(each.value)
  tags     = local.tags
}

# ── State machine definition (topology-specific) ───────────────────────────────────────────────
locals {
  asl_definition = local.is_multi ? templatefile("${var.asl_dir}/multi_agent.asl.json", {
    supervisor_lambda_arn = aws_lambda_function.supervisor[0].arn
    worker_lambda_arn     = aws_lambda_function.agent.arn
    approval_queue_url    = aws_sqs_queue.approval.url
    }) : templatefile("${var.asl_dir}/single_agent.asl.json", {
    agent_lambda_arn   = aws_lambda_function.agent.arn
    approval_queue_url = aws_sqs_queue.approval.url
  })
}
