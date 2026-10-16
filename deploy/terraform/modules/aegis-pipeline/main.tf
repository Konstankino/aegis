data "aws_caller_identity" "current" {}

locals {
  name          = var.project_name
  in_vpc        = length(var.vpc_subnet_ids) > 0
  policy_prefix = var.project_name
  agent_name    = "${var.project_name}-agent"
  # The isolated code-runner (ASI05), one per project.
  runner_name = "${var.project_name}-runner"
  # The runner's SG: its own deny-all group when provided, else the shared agent SG.
  runner_sg = length(var.runner_security_group_ids) > 0 ? var.runner_security_group_ids : var.vpc_security_group_ids

  # The policy set for this pipeline (pipelines/<name>/policies). All artifacts the extension may
  # load are uploaded to the shared bucket under this pipeline's prefix and fetched at cold start.
  policy_files = {
    "tools.json"            = "${var.policy_dir}/tools.json"
    "broker.cedar"          = "${var.policy_dir}/broker.cedar"
    "egress-allowlist.toml" = "${var.policy_dir}/egress-allowlist.toml"
    "meter.toml"            = "${var.policy_dir}/meter.toml"
    "pins.json"             = "${var.policy_dir}/pins.json"
    "sandbox.toml"          = "${var.policy_dir}/sandbox.toml"
    # NOTE: grants.toml is uploaded separately (see jit.tf) so its role/resource ARNs can be rendered
    # from the per-grant IAM role at deploy time (or emptied to default-deny when the feature is off).
    # Per-pipeline honeypot decoys/canaries (ASI05/ASI08). Fetched from S3 at cold start so each
    # pipeline has its own set; the layer-baked honeypots.json is the shared fallback.
    "honeypots.json" = "${var.policy_dir}/honeypots.json"
  }

  # The Lambda bundle staged into the agent zip: the generic engine + this pipeline's DATA
  # (tools.json schemas + pipeline.json manifest) + its tool implementations (code/pipeline.py).
  # The engine builds the model's tool registry from tools.json — nothing is hard-coded in Python.
  agent_bundle = {
    "agent.py"      = "${var.agent_source_dir}/agent/agent.py"
    "tools.json"    = "${var.policy_dir}/tools.json"
    "pipeline.json" = "${var.pipeline_dir}/pipeline.json"
    "pipeline.py"   = "${var.pipeline_dir}/code/pipeline.py"
  }

  tags = {
    Project   = var.project_name
    ManagedBy = "terraform"
    Component = "aegis-pipeline"
    Pipeline  = var.pipeline_name
  }
}

# ── Lambda packages ─────────────────────────────────────────────────────────────────────────────
# The agent zip = generic engine + this pipeline's bundle files, assembled from their source
# locations (no build step; agent.py is stdlib + boto3 only).
data "archive_file" "agent" {
  type        = "zip"
  output_path = "${path.module}/build/${var.project_name}-agent.zip"

  dynamic "source" {
    for_each = local.agent_bundle
    content {
      content  = file(source.value)
      filename = source.key
    }
  }
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

# ── State machine definition ────────────────────────────────────────────────────────────────────
# Each pipeline ships its own linear state machine (pipelines/<name>/asl/pipeline.asl.json). Every
# stage invokes the SAME agent function with a different agent_id (the Cedar principal).
locals {
  asl_definition = templatefile("${var.asl_dir}/pipeline.asl.json", {
    agent_lambda_arn = aws_lambda_function.agent.arn
  })
}
