# ── Code runner (ASI05): a separate, locked-down function for agent-generated code. ─────────────
# The agent NEVER executes model-authored code in-process. On an `allow` from the Aegis
# /sandbox/validate gate it invokes THIS function, which is a bare executor:
#   * its own minimal role — CloudWatch Logs only (no Bedrock, S3, DynamoDB, KMS, or ledger);
#   * no network — in the no-default-route VPC behind the deny-all runner SG, so a breakout
#     reaches nothing (requires enable_vpc = true on the stack);
#   * /tmp as the only writable, ephemeral working dir, plus per-process rlimits in the handler;
#   * a short timeout.
# Lambda is itself a Firecracker microVM, so that microVM boundary is the "container" here.

# Honeypot canary (§11, ASI08): a unique per-project DECOY token — NOT a real credential. The runner
# plants it as a decoy ~/.aws/credentials in the ephemeral working dir; the agent's gate (tool args)
# and egress allowlist (outbound URLs) are given the same value, so exfiltrating it trips a tripwire
# (immutable ledger entry + agent quarantine). Being a decoy, it needs no KMS protection.
resource "random_id" "canary" {
  byte_length = 18
}

locals {
  canary_token = "aegis-canary-${random_id.canary.hex}"
}

resource "aws_cloudwatch_log_group" "runner" {
  count             = var.enable_code_runner ? 1 : 0
  name              = "/aws/lambda/${local.runner_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = local.tags
}

resource "aws_lambda_function" "runner" {
  count         = var.enable_code_runner ? 1 : 0
  function_name = local.runner_name
  role          = aws_iam_role.runner[0].arn
  runtime       = var.python_runtime
  handler       = "runner.handler"
  architectures = [var.architecture]

  filename         = data.archive_file.runner[0].output_path
  source_code_hash = data.archive_file.runner[0].output_base64sha256

  timeout     = var.runner_timeout_seconds
  memory_size = var.runner_memory_mb

  # Deliberately NO layers, NO CMK env encryption, and NO policy/S3/DDB/Bedrock env vars: this is a
  # bare executor. Its context holds nothing sensitive, so it needs no KMS grant.
  environment {
    variables = {
      AEGIS_SANDBOX_DIR        = "/tmp/aegis-sandbox"
      AEGIS_SANDBOX_TIMEOUT_MS = tostring(var.runner_timeout_seconds * 1000 - 1000)
      # Planted as a decoy credential file; the executed child runs with a stripped env and cannot
      # read this var directly — only by reading the planted file (the exfiltration we detect).
      AEGIS_CANARY = local.canary_token
    }
  }

  dynamic "vpc_config" {
    for_each = local.in_vpc ? [1] : []
    content {
      subnet_ids         = var.vpc_subnet_ids
      security_group_ids = local.runner_sg
    }
  }

  tags       = local.tags
  depends_on = [aws_cloudwatch_log_group.runner, aws_iam_role_policy.runner]
}
