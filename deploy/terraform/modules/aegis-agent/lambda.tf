# ── Agent (single) / worker (multi): hosts the Aegis extension layer + the turn engine. ────────
resource "aws_cloudwatch_log_group" "agent" {
  name              = "/aws/lambda/${local.agent_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = local.tags
}

resource "aws_lambda_function" "agent" {
  function_name = local.agent_name
  role          = aws_iam_role.agent.arn
  runtime       = var.python_runtime
  handler       = "agent.handler"
  architectures = [var.architecture]

  filename         = data.archive_file.agent.output_path
  source_code_hash = data.archive_file.agent.output_base64sha256

  # The shared aegis-extension layer serves the inline-plane gate on loopback; the OTel collector
  # layer is attached alongside it when configured.
  layers = concat(
    [var.extension_layer_arn],
    var.otel_collector_layer_arn != "" ? [var.otel_collector_layer_arn] : [],
  )
  timeout     = 60
  memory_size = 512
  kms_key_arn = var.kms_key_arn

  environment {
    variables = merge(
      {
        MODEL_ID               = var.model_id
        AEGIS_AGENT_ID         = local.agent_name
        AEGIS_CHECKPOINT_TABLE = aws_dynamodb_table.checkpoints.name
        AEGIS_LEDGER_BUCKET    = aws_s3_bucket.ledger.id
        # Honeypot canary (ASI08): the gate detects this token in tool args / outbound URLs. Same
        # value the runner plants as a decoy credential file, so exfiltrating it trips a tripwire.
        AEGIS_CANARY    = local.canary_token
        AEGIS_GATE_ADDR = "127.0.0.1:8080"
        AEGIS_POLICY_S3_BUCKET = var.policy_bucket
        AEGIS_POLICY_S3_PREFIX = local.policy_prefix
        AEGIS_POLICY_DIR       = "/opt/policies"
        OTEL_SERVICE_NAME      = var.project_name
        RUST_LOG               = "aegis_extension=info,aegis=info"
      },
      # The isolated code runner, when enabled: the agent invokes it after /sandbox/validate allows.
      var.enable_code_runner ? {
        AEGIS_RUNNER_FUNCTION = aws_lambda_function.runner[0].function_name
      } : {},
      # Only export OTLP when a collector layer is attached; otherwise the extension logs only.
      var.otel_collector_layer_arn != "" ? {
        OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4317"
      } : {},
    )
  }

  dynamic "vpc_config" {
    for_each = local.in_vpc ? [1] : []
    content {
      subnet_ids         = var.vpc_subnet_ids
      security_group_ids = var.vpc_security_group_ids
    }
  }

  tags = local.tags
  depends_on = [
    aws_cloudwatch_log_group.agent,
    aws_iam_role_policy.agent,
    aws_iam_role_policy.agent_otel,
    aws_iam_role_policy.ledger_write,
    aws_s3_object.policy,
  ]
}

# ── Supervisor (multi only). ────────────────────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "supervisor" {
  count             = local.is_multi ? 1 : 0
  name              = "/aws/lambda/${local.name}-supervisor"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = local.tags
}

resource "aws_lambda_function" "supervisor" {
  count         = local.is_multi ? 1 : 0
  function_name = "${local.name}-supervisor"
  role          = aws_iam_role.supervisor[0].arn
  runtime       = var.python_runtime
  handler       = "supervisor.handler"
  architectures = [var.architecture]

  filename         = data.archive_file.supervisor[0].output_path
  source_code_hash = data.archive_file.supervisor[0].output_base64sha256

  timeout     = 30
  memory_size = 256
  kms_key_arn = var.kms_key_arn

  environment {
    variables = {
      MODEL_ID           = var.model_id
      AEGIS_WORKER_ROLES = join(",", var.worker_roles)
    }
  }

  dynamic "vpc_config" {
    for_each = local.in_vpc ? [1] : []
    content {
      subnet_ids         = var.vpc_subnet_ids
      security_group_ids = var.vpc_security_group_ids
    }
  }

  tags       = local.tags
  depends_on = [aws_cloudwatch_log_group.supervisor, aws_iam_role_policy.supervisor]
}

# ── Start (API front door). ─────────────────────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "start" {
  name              = "/aws/lambda/${local.name}-start"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = local.tags
}

resource "aws_lambda_function" "start" {
  function_name = "${local.name}-start"
  role          = aws_iam_role.start.arn
  runtime       = var.python_runtime
  handler       = "start.handler"
  architectures = [var.architecture]

  filename         = data.archive_file.start.output_path
  source_code_hash = data.archive_file.start.output_base64sha256

  timeout     = 30
  memory_size = 128

  environment {
    variables = {
      STATE_MACHINE_ARN = aws_sfn_state_machine.this.arn
    }
  }

  tags       = local.tags
  depends_on = [aws_cloudwatch_log_group.start, aws_iam_role_policy.start]
}

# ── Approver (auto_approve). ────────────────────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "approver" {
  count             = var.auto_approve ? 1 : 0
  name              = "/aws/lambda/${local.name}-approver"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = local.tags
}

resource "aws_lambda_function" "approver" {
  count         = var.auto_approve ? 1 : 0
  function_name = "${local.name}-approver"
  role          = aws_iam_role.approver[0].arn
  runtime       = var.python_runtime
  handler       = "approver.handler"
  architectures = [var.architecture]

  filename         = data.archive_file.approver[0].output_path
  source_code_hash = data.archive_file.approver[0].output_base64sha256

  timeout     = 30
  memory_size = 128

  tags       = local.tags
  depends_on = [aws_cloudwatch_log_group.approver, aws_iam_role_policy.approver]
}

resource "aws_lambda_event_source_mapping" "approver" {
  count            = var.auto_approve ? 1 : 0
  event_source_arn = aws_sqs_queue.approval.arn
  function_name    = aws_lambda_function.approver[0].arn
  batch_size       = 1
}
