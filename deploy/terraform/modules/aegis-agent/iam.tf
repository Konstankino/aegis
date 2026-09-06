locals {
  acct         = data.aws_caller_identity.current.account_id
  log_arn      = "arn:aws:logs:${var.region}:${local.acct}:log-group:/aws/lambda/${local.name}-*:*"
  sfn_log_arn  = "arn:aws:logs:${var.region}:${local.acct}:log-group:/aws/vendedlogs/states/${local.name}-*"
  bedrock_arn  = "arn:aws:bedrock:${var.region}::foundation-model/*"
  kms_actions  = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
  sm_arn       = aws_sfn_state_machine.this.arn
  exec_arn     = "arn:aws:states:${var.region}:${local.acct}:execution:${local.name}-orchestration:*"
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# Scoped CloudWatch Logs for all of this project's functions.
data "aws_iam_policy_document" "logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [local.log_arn]
  }
}

# ── Agent (also the worker in multi): S3 policies, KMS, DynamoDB, Bedrock. ───────────────────────
resource "aws_iam_role" "agent" {
  name               = "${local.name}-agent-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "agent" {
  source_policy_documents = [data.aws_iam_policy_document.logs.json]

  statement {
    sid       = "PolicyFetch"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${var.policy_bucket}/${local.policy_prefix}/*"]
  }
  statement {
    sid       = "Kms"
    actions   = local.kms_actions
    resources = [var.kms_key_arn]
  }
  statement {
    sid       = "Checkpointer"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:BatchGetItem", "dynamodb:BatchWriteItem"]
    resources = [aws_dynamodb_table.checkpoints.arn]
  }
  statement {
    sid       = "Bedrock"
    actions   = ["bedrock:InvokeModel"]
    resources = [local.bedrock_arn]
  }
  # Invoke ONLY the isolated code runner (ASI05) — nothing else. The agent hands allowed code to it.
  dynamic "statement" {
    for_each = var.enable_code_runner ? [1] : []
    content {
      sid       = "InvokeRunner"
      actions   = ["lambda:InvokeFunction"]
      resources = [aws_lambda_function.runner[0].arn]
    }
  }
}

resource "aws_iam_role_policy" "agent" {
  name   = "${local.name}-agent"
  role   = aws_iam_role.agent.id
  policy = data.aws_iam_policy_document.agent.json
}

resource "aws_iam_role_policy_attachment" "agent_vpc" {
  count      = local.in_vpc ? 1 : 0
  role       = aws_iam_role.agent.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# OTel collector export (X-Ray traces + CloudWatch metrics), only when a collector layer is set.
data "aws_iam_policy_document" "agent_otel" {
  count = var.otel_collector_layer_arn != "" ? 1 : 0
  statement {
    sid       = "XRay"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"]
    resources = ["*"]
  }
  statement {
    sid       = "CloudWatchMetrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = [var.project_name, "aegis"]
    }
  }
}

resource "aws_iam_role_policy" "agent_otel" {
  count  = var.otel_collector_layer_arn != "" ? 1 : 0
  name   = "${local.name}-agent-otel"
  role   = aws_iam_role.agent.id
  policy = data.aws_iam_policy_document.agent_otel[0].json
}

# ── Code runner (ASI05): CloudWatch Logs ONLY. No S3/DDB/Bedrock/KMS. VPC ENI when in a VPC. ─────
# This is the whole point of the separate function: even a full breakout of the executed code has
# no AWS permissions to abuse and (in VPC) no network to reach.
resource "aws_iam_role" "runner" {
  count              = var.enable_code_runner ? 1 : 0
  name               = "${local.name}-runner-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "runner" {
  count  = var.enable_code_runner ? 1 : 0
  name   = "${local.name}-runner"
  role   = aws_iam_role.runner[0].id
  policy = data.aws_iam_policy_document.logs.json
}

resource "aws_iam_role_policy_attachment" "runner_vpc" {
  count      = var.enable_code_runner && local.in_vpc ? 1 : 0
  role       = aws_iam_role.runner[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# ── Supervisor (multi only): Bedrock + logs (+VPC). Calls no tools. ──────────────────────────────
resource "aws_iam_role" "supervisor" {
  count              = local.is_multi ? 1 : 0
  name               = "${local.name}-supervisor-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "supervisor" {
  count                   = local.is_multi ? 1 : 0
  source_policy_documents = [data.aws_iam_policy_document.logs.json]
  statement {
    actions   = ["bedrock:InvokeModel"]
    resources = [local.bedrock_arn]
  }
  statement {
    actions   = local.kms_actions
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "supervisor" {
  count  = local.is_multi ? 1 : 0
  name   = "${local.name}-supervisor"
  role   = aws_iam_role.supervisor[0].id
  policy = data.aws_iam_policy_document.supervisor[0].json
}

resource "aws_iam_role_policy_attachment" "supervisor_vpc" {
  count      = local.is_multi && local.in_vpc ? 1 : 0
  role       = aws_iam_role.supervisor[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# ── Start (API front door): start + describe executions. ────────────────────────────────────────
resource "aws_iam_role" "start" {
  name               = "${local.name}-start-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "start" {
  source_policy_documents = [data.aws_iam_policy_document.logs.json]
  statement {
    actions   = ["states:StartExecution"]
    resources = [local.sm_arn]
  }
  statement {
    actions   = ["states:DescribeExecution"]
    resources = [local.exec_arn]
  }
}

resource "aws_iam_role_policy" "start" {
  name   = "${local.name}-start"
  role   = aws_iam_role.start.id
  policy = data.aws_iam_policy_document.start.json
}

# ── Step Functions role: invoke Lambdas, send to SQS, KMS, X-Ray, log delivery. ─────────────────
data "aws_iam_policy_document" "sfn_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "sfn" {
  name               = "${local.name}-sfn-role"
  assume_role_policy = data.aws_iam_policy_document.sfn_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "sfn" {
  statement {
    sid       = "InvokeAgents"
    actions   = ["lambda:InvokeFunction"]
    resources = compact([aws_lambda_function.agent.arn, "${aws_lambda_function.agent.arn}:*", local.is_multi ? aws_lambda_function.supervisor[0].arn : ""])
  }
  statement {
    sid       = "Approval"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.approval.arn]
  }
  statement {
    sid       = "Kms"
    actions   = local.kms_actions
    resources = [var.kms_key_arn]
  }
  statement {
    sid       = "XRay"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"]
    resources = ["*"]
  }
  statement {
    sid = "Logging"
    actions = [
      "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery", "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries", "logs:PutResourcePolicy", "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "sfn" {
  name   = "${local.name}-sfn"
  role   = aws_iam_role.sfn.id
  policy = data.aws_iam_policy_document.sfn.json
}

# ── Approver (auto_approve): resume tokens, consume the queue, KMS. ──────────────────────────────
resource "aws_iam_role" "approver" {
  count              = var.auto_approve ? 1 : 0
  name               = "${local.name}-approver-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "approver" {
  count                   = var.auto_approve ? 1 : 0
  source_policy_documents = [data.aws_iam_policy_document.logs.json]
  statement {
    actions   = ["states:SendTaskSuccess", "states:SendTaskFailure"]
    resources = ["*"]
  }
  statement {
    actions   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
    resources = [aws_sqs_queue.approval.arn]
  }
  statement {
    actions   = local.kms_actions
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "approver" {
  count  = var.auto_approve ? 1 : 0
  name   = "${local.name}-approver"
  role   = aws_iam_role.approver[0].id
  policy = data.aws_iam_policy_document.approver[0].json
}
