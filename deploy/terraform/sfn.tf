# The durable orchestrator (Architecture A): a Standard state machine that fans out over the
# proposed tool calls, mediates each through the Aegis agent Lambda, and pauses on
# .waitForTaskToken for human approval when the broker returns HumanApprove. State is encrypted
# with the CMK; execution history/logs go to a KMS-encrypted CloudWatch log group.

resource "aws_cloudwatch_log_group" "sfn" {
  name              = "/aws/vendedlogs/states/${var.project_name}-agent-orchestration"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.cmk.arn
  tags              = local.tags
}

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
  name               = "${var.project_name}-sfn-role"
  assume_role_policy = data.aws_iam_policy_document.sfn_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "sfn" {
  # Invoke the agent Lambda (and any version/alias).
  statement {
    sid       = "InvokeAgent"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.agent.arn, "${aws_lambda_function.agent.arn}:*"]
  }

  # Send the task token to the approval queue.
  statement {
    sid       = "SendApproval"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.approval.arn]
  }

  # Use the CMK (SQS is KMS-encrypted, and the state machine itself is CMK-encrypted).
  statement {
    sid       = "UseCmk"
    actions   = local.kms_use_actions
    resources = [aws_kms_key.cmk.arn]
  }

  # X-Ray tracing.
  statement {
    sid = "XRay"
    actions = [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
      "xray:GetSamplingRules",
      "xray:GetSamplingTargets",
    ]
    resources = ["*"]
  }

  # CloudWatch Logs delivery for Standard-workflow logging (requires "*").
  statement {
    sid = "Logging"
    actions = [
      "logs:CreateLogDelivery",
      "logs:GetLogDelivery",
      "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries",
      "logs:PutResourcePolicy",
      "logs:DescribeResourcePolicies",
      "logs:DescribeLogGroups",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "sfn" {
  name   = "${var.project_name}-sfn-policy"
  role   = aws_iam_role.sfn.id
  policy = data.aws_iam_policy_document.sfn.json
}

resource "aws_sfn_state_machine" "agent" {
  name     = "${var.project_name}-agent-orchestration"
  role_arn = aws_iam_role.sfn.arn
  type     = "STANDARD"

  definition = templatefile("${path.module}/asl/agent_orchestration.asl.json", {
    agent_lambda_arn   = aws_lambda_function.agent.arn
    approval_queue_url = aws_sqs_queue.approval.url
  })

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  tracing_configuration {
    enabled = true
  }

  # Encrypt state-machine data at rest with the customer-managed key.
  encryption_configuration {
    type                              = "CUSTOMER_MANAGED_KMS_KEY"
    kms_key_id                        = aws_kms_key.cmk.arn
    kms_data_key_reuse_period_seconds = 300
  }

  tags       = local.tags
  depends_on = [aws_iam_role_policy.sfn]
}
