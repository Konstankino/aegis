# Optional auto-approver (var.auto_approve): resumes waitForTaskToken pauses so the demo runs
# end to end without a human. Set auto_approve = false to approve manually (see README).

data "archive_file" "approver" {
  count       = var.auto_approve ? 1 : 0
  type        = "zip"
  source_dir  = "${path.module}/approver"
  output_path = "${path.module}/build/approver.zip"
}

data "aws_iam_policy_document" "approver_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "approver" {
  count              = var.auto_approve ? 1 : 0
  name               = "${var.project_name}-approver-role"
  assume_role_policy = data.aws_iam_policy_document.approver_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "approver" {
  count = var.auto_approve ? 1 : 0

  # Scoped CloudWatch Logs (pre-created group), instead of the managed basic-execution policy.
  statement {
    sid       = "WriteApproverLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.approver[0].arn}:*"]
  }

  # Resume the paused execution. SendTaskSuccess/Failure authorize on the task token, not a
  # resource ARN, so "*" is the only valid resource for these actions.
  statement {
    sid       = "ResumeStepFunctions"
    actions   = ["states:SendTaskSuccess", "states:SendTaskFailure"]
    resources = ["*"]
  }

  statement {
    sid = "ConsumeQueue"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]
    resources = [aws_sqs_queue.approval.arn]
  }

  statement {
    sid       = "UseCmk"
    actions   = local.kms_use_actions
    resources = [aws_kms_key.cmk.arn]
  }
}

resource "aws_iam_role_policy" "approver" {
  count  = var.auto_approve ? 1 : 0
  name   = "${var.project_name}-approver-policy"
  role   = aws_iam_role.approver[0].id
  policy = data.aws_iam_policy_document.approver[0].json
}

resource "aws_cloudwatch_log_group" "approver" {
  count             = var.auto_approve ? 1 : 0
  name              = "/aws/lambda/${var.project_name}-approver"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.cmk.arn
  tags              = local.tags
}

resource "aws_lambda_function" "approver" {
  count         = var.auto_approve ? 1 : 0
  function_name = "${var.project_name}-approver"
  role          = aws_iam_role.approver[0].arn
  runtime       = var.python_runtime
  handler       = "approver.handler"
  architectures = [var.architecture]

  filename         = data.archive_file.approver[0].output_path
  source_code_hash = data.archive_file.approver[0].output_base64sha256

  timeout     = 30
  memory_size = 128

  environment {
    variables = {
      AEGIS_AUTO_DECISION = "approve"
    }
  }

  tags = local.tags
  depends_on = [
    aws_cloudwatch_log_group.approver,
    aws_iam_role_policy.approver,
  ]
}

resource "aws_lambda_event_source_mapping" "approver" {
  count            = var.auto_approve ? 1 : 0
  event_source_arn = aws_sqs_queue.approval.arn
  function_name    = aws_lambda_function.approver[0].arn
  batch_size       = 1
}
