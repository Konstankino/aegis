data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${var.project_name}-agent-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

# CloudWatch Logs — scoped to THIS function's pre-created log group instead of the managed
# AWSLambdaBasicExecutionRole (which allows logs:* on "*", including CreateLogGroup). The group
# is created in lambda.tf, so CreateLogGroup is not needed.
data "aws_iam_policy_document" "agent_logs" {
  statement {
    sid       = "WriteAgentLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.agent.arn}:*"]
  }
}

resource "aws_iam_role_policy" "agent_logs" {
  name   = "${var.project_name}-agent-logs"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.agent_logs.json
}

# ENI management, only when the function runs inside the VPC. The AWS-managed policy is used
# here deliberately: the EC2 network-interface actions Lambda needs act on dynamically-created
# ENIs that cannot be safely scoped by ARN, and this is AWS's recommended policy for VPC Lambda.
resource "aws_iam_role_policy_attachment" "vpc" {
  count      = var.enable_vpc ? 1 : 0
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}
