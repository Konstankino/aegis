# Customer-managed KMS key (CMK) — the single encryption root for the demo, matching the doc's
# "DynamoDB (KMS-encrypted)" / least-privilege KMS posture (§1.4, §2.4). It encrypts: the policy
# S3 bucket, the DynamoDB checkpoint table, the SQS approval queue, the CloudWatch log groups,
# the Step Functions state, and the Lambda environment variables.
#
# Key-policy design avoids a dependency cycle: it grants the account root (so IAM policies on
# the roles are honored) plus the CloudWatch Logs service principal (which cannot be granted via
# IAM). Individual roles receive kms:Decrypt/GenerateDataKey*/DescribeKey via their own IAM
# policies (see agent_kms / sfn + approver policies), never via this key policy.

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "cmk" {
  statement {
    sid       = "EnableRootAccount"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:*"]
    }
  }
}

resource "aws_kms_key" "cmk" {
  description             = "${var.project_name} CMK: DynamoDB, S3, SQS, CloudWatch Logs, Step Functions, Lambda env."
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.cmk.json
  tags                    = local.tags
}

resource "aws_kms_alias" "cmk" {
  name          = "alias/${var.project_name}-cmk"
  target_key_id = aws_kms_key.cmk.key_id
}

# The kms actions the roles need. Kept least-privilege per the doc (§1.4).
locals {
  kms_use_actions = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
}

# Grant the agent Lambda role use of the CMK (for KMS-encrypted S3 policy objects, its env
# vars, and the checkpoint table).
data "aws_iam_policy_document" "agent_kms" {
  statement {
    sid       = "UseCmk"
    actions   = local.kms_use_actions
    resources = [aws_kms_key.cmk.arn]
  }
}

resource "aws_iam_role_policy" "agent_kms" {
  name   = "${var.project_name}-agent-kms"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.agent_kms.json
}
