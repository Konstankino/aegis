# The LangGraph checkpointer table (Architecture A, §1.3/§1.4): composite PK/SK, KMS-encrypted
# with the CMK. Keyed by thread_id/run_id — the same identity the broker session and the
# aegis-ledger use. The Python demo handler does not exercise it, but it is the durable store
# the agent loop would checkpoint into.

resource "aws_dynamodb_table" "checkpoints" {
  name         = "${var.project_name}-checkpoints"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "PK"
  range_key    = "SK"

  attribute {
    name = "PK"
    type = "S"
  }
  attribute {
    name = "SK"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.cmk.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = local.tags
}

# Least-privilege table access for the agent role (the checkpointer's minimum: §1.4).
data "aws_iam_policy_document" "agent_dynamodb" {
  statement {
    sid = "CheckpointerAccess"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:Query",
      "dynamodb:BatchGetItem",
      "dynamodb:BatchWriteItem",
    ]
    resources = [
      aws_dynamodb_table.checkpoints.arn,
      "${aws_dynamodb_table.checkpoints.arn}/index/*",
    ]
  }
}

resource "aws_iam_role_policy" "agent_dynamodb" {
  name   = "${var.project_name}-agent-dynamodb"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.agent_dynamodb.json
}
