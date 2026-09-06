# Per-project conversation checkpointer (KMS-encrypted). Keyed PK=thread#<id>, SK="messages".
resource "aws_dynamodb_table" "checkpoints" {
  name         = "${local.name}-checkpoints"
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
    kms_key_arn = var.kms_key_arn
  }
  point_in_time_recovery {
    enabled = true
  }
  tags = local.tags
}
