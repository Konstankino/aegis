# Per-project human-approval queue (carries the waitForTaskToken). KMS-encrypted.
resource "aws_sqs_queue" "approval_dlq" {
  name                      = "${local.name}-approval-dlq"
  kms_master_key_id         = var.kms_key_arn
  message_retention_seconds = 1209600
  tags                      = local.tags
}

resource "aws_sqs_queue" "approval" {
  name                       = "${local.name}-approval"
  kms_master_key_id          = var.kms_key_arn
  visibility_timeout_seconds = 60
  message_retention_seconds  = 3600
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.approval_dlq.arn
    maxReceiveCount     = 5
  })
  tags = local.tags
}
