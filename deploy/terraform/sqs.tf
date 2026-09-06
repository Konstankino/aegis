# The human-approval queue: when the broker returns HumanApprove, the state machine's
# waitForTaskToken task drops the task token here and pauses durably. A human (or the optional
# approver Lambda) then calls SendTaskSuccess to resume. KMS-encrypted with the CMK.

resource "aws_sqs_queue" "approval_dlq" {
  name                      = "${var.project_name}-approval-dlq"
  kms_master_key_id         = aws_kms_key.cmk.arn
  message_retention_seconds = 1209600 # 14 days
  tags                      = local.tags
}

resource "aws_sqs_queue" "approval" {
  name                       = "${var.project_name}-approval"
  kms_master_key_id          = aws_kms_key.cmk.arn
  visibility_timeout_seconds = 60
  message_retention_seconds  = 3600
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.approval_dlq.arn
    maxReceiveCount     = 5
  })
  tags = local.tags
}
