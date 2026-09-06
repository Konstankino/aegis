resource "aws_cloudwatch_log_group" "sfn" {
  name              = "/aws/vendedlogs/states/${local.name}-orchestration"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = local.tags
}

resource "aws_sfn_state_machine" "this" {
  name       = "${local.name}-orchestration"
  role_arn   = aws_iam_role.sfn.arn
  type       = "STANDARD"
  definition = local.asl_definition

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }
  tracing_configuration {
    enabled = true
  }
  encryption_configuration {
    type                              = "CUSTOMER_MANAGED_KMS_KEY"
    kms_key_id                        = var.kms_key_arn
    kms_data_key_reuse_period_seconds = 300
  }

  tags       = local.tags
  depends_on = [aws_iam_role_policy.sfn]
}
