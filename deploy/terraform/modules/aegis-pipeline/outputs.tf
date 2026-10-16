output "api_base_url" {
  description = "Base URL: POST {url}/chat, GET {url}/status?executionArn=... (null when the HTTP entry is disabled)."
  value       = var.enable_http_entry ? aws_apigatewayv2_api.http[0].api_endpoint : null
}

output "state_machine_arn" {
  value = aws_sfn_state_machine.this.arn
}

output "agent_function" {
  value = aws_lambda_function.agent.function_name
}

output "runner_function" {
  description = "Isolated code-runner function name (null when disabled)."
  value       = var.enable_code_runner ? aws_lambda_function.runner[0].function_name : null
}

output "approval_queue_url" {
  value = aws_sqs_queue.approval.url
}

output "checkpoint_table" {
  value = aws_dynamodb_table.checkpoints.name
}

output "ledger_bucket" {
  description = "Per-project immutable (S3 Object Lock) audit-ledger bucket."
  value       = aws_s3_bucket.ledger.id
}

output "source_read_role_arn" {
  description = <<-EOT
    The per-grant IAM role the JIT broker assumes to read a dropped source object — this is the
    PRINCIPAL to authorize on the source bucket's KMS key policy. When the source bucket is SSE-KMS,
    add a kms:Decrypt (and kms:DescribeKey) allow for this ARN to that CMK's key policy IF the key is
    cross-account or its policy does not delegate to IAM via the account-root statement; for a
    same-account CMK with the standard "EnableRoot" statement, the module's IAM grant is sufficient and
    no key-policy edit is needed. (null when the S3 file-drop feature is off.)
  EOT
  value       = local.source_enabled ? aws_iam_role.jit_source[0].arn : null
}

output "source_read_external_id" {
  description = "The sts:ExternalId the JIT broker passes when assuming source_read_role_arn (also set on the agent Lambda as AEGIS_JIT_EXTERNAL_ID). Add it as a Condition on the CMK grant only if you scope by ExternalId. (null when off.)"
  value       = local.source_enabled ? local.jit_external_id : null
}

output "source_drop_rule" {
  description = "EventBridge rule name that starts the pipeline on a *.txt drop (null when off)."
  value       = local.source_enabled ? aws_cloudwatch_event_rule.source_drop[0].name : null
}
