output "api_base_url" {
  description = "Base URL: POST {url}/chat, GET {url}/status?executionArn=..."
  value       = aws_apigatewayv2_api.http.api_endpoint
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
