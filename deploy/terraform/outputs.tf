output "function_name" {
  description = "The agent Lambda function name."
  value       = aws_lambda_function.agent.function_name
}

output "function_arn" {
  description = "The agent Lambda function ARN."
  value       = aws_lambda_function.agent.arn
}

output "layer_arn" {
  description = "The Aegis inline-plane layer version ARN."
  value       = aws_lambda_layer_version.aegis.arn
}

output "log_group" {
  description = "CloudWatch Logs group for the agent function (extension logs land here too)."
  value       = aws_cloudwatch_log_group.agent.name
}

output "policy_bucket" {
  description = "S3 bucket holding the versioned policy artifacts the extension loads at cold start."
  value       = aws_s3_bucket.policies.id
}

output "policy_s3_uri" {
  description = "S3 URI prefix the extension reads policies from."
  value       = "s3://${aws_s3_bucket.policies.id}/${local.policy_prefix}/"
}

output "kms_key_arn" {
  description = "The customer-managed CMK encrypting S3, DynamoDB, SQS, Logs, Step Functions, and Lambda env."
  value       = aws_kms_key.cmk.arn
}

output "checkpoint_table" {
  description = "KMS-encrypted DynamoDB checkpointer table (Architecture A)."
  value       = aws_dynamodb_table.checkpoints.name
}

output "ledger_bucket" {
  description = "Object Lock (immutable), KMS-encrypted S3 bucket for the tamper-evident audit ledger."
  value       = aws_s3_bucket.ledger.id
}

output "state_machine_arn" {
  description = "The Aegis agent-orchestration Step Functions state machine."
  value       = aws_sfn_state_machine.agent.arn
}

output "start_execution_command" {
  description = "Start an orchestration run that fans out over the example tool calls."
  value       = "aws stepfunctions start-execution --region ${var.region} --state-machine-arn ${aws_sfn_state_machine.agent.arn} --input file://asl/example-input.json"
}

output "approval_queue_url" {
  description = "SQS queue that receives waitForTaskToken approvals (for manual approval)."
  value       = aws_sqs_queue.approval.url
}

output "project_name" {
  description = "Resource name prefix."
  value       = var.project_name
}

output "egress_contained" {
  description = "Whether the function runs in the no-default-route VPC."
  value       = var.enable_vpc
}

output "invoke_command" {
  description = "Invoke the function from the CLI and print the decision trace."
  value       = "aws lambda invoke --region ${var.region} --function-name ${aws_lambda_function.agent.function_name} --cli-binary-format raw-in-base64-out --payload '{\"demo\":true}' /dev/stdout"
}

# The Aegis decision trace, shown right after apply when run_demo = true.
output "demo_trace" {
  description = "Aegis gate decisions returned by the function (broker/output/egress)."
  value       = var.run_demo ? jsondecode(data.aws_lambda_invocation.demo[0].result) : null
}
