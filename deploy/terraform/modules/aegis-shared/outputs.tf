output "extension_layer_arn" {
  value = aws_lambda_layer_version.aegis.arn
}

output "kms_key_arn" {
  value = aws_kms_key.cmk.arn
}

output "policy_bucket" {
  value = aws_s3_bucket.policies.id
}

output "vpc_subnet_ids" {
  description = "Private subnet ids for agent Lambdas (empty when enable_vpc = false)."
  value       = var.enable_vpc ? aws_subnet.private[*].id : []
}

output "lambda_security_group_ids" {
  description = "Security group ids for agent Lambdas (empty when enable_vpc = false)."
  value       = var.enable_vpc ? [aws_security_group.lambda[0].id] : []
}

output "runner_security_group_ids" {
  description = "Deny-all-egress security group ids for the code runner (empty when enable_vpc = false)."
  value       = var.enable_vpc ? [aws_security_group.runner[0].id] : []
}
