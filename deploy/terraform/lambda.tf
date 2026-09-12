resource "aws_lambda_layer_version" "aegis" {
  layer_name               = "${var.project_name}-inline-plane"
  description              = "Aegis inline plane: broker + output + egress gate (external extension) + policies."
  filename                 = data.archive_file.layer.output_path
  source_code_hash         = data.archive_file.layer.output_base64sha256
  compatible_architectures = [var.architecture]
}

resource "aws_cloudwatch_log_group" "agent" {
  name              = "/aws/lambda/${var.project_name}-agent"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.cmk.arn
  tags              = local.tags
}

resource "aws_lambda_function" "agent" {
  function_name = "${var.project_name}-agent"
  role          = aws_iam_role.lambda.arn
  runtime       = var.python_runtime
  handler       = "handler.handler"
  architectures = [var.architecture]

  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256

  # The Aegis inline-plane layer, plus the OTel collector layer when one is configured.
  layers = concat(
    [aws_lambda_layer_version.aegis.arn],
    var.otel_collector_layer_arn != "" ? [var.otel_collector_layer_arn] : [],
  )

  timeout     = 30
  memory_size = 256

  # Encrypt environment variables at rest with the customer-managed key.
  kms_key_arn = aws_kms_key.cmk.arn

  environment {
    variables = merge(
      {
        # Policies come from S3 (the §2.4 production shape). AEGIS_POLICY_DIR remains as a
        # fallback: policies are also baked into the layer at /opt/policies.
        AEGIS_POLICY_S3_BUCKET = aws_s3_bucket.policies.id
        AEGIS_POLICY_S3_PREFIX = local.policy_prefix
        AEGIS_POLICY_DIR       = "/opt/policies"
        # The LangGraph checkpointer table (Architecture A) — available to the agent loop.
        AEGIS_CHECKPOINT_TABLE = aws_dynamodb_table.checkpoints.name
        # The immutable (Object Lock) audit sink for the aegis-ledger.
        AEGIS_LEDGER_BUCKET = aws_s3_bucket.ledger.id
        # The handler reads AEGIS_GATE_ADDR to find the loopback gate.
        AEGIS_GATE_ADDR = "127.0.0.1:8080"
        # ExternalId the extension presents when assuming a JIT per-grant role (must match the
        # role trust policies in jit.tf). Harmless when no jit_grants are configured.
        AEGIS_JIT_EXTERNAL_ID = "${var.project_name}-jit"
        # Log level for the extension (also the OTel EnvFilter when otel is built in).
        RUST_LOG = "aegis_extension=info,aegis=info"
        # OpenTelemetry service name (resource attribute).
        OTEL_SERVICE_NAME = var.project_name
      },
      # Only point the OTLP exporter at the collector when one is attached; otherwise the
      # extension degrades to structured logs (no connection errors).
      var.otel_collector_layer_arn != "" ? {
        OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4317"
      } : {},
    )
  }

  # Egress containment: run in the private, no-default-route subnet when enabled.
  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = [aws_subnet.private[0].id]
      security_group_ids = [aws_security_group.lambda[0].id]
    }
  }

  tags = local.tags

  # The extension fetches policies from S3 at cold start (fail-closed), so everything it needs
  # to reach and decrypt S3 must exist before the first invoke.
  depends_on = [
    aws_cloudwatch_log_group.agent,
    aws_iam_role_policy.agent_logs,
    aws_iam_role_policy.policy_read,
    aws_iam_role_policy.agent_kms,
    aws_iam_role_policy.agent_dynamodb,
    aws_s3_object.policy,
    aws_vpc_endpoint.s3,
    aws_iam_role_policy.otel_export,
    aws_iam_role_policy.ledger_write,
    aws_iam_role_policy.agent_jit,
  ]
}

# Optionally invoke on apply to surface the Aegis decision trace as a Terraform output.
data "aws_lambda_invocation" "demo" {
  count         = var.run_demo ? 1 : 0
  function_name = aws_lambda_function.agent.function_name
  input         = jsonencode({ demo = true })
}
