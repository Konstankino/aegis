# Observability: when an OTel collector layer is attached (var.otel_collector_layer_arn), a
# collector runs as an extension in the same execution environment and uses the function's
# execution role to export. Grant it least-privilege X-Ray (traces) + CloudWatch (metrics).
#
# The extension always instruments with `tracing` and, built with the `otel` feature, exports
# OTLP to the collector on localhost:4317. With no collector attached this file is inert and the
# extension emits structured logs only.

data "aws_iam_policy_document" "otel_export" {
  count = var.otel_collector_layer_arn != "" ? 1 : 0

  statement {
    sid = "XRayTraces"
    actions = [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
      "xray:GetSamplingRules",
      "xray:GetSamplingTargets",
    ]
    resources = ["*"] # X-Ray ingestion APIs do not support resource-level restrictions.
  }

  statement {
    sid       = "CloudWatchMetrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"] # PutMetricData does not support resource-level restrictions; scope by namespace below.
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = [var.project_name, "aegis"]
    }
  }
}

resource "aws_iam_role_policy" "otel_export" {
  count  = var.otel_collector_layer_arn != "" ? 1 : 0
  name   = "${var.project_name}-otel-export"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.otel_export[0].json
}
