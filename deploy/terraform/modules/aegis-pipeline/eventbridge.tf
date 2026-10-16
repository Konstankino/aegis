# ── S3 file-drop trigger (optional) ───────────────────────────────────────────────────────────────
# A *.txt dropped under source_prefix in source_bucket starts one Step Functions execution. The rule
# passes only the object coordinates (bucket + key) as the execution input; the content is never read
# here — the agent-ingest stage fetches it with a short-lived, object-scoped JIT credential. All
# resources are gated on source_bucket, so nothing is created when the feature is off.

# Enable EventBridge notifications on the (existing) source bucket, unless managed elsewhere.
resource "aws_s3_bucket_notification" "source" {
  count       = local.source_enabled && var.manage_source_bucket_notifications ? 1 : 0
  bucket      = var.source_bucket
  eventbridge = true
}

# Fire only on ObjectCreated for keys matching "<prefix>*.txt" (prefix + suffix in one wildcard),
# so non-.txt files and other prefixes never start a run.
resource "aws_cloudwatch_event_rule" "source_drop" {
  count       = local.source_enabled ? 1 : 0
  name        = "${local.name}-source-drop"
  description = "Start the ${local.name} pipeline when a *.txt is dropped under ${var.source_prefix} in ${var.source_bucket}."
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["Object Created"]
    detail = {
      bucket = { name = [var.source_bucket] }
      object = { key = [{ wildcard = "${var.source_prefix}*.txt" }] }
    }
  })
  tags = local.tags
}

# The rule starts the state machine, mapping the S3 event to the execution input the ASL expects.
resource "aws_cloudwatch_event_target" "start_sfn" {
  count    = local.source_enabled ? 1 : 0
  rule     = aws_cloudwatch_event_rule.source_drop[0].name
  arn      = aws_sfn_state_machine.this.arn
  role_arn = aws_iam_role.eventbridge[0].arn

  input_transformer {
    input_paths = {
      bucket  = "$.detail.bucket.name"
      key     = "$.detail.object.key"
      version = "$.detail.object.version-id"
      etag    = "$.detail.object.etag"
    }
    # The S3 object coordinates + the exact version/etag that triggered the event become the execution
    # input (the version pin closes the TOCTOU window at read time). String placeholders are quoted so
    # a missing version-id (unversioned bucket) renders as "" rather than breaking the JSON.
    input_template = <<-EOT
      { "source_bucket": "<bucket>", "source_key": "<key>", "source_version_id": "<version>", "source_etag": "<etag>" }
    EOT
  }
}

# EventBridge's role: allowed ONLY to start THIS state machine — nothing else.
data "aws_iam_policy_document" "eventbridge_assume" {
  count = local.source_enabled ? 1 : 0
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eventbridge" {
  count              = local.source_enabled ? 1 : 0
  name               = "${local.name}-eventbridge-role"
  assume_role_policy = data.aws_iam_policy_document.eventbridge_assume[0].json
  tags               = local.tags
}

data "aws_iam_policy_document" "eventbridge_start" {
  count = local.source_enabled ? 1 : 0
  statement {
    sid       = "StartPipeline"
    actions   = ["states:StartExecution"]
    resources = [aws_sfn_state_machine.this.arn]
  }
}

resource "aws_iam_role_policy" "eventbridge" {
  count  = local.source_enabled ? 1 : 0
  name   = "${local.name}-eventbridge-start"
  role   = aws_iam_role.eventbridge[0].id
  policy = data.aws_iam_policy_document.eventbridge_start[0].json
}
