# ── JIT short-lived S3 read credential (ASI03/ASI06) ──────────────────────────────────────────────
# When source_bucket is set, the agent-ingest principal reads a dropped *.txt with a 5-minute STS
# session minted by the loopback JIT broker (/credentials/issue). Least-privilege in depth:
#   1. a dedicated per-grant role, assumable ONLY by the agent role and ONLY with the ExternalId;
#   2. that role can read ONLY source_prefix* in source_bucket (its permission ceiling);
#   3. the extension renders an inline session policy scoped to the exact object at mint time;
#   4. the agent role itself gains ONLY sts:AssumeRole on this one role — no standing S3 read.

locals {
  source_enabled = var.source_bucket != ""
  # Object ARN ceiling: exactly the watched prefix, nothing else in the bucket.
  source_object_arn = "arn:aws:s3:::${var.source_bucket}/${var.source_prefix}*"
  jit_role_name     = "${local.name}-jit-source-read"
  # A per-deployment ExternalId the trust policy requires and the agent passes on AssumeRole — a
  # defence against the confused-deputy problem even within the account.
  jit_external_id = "${local.name}-jit-source"

  # Placeholders in the committed grants.toml, replaced with the real ARNs at deploy. When the feature
  # is off we ship an empty (default-deny) catalog instead, so no unusable grant is ever live.
  grants_placeholder_role     = "arn:aws:iam::000000000000:role/aegis-editorial-jit-source-read"
  grants_placeholder_resource = "arn:aws:s3:::CHANGEME-source-bucket/incoming/*"

  # The minted STS session's inline policy is INTERSECTED with the per-grant role's policy, so it must
  # ALSO carry kms:Decrypt when the source objects are SSE-KMS — otherwise the object read is denied at
  # decrypt time despite the role allowing it. The committed catalog ships the s3-only form (valid for
  # SSE-S3 / an AWS-managed key); when a source CMK is given we swap in the s3 + kms:Decrypt form.
  # Built with jsonencode (proper policy objects, not hand-escaped text); `{resource}` is a literal the
  # extension substitutes with the matched object ARN at mint time. jsonencode sorts keys alphabetically,
  # so the committed grants.toml session_policy_template is written in the same (compact, sorted) form
  # for the `sess_policy_s3_only` match below to hold.
  sess_policy_s3_only = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:GetObjectVersion"]
      Resource = "{resource}"
    }]
  })
  sess_policy_s3_kms = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion"], Resource = "{resource}" },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = var.source_kms_key_arn },
    ]
  })

  # grants.toml with the real per-grant role + object ARNs rendered in (empty & guarded when off).
  grants_rendered = local.source_enabled ? replace(
    replace(file("${var.policy_dir}/grants.toml"), local.grants_placeholder_role, aws_iam_role.jit_source[0].arn),
    local.grants_placeholder_resource, local.source_object_arn
  ) : ""

  grants_content = local.source_enabled ? (
    var.source_kms_key_arn != "" ? replace(local.grants_rendered, local.sess_policy_s3_only, local.sess_policy_s3_kms) : local.grants_rendered
  ) : "grants = []\n"
}

# grants.toml uploaded with the real per-grant role/resource ARNs rendered in (or emptied off).
resource "aws_s3_object" "grants" {
  bucket       = var.policy_bucket
  key          = "${local.policy_prefix}/grants.toml"
  content      = local.grants_content
  content_type = "text/plain"
  etag         = md5(local.grants_content)
  tags         = local.tags
}

# The per-grant role: assumable only by the agent role, only with the ExternalId.
data "aws_iam_policy_document" "jit_source_trust" {
  count = local.source_enabled ? 1 : 0
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.agent.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [local.jit_external_id]
    }
  }
}

# The permission ceiling: read ONLY the watched prefix (the inline session policy narrows it further,
# to the exact object, at mint time).
data "aws_iam_policy_document" "jit_source_perm" {
  count = local.source_enabled ? 1 : 0
  statement {
    sid       = "SourceObjectRead"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"] # GetObjectVersion: pin the read to the event's version (TOCTOU)
    resources = [local.source_object_arn]
  }
  dynamic "statement" {
    for_each = var.source_kms_key_arn != "" ? [1] : []
    content {
      sid       = "SourceKmsDecrypt"
      actions   = ["kms:Decrypt"]
      resources = [var.source_kms_key_arn]
    }
  }
}

resource "aws_iam_role" "jit_source" {
  count                = local.source_enabled ? 1 : 0
  name                 = local.jit_role_name
  assume_role_policy   = data.aws_iam_policy_document.jit_source_trust[0].json
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy" "jit_source" {
  count  = local.source_enabled ? 1 : 0
  name   = "${local.jit_role_name}-read"
  role   = aws_iam_role.jit_source[0].id
  policy = data.aws_iam_policy_document.jit_source_perm[0].json
}

# The agent role gains ONLY the ability to assume the per-grant role (with a session tag for
# CloudTrail attribution) — no standing access to the source bucket itself.
data "aws_iam_policy_document" "agent_jit" {
  count = local.source_enabled ? 1 : 0
  statement {
    sid       = "AssumeSourceReadRole"
    actions   = ["sts:AssumeRole", "sts:TagSession"]
    resources = [aws_iam_role.jit_source[0].arn]
  }
}

resource "aws_iam_role_policy" "agent_jit" {
  count  = local.source_enabled ? 1 : 0
  name   = "${local.name}-agent-jit"
  role   = aws_iam_role.agent.id
  policy = data.aws_iam_policy_document.agent_jit[0].json
}
