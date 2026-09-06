# Versioned, encrypted, private S3 bucket that is the source of truth for the policy artifacts
# (architecture-considerations.md §2.4). The extension fetches these at cold start.

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "policies" {
  bucket        = "${var.project_name}-policies-${random_id.suffix.hex}"
  force_destroy = true # demo convenience: allow destroy with objects/versions present
  tags          = local.tags
}

resource "aws_s3_bucket_versioning" "policies" {
  bucket = aws_s3_bucket.policies.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "policies" {
  bucket = aws_s3_bucket.policies.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cmk.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "policies" {
  bucket                  = aws_s3_bucket.policies.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Upload the three artifacts under the configured prefix. `etag` triggers re-upload (and a new
# S3 version) whenever the local file changes.
locals {
  policy_prefix = "policies"
  policy_files = {
    "tools.json"            = "${local.workspace_dir}/policies/tools.json"
    "broker.cedar"          = "${local.workspace_dir}/policies/broker.cedar"
    "egress-allowlist.toml" = "${local.workspace_dir}/policies/egress-allowlist.toml"
    "meter.toml"            = "${local.workspace_dir}/policies/meter.toml"
    "pins.json"             = "${local.workspace_dir}/policies/pins.json"
  }
}

resource "aws_s3_object" "policy" {
  for_each = local.policy_files

  bucket = aws_s3_bucket.policies.id
  key    = "${local.policy_prefix}/${each.key}"
  source = each.value
  etag   = filemd5(each.value)
  tags   = local.tags
}

# Least-privilege read access for the function's execution role, scoped to this bucket/prefix.
data "aws_iam_policy_document" "policy_read" {
  statement {
    sid       = "ReadPolicyArtifacts"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.policies.arn}/${local.policy_prefix}/*"]
  }
  statement {
    sid       = "ListPolicyBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.policies.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${local.policy_prefix}/*"]
    }
  }
}

resource "aws_iam_role_policy" "policy_read" {
  name   = "${var.project_name}-policy-read"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.policy_read.json
}
