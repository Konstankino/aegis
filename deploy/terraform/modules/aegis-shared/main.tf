# Shared infrastructure built ONCE per stack and reused by every project's aegis-agent module:
# the aegis-extension Lambda layer, the customer-managed KMS CMK, and the policy S3 bucket
# (each project uploads its policies under its own prefix).

data "aws_caller_identity" "current" {}

locals {
  staging_dir = "${path.module}/build/staging"
  tags        = { ManagedBy = "terraform", Component = "aegis-shared" }
}

# ── KMS CMK ─────────────────────────────────────────────────────────────────────────────────────
data "aws_iam_policy_document" "cmk" {
  statement {
    sid       = "EnableRoot"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:*"]
    }
  }
}

resource "aws_kms_key" "cmk" {
  description             = "${var.name_prefix} shared CMK"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.cmk.json
  tags                    = local.tags
}

resource "aws_kms_alias" "cmk" {
  name          = "alias/${var.name_prefix}-shared-cmk"
  target_key_id = aws_kms_key.cmk.key_id
}

# ── Policy bucket (per-project prefixes) ────────────────────────────────────────────────────────
resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "policies" {
  bucket        = "${var.name_prefix}-policies-${random_id.suffix.hex}"
  force_destroy = true
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

# ── Extension layer (built once, with s3 + otel) ────────────────────────────────────────────────
resource "null_resource" "build_extension" {
  triggers = {
    arch       = var.architecture
    build_hash = filesha1(var.build_script)
    # Rebuild when any workspace source changes.
    src_hash = sha1(join("", [
      for f in fileset(var.workspace_dir, "crates/**/*.rs") : filesha1("${var.workspace_dir}/${f}")
    ]))
  }
  provisioner "local-exec" {
    command = "bash ${var.build_script}"
    environment = {
      AEGIS_ARCH      = var.architecture
      AEGIS_WORKSPACE = var.workspace_dir
      AEGIS_STAGING   = local.staging_dir
    }
  }
}

data "archive_file" "layer" {
  type        = "zip"
  source_dir  = local.staging_dir
  output_path = "${path.module}/build/aegis-extension-layer.zip"
  depends_on  = [null_resource.build_extension]
}

resource "aws_lambda_layer_version" "aegis" {
  layer_name               = "${var.name_prefix}-inline-plane"
  filename                 = data.archive_file.layer.output_path
  source_code_hash         = data.archive_file.layer.output_base64sha256
  compatible_architectures = [var.architecture]
}
