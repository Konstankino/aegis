# Immutable audit sink for the aegis-ledger (Phase 1, §2.4: "S3 with Object Lock for
# immutability, correlated to CloudTrail by run_id/thread_id"). The tamper-evident hash chain is
# produced by the extension; this bucket is the write-once durable store for it.
#
# Object Lock (versioning + retention) makes objects immutable for the retention window. The
# agent role gets PutObject ONLY — no Delete, no overwrite — so entries cannot be rewritten.

resource "aws_s3_bucket" "ledger" {
  bucket              = "${var.project_name}-ledger-${random_id.suffix.hex}"
  object_lock_enabled = true
  force_destroy       = true # demo convenience; see the retention-mode note below
  tags                = local.tags
}

resource "aws_s3_bucket_versioning" "ledger" {
  bucket = aws_s3_bucket.ledger.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ledger" {
  bucket = aws_s3_bucket.ledger.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cmk.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "ledger" {
  bucket                  = aws_s3_bucket.ledger.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# GOVERNANCE mode (with a short window) so the demo can be torn down; production should use
# COMPLIANCE mode with a real retention period — nobody, including root, can then delete early.
resource "aws_s3_bucket_object_lock_configuration" "ledger" {
  bucket = aws_s3_bucket.ledger.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 1
    }
  }
}

# Append-only access for the agent role: PutObject (+ retention) on the ledger prefix, and NO
# delete/overwrite. Combined with Object Lock, entries are write-once.
data "aws_iam_policy_document" "ledger_write" {
  statement {
    sid = "AppendLedgerEntries"
    actions = [
      "s3:PutObject",
      "s3:PutObjectRetention",
    ]
    resources = ["${aws_s3_bucket.ledger.arn}/*"]
  }
}

resource "aws_iam_role_policy" "ledger_write" {
  name   = "${var.project_name}-ledger-write"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.ledger_write.json
}
