# Per-project immutable audit sink for the aegis-ledger (§2.4). Mirrors the standalone stack's
# ledger.tf, but scoped to this project so each project's tamper-evident audit trail is isolated —
# the same isolation model as its own checkpointer table, SQS queue, and IAM roles.
#
# The extension (running in the agent/worker Lambda) writes each hash-chained entry here via
# AEGIS_LEDGER_BUCKET. Object Lock (versioning + retention) makes objects immutable; the agent role
# gets PutObject ONLY — no Delete, no overwrite — so entries are write-once and cannot be rewritten.

resource "random_id" "ledger" {
  byte_length = 4
}

resource "aws_s3_bucket" "ledger" {
  bucket              = "${local.name}-ledger-${random_id.ledger.hex}"
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
      kms_master_key_id = var.kms_key_arn
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

# GOVERNANCE mode (short window) so the demo can be torn down; production should use COMPLIANCE mode
# with a real retention period — nobody, including root, can then delete an entry early.
resource "aws_s3_bucket_object_lock_configuration" "ledger" {
  bucket = aws_s3_bucket.ledger.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 1
    }
  }
}

# Append-only access for the agent/worker role: PutObject (+ retention) on the ledger, and NO
# delete/overwrite. Combined with Object Lock, entries are write-once. (KMS for the SSE-KMS write is
# already granted to the agent role by the "Kms" statement in iam.tf.)
data "aws_iam_policy_document" "ledger_write" {
  statement {
    sid       = "AppendLedgerEntries"
    actions   = ["s3:PutObject", "s3:PutObjectRetention"]
    resources = ["${aws_s3_bucket.ledger.arn}/*"]
  }
}

resource "aws_iam_role_policy" "ledger_write" {
  name   = "${local.name}-ledger-write"
  role   = aws_iam_role.agent.id
  policy = data.aws_iam_policy_document.ledger_write.json
}
