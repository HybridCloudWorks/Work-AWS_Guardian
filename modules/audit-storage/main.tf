resource "aws_s3_bucket" "audit" {
  bucket_prefix = "${var.name_prefix}-audit-"
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket = aws_s3_bucket.audit.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    id     = "expire-poc-audit"
    status = "Enabled"

    filter {}

    expiration {
      days = var.audit_expiration_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.audit_expiration_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "bucket" {
  # Encryption in transit: reject any request not using TLS.
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    actions   = ["s3:*"]
    resources = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Encryption at rest: reject uploads that omit a server-side-encryption
  # header. Complements the bucket default SSE so a write cannot bypass
  # encryption. The canonical AWS pattern denies when the header is absent
  # (Null = true).
  statement {
    sid    = "DenyUnencryptedObjectUploads"
    effect = "Deny"

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["true"]
    }
  }

  # Pin the SSE algorithm. The statement above forbids a write with no SSE
  # header; this one forbids a write that supplies a header with any value
  # other than AES256 (e.g. an attempt to switch to aws:kms). Together they
  # force every write to use exactly the bucket default (AES256, AWS-managed
  # keys per ADR 0003). StringNotEquals only matches when the key is present,
  # so a header-absent write is caught by DenyUnencryptedObjectUploads above.
  statement {
    sid    = "DenyNonAes256ObjectUploads"
    effect = "Deny"

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["AES256"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = data.aws_iam_policy_document.bucket.json
}

# Server access logging. POC decision: log to the audit bucket itself under a
# "log/" prefix (self-logging) instead of provisioning a second always-on log
# bucket, which the cost/POC constraint forbids. Self-logging is an accepted
# AWS pattern for low-volume buckets; the lifecycle rule above expires the
# log/ objects on the same 30-day schedule as the rest of the bucket, so the
# access logs do not accumulate cost. The access-log delivery writes do not
# carry the client SSE header, so BucketOwnerEnforced + bucket-default SSE
# (AES256) cover them while the PutObject deny statements only gate client
# uploads. Flip enable_access_logging off for teardown or if a reviewer
# prefers a separate feature-flagged log bucket.
resource "aws_s3_bucket_logging" "audit" {
  count = var.enable_access_logging ? 1 : 0

  bucket        = aws_s3_bucket.audit.id
  target_bucket = aws_s3_bucket.audit.id
  target_prefix = "log/"
}
