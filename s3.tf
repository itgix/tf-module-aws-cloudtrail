# S3 bucket to store CloudTrail logs
resource "aws_s3_bucket" "itgix_cloudtrail_primary" {
  count  = var.cloudtrail_organization_audit_account ? 1 : 0
  bucket = var.s3_bucket_name
}

# Attaching policy to S3 bucket allowing CloudTrail to write logs in it 
resource "aws_s3_bucket_policy" "s3_bucket_policy" {
  count  = var.cloudtrail_organization_audit_account ? 1 : 0
  bucket = aws_s3_bucket.itgix_cloudtrail_primary[0].bucket
  policy = data.aws_iam_policy_document.cloudtrail_s3[0].json
}

# S3 bucket lifecycle rule
resource "aws_s3_bucket_lifecycle_configuration" "s3_bucket_lifecycle" {
  count  = var.cloudtrail_organization_audit_account ? 1 : 0
  bucket = aws_s3_bucket.itgix_cloudtrail_primary[0].bucket
  rule {
    id     = "expire-objects-older-than-two-years"
    status = "Enabled"

    expiration {
      days = var.expire_s3_objects_after
    }
  }
}

# Policy document for S3 bucket
data "aws_iam_policy_document" "cloudtrail_s3" {
  count = var.cloudtrail_organization_audit_account ? 1 : 0
  statement {
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = ["arn:aws:s3:::${aws_s3_bucket.itgix_cloudtrail_primary[0].bucket}"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${var.security_account_id}:trail/${var.cloudtrail_name}"]
    }
  }
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${aws_s3_bucket.itgix_cloudtrail_primary[0].bucket}/AWSLogs/${var.aws_organization_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${var.security_account_id}:trail/${var.cloudtrail_name}"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${aws_s3_bucket.itgix_cloudtrail_primary[0].bucket}/AWSLogs/${var.security_account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${var.security_account_id}:trail/${var.cloudtrail_name}"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}
