# S3 bucket to store CloudTrail logs - can be stored either in Cloudwatch or S3 or both
resource "aws_s3_bucket" "itgix_cloudtrail_primary" {
  count  = var.cloudtrail_organization_audit_account ? 1 : 0
  bucket = var.cloudtrail_s3_bucket_name
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

    filter {
      prefix = ""
    }

    expiration {
      days = var.cloudtrail_expire_s3_logs_after_days
    }
  }
}

# Policy document for S3 bucket
data "aws_iam_policy_document" "cloudtrail_s3" {
  count = var.cloudtrail_organization_audit_account ? 1 : 0
  # allows CloudTrail to call the Amazon S3 GetBucketAcl action on the Amazon S3 bucket
  statement {
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.itgix_cloudtrail_primary[0].arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values = [
        "arn:aws:cloudtrail:${var.aws_region}:${var.security_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.management_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.shared_services_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.audit_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.dev_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.stage_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.prod_account_id}:trail/${var.cloudtrail_name}"
      ]
    }
  }

  # allows logging in the event the trail is changed from an organization trail to a trail for that account only
  statement {
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.itgix_cloudtrail_primary[0].arn}/AWSLogs/${var.security_account_id}/*",
      "${aws_s3_bucket.itgix_cloudtrail_primary[0].arn}/AWSLogs/${var.management_account_id}/*",
      "${aws_s3_bucket.itgix_cloudtrail_primary[0].arn}/AWSLogs/${var.shared_services_account_id}/*",
      "${aws_s3_bucket.itgix_cloudtrail_primary[0].arn}/AWSLogs/${var.audit_account_id}/*",
      "${aws_s3_bucket.itgix_cloudtrail_primary[0].arn}/AWSLogs/${var.dev_account_id}/*",
      "${aws_s3_bucket.itgix_cloudtrail_primary[0].arn}/AWSLogs/${var.stage_account_id}/*",
      "${aws_s3_bucket.itgix_cloudtrail_primary[0].arn}/AWSLogs/${var.prod_account_id}/*"
    ]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values = [
        "arn:aws:cloudtrail:${var.aws_region}:${var.security_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.management_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.shared_services_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.audit_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.dev_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.stage_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.prod_account_id}:trail/${var.cloudtrail_name}"
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  # allows logging for an organization trail
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.itgix_cloudtrail_primary[0].arn}/AWSLogs/${var.aws_organization_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values = [
        "arn:aws:cloudtrail:${var.aws_region}:${var.security_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.management_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.shared_services_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.audit_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.dev_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.stage_account_id}:trail/${var.cloudtrail_name}",
        "arn:aws:cloudtrail:${var.aws_region}:${var.prod_account_id}:trail/${var.cloudtrail_name}"
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}