# TO DO: S3 needs to be in logging account

# S3 bucket to store CloudTrail logs
resource "aws_s3_bucket" "s3_bucket" {
  bucket = var.s3_bucket_name
}

# Attaching policy to S3 bucket allowing CloudTrail to write logs in it 
resource "aws_s3_bucket_policy" "s3_bucket_policy" {
  bucket = aws_s3_bucket.s3_bucket.bucket
  policy = data.aws_iam_policy_document.s3_policy_document.json
}

# S3 bucket lifecycle rule
resource "aws_s3_bucket_lifecycle_configuration" "s3_bucket_lifecycle" {
  bucket = aws_s3_bucket.s3_bucket.bucket
  rule {
    id     = "expire-objects-older-than-two-years"
    status = "Enabled"

    expiration {
      days = var.expire_s3_objects_after
    }
  }
}

# Policy document for S3 bucket
data "aws_iam_policy_document" "s3_policy_document" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = ["arn:aws:s3:::${aws_s3_bucket.s3_bucket.bucket}"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${var.account_id}:trail/${var.cloudtrail_name}"]
    }
  }
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${aws_s3_bucket.s3_bucket.bucket}/AWSLogs/${var.aws_organization_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${var.account_id}:trail/${var.cloudtrail_name}"]
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
    resources = ["arn:aws:s3:::${aws_s3_bucket.s3_bucket.bucket}/AWSLogs/${var.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${var.account_id}:trail/${var.cloudtrail_name}"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

# CloudWatch log group
resource "aws_cloudwatch_log_group" "cw_log_group" {
  name              = "${var.cloudtrail_name}-log-group"
  depends_on        = [aws_s3_bucket.s3_bucket]
  retention_in_days = var.cw_log_retention_days
}

# IAM Role for CloudTrail to have access to CloudWatch logs
resource "aws_iam_role" "ct_cw_iam_role" {
  name               = "CloudTrailRoleForCloudWatchLogs_${var.cloudtrail_name}"
  assume_role_policy = data.aws_iam_policy_document.ct_role_policy_document.json
}

# Policy document for CloudTrail IAM Role
data "aws_iam_policy_document" "ct_role_policy_document" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

# IAM Policy allowing CloudTrail to create logs
resource "aws_iam_policy" "ct_cw_logs_policy" {
  name   = "CloudTrailCloudWatchLogsPolicy"
  policy = data.aws_iam_policy_document.ct_cw_logs_policy_document.json
}

# Policy document for CloudTrail to create logs
data "aws_iam_policy_document" "ct_cw_logs_policy_document" {
  version = "2012-10-17"

  statement {
    sid    = "AWSCloudTrailCreateLogStream2014110"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
    ]
    resources = [
      "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:management-log-group:log-stream:${var.account_id}_CloudTrail_${var.aws_region}*",
      "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:management-log-group:log-stream:${var.aws_organization_id}_*",
    ]
  }

  statement {
    sid    = "AWSCloudTrailPutLogEvents20141101"
    effect = "Allow"
    actions = [
      "logs:PutLogEvents",
    ]
    resources = [
      "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:management-log-group:log-stream:${var.account_id}_CloudTrail_${var.aws_region}*",
      "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:management-log-group:log-stream:${var.aws_organization_id}_*",
    ]
  }
}

# Attaching IAM policy to the CloudTrail IAM Role
resource "aws_iam_role_policy_attachment" "ct_cw_iam_role_policy_attachment" {
  role       = aws_iam_role.ct_cw_iam_role.name
  policy_arn = aws_iam_policy.ct_cw_logs_policy.arn
}

# TO DO: KMS needs to be in logging account
# KMS key to encrypt CloudTrail logs
resource "aws_kms_key" "cloudtrail_kms" {
  description         = "A KMS key used to encrypt CloudTrail log files stored in S3."
  enable_key_rotation = "true"
  policy              = data.aws_iam_policy_document.kms.json
}

# Policy document for the KMS key used in CloudTrail
data "aws_iam_policy_document" "kms" {
  version = "2012-10-17"
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
  statement {
    sid    = "Allow CloudTrail to encrypt logs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:logs:cloudtrail:*:${var.account_id}:trail/*"]
    }
  }

  statement {
    sid    = "Allow CloudTrail to describe key"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:DescribeKey"]
    resources = ["*"]
  }

  statement {
    sid    = "Allow principals in the account to decrypt log files"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:Decrypt",
      "kms:ReEncryptFrom"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [var.account_id]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:logs:cloudtrail:*:${var.account_id}:trail/*"]
    }
  }

  statement {
    sid    = "Allow alias creation during setup"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["kms:CreateAlias"]
    resources = ["*"]
  }
}

# CloudTrail config
resource "aws_cloudtrail" "default" {
  name                       = var.cloudtrail_name
  is_organization_trail      = var.is_organization_trail
  s3_bucket_name             = aws_s3_bucket.s3_bucket.bucket
  enable_log_file_validation = var.enable_log_file_validation
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cw_log_group.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.ct_cw_iam_role.arn
  kms_key_id                 = aws_kms_key.cloudtrail_kms.arn
}
















