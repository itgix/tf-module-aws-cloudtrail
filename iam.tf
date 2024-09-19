# IAM Role for CloudTrail to have access to CloudWatch logs
resource "aws_iam_role" "cloudtrail_access_to_cloudwatch" {
  count              = var.cloudtrail_organization_security_account ? 1 : 0
  name               = "CloudTrailRoleForCloudWatchLogs_${var.cloudtrail_name}"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_logs[0].json
}

# Policy document for CloudTrail IAM Role
data "aws_iam_policy_document" "cloudtrail_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

# IAM Policy allowing CloudTrail to create logs
resource "aws_iam_policy" "cloudtrail_access_to_cloudwatch_policy" {
  count  = var.cloudtrail_organization_security_account ? 1 : 0
  name   = "CloudTrailCloudWatchLogsPolicy"
  policy = data.aws_iam_policy_document.cloudtrail_logs[0].json
}

# Policy document for CloudTrail to create logs
data "aws_iam_policy_document" "cloudtrail_logs" {
  count   = var.cloudtrail_organization_security_account ? 1 : 0
  version = "2012-10-17"

  statement {
    sid    = "AWSCloudTrailCreateLogStream2014110"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
    ]
    resources = [
      "arn:aws:logs:${var.aws_region}:${var.security_account_id}:log-group:management-log-group:log-stream:${var.security_account_id}_CloudTrail_${var.aws_region}*",
      "arn:aws:logs:${var.aws_region}:${var.security_account_id}:log-group:management-log-group:log-stream:${var.aws_organization_id}_*",
    ]
  }

  statement {
    sid    = "AWSCloudTrailPutLogEvents20141101"
    effect = "Allow"
    actions = [
      "logs:PutLogEvents",
    ]
    resources = [
      "arn:aws:logs:${var.aws_region}:${var.security_account_id}:log-group:management-log-group:log-stream:${var.security_account_id}_CloudTrail_${var.aws_region}*",
      "arn:aws:logs:${var.aws_region}:${var.security_account_id}:log-group:management-log-group:log-stream:${var.aws_organization_id}_*",
    ]
  }
}

# Attach IAM policy to the CloudTrail IAM Role
resource "aws_iam_role_policy_attachment" "ct_cw_iam_role_policy_attachment" {
  role       = aws_iam_role.cloudtrail_access_to_cloudwatch[0].name
  policy_arn = aws_iam_policy.cloudtrail_access_to_cloudwatch_policy[0].arn
}
