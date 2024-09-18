# CloudWatch log group
resource "aws_cloudwatch_log_group" "itgix_primary_cloudtrail" {
  count             = var.guardduty_organization_security_account ? 1 : 0
  name              = "${var.cloudtrail_name}-log-group"
  retention_in_days = var.cw_log_retention_days

  depends_on = [
    aws_s3_bucket.itgix_cloudtrail_primary
  ]
}

# CloudTrail config
resource "aws_cloudtrail" "itgix_primary" {
  count                      = var.guardduty_organization_security_account ? 1 : 0
  name                       = var.cloudtrail_name
  is_organization_trail      = var.is_organization_trail
  s3_bucket_name             = aws_s3_bucket.s3_bucket.bucket
  enable_log_file_validation = var.enable_log_file_validation
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.itgix_primary_cloudtrail[0].arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.ct_cw_iam_role.arn
  kms_key_id                 = aws_kms_key.cloudtrail_kms.arn
}
