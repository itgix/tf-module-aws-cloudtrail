# CloudTrail config
resource "aws_cloudtrail" "itgix_primary" {
  count = var.cloudtrail_organization_security_account ? 1 : 0
  name  = var.cloudtrail_name

  # s3 bucket to store cloudtrail logs
  s3_bucket_name             = var.cloudtrail_s3_bucket_name
  enable_log_file_validation = var.enable_log_file_validation

  kms_key_id = var.cloudtrail_s3_kms_arn

  # whether the trail is an AWS Organizations trail. Organization trails log events for the master account and all member accounts. Can only be created in the organization master account.
  is_organization_trail = var.is_organization_trail

  # enable global service events like IAM
  include_global_service_events = var.include_global_service_events

  is_multi_region_trail = var.is_multi_region_trail

  # cloudwatch logging
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.itgix_primary_cloudtrail[0].arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.itgix_iam_role_for_cloudtrail[0].arn
}
