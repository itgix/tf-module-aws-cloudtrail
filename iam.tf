# TODO: remove cloudwatch log group because it doesn't work cross account from cloudtrail
## IAM Role for CloudTrail to have access to CloudWatch logs in the Audit account
#resource "aws_iam_role" "cloudtrail_access_to_cloudwatch" {
#count              = var.cloudtrail_organization_audit_account ? 1 : 0
#name               = "CloudTrailRoleForCloudWatchLogs-${var.cloudtrail_name}"
#assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume_role[0].json
#}

## Policy document for CloudTrail IAM Role
#data "aws_iam_policy_document" "cloudtrail_assume_role" {
#count = var.cloudtrail_organization_audit_account ? 1 : 0
#statement {
#actions = ["sts:AssumeRole"]

#principals {
#type        = "Service"
#identifiers = ["cloudtrail.amazonaws.com"]
#}

#principals {
#type        = "AWS"
#identifiers = var.assume_role_principals
#}
#}
#}

## IAM Policy allowing CloudTrail to create logs
#resource "aws_iam_policy" "cloudtrail_access_to_cloudwatch_policy" {
#count  = var.cloudtrail_organization_audit_account ? 1 : 0
#name   = "CloudTrailCloudWatchLogsPolicy"
#policy = data.aws_iam_policy_document.cloudtrail_logs[0].json
#}

## Policy document for CloudTrail to create logs
#data "aws_iam_policy_document" "cloudtrail_logs" {
#count   = var.cloudtrail_organization_audit_account ? 1 : 0
#version = "2012-10-17"

#statement {
#sid    = "AWSCloudTrailLogs"
#effect = "Allow"
#actions = [
#"logs:CreateLogStream",
#"logs:PutLogEvents",
#]
#resources = [
##"arn:aws:logs:${var.aws_region}:${var.security_account_id}:log-group:cloudtrail-logs:log-stream:${var.security_account_id}_CloudTrail_${var.aws_region}*",
##"arn:aws:logs:${var.aws_region}:${var.security_account_id}:log-group:cloudtrail-logs:log-stream:${var.aws_organization_id}_*",
#"${aws_cloudwatch_log_group.itgix_primary_cloudtrail[0].arn}:log-stream:${var.security_account_id}_CloudTrail_${var.aws_region}*",
#"${aws_cloudwatch_log_group.itgix_primary_cloudtrail[0].arn}:log-stream:${var.aws_organization_id}_*",
#]
#}
#}

## Attach IAM policy to the CloudTrail IAM Role
#resource "aws_iam_role_policy_attachment" "cloudtrail_to_cloudwatch_access" {
#count      = var.cloudtrail_organization_audit_account ? 1 : 0
#role       = aws_iam_role.cloudtrail_access_to_cloudwatch[0].name
#policy_arn = aws_iam_policy.cloudtrail_access_to_cloudwatch_policy[0].arn
#}
