# TODO: remove cloudwatch log group because it doesn't work cross account from cloudtrail
# CloudWatch log group where Clodutrail logs will be stored - can be stored either in Cloudwatch or S3 or both
#resource "aws_cloudwatch_log_group" "itgix_primary_cloudtrail" {
#count             = var.cloudtrail_organization_audit_account ? 1 : 0
#name              = var.cloudtrail_log_group_name
#retention_in_days = var.cloudtrail_log_retention_days

#depends_on = [
#aws_s3_bucket.itgix_cloudtrail_primary
#]
#}
