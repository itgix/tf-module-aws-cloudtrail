output "cloudtrail_s3_bucket_arn" {
  value = try(aws_s3_bucket.itgix_cloudtrail_primary[0].arn, null)
}

output "cloudtrail_s3_kms_arn" {
  value = try(aws_kms_key.cloudtrail_kms[0].arn, null)
}

output "cloudtrail_cw_log_group" {
  value = try(aws_cloudwatch_log_group.itgix_primary_cloudtrail[0].arn, null)
}

output "cloudtrail_cw_iam_role" {
  value = try(aws_iam_role.cloudtrail_access_to_cloudwatch[0].arn, null)
}
