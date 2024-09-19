output "cloudtrail_s3_bucket_arn" {
  value = try(aws_s3_bucket.itgix_cloudtrail_primary[0].arn, null)
}

output "cloudtrail_s3_kms_arn" {
  value = try(aws_kms_key.cloudtrail_kms[0].arn, null)
}
