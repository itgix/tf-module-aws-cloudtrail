The Terraform module is used by the ITGix AWS Landing Zone - https://itgix.com/itgix-landing-zone/

# AWS CloudTrail Terraform Module

This module deploys AWS CloudTrail with S3 storage, KMS encryption, CloudWatch Logs integration, and support for AWS Organizations multi-account trails.

Part of the [ITGix AWS Landing Zone](https://itgix.com/itgix-landing-zone/).

## Resources Created

- AWS CloudTrail trail (organization or single-account)
- S3 bucket for CloudTrail log storage (with lifecycle policies)
- KMS key for CloudTrail encryption
- CloudWatch Log Group for CloudTrail logs
- IAM role and policy for CloudTrail-to-CloudWatch delivery

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `aws_region` | AWS region for resource deployment | `string` | — | yes |
| `security_account_id` | AWS Account ID where CloudTrail is deployed (security account) | `string` | `null` | no |
| `management_account_id` | AWS Account ID of the management account | `string` | `null` | no |
| `shared_services_account_id` | AWS Account ID of the shared services account | `string` | `null` | no |
| `logging_and_audit_account_id` | AWS Account ID of the logging and audit account | `string` | `null` | no |
| `dev_account_id` | AWS Account ID of the dev account | `string` | `null` | no |
| `stage_account_id` | AWS Account ID of the stage account | `string` | `null` | no |
| `prod_account_id` | AWS Account ID of the prod account | `string` | `null` | no |
| `aws_organization_id` | Identifier for AWS Organization | `string` | `null` | no |
| `cloudtrail_organization_audit_account` | Set to true when running from organization audit account | `bool` | `false` | no |
| `cloudtrail_organization_security_account` | Set to true when running from organization security account | `bool` | `false` | no |
| `cloudtrail_s3_bucket_name` | Name of the S3 bucket for CloudTrail logs | `string` | `"itgix-landing-zones-cloudtrail-logs"` | no |
| `cloudtrail_expire_s3_logs_after_days` | Days after which S3 objects will expire | `number` | `730` | no |
| `cloudtrail_s3_key_alias` | Alias name for the KMS key | `string` | `"alias/cloudtrail-s3-bucket-key"` | no |
| `cloudtrail_s3_kms_arn` | ARN of KMS key associated with CloudTrail S3 bucket | `string` | `null` | no |
| `cloudtrail_name` | Name of the CloudTrail | `string` | `"itgix-landing-zones"` | no |
| `is_organization_trail` | Whether the trail is an AWS Organizations trail | `bool` | `true` | no |
| `include_global_service_events` | Whether the trail publishes events from global services | `bool` | `true` | no |
| `enable_log_file_validation` | Enables CloudTrail log file validation | `bool` | `true` | no |
| `is_multi_region_trail` | Whether the trail is created in all regions | `bool` | `false` | no |
| `cloudtrail_log_group_name` | CloudWatch Log Group name for CloudTrail logs | `string` | `"/aws/cloudtrail/itgix-landing-zones"` | no |
| `cloudtrail_log_retention_days` | Retention period for CloudTrail logs in CloudWatch (days) | `number` | `7` | no |
| `cloudtrail_iam_role_name` | IAM role name for CloudTrail to CloudWatch delivery | `string` | `"itgix-cloudtrail-to-cloudwatch-role"` | no |
| `cloudtrail_iam_policy_name` | IAM policy name for the CloudTrail IAM role | `string` | `"ITGixCloudTrailLogsPolicy"` | no |

## Outputs

| Name | Description |
|------|-------------|
| `cloudtrail_s3_bucket_arn` | CloudTrail S3 bucket ARN |
| `cloudtrail_s3_kms_arn` | CloudTrail KMS key ARN |
| `cloudtrail_cw_log_group_arn` | CloudWatch Log Group ARN |
| `cloudtrail_cw_iam_role_arn` | IAM role ARN for CloudTrail-to-CloudWatch |

## Usage Example

```hcl
module "cloudtrail" {
  source = "path/to/tf-module-aws-cloudtrail"

  aws_region          = "eu-central-1"
  aws_organization_id = "o-abc123def4"

  cloudtrail_organization_security_account = true
  security_account_id                      = "111111111111"
  management_account_id                    = "222222222222"
  logging_and_audit_account_id             = "333333333333"

  cloudtrail_s3_bucket_name = "my-org-cloudtrail-logs"
  cloudtrail_name           = "my-org-trail"
  is_organization_trail     = true
}
```
