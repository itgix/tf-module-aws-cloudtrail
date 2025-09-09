The Terraform module is used by the ITGix AWS Landing Zone - https://itgix.com/itgix-landing-zone/

<!-- BEGIN_TF_DOCS -->
## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_cloudtrail.itgix_primary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail) | resource |
| [aws_cloudwatch_log_group.itgix_primary_cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_iam_role.itgix_iam_role_for_cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.itgix_iam_policy_for_cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_kms_alias.cloudtrail_key_alias](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias) | resource |
| [aws_kms_key.cloudtrail_kms](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_s3_bucket.itgix_cloudtrail_primary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_lifecycle_configuration.s3_bucket_lifecycle](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_lifecycle_configuration) | resource |
| [aws_s3_bucket_policy.s3_bucket_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.cloudtrail_kms](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.cloudtrail_s3](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_audit_account_id"></a> [audit\_account\_id](#input\_audit\_account\_id) | AWS Account ID of the management account for additional permissions | `string` | `null` | no |
| <a name="input_aws_organization_id"></a> [aws\_organization\_id](#input\_aws\_organization\_id) | Identifier for AWS Organization | `string` | `null` | no |
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | AWS region for resource deployment | `string` | `"eu-central-1"` | no |
| <a name="input_cloudtrail_enabled"></a> [cloudtrail\_enabled](#input\_cloudtrail\_enabled) | Whether CloudTrail is enabled | `bool` | `true` | no |
| <a name="input_cloudtrail_expire_s3_logs_after_days"></a> [cloudtrail\_expire\_s3\_logs\_after\_days](#input\_cloudtrail\_expire\_s3\_logs\_after\_days) | Days after which S3 objects will expire | `number` | `730` | no |
| <a name="input_cloudtrail_iam_policy_name"></a> [cloudtrail\_iam\_policy\_name](#input\_cloudtrail\_iam\_policy\_name) | Name of the IAM policy attached to the CloudTrail-to-CloudWatch IAM role | `string` | `"ITGixCloudTrailLogsPolicy"` | no |
| <a name="input_cloudtrail_iam_role_name"></a> [cloudtrail\_iam\_role\_name](#input\_cloudtrail\_iam\_role\_name) | Name of the IAM role used by CloudTrail to deliver logs to CloudWatch Logs | `string` | `"itgix-cloudtrail-to-cloudwatch-role"` | no |
| <a name="input_cloudtrail_log_group_name"></a> [cloudtrail\_log\_group\_name](#input\_cloudtrail\_log\_group\_name) | The name of the CloudWatch Log Group to which CloudTrail logs will be delivered | `string` | `"/aws/cloudtrail/itgix-landing-zones"` | no |
| <a name="input_cloudtrail_log_retention_days"></a> [cloudtrail\_log\_retention\_days](#input\_cloudtrail\_log\_retention\_days) | Number of days to retain CloudTrail logs in CloudWatch Logs | `number` | `7` | no |
| <a name="input_cloudtrail_name"></a> [cloudtrail\_name](#input\_cloudtrail\_name) | Name of  the CloudTrail | `string` | `"itgix-landing-zones"` | no |
| <a name="input_cloudtrail_organization_audit_account"></a> [cloudtrail\_organization\_audit\_account](#input\_cloudtrail\_organization\_audit\_account) | Set to true when running from organization audit account to configure S3 bucket, KMS key and policies for storing and archiving Cloudtrail events in the central audit account | `bool` | `false` | no |
| <a name="input_cloudtrail_organization_security_account"></a> [cloudtrail\_organization\_security\_account](#input\_cloudtrail\_organization\_security\_account) | Set to true when running from organization security account to configure the cloudtrail in the organization and invite member accounts | `bool` | `false` | no |
| <a name="input_cloudtrail_s3_bucket_name"></a> [cloudtrail\_s3\_bucket\_name](#input\_cloudtrail\_s3\_bucket\_name) | Name of the S3 bucket where Cloudtrail logs will be stored - can be stored either in Cloudwatch or S3 or both | `string` | `"itgix-landing-zones-cloudtrail-logs"` | no |
| <a name="input_cloudtrail_s3_key_alias"></a> [cloudtrail\_s3\_key\_alias](#input\_cloudtrail\_s3\_key\_alias) | Alias name to configured on KMS key | `string` | `"alias/cloudtrail-s3-bucket-key"` | no |
| <a name="input_cloudtrail_s3_kms_arn"></a> [cloudtrail\_s3\_kms\_arn](#input\_cloudtrail\_s3\_kms\_arn) | ARN of KMS key associated with Guardduty S3 bucket | `string` | `null` | no |
| <a name="input_dev_account_id"></a> [dev\_account\_id](#input\_dev\_account\_id) | AWS Account ID of the management account for additional permissions | `string` | `null` | no |
| <a name="input_enable_log_file_validation"></a> [enable\_log\_file\_validation](#input\_enable\_log\_file\_validation) | Enables CloudTrail log file validation | `bool` | `true` | no |
| <a name="input_include_global_service_events"></a> [include\_global\_service\_events](#input\_include\_global\_service\_events) | Whether the trail is publishing events from global services such as IAM to the log files | `bool` | `true` | no |
| <a name="input_is_multi_region_trail"></a> [is\_multi\_region\_trail](#input\_is\_multi\_region\_trail) | Whether the trail is created in the current region or in all regions | `bool` | `false` | no |
| <a name="input_is_organization_trail"></a> [is\_organization\_trail](#input\_is\_organization\_trail) | Whether the trail is an AWS Organizations trail. Organization trails log events for the master account and all member accounts. Can only be created in the organization master account. | `bool` | `true` | no |
| <a name="input_management_account_id"></a> [management\_account\_id](#input\_management\_account\_id) | AWS Account ID of the management account for additional permissions | `string` | `null` | no |
| <a name="input_organization_security_account_id"></a> [organization\_security\_account\_id](#input\_organization\_security\_account\_id) | The account ID of the organization security account | `string` | `""` | no |
| <a name="input_prod_account_id"></a> [prod\_account\_id](#input\_prod\_account\_id) | AWS Account ID of the management account for additional permissions | `string` | `null` | no |
| <a name="input_security_account_id"></a> [security\_account\_id](#input\_security\_account\_id) | AWS Account ID where Cloudtrail is deployed - security account | `string` | `null` | no |
| <a name="input_shared_services_account_id"></a> [shared\_services\_account\_id](#input\_shared\_services\_account\_id) | AWS Account ID of the management account for additional permissions | `string` | `null` | no |
| <a name="input_stage_account_id"></a> [stage\_account\_id](#input\_stage\_account\_id) | AWS Account ID of the management account for additional permissions | `string` | `null` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_cloudtrail_cw_iam_role_arn"></a> [cloudtrail\_cw\_iam\_role\_arn](#output\_cloudtrail\_cw\_iam\_role\_arn) | n/a |
| <a name="output_cloudtrail_cw_log_group_arn"></a> [cloudtrail\_cw\_log\_group\_arn](#output\_cloudtrail\_cw\_log\_group\_arn) | n/a |
| <a name="output_cloudtrail_s3_bucket_arn"></a> [cloudtrail\_s3\_bucket\_arn](#output\_cloudtrail\_s3\_bucket\_arn) | n/a |
| <a name="output_cloudtrail_s3_kms_arn"></a> [cloudtrail\_s3\_kms\_arn](#output\_cloudtrail\_s3\_kms\_arn) | n/a |
<!-- END_TF_DOCS -->
