variable "aws_region" {
  type        = string
  description = "AWS region for resource deployment"
}

variable "security_account_id" {
  type        = string
  description = "AWS Account ID where the resources are going to be deployed"
}

variable "aws_organization_id" {
  type        = string
  description = "Identifier for AWS Organization"
}

variable "s3_bucket_name" {
  type        = string
  description = "Name of the S3 bucket"
}

variable "expire_s3_objects_after" {
  type        = number
  description = "Days after which S3 objects will expire"
  default     = 730
}

variable "cw_log_retention_days" {
  type        = number
  description = "Retention days for CloudWatch logs"
  default     = 180
}

variable "cloudtrail_enabled" {
  type        = bool
  default     = true
  description = "Whether CloudTrail is enabled"
}

variable "cloudtrail_name" {
  type        = string
  description = "Name of  the CloudTrail"
  default     = "default-cloudtrail"
}

variable "is_organization_trail" {
  type        = bool
  description = "If the trail is for AWS Organization"
  default     = true
}

variable "enable_log_file_validation" {
  type        = bool
  description = "Enables CloudTrail log file validation"
  default     = true
}

variable "cloudtrail_organization_management_account" {
  type        = bool
  default     = false
  description = "Set to true when running from organization management account to configure the cloudtrail delegated admin"
}

variable "cloudtrail_organization_audit_account" {
  type        = bool
  default     = false
  description = "Set to true when running from organization audit account to configure S3 bucket, KMS key and policies for storing and archiving Cloudtrail events in the central audit account"
}

variable "cloudtrail_organization_security_account" {
  type        = bool
  default     = false
  description = "Set to true when running from organization security account to configure the cloudtrail in the organization and invite member accounts"
}

variable "organization_security_account_id" {
  type        = string
  description = "The account ID of the organization security account"
  default     = ""
}
