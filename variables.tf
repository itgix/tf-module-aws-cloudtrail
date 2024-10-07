# Main
variable "aws_region" {
  type        = string
  description = "AWS region for resource deployment"
  default     = "eu-central-1"
}

variable "security_account_id" {
  type        = string
  description = "AWS Account ID where Cloudtrail is deployed - security account"
  default     = null
}

# TODO: check if this is really needed
variable "management_account_id" {
  type        = string
  description = "AWS Account ID of the management account for additional permissions"
  default     = null
}

variable "aws_organization_id" {
  type        = string
  description = "Identifier for AWS Organization"
  default     = null
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

# S3
variable "cloudtrail_s3_bucket_name" {
  type        = string
  description = "Name of the S3 bucket where Cloudtrail logs will be stored - can be stored either in Cloudwatch or S3 or both"
  default     = "itgix-landing-zones-cloudtrail-logs"
}

variable "cloudtrail_expire_s3_logs_after_days" {
  type        = number
  description = "Days after which S3 objects will expire"
  default     = 730
}

# KMS
variable "cloudtrail_s3_key_alias" {
  type        = string
  description = "Alias name to configured on KMS key"
  default     = "alias/cloudtrail-s3-bucket-key"
}

variable "cloudtrail_s3_kms_arn" {
  type        = string
  description = "ARN of KMS key associated with Guardduty S3 bucket"
  default     = null
}

# Cloudtrail
variable "cloudtrail_enabled" {
  type        = bool
  default     = true
  description = "Whether CloudTrail is enabled"
}

variable "cloudtrail_name" {
  type        = string
  description = "Name of  the CloudTrail"
  default     = "itgix-landing-zones"
}

variable "is_organization_trail" {
  type        = bool
  description = "Whether the trail is an AWS Organizations trail. Organization trails log events for the master account and all member accounts. Can only be created in the organization master account."
  default     = true
}

variable "include_global_service_events" {
  type        = bool
  default     = true
  description = "Whether the trail is publishing events from global services such as IAM to the log files"
}

variable "enable_log_file_validation" {
  type        = bool
  description = "Enables CloudTrail log file validation"
  default     = true
}

variable "is_multi_region_trail" {
  type        = bool
  default     = false
  description = "Whether the trail is created in the current region or in all regions"
}
