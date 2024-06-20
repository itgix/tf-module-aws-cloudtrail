variable "aws_region" {
  type        = string
  description = "AWS region for resource deployment"
}

variable "account_id" {
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

