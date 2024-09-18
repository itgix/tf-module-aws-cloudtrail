resource "aws_cloudtrail_organization_delegated_admin_account" "security" {
  count      = var.guardduty_organization_management_account ? 1 : 0
  account_id = var.organization_security_account_id
}
