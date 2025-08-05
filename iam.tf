resource "aws_iam_role" "itgix_iam_role_for_cloudtrail" {
  count = var.cloudtrail_organization_security_account ? 1 : 0
  name  = var.cloudtrail_iam_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role_policy" "itgix_iam_policy_for_cloudtrail" {
  count = var.cloudtrail_organization_security_account ? 1 : 0
  name  = var.cloudtrail_iam_policy_name
  role  = aws_iam_role.itgix_iam_role_for_cloudtrail[0].id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:${var.cloudtrail_log_group_name}:*"
      },
      {
        Effect = "Allow",
        Action = [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ],
        Resource = "*"
      }
    ]
  })
}
