# The application's own role (IRSA): read its one secret, decrypt with the project key, invoke
# the approved Bedrock models. Nothing else; no wildcards on actions or resources.
locals {
  oidc = replace(aws_iam_openid_connect_provider.eks.url, "https://", "")
}

resource "aws_secretsmanager_secret" "app" {
  #checkov:skip=CKV2_AWS_57:Holds connector tokens issued by third-party SaaS admins; they are rotated by the connector runbook (docs/RUNBOOK.md), not by a Lambda. The database master password is rotated by RDS (manage_master_user_password).
  name       = "irg/${var.environment}/app"
  kms_key_id = aws_kms_key.this.arn
}

resource "aws_iam_role" "app" {
  name = "${var.name}-app"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow", Action = "sts:AssumeRoleWithWebIdentity",
      Principal = { Federated = aws_iam_openid_connect_provider.eks.arn },
      Condition = { StringEquals = { "${local.oidc}:sub" = "system:serviceaccount:irg:irg", "${local.oidc}:aud" = "sts.amazonaws.com" } }
    }]
  })
}

resource "aws_iam_role_policy" "app" {
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "ReadOwnSecret", Effect = "Allow", Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"], Resource = aws_secretsmanager_secret.app.arn },
      { Sid = "DecryptWithProjectKey", Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.this.arn },
      { Sid = "ExplainFindings", Effect = "Allow", Action = ["bedrock:InvokeModel"], Resource = var.bedrock_model_arns },
    ]
  })
}
