resource "aws_ssm_parameter" "passport_tls_cert" {
  name        = "/${var.environment}/cri/passport/tls-cert"
  description = "The TLS certificate used by the passport CRI"
  type        = "String"
  value       = var.passport_tls_cert
}

resource "aws_ssm_parameter" "passport_signing_cert" {
  name        = "/${var.environment}/cri/passport/signing-cert"
  description = "The signing certificate used by the passport CRI"
  type        = "String"
  value       = var.passport_signing_cert
}

resource "aws_ssm_parameter" "passport_encryption_cert" {
  name        = "/${var.environment}/cri/passport/encryption-cert"
  description = "The encryption certificate used by the passport CRI"
  type        = "String"
  value       = var.passport_encryption_cert
}

resource "aws_ssm_parameter" "dcs_encryption_cert" {
  name        = "/${var.environment}/dcs/encryption-cert"
  description = "The DCS's public encryption cert"
  type        = "String"
  value       = var.dcs_encryption_cert
}

resource "aws_iam_role_policy" "get-parameters" {
  name = "get-parameters"
  role = module.passport.iam_role_id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "GetParameters"
        Action = [
          "ssm:GetParameter"
        ]
        Effect = "Allow"
        Resource = [
          "arn:aws:ssm:eu-west-2:${data.aws_caller_identity.current.account_id}:parameter/dev/cri/passport/tls-key",
          aws_ssm_parameter.passport_tls_cert.arn,
          aws_ssm_parameter.passport_signing_cert.arn,
          aws_ssm_parameter.passport_encryption_cert.arn,
          aws_ssm_parameter.dcs_encryption_cert.arn
        ]
      }
    ]
  })
}
