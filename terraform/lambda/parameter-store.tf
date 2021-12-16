resource "aws_ssm_parameter" "passport_tls_key" {
  name        = "/${var.environment}/cri/passport/tls-key"
  description = "The TLS key used by the passport CRI"
  type        = "SecureString"
  value       = "" # Will be set by hand
  overwrite   = false
}

resource "aws_ssm_parameter" "passport_tls_cert" {
  name        = "/${var.environment}/cri/passport/tls-cert"
  description = "The TLS certificate used by the passport CRI"
  type        = "String"
  value       = "" # Will be set by hand after a cert has been issued
  overwrite   = false
}

resource "aws_ssm_parameter" "passport_signing_cert" {
  name        = "/${var.environment}/cri/passport/signing-cert"
  description = "The signing certificate used by the passport CRI"
  type        = "String"
  value       = "" # Will be set by hand after a cert has been issued
  overwrite   = false
}

resource "aws_ssm_parameter" "passport_encryption_cert" {
  name        = "/${var.environment}/cri/passport/signing-cert"
  description = "The encryption certificate used by the passport CRI"
  type        = "String"
  value       = "" # Will be set by hand after a cert has been issued
  overwrite   = false
}

resource "aws_ssm_parameter" "dcs_encryption_cert" {
  name        = "/${var.environment}/dcs/encryption-cert"
  description = "The DCS's public encryption cert"
  type        = "String"
  value       = "" # Will be set by hand
  overwrite   = false
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
          aws_ssm_parameter.passport_tls_key.arn,
          aws_ssm_parameter.passport_tls_cert.arn,
          aws_ssm_parameter.passport_signing_cert.arn,
          aws_ssm_parameter.passport_encryption_cert.arn,
          aws_ssm_parameter.dcs_encryption_cert.arn
        ]
      }
    ]
  })
}
