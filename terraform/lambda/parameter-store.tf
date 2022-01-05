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

resource "aws_ssm_parameter" "dcs_tls_intermediate_cert" {
  name        = "/${var.environment}/dcs/tls-intermediate-certificate"
  description = "The DCS's tls certificate chain intermediate cert"
  type        = "String"
  value       = var.dcs_tls_intermediate_cert
}

resource "aws_ssm_parameter" "dcs_tls_root_cert" {
  name        = "/${var.environment}/dcs/tls-root-certificate"
  description = "The DCS's tls certificate chain root cert"
  type        = "String"
  value       = var.dcs_tls_root_cert
}

resource "aws_ssm_parameter" "dcs_post_url" {
  name        = "/${var.environment}/dcs/post-url"
  description = "The DCS's url for passport valid check"
  type        = "String"
  value       = var.dcs_post_url
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
          "arn:aws:ssm:eu-west-2:${data.aws_caller_identity.current.account_id}:parameter/${var.environment}/cri/passport/tls-key",
          aws_ssm_parameter.passport_tls_cert.arn,
          "arn:aws:ssm:eu-west-2:${data.aws_caller_identity.current.account_id}:parameter/${var.environment}/cri/passport/signing-key",
          aws_ssm_parameter.passport_signing_cert.arn,
          "arn:aws:ssm:eu-west-2:${data.aws_caller_identity.current.account_id}:parameter/${var.environment}/cri/passport/encryption-key",
          aws_ssm_parameter.passport_encryption_cert.arn,
          aws_ssm_parameter.dcs_encryption_cert.arn,
          aws_ssm_parameter.dcs_tls_intermediate_cert.arn,
          aws_ssm_parameter.dcs_tls_root_cert.arn
        ]
      }
    ]
  })
}
