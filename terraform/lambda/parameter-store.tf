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

resource "aws_ssm_parameter" "dcs_signing_cert" {
  name        = "/${var.environment}/dcs/signing-cert"
  description = "The DCS's public signing cert"
  type        = "String"
  value       = var.dcs_signing_cert
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
  value       = var.use_localstack ? "http://localhost:4567/restapis/${aws_api_gateway_rest_api.ipv_cri_uk_passport.id}/local-dev/_user_request_/stub-dcs-check-passport" : var.dcs_post_url
}

resource "aws_ssm_parameter" "stub_dcs_signing_key" {
  count      = var.use_localstack ? 1 : 0
  name        = "/${var.environment}/stub-dcs/signing-key"
  description = "The signing key used by the stub DCS"
  type        = "SecureString"
  value       = var.stub_dcs_signing_key
}

resource "aws_ssm_parameter" "stub_dcs_encryption_key" {
  count      = var.use_localstack ? 1 : 0
  name        = "/${var.environment}/stub-dcs/encryption-key"
  description = "The encryption key used by the stub DCS"
  type        = "SecureString"
  value       = var.stub_dcs_encryption_key
}

resource "aws_ssm_parameter" "local_only_passport_signing_key" {
  count      = var.use_localstack ? 1 : 0
  name        = "/${var.environment}/cri/passport/signing-key"
  description = "The signing key used by the passport CRI when running in local stack."
  type        = "SecureString"
  value       = var.local_only_passport_signing_key
}

resource "aws_ssm_parameter" "local_only_passport_encryption_key" {
  count      = var.use_localstack ? 1 : 0
  name        = "/${var.environment}/cri/passport/encryption-key"
  description = "The encryption key used by the passport CRI when running in local stack."
  type        = "SecureString"
  value       = var.local_only_passport_encryption_key
}

resource "aws_ssm_parameter" "local_only_passport_tls_key" {
  count      = var.use_localstack ? 1 : 0
  name        = "/${var.environment}/cri/passport/tls-key"
  description = "The tls key used by the passport CRI when running in local stack."
  type        = "SecureString"
  value       = var.local_only_passport_tls_key
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
          aws_ssm_parameter.dcs_signing_cert.arn,
          aws_ssm_parameter.dcs_tls_intermediate_cert.arn,
          aws_ssm_parameter.dcs_tls_root_cert.arn,
          aws_ssm_parameter.dcs_post_url.arn
        ]
      }
    ]
  })
}
