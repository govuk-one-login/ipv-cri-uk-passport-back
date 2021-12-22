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

resource "aws_ssm_parameter" "dcs_post_url" {
  name        = "/${var.environment}/dcs/post-url"
  description = "The DCS's endpoint URL"
  type        = "String"
  value       = var.dcs_post_url
}

resource "aws_iam_role_policy" "get_parameters" {
  name   = "get-parameters"
  role   = module.passport.iam_role_id
  policy = data.aws_iam_policy_document.get_parameters_policy.json
}

data "aws_iam_policy_document" "get_parameters_policy" {
  version = "2012-10-17"

  statement {
    sid    = "AllowGetParameters"
    effect = "Allow"

    actions = [
      "sts:AssumeRole"
    ]

    resources = [
      "arn:aws:ssm:eu-west-2:${data.aws_caller_identity.current.account_id}:parameter/dev/cri/passport/tls-key",
      aws_ssm_parameter.passport_tls_cert.arn,
      "arn:aws:ssm:eu-west-2:${data.aws_caller_identity.current.account_id}:parameter/dev/cri/passport/signing-key",
      aws_ssm_parameter.passport_signing_cert.arn,
      "arn:aws:ssm:eu-west-2:${data.aws_caller_identity.current.account_id}:parameter/dev/cri/passport/encryption-key",
      aws_ssm_parameter.passport_encryption_cert.arn,
      aws_ssm_parameter.dcs_encryption_cert.arn
    ]
  }
}
