module "passport" {
  source      = "../modules/endpoint"
  environment = var.environment

  rest_api_id            = aws_api_gateway_rest_api.ipv_cri_uk_passport.id
  rest_api_execution_arn = aws_api_gateway_rest_api.ipv_cri_uk_passport.execution_arn
  root_resource_id       = aws_api_gateway_rest_api.ipv_cri_uk_passport.root_resource_id
  http_method            = "POST"
  path_part              = "passport"
  handler                = "uk.gov.di.ipv.cri.passport.lambda.PassportHandler::handleRequest"
  function_name          = "${var.environment}-passport"
  role_name              = "${var.environment}-passport-role"

  env_vars = {
    "DCS_ENCRYPTION_CERT_PARAM"                = aws_ssm_parameter.dcs_encryption_cert.name
    "PASSPORT_CRI_ENCRYPTION_CERT_PARAM"       = "/${var.environment}/cri/passport/alpha-dcs-encryption-cert"
    "PASSPORT_CRI_ENCRYPTION_KEY_PARAM"        = "/${var.environment}/cri/passport/alpha-dcs-encryption-key"
    "PASSPORT_CRI_SIGNING_CERT_PARAM"          = "/${var.environment}/cri/passport/alpha-dcs-signing-cert"
    "PASSPORT_CRI_SIGNING_KEY_PARAM"           = "/${var.environment}/cri/passport/alpha-dcs-signing-key"
    "PASSPORT_CRI_TLS_CERT_PARAM"              = "/${var.environment}/cri/passport/alpha-dcs-tls-cert"
    "PASSPORT_CRI_TLS_KEY_PARAM"               = "/${var.environment}/cri/passport/alpha-dcs-tls-key"
    "PASSPORT_CRI_KMS_SIGNING_KEY_ID_PARAM"    = aws_kms_key.signing.id,
    "PASSPORT_CRI_KMS_ENCRYPTION_KEY_ID_PARAM" = aws_kms_key.encryption.id,
    "PASSPORT_CRI_KMS_SIGNING_CERT_PARAM"      = aws_ssm_parameter.passport_signing_cert.name
    "PASSPORT_CRI_KMS_ENCRYPTION_CERT_PARAM"   = aws_ssm_parameter.passport_encryption_cert.name
    "PASSPORT_CRI_TLS_KEY_PARAM"               = aws_ssm_parameter.passport_tls_key.name
    "PASSPORT_CRI_TLS_CERT_PARAM"              = aws_ssm_parameter.passport_tls_cert.name
  }
}

