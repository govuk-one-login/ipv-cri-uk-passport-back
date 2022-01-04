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

  allow_access_to_cri_passport_auth_codes_table = true
  cri_passport_auth_codes_table_policy_arn      = aws_iam_policy.policy-cri-passport-auth-codes-table.arn

  allow_access_to_cri_passport_credentials_table = true
  cri_passport_credentials_table_policy_arn      = aws_iam_policy.policy-cri-passport-credentials-table.arn

  env_vars = {
    "DCS_ENCRYPTION_CERT_PARAM"                = aws_ssm_parameter.dcs_encryption_cert.name
    "PASSPORT_CRI_SIGNING_KEY_PARAM"           = "/${var.environment}/cri/passport/signing-key"
    "PASSPORT_CRI_ENCRYPTION_KEY_PARAM"        = "/${var.environment}/cri/passport/encryption-key"
    "PASSPORT_CRI_TLS_KEY_PARAM"               = "/${var.environment}/cri/passport/tls-key"
    "PASSPORT_CRI_SIGNING_CERT_PARAM"          = aws_ssm_parameter.passport_signing_cert.name
    "PASSPORT_CRI_ENCRYPTION_CERT_PARAM"       = aws_ssm_parameter.passport_encryption_cert.name
    "PASSPORT_CRI_TLS_CERT_PARAM"              = aws_ssm_parameter.passport_tls_cert.name
    "CRI_PASSPORT_CREDENTIALS_TABLE_NAME"      = aws_dynamodb_table.cri-passport-credentials.name
    "AUTH_CODES_TABLE_NAME"                    = aws_dynamodb_table.cri-passport-auth-codes.name
    "ACCESS_TOKENS_TABLE_NAME"                 = aws_dynamodb_table.cri-passport-access-tokens.name
    "DCS_POST_URL_PARAM"                       = aws_ssm_parameter.dcs_post_url.name
  }
}

