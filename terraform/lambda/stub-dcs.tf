module "stub-dcs" {
  count      = var.use_localstack ? 1 : 0
  source      = "../modules/endpoint"
  environment = var.environment

  rest_api_id            = aws_api_gateway_rest_api.ipv_cri_uk_passport.id
  rest_api_execution_arn = aws_api_gateway_rest_api.ipv_cri_uk_passport.execution_arn
  root_resource_id       = aws_api_gateway_rest_api.ipv_cri_uk_passport.root_resource_id
  http_method            = "POST"
  path_part              = "stub-dcs-check-passport"
  handler                = "uk.gov.di.ipv.cri.passport.lambda.StubDcsHandler::handleRequest"
  function_name          = "${var.environment}-stub-dcs"
  role_name              = "${var.environment}-stub-dcs-role"

  env_vars = {
    "DCS_SIGNING_CERT_PARAM"             = aws_ssm_parameter.dcs_signing_cert.name
    "STUB_DCS_SIGNING_KEY_PARAM"         = aws_ssm_parameter.stub_dcs_signing_key[0].name
    "STUB_DCS_ENCRYPTION_KEY_PARAM"      = aws_ssm_parameter.stub_dcs_encryption_key[0].name
    "PASSPORT_CRI_SIGNING_CERT_PARAM"    = aws_ssm_parameter.passport_signing_cert.name
    "PASSPORT_CRI_ENCRYPTION_CERT_PARAM" = aws_ssm_parameter.passport_encryption_cert.name
  }
}

