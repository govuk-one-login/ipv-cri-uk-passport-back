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


  dcs_integration_encryption_cert_param = "/${var.environment}/dcs/integration-encryption-cert"
  dcs_encryption_cert_param             = "/${var.environment}/cri/passport/alpha-dcs-encryption-cert"
  dcs_encryption_key_param              = "/${var.environment}/cri/passport/alpha-dcs-encryption-key"
  dcs_signing_cert_param                = "/${var.environment}/cri/passport/alpha-dcs-signing-cert"
  dcs_signing_key_param                 = "/${var.environment}/cri/passport/alpha-dcs-signing-key"
  dcs_tls_cert_param                    = "/${var.environment}/cri/passport/alpha-dcs-tls-cert"
  dcs_tls_key_param                     = "/${var.environment}/cri/passport/alpha-dcs-tls-key"
}

