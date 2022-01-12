module "dcs-credential" {
  source      = "../modules/endpoint"
  environment = var.environment

  rest_api_id            = aws_api_gateway_rest_api.ipv_cri_uk_passport.id
  rest_api_execution_arn = aws_api_gateway_rest_api.ipv_cri_uk_passport.execution_arn
  root_resource_id       = aws_api_gateway_rest_api.ipv_cri_uk_passport.root_resource_id
  http_method            = "GET"
  path_part              = "credential"
  handler                = "uk.gov.di.ipv.cri.passport.lambda.DcsCredentialHandler::handleRequest"
  function_name          = "${var.environment}-dcs-credential"
  role_name              = "${var.environment}-dcs-credential-role"

  allow_access_to_cri_passport_access_tokens_table = true
  cri_passport_access_tokens_table_policy_arn      = aws_iam_policy.policy-cri-passport-access-tokens-table.arn
  allow_access_to_dcs_response_table               = true
  dcs_response_table_policy_arn                    = aws_iam_policy.policy-dcs-response-table.arn

  env_vars = {
    "DCS_RESPONSE_TABLE_NAME"    = aws_dynamodb_table.dcs-response.name
    "CRI_PASSPORT_ACCESS_TOKENS_TABLE_NAME" = aws_dynamodb_table.cri-passport-access-tokens.name
  }
}

