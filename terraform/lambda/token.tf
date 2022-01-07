module "token" {
  source      = "../modules/endpoint"
  environment = var.environment

  rest_api_id            = aws_api_gateway_rest_api.ipv_cri_uk_passport.id
  rest_api_execution_arn = aws_api_gateway_rest_api.ipv_cri_uk_passport.execution_arn
  root_resource_id       = aws_api_gateway_rest_api.ipv_cri_uk_passport.root_resource_id
  http_method            = "POST"
  path_part              = "token"
  handler                = "uk.gov.di.ipv.cri.passport.lambda.AccessTokenHandler::handleRequest"
  function_name          = "${var.environment}-dcs-token"
  role_name              = "${var.environment}-dcs-token-role"

  allow_access_to_cri_passport_auth_codes_table = true
  cri_passport_auth_codes_table_policy_arn      = aws_iam_policy.policy-cri-passport-auth-codes-table.arn

  allow_access_to_cri_passport_access_tokens_table = true
  cri_passport_access_tokens_table_policy_arn      = aws_iam_policy.policy-cri-passport-access-tokens-table.arn

  env_vars = {
    "CRI_PASSPORT_AUTH_CODES_TABLE_NAME"    = aws_dynamodb_table.cri-passport-auth-codes.name
    "CRI_PASSPORT_ACCESS_TOKENS_TABLE_NAME" = aws_dynamodb_table.cri-passport-access-tokens.name
  }
}
