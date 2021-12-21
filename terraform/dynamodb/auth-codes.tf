module "auth-codes" {
  source      = "../modules/dynamodb"
  environment = var.environment

  table_name = "${var.environment}-cri-passport-auth-codes"
  hash_key   = "authCode"
  range_key  = null
  table_policy_name = "policy-cri-passportauth-codes-table"
  table_policy_sid  = "PolicyCriPassportAuthCodesTable"

  attributes = [
    {
      name = "authCode",
      type = "S",
    },
  ]
}