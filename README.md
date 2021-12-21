# Digital Identity IPV UK Passport CRI Backend

`di-ipv-cri-uk-passport-back`

This the back-end code for the UK Passport Credential Issuer(CRI) for the Identity Proofing and Verification (IPV) system within the GDS digital identity platform, GOV.UK Sign In.

## Environment variables

* IS_LOCAL - This only needs to be assigned when running locally. This is set to `true` in `local-startup`.
### DynamoDB table name variables:
Each environment has a specific table name prefix e.g. `dev-{dynamo-table-name}`

These values are automatically assigned by terraform within the `aws_lambda_function` resource
* ACCESS_TOKENS_TABLE_NAME
* AUTH_CODES_TABLE_NAME
* CRI_PASSPORT_CREDENTIALS_TABLE_NAME
