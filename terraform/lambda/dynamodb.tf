resource "aws_dynamodb_table" "dcs-response" {
  name         = "${var.environment}-dcs-response"
  hash_key     = "resourceId"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "resourceId"
    type = "S"
  }

  tags = local.default_tags
}

resource "aws_dynamodb_table" "cri-passport-auth-codes" {
  name         = "${var.environment}-cri-passport-auth-codes"
  hash_key     = "authCode"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "authCode"
    type = "S"
  }

  tags = local.default_tags
}

resource "aws_dynamodb_table" "cri-passport-access-tokens" {
  name         = "${var.environment}-cri-passport-access-tokens"
  hash_key     = "accessToken"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "accessToken"
    type = "S"
  }

  tags = local.default_tags
}

resource "aws_iam_policy" "policy-dcs-response-table" {
  name = "policy-dcs-response-table"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "PolicyDcsResponseTable"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:BatchWriteItem",
          "dynamodb:GetItem",
          "dynamodb:BatchGetItem",
          "dynamodb:Scan",
          "dynamodb:Query",
          "dynamodb:ConditionCheckItem"
        ]
        Effect = "Allow"
        Resource = [
          aws_dynamodb_table.dcs-response.arn,
          "${aws_dynamodb_table.dcs-response.arn}/index/*"
        ]
      },
    ]
  })
}

resource "aws_iam_policy" "policy-cri-passport-auth-codes-table" {
  name = "policy-cri-passport-auth-codes-table"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "PolicyCriPassportAuthCodesTable"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query"
        ]
        Effect = "Allow"
        Resource = [
          aws_dynamodb_table.cri-passport-auth-codes.arn,
          "${aws_dynamodb_table.cri-passport-auth-codes.arn}/index/*"
        ]
      },
    ]
  })
}

resource "aws_iam_policy" "policy-cri-passport-access-tokens-table" {
  name = "policy-cri-passport-access-tokens-table"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "PolicyCriPassportAccessTokensTable"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query"
        ]
        Effect = "Allow"
        Resource = [
          aws_dynamodb_table.cri-passport-access-tokens.arn,
          "${aws_dynamodb_table.cri-passport-access-tokens.arn}/index/*"
        ]
      },
    ]
  })
}
