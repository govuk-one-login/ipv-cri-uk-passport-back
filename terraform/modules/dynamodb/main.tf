resource "aws_dynamodb_table" "dynamodb-table" {
  name         = var.table_name
  hash_key     = var.hash_key
  range_key    = var.range_key
  billing_mode = "PAY_PER_REQUEST"

  dynamic "attribute" {
    for_each = var.attributes
    content {
      name = attribute.value.name
      type = attribute.value.type
    }
  }

  tags = local.default_tags
}

resource "aws_iam_policy" "policy-dynamodb-table" {
  name = var.table_policy_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = var.table_policy_sid
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
          aws_dynamodb_table.dynamodb-table.arn,
          "${aws_dynamodb_table.dynamodb-table.arn}/index/*"
        ]
      },
    ]
  })
}
