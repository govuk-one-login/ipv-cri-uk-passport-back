resource "aws_kms_key" "signing" {
  description              = "Signing key for messages sent to DCS"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_2048"
  policy                   = data.aws_iam_policy_document.kms_key_access.json
  tags                     = local.default_tags
}

resource "aws_kms_alias" "signing" {
  name          = "alias/${var.environment}/cri/passport/signing"
  target_key_id = aws_kms_key.signing.key_id
}

resource "aws_kms_key" "encryption" {
  description              = "Encryption key for messages from DCS"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "RSA_2048"
  policy                   = data.aws_iam_policy_document.kms_key_access.json
  tags                     = local.default_tags
}

resource "aws_kms_alias" "encryption" {
  name          = "alias/${var.environment}/cri/passport/encryption"
  target_key_id = aws_kms_key.encryption.key_id
}

data "aws_iam_policy_document" "kms_key_access" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
      type        = "AWS"
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "Allow access for Key Administrators"
    effect = "Allow"
    principals {
      identifiers = data.aws_iam_roles.admins.arns
      type        = "AWS"
    }
    actions = [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "Allow use of the key"
    effect = "Allow"
    principals {
      identifiers = concat(tolist(data.aws_iam_roles.admins.arns), [module.passport.iam_role_arn])
      type        = "AWS"
    }
    actions = [
      "kms:DescribeKey",
      "kms:GetPublicKey",
      "kms:Sign",
      "kms:Verify",
      "kms:Encrypt",
      "kms:Decrypt",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "Allow attachment of persistent resources"
    effect = "Allow"
    principals {
      identifiers = data.aws_iam_roles.admins.arns
      type        = "AWS"
    }
    actions = [
      "kms:CreateGrant",
      "kms:ListGrants",
      "kms:RevokeGrant"
    ]
    resources = ["*"]
    condition {
      test     = "Bool"
      values   = ["true"]
      variable = "kms:GrantIsForAWSResource"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_iam_roles" "admins" {
  name_regex = ".*-admin"
}
