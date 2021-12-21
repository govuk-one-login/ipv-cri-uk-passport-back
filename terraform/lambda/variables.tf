variable "environment" {
  type = string
}

variable "use_localstack" {
  type    = bool
  default = false
}

variable "passport_tls_cert" { type = string }

variable "passport_signing_cert" { type = string }

variable "passport_encryption_cert" { type = string }

variable "dcs_encryption_cert" { type = string }

variable "attributes" {
  default = [
    {
      name = "authCode",
      type = "S",
    },
  ]
  type = list(object({ name = string, type = string }))
}

locals {
  default_tags = var.use_localstack ? null : {
    Environment = var.environment
    Source      = "github.com/alphagov/di-ipv-cri-uk-passport-back/terraform/lambda"
  }
}

data "aws_caller_identity" "current" { }

