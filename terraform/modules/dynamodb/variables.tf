variable "environment" {
  type = string
}

variable "table_name" {
  type = string
}

variable "hash_key" {
  type = string
}

variable "range_key" {
  type = string
}

variable "attributes" {
  default = [
    {
      name = "TestTableHashKey",
      type = "S",
    },
    {
      name = "TestTableRangeKey",
      type = "S",
    },
  ]
  type = list(object({ name = string, type = string }))
}

variable "table_policy_name" {
  type = string
}

variable "table_policy_sid" {
  type = string
}

locals {
  default_tags = {
    Environment = var.environment
    Source      = "github.com/alphagov/di-ipv-cri-uk-passport-back/terraform/lambda"
  }
}