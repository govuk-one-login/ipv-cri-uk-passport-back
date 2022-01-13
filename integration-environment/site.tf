# For setting up aws infrastructure for integration tests

terraform {
  required_version = "1.0.9"

  backend "local" {}

  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "3.66"
    }
  }
}

provider "aws" {
  access_key                  = "mock_access_key"
  region                      = "eu-west-2"
  s3_force_path_style         = true
  secret_key                  = "mock_secret_key"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    dynamodb   = "http://0.0.0.0:4566"
  }
}

module "cri-passport-lambda" {
  source                             = "../terraform/lambda"
  environment                        = var.environment
  use_localstack                     = true
  dcs_tls_root_cert                  = ""
  passport_tls_cert                  = ""
  local_only_passport_tls_key        = ""
  passport_signing_cert              = ""
  local_only_passport_signing_key    = ""
  passport_encryption_cert           = ""
  local_only_passport_encryption_key = ""
  dcs_signing_cert                   = ""
  stub_dcs_signing_key               = ""
  dcs_encryption_cert                = ""
  stub_dcs_encryption_key            = ""
  dcs_tls_intermediate_cert          = ""
}

variable "environment" {}

