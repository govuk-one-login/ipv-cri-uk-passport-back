variable "environment" {
  type = string
}

variable "rest_api_id" {
  type        = string
  description = "id of the API Gateway REST API to register the lambda with"
}

variable "rest_api_execution_arn" {
  type        = string
  description = "ARN of the API Gateway REST API execution role"
}

variable "root_resource_id" {
  type        = string
  description = "id of the root resource within the REST API to register the lambda with"
}

variable "http_method" {
  type        = string
  description = "http request type"
}

variable "path_part" {
  type        = string
  description = "path part to register the new resource under"
}

variable "handler" {
  type        = string
  description = "Class handler for each of the lambdas"
}

variable "function_name" {
  type        = string
  description = "Lambda function name"
}

variable "role_name" {
  type        = string
  description = "Lambda iam role name"
}

variable "dcs_integration_encryption_cert_param" {
  type        = string
  description = "DCS Integration Encryption Certificate Parameter Name"
}

variable "dcs_encryption_cert_param" {
  type        = string
  description = "DCS Encryption Certificate Parameter Name"
}

variable "dcs_encryption_key_param" {
  type        = string
  description = "DCS Encryption Key Parameter Name"
}

variable "dcs_signing_cert_param" {
  type        = string
  description = "DCS Signing Certificate Parameter Name"
}

variable "dcs_signing_key_param" {
  type        = string
  description = "DCS Signing Key Parameter Name"
}

variable "dcs_tls_cert_param" {
  type        = string
  description = "DCS TLS Certificate Parameter Name"
}

variable "dcs_tls_key_param" {
  type        = string
  description = "DCS TLS Key Parameter Name"
}

locals {
  default_tags = {
    Environment = var.environment
    Source      = "github.com/alphagov/di-ipv-cri-uk-passport-back/terraform/lambda"
  }
}
