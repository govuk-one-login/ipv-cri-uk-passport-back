resource "aws_api_gateway_rest_api" "ipv_cri_uk_passport" {
  name = "${var.environment}-ipv-cri-uk-passport"
  tags = local.default_tags

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.ipv_cri_uk_passport.id

  triggers = {
    authorize = module.passport.trigger
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "endpoint_stage" {
  deployment_id = aws_api_gateway_deployment.deployment.id
  rest_api_id   = aws_api_gateway_rest_api.ipv_cri_uk_passport.id
  stage_name    = var.environment
}
