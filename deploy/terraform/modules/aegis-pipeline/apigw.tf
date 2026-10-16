# HTTP API front door -> start Lambda. POST /chat starts an execution; GET /status polls it.
# Optional: created only when var.enable_http_entry is true (an event-driven-only pipeline, e.g. the
# S3-ingestion-only editorial pipeline, sets it false and has no HTTP entry at all).
# NOTE: this is unauthenticated scaffolding — add a JWT/IAM authorizer before production use.
resource "aws_apigatewayv2_api" "http" {
  count         = var.enable_http_entry ? 1 : 0
  name          = "${local.name}-api"
  protocol_type = "HTTP"
  tags          = local.tags
}

resource "aws_apigatewayv2_integration" "start" {
  count                  = var.enable_http_entry ? 1 : 0
  api_id                 = aws_apigatewayv2_api.http[0].id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.start[0].invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "chat" {
  count     = var.enable_http_entry ? 1 : 0
  api_id    = aws_apigatewayv2_api.http[0].id
  route_key = "POST /chat"
  target    = "integrations/${aws_apigatewayv2_integration.start[0].id}"
}

resource "aws_apigatewayv2_route" "status" {
  count     = var.enable_http_entry ? 1 : 0
  api_id    = aws_apigatewayv2_api.http[0].id
  route_key = "GET /status"
  target    = "integrations/${aws_apigatewayv2_integration.start[0].id}"
}

resource "aws_apigatewayv2_stage" "default" {
  count       = var.enable_http_entry ? 1 : 0
  api_id      = aws_apigatewayv2_api.http[0].id
  name        = "$default"
  auto_deploy = true
  tags        = local.tags
}

resource "aws_lambda_permission" "apigw" {
  count         = var.enable_http_entry ? 1 : 0
  statement_id  = "AllowApiGwInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.start[0].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http[0].execution_arn}/*/*"
}
