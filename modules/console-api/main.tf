locals {
  # Use the built CCG package when provided; fall back to the committed
  # placeholder so the module still validates/plans before a real build.
  lambda_package = var.lambda_package_path != "" ? var.lambda_package_path : "${path.module}/placeholder.zip"
}

# Console API: Cognito POC user pool, HTTP API Gateway, and API Lambda stub.
#
# Design §3.4:
#   - Cognito authenticates the POC admin. API Gateway and Lambda provide
#     read-only findings/policy views and admin activation/deactivation requests.
#   - The console authenticates the operator (Cognito); Cedar/Gateway authorizes
#     the mutation at the tool boundary. These are separate concerns.
#   - The console may send a request but cannot decide that a request is
#     authorized; server-side validation always applies (CCG-REQ-028).
#
# GATING: Cognito user pool is always created (no runtime cost, required for
# user provisioning review). API Gateway and Lambda are gated behind
# `enable_console` (default false).
#
# PREREQUISITES (gate-0.2 before enabling):
#   - Console acceptance scenarios ACC-01 through ACC-11 must be demonstrable.
#   - Cognito callback and logout URLs must be known (Next.js hosting mode).
#   - API Lambda deployment package must be built (placeholder used here).
#
# COST: Cognito, HTTP API Gateway, and Lambda are all pay-per-use and well
# within the $150/month POC budget. No always-on compute is provisioned.

# --- Cognito user pool (always created) --------------------------------------
# The user pool is created unconditionally so it can be reviewed before the API
# is enabled. No users are provisioned by Terraform; the POC admin is seeded
# manually through the AWS console or CLI.
resource "aws_cognito_user_pool" "poc" {
  name = "${var.name_prefix}-poc-admins"

  # MFA is not enforced for this sandbox demo; the POC admin is a named
  # individual using a personal email address.
  mfa_configuration = "OFF"

  # Password policy: minimum requirements only. The POC admin sets their own
  # password; a policy refresh cadence is not enforced.
  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = false
  }

  # Delete protection prevents accidental teardown during a demo; disable
  # explicitly in the teardown plan (design §7 / task 6.5).
  deletion_protection = "ACTIVE"

  tags = {
    Component = "console-api"
    CCGDemo   = "true"
  }
}

resource "aws_cognito_user_pool_client" "console" {
  name         = "${var.name_prefix}-console-client"
  user_pool_id = aws_cognito_user_pool.poc.id

  # No client secret — the Next.js console is a confidential server-side app
  # but this is a public client for the POC. Revisit for production.
  generate_secret = false

  # Use Cognito-hosted UI for the POC to avoid a custom sign-in page.
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]

  # Callback/logout URLs must be updated when the Next.js hosting URL is known.
  # Placeholder values keep the resource valid; these are never production URLs.
  callback_urls = ["https://localhost:3000/api/auth/callback/cognito"]
  logout_urls   = ["https://localhost:3000/logout"]

  supported_identity_providers = ["COGNITO"]
}

# --- API Gateway and Lambda (gated) ------------------------------------------

resource "aws_lambda_function" "api" {
  count = var.enable_console ? 1 : 0

  function_name = "${var.name_prefix}-api"
  description   = "CCG POC read/control-plane API: findings, policy status, activation."

  runtime = "python3.14"
  handler = "ccg.api_handler.lambda_handler"
  # Role placeholder: the console/API Lambda runs under the dedicated API role
  # (identity module, `-api`). That role reads findings/audit and assumes the
  # control-plane role for activation; it holds NO remediation permissions and
  # cannot invoke the tool Lambdas, so the API cannot bypass the Gateway.
  # Wired to the real ARN once `enable_roles = true`.
  role             = "arn:aws:iam::${var.account_id}:role/${var.name_prefix}-api"
  filename         = local.lambda_package
  source_code_hash = var.lambda_package_hash != "" ? var.lambda_package_hash : null

  timeout     = var.lambda_timeout_seconds
  memory_size = var.lambda_memory_mb

  environment {
    variables = {
      FINDINGS_TABLE_NAME = var.findings_table_name
      AUDIT_BUCKET_NAME   = var.audit_bucket_name
      LOG_GROUP_NAME      = var.log_group_name
      USER_POOL_ID        = aws_cognito_user_pool.poc.id
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Component = "console-api"
    CCGDemo   = "true"
  }
}

# HTTP API Gateway with JWT Cognito authorizer.
resource "aws_apigatewayv2_api" "console" {
  count = var.enable_console ? 1 : 0

  name          = "${var.name_prefix}-console-api"
  protocol_type = "HTTP"
  description   = "CCG POC authenticated console API."
}

resource "aws_apigatewayv2_authorizer" "cognito" {
  count  = var.enable_console ? 1 : 0
  api_id = aws_apigatewayv2_api.console[0].id

  name            = "cognito-jwt"
  authorizer_type = "JWT"

  identity_sources = ["$request.header.Authorization"]

  jwt_configuration {
    audience = [aws_cognito_user_pool_client.console.id]
    issuer   = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.poc.id}"
  }
}

resource "aws_apigatewayv2_integration" "lambda" {
  count  = var.enable_console ? 1 : 0
  api_id = aws_apigatewayv2_api.console[0].id

  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api[0].invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "proxy" {
  count  = var.enable_console ? 1 : 0
  api_id = aws_apigatewayv2_api.console[0].id

  route_key          = "$default"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito[0].id
  target             = "integrations/${aws_apigatewayv2_integration.lambda[0].id}"
}

resource "aws_apigatewayv2_stage" "default" {
  count  = var.enable_console ? 1 : 0
  api_id = aws_apigatewayv2_api.console[0].id

  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "api_gateway_invoke" {
  count = var.enable_console ? 1 : 0

  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api[0].function_name
  principal     = "apigateway.amazonaws.com"

  source_arn = "${aws_apigatewayv2_api.console[0].execution_arn}/*/*"
}
