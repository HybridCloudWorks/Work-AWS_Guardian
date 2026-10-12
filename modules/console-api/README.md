# Module: console-api

**Status:** Cognito user pool always created; API Gateway + Lambda gated off by default (`enable_console = false`).

## Purpose

Provisions the authenticated Next.js console backend: Cognito POC user pool, HTTP API Gateway with JWT authorizer, and the API Lambda (CCG-REQ-027 through CCG-REQ-029).

The console authenticates the operator (Cognito) and the Gateway authorizes mutations (Cedar). These are separate concerns — the console may send a request but cannot decide that a request is authorized.

## Resources

Always created (no runtime cost, safe to review):
- `aws_cognito_user_pool.poc` — POC admin user pool with deletion protection.
- `aws_cognito_user_pool_client.console` — OAuth2 code-flow client; callback URLs are localhost placeholders until Next.js hosting URL is known.

Created when `enable_console = true`:
- `aws_lambda_function.api` — Python 3.14 read/control-plane handler.
- `aws_apigatewayv2_api.console` — HTTP API with JWT Cognito authorizer.
- `aws_apigatewayv2_authorizer.cognito`, `aws_apigatewayv2_integration.lambda`, `aws_apigatewayv2_route.proxy`, `aws_apigatewayv2_stage.default` — API wiring.
- `aws_lambda_permission.api_gateway_invoke` — resource-based policy for API Gateway to invoke Lambda.

## Gating conditions

Enable `enable_console = true` only after:

1. Gate-0.2 Cognito/API Gateway contract is confirmed.
2. Next.js hosting URL is known (update `callback_urls` and `logout_urls`).
3. Console acceptance scenarios ACC-01 through ACC-11 are demonstrable.
4. API Lambda deployment package is built and `filename` is updated.

## Inputs

| Name | Type | Default | Description |
|---|---|---|---|
| `name_prefix` | `string` | — | Resource name prefix. |
| `region` | `string` | — | AWS region. |
| `account_id` | `string` | — | AWS account ID. |
| `log_group_arn` | `string` | — | CloudWatch log group ARN. |
| `log_group_name` | `string` | — | CloudWatch log group name (Lambda env var). |
| `findings_table_name` | `string` | — | DynamoDB table name. |
| `audit_bucket_name` | `string` | — | Audit S3 bucket name. |
| `lambda_timeout_seconds` | `number` | `30` | API Lambda max execution time. |
| `lambda_memory_mb` | `number` | `256` | API Lambda memory (128–3008 MB). |
| `enable_console` | `bool` | `false` | Feature flag for API Gateway + Lambda. |

## Outputs

| Name | Description |
|---|---|
| `user_pool_id` | Cognito user pool ID (always available after first apply). |
| `user_pool_arn` | Cognito user pool ARN. |
| `api_lambda_arn` | API Lambda ARN (null when disabled). |
| `api_lambda_name` | API Lambda name (null when disabled). |
| `api_gateway_id` | HTTP API Gateway ID (null when disabled). |
| `api_gateway_endpoint` | HTTP API invoke URL (null when disabled). |
