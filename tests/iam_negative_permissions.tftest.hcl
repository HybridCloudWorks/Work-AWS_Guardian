# Native Terraform tests (Terraform 1.6+; repo runtime 1.16.5) for the task-2.3
# negative-permission assertions on the IAM policy documents.
#
# Credential-free by design:
#   - A REAL (not mock) AWS provider is used so aws_iam_policy_document renders
#     its actual JSON. That data source is computed locally by the provider and
#     makes NO AWS API calls, and the iam-policies module contains only
#     policy-document data sources, so no credentials are needed. The provider
#     settings below suppress every credential/metadata lookup.
#   - The run targets the iam-policies module directly via
#     `module { source = "./modules/iam-policies" }`, so unrelated
#     Gateway/storage wiring need not resolve.
#   - Each role document inlines its allow + deny statements (no
#     source_policy_documents chaining), which is required for the module to be
#     renderable in `terraform test` (hashicorp/terraform-provider-aws#36700).
#
# These assertions prove the structural guarantees documented in
# tests/terraform/iam_negative_permissions.md (N1-N7): the generated policy JSON
# contains the expected Deny statements and does NOT contain the forbidden Allow
# actions. Semantic simulation (iam:SimulatePrincipalPolicy) still requires a
# reviewed credentialed run and is tracked in that document.
#
# NOTE: aws_iam_policy_document renders a single-element Action/Resource as a
# JSON string and a multi-element one as a JSON array. The assertions normalize
# both to a list with flatten([x]) before calling contains().
#
# Run from the repository root:
#   terraform init -backend=false -input=false
#   terraform test

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "testonly"
  secret_key                  = "testonly"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

variables {
  name_prefix        = "ccg-poc"
  account_id         = "111122223333"
  region             = "us-east-1"
  audit_bucket_arn   = "arn:aws:s3:::ccg-poc-audit"
  findings_table_arn = "arn:aws:dynamodb:us-east-1:111122223333:table/ccg-poc-findings"
  log_group_arn      = "arn:aws:logs:us-east-1:111122223333:log-group:/ccg-poc"
}

run "iam_negative_permissions" {
  command = plan

  module {
    source = "./modules/iam-policies"
  }

  # ===========================================================================
  # N1 — Discovery cannot mutate
  # ===========================================================================

  # N1 (deny): the discovery document denies SG ingress, bucket policy/ACL,
  # all IAM, sts:AssumeRole, and CloudTrail stop/delete.
  assert {
    condition = anytrue([
      for s in jsondecode(output.discovery_policy_json).Statement :
      s.Effect == "Deny" &&
      contains(flatten([s.Action]), "sts:AssumeRole") &&
      contains(flatten([s.Action]), "iam:*") &&
      contains(flatten([s.Action]), "cloudtrail:StopLogging") &&
      contains(flatten([s.Action]), "ec2:AuthorizeSecurityGroupIngress")
    ])
    error_message = "N1: discovery must Deny sts:AssumeRole, iam:*, cloudtrail:StopLogging, and SG ingress."
  }

  # N1 (allow side): discovery grants no sts:AssumeRole allow.
  assert {
    condition = alltrue([
      for s in jsondecode(output.discovery_policy_json).Statement :
      s.Effect == "Deny" || !contains(flatten([s.Action]), "sts:AssumeRole")
    ])
    error_message = "N1: discovery must not ALLOW sts:AssumeRole."
  }

  # ===========================================================================
  # N2 — Tools cannot activate policy
  # ===========================================================================
  assert {
    condition     = length(regexall("bedrock-agentcore", output.tool_execution_policy_json)) == 0
    error_message = "N2: tool_execution must contain no bedrock-agentcore action (cannot activate policy)."
  }

  # ===========================================================================
  # N3 — Tools cannot touch production
  # ===========================================================================
  assert {
    condition = anytrue([
      for s in jsondecode(output.tool_execution_policy_json).Statement :
      s.Effect == "Deny" && try(s.Condition.StringEquals["aws:ResourceTag/Environment"], null) == "prod"
    ])
    error_message = "N3: tool_execution must Deny targets tagged Environment=prod."
  }

  # ===========================================================================
  # N4 — Tools cannot disable audit or make buckets public
  # ===========================================================================
  assert {
    condition = anytrue([
      for s in jsondecode(output.tool_execution_policy_json).Statement :
      s.Effect == "Deny" &&
      contains(flatten([s.Action]), "cloudtrail:StopLogging") &&
      contains(flatten([s.Action]), "s3:PutBucketPublicAccessBlock")
    ])
    error_message = "N4: tool_execution must Deny CloudTrail stop and S3 public-access-block changes."
  }

  # ===========================================================================
  # N5 — Tool S3 scope is explicit ARNs, not a wildcard (P1.3 / H1)
  # ===========================================================================
  assert {
    condition     = length(regexall("arn:aws:s3:::\\*", output.tool_execution_policy_json)) == 0
    error_message = "N5: tool_execution must not grant S3 on arn:aws:s3:::* ."
  }

  assert {
    condition     = length(regexall("ccg-poc-sandbox-", output.tool_execution_policy_json)) > 0
    error_message = "N5: S3EncryptionEnablement must be scoped to the sandbox bucket prefix (default path)."
  }

  # Only the EC2 security-group statement may carry the CCGDemo tag condition
  # (it is enforceable there). The removed S3 tag condition would make this 2.
  assert {
    condition     = length(regexall("aws:ResourceTag/CCGDemo", output.tool_execution_policy_json)) == 1
    error_message = "N5: only the EC2 SG statement may carry the CCGDemo tag condition (S3 tag condition must be removed)."
  }

  # ===========================================================================
  # N6 — Control plane cannot remediate
  # ===========================================================================
  assert {
    condition     = length(regexall("bedrock-agentcore:UpdatePolicy", output.control_plane_policy_json)) > 0
    error_message = "N6: control_plane must Allow bedrock-agentcore:UpdatePolicy (its only job)."
  }

  assert {
    condition = anytrue([
      for s in jsondecode(output.control_plane_policy_json).Statement :
      s.Effect == "Deny" &&
      contains(flatten([s.Action]), "ec2:AuthorizeSecurityGroupIngress") &&
      contains(flatten([s.Action]), "s3:PutEncryptionConfiguration") &&
      contains(flatten([s.Action]), "iam:CreateAccessKey")
    ])
    error_message = "N6: control_plane must Deny remediation actions."
  }

  # ===========================================================================
  # N7 — Console/API cannot bypass the Gateway
  # ===========================================================================

  # Deny lambda:InvokeFunction + direct policy activation + remediation.
  assert {
    condition = anytrue([
      for s in jsondecode(output.api_policy_json).Statement :
      s.Effect == "Deny" &&
      contains(flatten([s.Action]), "lambda:InvokeFunction") &&
      contains(flatten([s.Action]), "bedrock-agentcore:UpdatePolicy") &&
      contains(flatten([s.Action]), "s3:PutEncryptionConfiguration")
    ])
    error_message = "N7: api must Deny lambda:InvokeFunction, bedrock-agentcore:UpdatePolicy, and remediation."
  }

  # The API reaches activation only by assuming the control-plane role ARN.
  assert {
    condition = anytrue([
      for s in jsondecode(output.api_policy_json).Statement :
      s.Effect == "Allow" &&
      contains(flatten([s.Action]), "sts:AssumeRole") &&
      contains(flatten([s.Resource]), "arn:aws:iam::111122223333:role/ccg-poc-ctrl-plane")
    ])
    error_message = "N7: api must Allow sts:AssumeRole only on the control-plane role ARN."
  }

  # The API grants no direct lambda:InvokeFunction allow (only the Gateway does).
  assert {
    condition = alltrue([
      for s in jsondecode(output.api_policy_json).Statement :
      s.Effect == "Deny" || !contains(flatten([s.Action]), "lambda:InvokeFunction")
    ])
    error_message = "N7: api must not ALLOW lambda:InvokeFunction."
  }

  # ===========================================================================
  # Gateway is the sole invoker of tool targets
  # ===========================================================================
  assert {
    condition     = length(regexall("function:ccg-poc-tool-\\*", output.gateway_execution_policy_json)) > 0
    error_message = "Gateway lambda:InvokeFunction must be scoped to the ccg-poc-tool-* prefix."
  }
}

# --- Variable-validation guard: no all-buckets wildcard ----------------------
run "remediation_bucket_arns_rejects_wildcard" {
  command = plan

  module {
    source = "./modules/iam-policies"
  }

  variables {
    remediation_bucket_arns = ["arn:aws:s3:::*"]
  }

  expect_failures = [
    var.remediation_bucket_arns,
  ]
}

# --- Variable-validation guard: explicit ARNs are honored --------------------
run "remediation_bucket_arns_explicit_scope" {
  command = plan

  module {
    source = "./modules/iam-policies"
  }

  variables {
    remediation_bucket_arns = [
      "arn:aws:s3:::ccg-poc-sandbox-alpha",
      "arn:aws:s3:::ccg-poc-sandbox-beta",
    ]
  }

  assert {
    condition     = length(regexall("ccg-poc-sandbox-alpha", output.tool_execution_policy_json)) > 0
    error_message = "Explicit remediation_bucket_arns must be used verbatim in the S3 statement."
  }

  assert {
    condition     = length(regexall("arn:aws:s3:::\\*", output.tool_execution_policy_json)) == 0
    error_message = "Explicit scoping must still contain no all-buckets wildcard."
  }
}
