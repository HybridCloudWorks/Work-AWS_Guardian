# Least-privilege IAM policy documents for the CCG role boundaries.
#
# These are policy *documents* (data sources), not attached roles. They are the
# reviewable least-privilege source of truth; the actual roles are created and
# attached during gate-0.2 work once the sandbox account and the live AgentCore
# Gateway/tool ARNs are known. No statement uses a bare "*" resource except
# where the AWS API genuinely requires it (read-only Describe/List calls that
# do not support resource-level permissions), and those are read-only.
#
# Separation of duties (design §6):
#   discovery     -> read sources + write evidence; cannot mutate or assume roles
#   tool          -> narrowly scoped remediation on sandbox-tagged targets only
#   control_plane -> policy activation only; no remediation permissions
#   audit_reader  -> read-only on the audit bucket

locals {
  # CloudWatch log write, shared by the runtime roles.
  log_write_actions = [
    "logs:CreateLogStream",
    "logs:PutLogEvents",
  ]
}

# --- Discovery role: read-only sources + write evidence -----------------------

data "aws_iam_policy_document" "discovery" {
  # Read-only collection. These Describe/Get/List actions do not support
  # resource-level scoping, so the resource is "*" but the actions are strictly
  # read-only and confined to the three approved services.
  statement {
    sid    = "ReadOnlySources"
    effect = "Allow"
    actions = [
      "config:Describe*",
      "config:Get*",
      "config:List*",
      "config:BatchGet*",
      "securityhub:Get*",
      "securityhub:List*",
      "securityhub:Describe*",
      "cloudtrail:LookupEvents",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:DescribeTrails",
    ]
    resources = ["*"]
  }

  # Write current-finding state only to the specific findings table.
  statement {
    sid    = "WriteFindings"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:GetItem",
      "dynamodb:Query",
    ]
    resources = [var.findings_table_arn]
  }

  # Write immutable audit JSON only to the specific audit bucket, and only with
  # server-side encryption (matches the bucket's DenyUnencryptedObjectUploads).
  statement {
    sid       = "WriteAuditObjects"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${var.audit_bucket_arn}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["AES256"]
    }
  }

  statement {
    sid       = "WriteLogs"
    effect    = "Allow"
    actions   = local.log_write_actions
    resources = ["${var.log_group_arn}:*"]
  }
}

# Explicit denies that make the read-only guarantee robust regardless of any
# future additive statement: discovery can never mutate audited resources or
# assume another role.
data "aws_iam_policy_document" "discovery_boundary" {
  source_policy_documents = [data.aws_iam_policy_document.discovery.json]

  statement {
    sid    = "DenyResourceMutation"
    effect = "Deny"
    actions = [
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupIngress",
      "s3:PutBucketPolicy",
      "s3:PutBucketAcl",
      "iam:*",
      "sts:AssumeRole",
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
    ]
    resources = ["*"]
  }
}

# --- Tool-execution role: narrow, sandbox-gated remediation -------------------

data "aws_iam_policy_document" "tool_execution" {
  # Security-group correction: modify ingress only on sandbox-tagged SGs.
  statement {
    sid    = "SecurityGroupCorrection"
    effect = "Allow"
    actions = [
      "ec2:RevokeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupIngress",
    ]
    resources = ["arn:aws:ec2:${var.region}:${var.account_id}:security-group/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${var.sandbox_tag_key}"
      values   = [var.sandbox_tag_value]
    }
  }

  # S3 encryption enablement on sandbox-tagged buckets; never make public.
  statement {
    sid       = "S3EncryptionEnablement"
    effect    = "Allow"
    actions   = ["s3:PutEncryptionConfiguration", "s3:GetEncryptionConfiguration"]
    resources = ["arn:aws:s3:::*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${var.sandbox_tag_key}"
      values   = [var.sandbox_tag_value]
    }
  }

  # Compliant tagging on sandbox-tagged resources.
  statement {
    sid    = "CompliantTagging"
    effect = "Allow"
    actions = [
      "tag:GetResources",
      "tag:TagResources",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${var.sandbox_tag_key}"
      values   = [var.sandbox_tag_value]
    }
  }

  statement {
    sid       = "WriteLogs"
    effect    = "Allow"
    actions   = local.log_write_actions
    resources = ["${var.log_group_arn}:*"]
  }
}

# Tool role can never touch production-tagged targets, activate policy, or
# disable CloudTrail — belt-and-suspenders alongside the Cedar boundary.
data "aws_iam_policy_document" "tool_execution_boundary" {
  source_policy_documents = [data.aws_iam_policy_document.tool_execution.json]

  statement {
    sid       = "DenyProductionTargets"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Environment"
      values   = ["prod"]
    }
  }

  statement {
    sid    = "DenyPolicyAndTrailControl"
    effect = "Deny"
    actions = [
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketAcl",
    ]
    resources = ["*"]
  }
}

# --- Control-plane role: policy activation only -------------------------------

data "aws_iam_policy_document" "control_plane" {
  # Activation of the AgentCore policy enforcement mode only. The exact action
  # IDs are confirmed at gate 0.2; these are the documented Bedrock AgentCore
  # policy control-plane operations and carry no remediation permissions.
  statement {
    sid    = "PolicyActivation"
    effect = "Allow"
    actions = [
      "bedrock-agentcore:UpdateGatewayPolicy",
      "bedrock-agentcore:GetGatewayPolicy",
      "bedrock-agentcore:ListGatewayPolicies",
    ]
    resources = ["arn:aws:bedrock-agentcore:${var.region}:${var.account_id}:gateway/*"]
  }

  statement {
    sid       = "WriteLogs"
    effect    = "Allow"
    actions   = local.log_write_actions
    resources = ["${var.log_group_arn}:*"]
  }
}

data "aws_iam_policy_document" "control_plane_boundary" {
  source_policy_documents = [data.aws_iam_policy_document.control_plane.json]

  # The control plane authorizes activation; it must never itself perform a
  # remediation mutation.
  statement {
    sid    = "DenyRemediationActions"
    effect = "Deny"
    actions = [
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupIngress",
      "s3:PutEncryptionConfiguration",
      "iam:CreateAccessKey",
      "iam:DeleteAccessKey",
      "iam:UpdateAccessKey",
    ]
    resources = ["*"]
  }
}

# --- Audit-reader role: read-only on the audit bucket -------------------------

data "aws_iam_policy_document" "audit_reader" {
  statement {
    sid       = "ReadAuditObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [var.audit_bucket_arn, "${var.audit_bucket_arn}/*"]
  }
}
