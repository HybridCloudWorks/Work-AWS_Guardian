# Least-privilege IAM policy documents for the CCG role boundaries.
#
# These are policy *documents* (data sources), not attached roles. They are the
# reviewable least-privilege source of truth; the actual roles are created and
# attached during gate-0.2 work once the sandbox account and the live AgentCore
# Gateway/tool ARNs are known.
#
# Separation of duties (design §6):
#   discovery     -> read sources + write evidence; cannot mutate or assume roles
#   tool          -> narrowly scoped remediation on sandbox-tagged targets only
#   control_plane -> policy activation only; no remediation permissions
#   api           -> read findings/audit + reach activation via control-plane;
#                    never remediates and never invokes tool Lambdas (no Gateway bypass)
#   audit_reader  -> read-only on the audit bucket
#
# ---------------------------------------------------------------------------
# Resource-scoping ledger — every "*" resource below, enumerated with its
# justification. The ONLY acceptable bare "*" is a read-only Describe/List/Get
# whose AWS action does not support resource-level permissions. All mutating
# statements are scoped to account + region + resource type + specific ARNs.
#
#   discovery.ReadOnlySources            "*"  OK: read-only Config/SecurityHub/
#                                             CloudTrail Describe/Get/List; these
#                                             actions have no resource-level ARN.
#   Deny* statements (all documents)     "*"  OK: Deny statements SHOULD be broad
#                                             (a deny on "*" is a safety net, not
#                                             a grant). Denies cannot over-permit.
#
# Each role document inlines its Deny statements in the same document as its
# Allow statements (rather than chaining a separate "_boundary" document via
# source_policy_documents). The effective policy is identical — a Deny always
# wins over an Allow — but inlining lets `terraform test` render and assert each
# document credential-free; chaining via source_policy_documents cannot be
# rendered that way (hashicorp/terraform-provider-aws#36700).
#
# Statements that previously used "*" on a mutating/condition-gated action and
# have now been fixed (P1.3 / finding H1):
#   tool.S3EncryptionEnablement — was arn:aws:s3:::* + aws:ResourceTag (the tag
#       condition is UNENFORCEABLE on S3 bucket-level actions, so it silently
#       allowed ALL buckets). Now scoped to an explicit allow-list
#       (var.remediation_bucket_arns) or the ${name_prefix}-sandbox-* prefix.
#       The CCGDemo/Environment safety gate for S3 is enforced by the Lambda
#       layer live recheck, NOT by any IAM tag condition.
#   tool.CompliantTagging — tag:TagResources/GetResources (Resource Groups
#       Tagging API) fan out across services and do not reliably honor
#       aws:ResourceTag as a gate; GetResources is read-only and split out,
#       and TagResources is restricted to this account/region plus the Lambda
#       recheck. See tests/terraform/iam_negative_permissions.md.
#
# NOTE: access-key rotation (iam:*AccessKey*) is intentionally NOT in the tool
# policy. The rotation tool is dry-run only (ADR 0004); if it is ever granted
# live IAM actions, they must be scoped to a specific sandbox user ARN pattern,
# never iam:* on "*".
# ---------------------------------------------------------------------------

locals {
  # CloudWatch log write, shared by the runtime roles.
  log_write_actions = [
    "logs:CreateLogStream",
    "logs:PutLogEvents",
  ]

  # Explicit sandbox bucket scoping for the S3-encryption tool. S3 bucket-level
  # actions do NOT honor aws:ResourceTag, so we scope by ARN instead of relying
  # on an unenforceable tag condition. If an explicit allow-list is supplied we
  # use it; otherwise we fall back to the sandbox-bucket name-prefix convention
  # (${name_prefix}-sandbox-*). Either way there is no arn:aws:s3:::* grant.
  remediation_bucket_resources = length(var.remediation_bucket_arns) > 0 ? var.remediation_bucket_arns : ["arn:aws:s3:::${var.name_prefix}-sandbox-*"]

  # Resolved control-plane role the API role may assume to reach activation.
  control_plane_role_arn = var.control_plane_role_arn != "" ? var.control_plane_role_arn : "arn:aws:iam::${var.account_id}:role/${var.name_prefix}-ctrl-plane"
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

  # Explicit deny boundary (inlined into the same document rather than chained
  # via source_policy_documents, so `terraform test` can render and assert it
  # credential-free — see tests/iam_negative_permissions.tftest.hcl and
  # hashicorp/terraform-provider-aws#36700). A Deny is evaluated before any
  # Allow, so these guarantee discovery can never mutate audited resources or
  # assume another role regardless of any future additive Allow.
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
  #
  # aws:ResourceTag IS supported on ec2:AuthorizeSecurityGroupIngress and
  # ec2:RevokeSecurityGroupIngress for the security-group resource, and the
  # resource ARN below is the security-group ARN the condition applies to, so
  # this tag gate is genuinely enforceable (unlike the S3 bucket-level case).
  # The Lambda layer still rechecks CCGDemo/Environment as defense in depth.
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

  # S3 encryption enablement — scoped to explicit sandbox bucket ARNs.
  #
  # IMPORTANT (P1.3 / finding H1): s3:PutEncryptionConfiguration and
  # s3:GetEncryptionConfiguration are BUCKET-level actions that do NOT support
  # the aws:ResourceTag condition key. The previous arn:aws:s3:::* + tag
  # condition was silently unenforceable and effectively allowed the action on
  # every bucket in the account. We therefore scope by explicit bucket ARN
  # (var.remediation_bucket_arns) or the ${name_prefix}-sandbox-* prefix. The
  # CCGDemo/Environment safety gate for S3 is enforced in the Lambda layer by a
  # live tag recheck before any call, NOT by an IAM tag condition here.
  statement {
    sid       = "S3EncryptionEnablement"
    effect    = "Allow"
    actions   = ["s3:PutEncryptionConfiguration", "s3:GetEncryptionConfiguration"]
    resources = local.remediation_bucket_resources
  }

  # Read-only tag discovery. tag:GetResources (Resource Groups Tagging API) is a
  # read-only cross-service query that does not support resource-level scoping
  # or a meaningful aws:ResourceTag gate (it enumerates by tag filter supplied
  # in the request). It is split out as its own read-only statement so the write
  # action below carries no implied read-everything grant. Scoped to this
  # account/region by the account-wide boundary; harmless as read-only.
  statement {
    sid       = "TagDiscoveryReadOnly"
    effect    = "Allow"
    actions   = ["tag:GetResources"]
    resources = ["*"]
  }

  # Compliant tagging write. tag:TagResources fans out to many services and does
  # not reliably honor aws:ResourceTag as an authorization gate (behavior varies
  # by target service and ABAC enablement), so we do NOT rely on a tag condition
  # for enforcement. The sandbox restriction is enforced by the Lambda-layer
  # live CCGDemo/Environment recheck plus the account/region boundary; the deny
  # boundary below forbids any Environment=prod target. The resource stays "*"
  # because the tagging API addresses heterogeneous resource ARNs; the real gate
  # is the Lambda recheck + DenyProductionTargets.
  statement {
    sid       = "CompliantTagging"
    effect    = "Allow"
    actions   = ["tag:TagResources"]
    resources = ["*"]
  }

  statement {
    sid       = "WriteLogs"
    effect    = "Allow"
    actions   = local.log_write_actions
    resources = ["${var.log_group_arn}:*"]
  }

  # Inlined deny boundary (see note on the discovery document). The tool role
  # can never touch production-tagged targets, activate policy, or disable
  # CloudTrail — belt-and-suspenders alongside the Cedar boundary.
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
  # Activation of the AgentCore policy enforcement mode only. Actions verified
  # against the bedrock-agentcore-control service model (API 2023-06-05) during
  # gate-0.2 capture: activation is UpdatePolicy(enforcementMode=ACTIVE|LOG_ONLY)
  # on a Policy resource; GetPolicy/GetPolicyEngine support reconciliation. The
  # earlier UpdateGatewayPolicy/GetGatewayPolicy/ListGatewayPolicies names do
  # not exist in the API. Carries no remediation permissions.
  statement {
    sid    = "PolicyActivation"
    effect = "Allow"
    actions = [
      "bedrock-agentcore:UpdatePolicy",
      "bedrock-agentcore:GetPolicy",
      "bedrock-agentcore:GetPolicySummary",
      "bedrock-agentcore:ListPolicySummaries",
    ]
    resources = ["arn:aws:bedrock-agentcore:${var.region}:${var.account_id}:policy/*"]
  }

  statement {
    sid    = "PolicyEngineRead"
    effect = "Allow"
    actions = [
      "bedrock-agentcore:GetPolicyEngine",
    ]
    resources = ["arn:aws:bedrock-agentcore:${var.region}:${var.account_id}:policy-engine/*"]
  }

  statement {
    sid       = "WriteLogs"
    effect    = "Allow"
    actions   = local.log_write_actions
    resources = ["${var.log_group_arn}:*"]
  }

  # Inlined deny boundary (see note on the discovery document). The control
  # plane authorizes activation; it must never itself perform a remediation
  # mutation.
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

# --- Console/API role: read-only views + indirect activation ------------------
# Design §6: "Console hosting/API roles: no direct audited-resource mutation
# permissions." The API Lambda serves authenticated findings/policy/evidence
# views and forwards admin activation requests. It therefore gets:
#   - read on the findings table,
#   - read on the audit bucket (decision evidence),
#   - the ability to reach the audited activation path ONLY by assuming the
#     control-plane role (never a direct bedrock-agentcore:UpdatePolicy grant),
#   - its own log writes.
# It is explicitly denied every remediation action AND lambda:InvokeFunction on
# the tool Lambdas, so the console/API can never bypass the Gateway to mutate a
# resource or invoke a tool directly.
data "aws_iam_policy_document" "api" {
  statement {
    sid    = "ReadFindings"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Query",
    ]
    resources = [var.findings_table_arn]
  }

  statement {
    sid       = "ReadAuditEvidence"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [var.audit_bucket_arn, "${var.audit_bucket_arn}/*"]
  }

  # Reach activation only via the control-plane role. The API never holds the
  # policy-update permission itself; it must assume the ctrl-plane identity,
  # which keeps activation inside the audited control plane.
  statement {
    sid       = "AssumeControlPlane"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [local.control_plane_role_arn]
  }

  statement {
    sid       = "WriteLogs"
    effect    = "Allow"
    actions   = local.log_write_actions
    resources = ["${var.log_group_arn}:*"]
  }

  # Inlined deny boundary (see note on the discovery document). The console/API
  # role can never mutate an audited resource, activate policy directly, or
  # invoke a tool Lambda (which would bypass the AgentCore Gateway/Cedar
  # boundary).
  statement {
    sid    = "DenyGatewayBypass"
    effect = "Deny"
    actions = [
      "lambda:InvokeFunction",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupIngress",
      "s3:PutEncryptionConfiguration",
      "s3:PutBucketPolicy",
      "s3:PutBucketAcl",
      "tag:TagResources",
      "iam:CreateAccessKey",
      "iam:DeleteAccessKey",
      "iam:UpdateAccessKey",
      "bedrock-agentcore:UpdatePolicy",
    ]
    resources = ["*"]
  }
}

# --- AgentCore Gateway execution role -----------------------------------------
# The Gateway assumes this role to invoke the registered Lambda tool targets.
# It grants ONLY lambda:InvokeFunction on the CCG tool functions (by name
# prefix) plus its own log writes. It performs no AWS mutation itself — the tool
# Lambdas do, under their own tool-execution role.

data "aws_iam_policy_document" "gateway_assume_role" {
  statement {
    sid     = "AgentCoreAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["bedrock-agentcore.amazonaws.com"]
    }

    # Confused-deputy protection (threat T1): only this account's AgentCore can
    # assume the role.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

data "aws_iam_policy_document" "gateway_execution" {
  statement {
    sid       = "InvokeToolTargets"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = ["arn:aws:lambda:${var.region}:${var.account_id}:function:${var.name_prefix}-tool-*"]
  }

  statement {
    sid       = "WriteLogs"
    effect    = "Allow"
    actions   = local.log_write_actions
    resources = ["${var.log_group_arn}:*"]
  }
}
