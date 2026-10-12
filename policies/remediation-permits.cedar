// CCG remediation-permits.cedar — versioned permit policies
//
// SCHEMA STATUS: Intent stubs. The action IDs and gateway ARN below are
// PLACEHOLDERS that will fail the policy analyzer until replaced with values
// from the first sandbox deploy. Do NOT set any policy to enforcementMode=ACTIVE
// until the analyzer passes with the real identifiers.
//
// ACTIVATION MODEL (from AGENTCORE_CAPABILITY_RECORD.md §3):
//   - Each policy below is created with enforcementMode=LOG_ONLY (inactive).
//   - Activation = UpdatePolicy(enforcementMode=ACTIVE) via the audited
//     PolicyActivationService control plane (src/ccg/policy.py).
//   - Deactivation = UpdatePolicy(enforcementMode=LOG_ONLY).
//   - Forbid-wins semantics: a matching forbid in guardrails.cedar overrides
//     any permit here, regardless of both policies' enforcementMode.
//   - Default deny: all four permit policies must be in ACTIVE mode for any
//     tool call to be allowed. With all policies in LOG_ONLY, every call is
//     denied by default.
//
// ACTIVATION GATE:
//   - Replace <GATEWAY_ARN> with the deployed gateway ARN.
//   - Replace each <PLACEHOLDER_ACTION_ID> with the confirmed generated string
//     from `agentcore status` / ListGatewayTargets after first deploy.
//   - Run the policy analyzer (validationMode=FAIL_ON_ANY_FINDINGS) on each
//     policy before any activation request.
//   - Only activate through the audited control-plane operation; never toggle
//     via Terraform or a direct AWS CLI call outside the reviewed activation flow.
//
// PRINCIPAL MODEL (AWS_IAM authorizer, from AGENTCORE_CAPABILITY_RECORD.md §1.4):
//   - Principal type: AgentCore::IamEntity
//   - principal.id contains the caller's IAM ARN:
//     "arn:aws:sts::<account>:assumed-role/<role-name>"
//   - Use principal.id like "..." for account/role matching.
//   - Replace <ACCOUNT_ID> and <REMEDIATOR_ROLE_NAME> with actual values before deploy.
//
// SAFETY ATTRIBUTES (from AGENTCORE_CAPABILITY_RECORD.md §2):
//   - CCGDemo=true and Environment≠prod are NOT expressible as Cedar context
//     attributes. They are enforced server-side:
//       (a) IAM deny condition on the tool execution role (aws:ResourceTag/Environment=prod)
//       (b) Live tag recheck inside each tool Lambda before mutation
//   - These permits intentionally do NOT include CCGDemo/Environment conditions
//     in Cedar; that enforcement is at the IAM and Lambda layers.
//
// REFERENCES:
//   AGENTCORE_CAPABILITY_RECORD.md §1.3, §1.4, §1.5, §1.6, §2, §3
//   src/ccg/policy.py (PolicyActivationService)
//   policies/guardrails.cedar (always-on forbids; override these permits)

// --- Permit: security-group correction ---
// Allows the security-group tool for authenticated CCG remediators.
// The guardrails.cedar forbids on proposed_cidr=0.0.0.0/0 and ::/0 override
// this permit when the CIDR is globally open.
//
// PLACEHOLDER action ID — replace after first deploy:
//   AgentCore::Action::"RemediationTarget___security_group_correction"
permit(
  principal is AgentCore::IamEntity,
  action == AgentCore::Action::"RemediationTarget___security_group_correction",
  resource == AgentCore::Gateway::"<GATEWAY_ARN>"
) when {
  principal.id like "arn:aws:sts::<ACCOUNT_ID>:assumed-role/<REMEDIATOR_ROLE_NAME>*"
};

// --- Permit: S3 encryption enablement ---
// The guardrails.cedar forbid on make_public=true overrides this permit
// if the caller supplies make_public=true.
//
// PLACEHOLDER action ID — replace after first deploy:
//   AgentCore::Action::"RemediationTarget___s3_encryption_enablement"
permit(
  principal is AgentCore::IamEntity,
  action == AgentCore::Action::"RemediationTarget___s3_encryption_enablement",
  resource == AgentCore::Gateway::"<GATEWAY_ARN>"
) when {
  principal.id like "arn:aws:sts::<ACCOUNT_ID>:assumed-role/<REMEDIATOR_ROLE_NAME>*"
};

// --- Permit: compliant tagging ---
//
// PLACEHOLDER action ID — replace after first deploy:
//   AgentCore::Action::"RemediationTarget___compliant_tagging"
permit(
  principal is AgentCore::IamEntity,
  action == AgentCore::Action::"RemediationTarget___compliant_tagging",
  resource == AgentCore::Gateway::"<GATEWAY_ARN>"
) when {
  principal.id like "arn:aws:sts::<ACCOUNT_ID>:assumed-role/<REMEDIATOR_ROLE_NAME>*"
};

// --- Permit: access-key rotation ---
// Dry-run unless confirm=true (enforced in the tool Lambda, not in Cedar).
//
// PLACEHOLDER action ID — replace after first deploy:
//   AgentCore::Action::"RemediationTarget___access_key_rotation"
permit(
  principal is AgentCore::IamEntity,
  action == AgentCore::Action::"RemediationTarget___access_key_rotation",
  resource == AgentCore::Gateway::"<GATEWAY_ARN>"
) when {
  principal.id like "arn:aws:sts::<ACCOUNT_ID>:assumed-role/<REMEDIATOR_ROLE_NAME>*"
};
