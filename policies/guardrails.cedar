// CCG guardrails.cedar — always-on forbid policies
//
// SCHEMA STATUS: Intent stubs. These policies use the confirmed AgentCore Cedar
// namespace and context shape but contain PLACEHOLDER action IDs.
//
// Exact action identifiers are generated from the Gateway target name and tool
// name at deploy time (format: AgentCore::Action::"<TargetName>___<tool_name>").
// The proposed target name is "RemediationTarget". Replace each placeholder
// below with the confirmed identifier from `agentcore status` / ListGatewayTargets
// after the first sandbox deploy, then re-run the policy analyzer before
// task 1.3 is considered complete.
//
// Resource: every policy that names a specific action MUST use a specific
// gateway ARN: resource == AgentCore::Gateway::"<gateway-arn>".
// Replace <GATEWAY_ARN> with the value from `agentcore status` after deploy.
//
// IMPORTANT — what changed from the previous version (and why):
//
//   1. Removed: resource.hasTag("Environment", "prod")
//      REASON: AgentCore::Gateway entities do not support .hasTag(). Resource
//      tags are NOT available in Cedar context. The prod-target gate is enforced
//      at two server-side layers: IAM deny condition (aws:ResourceTag/Environment=prod)
//      on the tool execution role, and a live tag recheck inside each tool Lambda
//      before mutation. See AGENTCORE_CAPABILITY_RECORD.md §2.
//
//   2. Changed: Action::"ModifySecurityGroup" → Action::"RemediationTarget___security_group_correction"
//      REASON: Real action IDs follow <TargetName>___<tool_name> format. The
//      old name was a placeholder that would have been rejected by the analyzer.
//
//   3. Changed: resource.proposedCidr → context.input.proposed_cidr
//      REASON: Tool parameters are in context.input, not on the resource entity.
//
//   4. Changed: Action::"MakeS3Public" → Action::"RemediationTarget___s3_encryption_enablement"
//      and added context.input.make_public condition.
//      REASON: Same format issue; the real tool has a make_public parameter.
//
//   5. Changed: Action::"DisableCloudTrail" → Action::"RemediationTarget___access_key_rotation"
//      NOTE: CloudTrail disablement is not one of the four registered CCG tools.
//      The original intent was to block any unregistered tool that could disable
//      CloudTrail. Because Cedar default-deny already handles unregistered actions,
//      no explicit forbid is needed for a non-existent action. This policy is
//      replaced with a catch-all forbid for any action that is not in the registered
//      tool set — expressed as forbid-unless-CallTool, which is the parent action
//      group for all registered MCP tools. Actions outside the MCP hierarchy are
//      denied by default; this forbid makes the intent explicit.
//
// REFERENCES:
//   AGENTCORE_CAPABILITY_RECORD.md §1.3 (action format), §1.5 (resource),
//   §1.6 (context), §2 (CCGDemo/Environment enforcement)

// PLACEHOLDER — replace <GATEWAY_ARN> with the deployed gateway ARN.
// Forbid open-internet ingress on security-group correction.
// context.input.proposed_cidr must be a String (Cedar type), which matches the
// inputSchema "type": "string" declaration for the proposed_cidr parameter.
forbid(
  principal,
  action == AgentCore::Action::"RemediationTarget___security_group_correction",
  resource == AgentCore::Gateway::"<GATEWAY_ARN>"
) when {
  context.input.proposed_cidr == "0.0.0.0/0"
};

forbid(
  principal,
  action == AgentCore::Action::"RemediationTarget___security_group_correction",
  resource == AgentCore::Gateway::"<GATEWAY_ARN>"
) when {
  context.input.proposed_cidr == "::/0"
};

// Forbid the make_public flag on S3 encryption enablement.
// make_public must be a Bool in the tool inputSchema.
forbid(
  principal,
  action == AgentCore::Action::"RemediationTarget___s3_encryption_enablement",
  resource == AgentCore::Gateway::"<GATEWAY_ARN>"
) when {
  context.input.make_public == true
};

// Forbid any action that is not an MCP tool call (i.e. not in the CallTool
// action group). All four registered CCG tools inherit from CallTool → Mcp.
// Any non-tool invocation attempt is denied explicitly here in addition to
// the default-deny baseline.
//
// NOTE: This policy does NOT use a specific gateway ARN because it is
// intended to apply to the gateway at type level. Cedar requires:
//   - Specific actions → specific gateway ARN
//   - Unconstrained action → type-check (resource is AgentCore::Gateway) is acceptable
// This forbid leaves `action` unconstrained (no == or in), so the type-check form is valid.
forbid(
  principal,
  action,
  resource is AgentCore::Gateway
) unless {
  action in AgentCore::Action::"CallTool"
};
