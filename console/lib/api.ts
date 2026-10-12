// API client for the CCG console.
//
// This module is a view + request sender only. It contains no local
// authorization decision and no AWS mutation client. Every mutation is a
// versioned request to the authenticated API, which delegates to the
// AgentCore Gateway Policy Engine. The browser never flips a finding or policy
// to "authorized" on its own; it only reflects server-confirmed state.

export type EnforcementMode = "LOG_ONLY" | "ACTIVE";

export type PolicyState = {
  policy_engine_id: string;
  // The version the server currently reports as effective. The console treats
  // this as the activation target rather than hardcoding a version literal.
  policy_set_version: string;
  enforcement_mode: EnforcementMode;
  generation: number;
  updated_by: string;
  updated_at: string;
};

export type Finding = {
  finding_id: string;
  rule_id: string;
  severity: string;
  title: string;
  target_arn: string;
  status: string;
};

export type Decision = "ALLOW" | "DENY";

// Mirrors src/ccg/contracts.py DecisionEvidence (§4.2). Rendered per finding so
// a reviewer sees determining policy IDs, policy version, action id, and
// timestamp — the evidence demanded by ACC-02..ACC-06 and ACC-11.
export type DecisionEvidence = {
  decision_id: string;
  request_id: string;
  correlation_id: string;
  actor: string;
  gateway_id: string;
  action_id: string;
  target: string;
  decision: Decision;
  determining_policy_ids: string[];
  policy_set_version: string;
  enforcement_mode: EnforcementMode;
  validation_errors: string[];
  created_at: string;
};

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      "content-type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export function getPolicyState(): Promise<PolicyState> {
  return apiFetch<PolicyState>("/policy");
}

export async function getFindings(): Promise<Finding[]> {
  const response = await apiFetch<{ findings: Finding[] }>("/findings");
  return response.findings;
}

// Read-only decision evidence for a finding (GET /decisions?finding_id=...),
// wired to the endpoint added in task 5.1. Returns an empty list when no
// evidence has been recorded yet.
export async function getDecisionEvidence(findingId: string): Promise<DecisionEvidence[]> {
  const query = new URLSearchParams({ finding_id: findingId });
  const response = await apiFetch<{ decisions: DecisionEvidence[] }>(`/decisions?${query.toString()}`);
  return response.decisions;
}

// Build an activation request from server-reported state. The requested
// version is the version the server advertises as effective (`policy_set_version`)
// and the optimistic-concurrency guard is the server's `generation`. There is
// no hardcoded version literal: the console can only ask the server to confirm
// a version the server itself reported.
export function activationRequestFromState(
  state: PolicyState,
  reason: string,
): {
  requestedVersion: string;
  expectedGeneration: number;
  reason: string;
  activate: boolean;
} {
  return {
    requestedVersion: state.policy_set_version,
    expectedGeneration: state.generation,
    reason,
    // Toggle relative to the server-confirmed mode; the server still decides
    // whether the change is accepted.
    activate: state.enforcement_mode !== "ACTIVE",
  };
}

export function requestPolicyActivation(input: {
  requestedVersion: string;
  expectedGeneration: number;
  reason: string;
  activate: boolean;
}): Promise<unknown> {
  return apiFetch("/policy/activation", {
    method: "POST",
    body: JSON.stringify(input),
  });
}
