import { afterEach, describe, expect, it, vi } from "vitest";
import {
  activationRequestFromState,
  getDecisionEvidence,
  getFindings,
  getPolicyState,
  PolicyState,
  requestPolicyActivation,
} from "../lib/api";

function mockFetch(payload: unknown, ok = true, status = 200) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok,
    status,
    json: async () => payload,
  } as Response);
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const baseState: PolicyState = {
  policy_engine_id: "pe-1",
  policy_set_version: "2026-10-10T00:00:00Z",
  enforcement_mode: "LOG_ONLY",
  generation: 7,
  updated_by: "admin@example.com",
  updated_at: "2026-10-10T00:00:00Z",
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("getPolicyState", () => {
  it("fetches /policy and parses the state", async () => {
    const fetchMock = mockFetch(baseState);
    const state = await getPolicyState();
    expect(state).toEqual(baseState);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/policy");
    expect(init?.credentials).toBe("include");
  });
});

describe("getFindings", () => {
  it("unwraps the findings array from the response envelope", async () => {
    const findings = [
      { finding_id: "f1", rule_id: "r1", severity: "HIGH", title: "t", target_arn: "arn", status: "OPEN" },
    ];
    const fetchMock = mockFetch({ findings });
    const result = await getFindings();
    expect(result).toEqual(findings);
    expect(fetchMock.mock.calls[0][0]).toBe("/findings");
  });
});

describe("getDecisionEvidence", () => {
  it("requests /decisions with the finding_id query and unwraps decisions", async () => {
    const decisions = [
      {
        decision_id: "d1",
        request_id: "req1",
        correlation_id: "c1",
        actor: "admin",
        gateway_id: "gw",
        action_id: "action::RestrictIngress",
        target: "arn:aws:ec2:...:sg/sg-1",
        decision: "DENY",
        determining_policy_ids: ["forbid-prod"],
        policy_set_version: "2026-10-10T00:00:00Z",
        enforcement_mode: "LOG_ONLY",
        validation_errors: [],
        created_at: "2026-10-10T00:01:00Z",
      },
    ];
    const fetchMock = mockFetch({ decisions });
    const result = await getDecisionEvidence("f1");
    expect(result).toEqual(decisions);
    expect(fetchMock.mock.calls[0][0]).toBe("/decisions?finding_id=f1");
  });

  it("encodes finding ids with special characters", async () => {
    const fetchMock = mockFetch({ decisions: [] });
    await getDecisionEvidence("arn:aws:s3:::bucket/key");
    expect(fetchMock.mock.calls[0][0]).toBe(
      "/decisions?finding_id=arn%3Aaws%3As3%3A%3A%3Abucket%2Fkey",
    );
  });
});

describe("requestPolicyActivation", () => {
  it("POSTs the activation body as JSON", async () => {
    const fetchMock = mockFetch({});
    await requestPolicyActivation({
      requestedVersion: "2026-10-10T00:00:00Z",
      expectedGeneration: 7,
      reason: "demo",
      activate: true,
    });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/policy/activation");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({
      requestedVersion: "2026-10-10T00:00:00Z",
      expectedGeneration: 7,
      reason: "demo",
      activate: true,
    });
  });

  it("throws on a non-ok response (surfaces stale-version rejection)", async () => {
    mockFetch({}, false, 409);
    await expect(
      requestPolicyActivation({
        requestedVersion: "v",
        expectedGeneration: 1,
        reason: "demo",
        activate: true,
      }),
    ).rejects.toThrow("API request failed: 409");
  });
});

describe("activationRequestFromState", () => {
  it("derives version and generation from server state, never a hardcoded literal", () => {
    const request = activationRequestFromState(baseState, "demo");
    expect(request.requestedVersion).toBe(baseState.policy_set_version);
    expect(request.requestedVersion).not.toBe("v1");
    expect(request.expectedGeneration).toBe(baseState.generation);
    expect(request.reason).toBe("demo");
  });

  it("requests activation when the server reports LOG_ONLY", () => {
    expect(activationRequestFromState({ ...baseState, enforcement_mode: "LOG_ONLY" }, "r").activate).toBe(true);
  });

  it("requests deactivation when the server reports ACTIVE", () => {
    const state = { ...baseState, enforcement_mode: "ACTIVE" as const, policy_set_version: "gen-9" };
    const request = activationRequestFromState(state, "r");
    expect(request.activate).toBe(false);
    // Still uses the server-reported version, not a literal.
    expect(request.requestedVersion).toBe("gen-9");
  });
});
