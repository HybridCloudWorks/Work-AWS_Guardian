import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import HomePage from "../app/page";
import type { DecisionEvidence, Finding, PolicyState } from "../lib/api";

const policyState: PolicyState = {
  policy_engine_id: "pe-1",
  policy_set_version: "2026-10-10T00:00:00Z",
  enforcement_mode: "LOG_ONLY",
  generation: 7,
  updated_by: "admin@example.com",
  updated_at: "2026-10-10T00:00:00Z",
};

const findings: Finding[] = [
  {
    finding_id: "f1",
    rule_id: "sg-open-ingress",
    severity: "HIGH",
    title: "Open security group ingress",
    target_arn: "arn:aws:ec2:us-east-1:111:security-group/sg-1",
    status: "OPEN",
  },
];

const denyEvidence: DecisionEvidence = {
  decision_id: "d1",
  request_id: "req1",
  correlation_id: "corr-1",
  actor: "admin@example.com",
  gateway_id: "agentcore-gateway",
  action_id: "action::RestrictIngress",
  target: findings[0].target_arn,
  decision: "DENY",
  determining_policy_ids: ["forbid-prod", "default-deny"],
  policy_set_version: "2026-10-10T00:00:00Z",
  enforcement_mode: "LOG_ONLY",
  validation_errors: [],
  created_at: "2026-10-10T00:01:00Z",
};

type FetchResult = { body: unknown; ok?: boolean; status?: number };

// Route a mocked fetch by URL so the page's parallel loads resolve correctly.
function routeFetch(router: (url: string, init?: RequestInit) => FetchResult) {
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    const { body, ok = true, status = 200 } = router(url, init);
    return { ok, status, json: async () => body } as Response;
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("HomePage", () => {
  it("renders policy mode, version, and generation from server state", async () => {
    routeFetch((url) => {
      if (url.startsWith("/policy")) return { body: policyState };
      if (url.startsWith("/findings")) return { body: { findings: [] } };
      if (url.startsWith("/decisions")) return { body: { decisions: [] } };
      return { body: {} };
    });

    render(<HomePage />);

    await waitFor(() => expect(screen.getByText("LOG_ONLY")).toBeDefined());
    expect(screen.getByText(policyState.policy_set_version)).toBeDefined();
    expect(screen.getByText(String(policyState.generation))).toBeDefined();
    expect(screen.getByText(policyState.updated_by)).toBeDefined();
  });

  it("labels the activation control from server-confirmed mode (no local flip)", async () => {
    routeFetch((url) => {
      if (url.startsWith("/policy")) return { body: { ...policyState, enforcement_mode: "ACTIVE" } };
      if (url.startsWith("/findings")) return { body: { findings: [] } };
      if (url.startsWith("/decisions")) return { body: { decisions: [] } };
      return { body: {} };
    });

    render(<HomePage />);
    // ACTIVE server state => button offers to deactivate; the console reads
    // mode from the fetched state rather than inventing an "authorized" flag.
    await waitFor(() => expect(screen.getByRole("button", { name: "Deactivate permits" })).toBeDefined());
  });

  it("renders decision evidence when present (ACC-03/ACC-06)", async () => {
    routeFetch((url) => {
      if (url.startsWith("/policy")) return { body: policyState };
      if (url.startsWith("/findings")) return { body: { findings } };
      if (url.startsWith("/decisions")) return { body: { decisions: [denyEvidence] } };
      return { body: {} };
    });

    render(<HomePage />);

    await waitFor(() => expect(screen.getByText("Decision evidence")).toBeDefined());
    expect(screen.getByText("DENY")).toBeDefined();
    expect(screen.getByText("action::RestrictIngress")).toBeDefined();
    expect(screen.getByText("forbid-prod")).toBeDefined();
    expect(screen.getByText("default-deny")).toBeDefined();
  });

  it("sends an activation request derived from server state, not a hardcoded v1", async () => {
    const fetchMock = routeFetch((url) => {
      if (url.startsWith("/policy/activation")) return { body: {} };
      if (url.startsWith("/policy")) return { body: policyState };
      if (url.startsWith("/findings")) return { body: { findings: [] } };
      if (url.startsWith("/decisions")) return { body: { decisions: [] } };
      return { body: {} };
    });

    render(<HomePage />);
    await waitFor(() => expect(screen.getByText("LOG_ONLY")).toBeDefined());

    await userEvent.click(screen.getByRole("button", { name: "Activate permits" }));

    await waitFor(() => {
      const activationCall = fetchMock.mock.calls.find((call) => String(call[0]).startsWith("/policy/activation"));
      expect(activationCall).toBeDefined();
      const body = JSON.parse(String((activationCall![1] as RequestInit).body));
      expect(body.requestedVersion).toBe(policyState.policy_set_version);
      expect(body.requestedVersion).not.toBe("v1");
      expect(body.expectedGeneration).toBe(policyState.generation);
      expect(body.activate).toBe(true);
    });
  });

  it("surfaces a stale-version activation rejection as an error (ACC-09)", async () => {
    routeFetch((url) => {
      if (url.startsWith("/policy/activation")) return { body: {}, ok: false, status: 409 };
      if (url.startsWith("/policy")) return { body: policyState };
      if (url.startsWith("/findings")) return { body: { findings: [] } };
      if (url.startsWith("/decisions")) return { body: { decisions: [] } };
      return { body: {} };
    });

    render(<HomePage />);
    await waitFor(() => expect(screen.getByText("LOG_ONLY")).toBeDefined());

    await userEvent.click(screen.getByRole("button", { name: "Activate permits" }));

    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("409"));
  });
});
