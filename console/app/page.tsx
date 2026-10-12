"use client";

import { useEffect, useState } from "react";
import {
  activationRequestFromState,
  DecisionEvidence,
  Finding,
  getDecisionEvidence,
  getFindings,
  getPolicyState,
  PolicyState,
  requestPolicyActivation,
} from "../lib/api";

export default function HomePage() {
  const [policy, setPolicy] = useState<PolicyState | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [evidence, setEvidence] = useState<Record<string, DecisionEvidence[]>>({});
  const [reason, setReason] = useState("Approved sandbox demo activation");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function refresh() {
    try {
      setError(null);
      const [nextPolicy, nextFindings] = await Promise.all([getPolicyState(), getFindings()]);
      setPolicy(nextPolicy);
      setFindings(nextFindings);
      // Load decision evidence per finding so determining policies, version,
      // action id, and timestamp are visible (ACC-02..ACC-06, ACC-11).
      const pairs = await Promise.all(
        nextFindings.map(async (finding) => {
          try {
            return [finding.finding_id, await getDecisionEvidence(finding.finding_id)] as const;
          } catch {
            // A missing evidence read must not blank the findings view.
            return [finding.finding_id, [] as DecisionEvidence[]] as const;
          }
        }),
      );
      setEvidence(Object.fromEntries(pairs));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load compliance state");
    }
  }

  useEffect(() => {
    const refreshTimer = window.setTimeout(() => {
      void refresh();
    }, 0);
    return () => window.clearTimeout(refreshTimer);
  }, []);

  async function activate() {
    if (!policy) return;
    try {
      setBusy(true);
      setError(null);
      // Request derives version/generation from server-confirmed state; the
      // console never sends a hardcoded version literal.
      await requestPolicyActivation(activationRequestFromState(policy, reason));
      await refresh();
    } catch (err) {
      // Stale-version / replay rejections (ACC-09) surface here as an error;
      // the console does not optimistically flip local mode.
      setError(err instanceof Error ? err.message : "Policy activation failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main>
      <header>
        <div>
          <h1>Continuous Compliance Guardian</h1>
          <p>Dedicated sandbox findings and Cedar-governed remediation evidence.</p>
        </div>
        <button type="button" onClick={() => void refresh()} disabled={busy}>Refresh</button>
      </header>

      {error && <p className="error" role="alert">{error}</p>}

      <section aria-labelledby="policy-heading">
        <h2 id="policy-heading">Effective policy state</h2>
        <div className="grid">
          <div className="card"><strong>Mode</strong><p className="status">{policy?.enforcement_mode ?? "Loading"}</p></div>
          <div className="card"><strong>Policy set</strong><p><code>{policy?.policy_set_version ?? "Loading"}</code></p></div>
          <div className="card"><strong>Generation</strong><p>{policy?.generation ?? "Loading"}</p></div>
          <div className="card"><strong>Updated by</strong><p>{policy?.updated_by ?? "Loading"}</p></div>
        </div>
        <p>Changing this control submits a versioned server request. The browser never authorizes a remediation; mutations must still pass the AgentCore Gateway Policy Engine. The requested version and generation are taken from the server-reported state above.</p>
        <label>
          Activation reason
          <input value={reason} onChange={(event) => setReason(event.target.value)} disabled={busy} />
        </label>{" "}
        <button type="button" onClick={() => void activate()} disabled={!policy || busy}>
          {policy?.enforcement_mode === "ACTIVE" ? "Deactivate permits" : "Activate permits"}
        </button>
      </section>

      <section aria-labelledby="findings-heading">
        <h2 id="findings-heading">Current findings</h2>
        {findings.length === 0 ? <p>No findings returned.</p> : findings.map((finding) => (
          <article className="card" key={finding.finding_id}>
            <h3>{finding.title}</h3>
            <p>{finding.severity} · {finding.status} · <code>{finding.target_arn}</code></p>
            <DecisionEvidenceList records={evidence[finding.finding_id] ?? []} />
          </article>
        ))}
      </section>

      <section>
        <h2>Authorization boundary</h2>
        <p>Remediation requests are sent to the authenticated API and delegated to the AgentCore Gateway. This console has no direct AWS mutation client and voice is disabled by default.</p>
      </section>
    </main>
  );
}

function DecisionEvidenceList({ records }: { records: DecisionEvidence[] }) {
  if (records.length === 0) {
    return <p className="evidence-empty">No decision evidence recorded yet.</p>;
  }
  return (
    <div className="evidence">
      <h4>Decision evidence</h4>
      <ul>
        {records.map((record) => (
          <li className="evidence-item" key={record.decision_id}>
            <span className={record.decision === "ALLOW" ? "decision-allow" : "decision-deny"}>
              {record.decision}
            </span>{" "}
            <code>{record.action_id}</code> · policy <code>{record.policy_set_version}</code> ·{" "}
            <span>{record.enforcement_mode}</span>
            <p className="evidence-policies">
              Determining policies:{" "}
              {record.determining_policy_ids.length === 0
                ? "none (default deny)"
                : record.determining_policy_ids.map((id) => <code key={id}>{id}</code>)}
            </p>
            {record.validation_errors.length > 0 && (
              <p className="evidence-errors">Validation errors: {record.validation_errors.join(", ")}</p>
            )}
            <p className="evidence-meta">
              <time dateTime={record.created_at}>{record.created_at}</time> · correlation{" "}
              <code>{record.correlation_id}</code>
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}
