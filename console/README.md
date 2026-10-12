# CCG console

This Next.js App Router console is a static-exportable read/control surface. It calls an authenticated API configured with `NEXT_PUBLIC_API_BASE_URL` for findings, effective policy state, decision evidence, and policy activation requests.

## No hidden bypass

The browser does not authorize mutations. There is no local authorizer and no AWS mutation client in this app. The guarantees:

- Remediation mode is **server-confirmed state only**. The page reads `enforcement_mode`, `policy_set_version`, and `generation` from the API and renders them; it never flips a local flag to "authorized".
- Policy activation is a **versioned server request**. The requested version and the optimistic-concurrency `expectedGeneration` are derived from the server-reported state (`activationRequestFromState`), never a hardcoded version literal. A stale or replayed version is rejected by the control plane and surfaced in the UI as an error (it does not optimistically change local mode).
- Every remediation request is delegated to the AgentCore Gateway Policy Engine. Cedar is the decision boundary; this console only sends a request and renders the server-confirmed outcome and decision evidence.
- Nova Sonic is not exposed by this shell and remains disabled by default.

## ACC scenario → UI mapping

The console renders the fields the API returns, so the acceptance scenarios are demonstrable once the API is wired (no live data required to see where each shows):

| Scenario | Where it shows in the UI |
|---|---|
| ACC-01 normalized finding + one correlation ID | Current findings list (title, severity, status, target ARN); the per-finding decision evidence shows the correlation ID. |
| ACC-02 denied-while-inactive (default deny) | Decision evidence under the finding: `DENY` with `determining_policy_ids` of `default-deny` and `enforcement_mode` `LOG_ONLY`. |
| ACC-03 allowed with determining permit | Decision evidence: `ALLOW` with the determining permit policy id, action id, and policy version. |
| ACC-04 `Environment=prod` deny | Decision evidence: `DENY` with the prod forbid in `determining_policy_ids`. |
| ACC-05 missing `CCGDemo` deny | Decision evidence: `DENY` recorded for the finding; no target call. |
| ACC-06 forbid precedence over an active permit | Decision evidence: `DENY` listing both the matching forbid and permit in `determining_policy_ids`. |
| ACC-07 idempotent repeated request | Server-confirmed outcome returned by the activation/remediation path (no second mutation); reflected after refresh. |
| ACC-08 activation pre/post audit visibility | Effective policy state panel (mode/version/generation/updated-by) changes to the server-confirmed state after an audited activation. |
| ACC-09 stale/replayed version rejected | Activation error banner (`role="alert"`); effective state is unchanged because the request derives version/generation from server state. |
| ACC-10 partial discovery note | Findings view (findings still render; no false "all clear"); partial-run evidence from the API is surfaced per finding. |
| ACC-11 unregistered/malformed denied | Decision evidence: `DENY` with `validation_errors` populated for a malformed/unregistered request. |

ACC-12/ACC-13 (voice) are out of scope for this shell; voice is disabled by default and no microphone or Nova Sonic stream is started.

## Install and validate

Install and validate with the pinned versions in `package.json`:

```powershell
npm install
npm run typecheck
npm run lint
npm test
npm run build
```
