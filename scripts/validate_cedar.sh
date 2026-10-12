#!/usr/bin/env bash
# validate_cedar.sh — Cedar policy + schema validation gate for CCG
#
# Usage:
#   ./scripts/validate_cedar.sh
#
# CI use:
#   - Run after any change to policies/ or the schema file.
#   - Exits non-zero if `cedar validate` finds any errors.
#   - A <GATEWAY_ARN> placeholder warning is informational only (exit 0).
#   - Requires the `cedar` CLI from https://github.com/cedar-policy/cedar
#     (install: cargo install cedar-policy-cli  OR  brew install cedar-policy/tap/cedar)
#
# Missing-CLI behavior:
#   - By default (local/dev) a missing `cedar` CLI is a HARD FAILURE (exit 1):
#     developers are expected to have the analyzer installed before touching
#     policies.
#   - In CI the binary is not guaranteed on the hosted runner. Set
#     CEDAR_SOFT_SKIP=1 to downgrade "cedar not found" to a soft skip (exit 0)
#     with a clear log line, so PR CI does not hard-fail on a missing binary but
#     STILL validates whenever the CLI is present (e.g. a cache hit or a future
#     install step). This only affects the missing-binary path; when `cedar`
#     IS present, validation runs and real validation errors still fail the job.
#
# Expected files (relative to repo root):
#   policies/guardrails.cedar
#   policies/remediation-permits.cedar
#   policies/ccg-schema.cedarschema

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="${REPO_ROOT}/policies/ccg-schema.cedarschema"
GUARDRAILS="${REPO_ROOT}/policies/guardrails.cedar"
PERMITS="${REPO_ROOT}/policies/remediation-permits.cedar"

# ---------------------------------------------------------------------------
# 1. Check cedar CLI availability
# ---------------------------------------------------------------------------
if ! command -v cedar &>/dev/null; then
  if [[ "${CEDAR_SOFT_SKIP:-0}" == "1" ]]; then
    echo "[SKIP] 'cedar' CLI not found and CEDAR_SOFT_SKIP=1 — skipping Cedar" \
         "schema validation for this run."
    echo "       Policy baseline checks (scripts/validate_policy_baseline.py)" \
         "still ran. Install the cedar CLI to enable full schema/analyzer" \
         "validation in this environment."
    exit 0
  fi
  echo "[ERROR] 'cedar' CLI not found." >&2
  echo "        Install: cargo install cedar-policy-cli" >&2
  echo "        or:      brew install cedar-policy/tap/cedar" >&2
  echo "        (CI only: set CEDAR_SOFT_SKIP=1 to soft-skip a missing CLI.)" >&2
  exit 1
fi

echo "[INFO] cedar CLI found: $(cedar --version 2>&1 | head -1)"
echo "[INFO] Schema: ${SCHEMA}"

# ---------------------------------------------------------------------------
# 2. Warn (but do not fail) if <GATEWAY_ARN> placeholder is still present
# ---------------------------------------------------------------------------
placeholder_files=()
for f in "$GUARDRAILS" "$PERMITS"; do
  if grep -q '<GATEWAY_ARN>' "$f" 2>/dev/null; then
    placeholder_files+=("$f")
  fi
done

if [[ ${#placeholder_files[@]} -gt 0 ]]; then
  echo ""
  echo "[WARN] <GATEWAY_ARN> placeholder is still present in:"
  for f in "${placeholder_files[@]}"; do
    echo "       $f"
  done
  echo "       Replace it with the deployed gateway ARN before any ACTIVE policy"
  echo "       activation. Placeholder policies can only be activated with"
  echo "       validationMode=IGNORE_ALL_FINDINGS (LOG_ONLY shadow testing)."
  echo ""
fi

# ---------------------------------------------------------------------------
# 3. Validate each policy file against the schema
# ---------------------------------------------------------------------------
FAIL=0

validate_policy() {
  local label="$1"
  local policy_file="$2"
  echo "[INFO] Validating ${label}..."
  if cedar validate \
       --schema "${SCHEMA}" \
       --schema-format json \
       --policies "${policy_file}" 2>&1; then
    echo "[OK]   ${label} passed validation."
  else
    echo "[FAIL] ${label} failed validation." >&2
    FAIL=1
  fi
  echo ""
}

validate_policy "guardrails.cedar"          "$GUARDRAILS"
validate_policy "remediation-permits.cedar" "$PERMITS"

# ---------------------------------------------------------------------------
# 4. Summary and exit
# ---------------------------------------------------------------------------
if [[ $FAIL -ne 0 ]]; then
  echo "[ERROR] One or more policy files failed Cedar validation. Fix errors" >&2
  echo "        above before proceeding with any policy activation." >&2
  exit 1
fi

echo "[INFO] All Cedar policy files passed schema validation."
echo "[INFO] Note: placeholder ARNs must be replaced before live activation."
echo "[INFO] Run the policy analyzer (validationMode=FAIL_ON_ANY_FINDINGS)"
echo "[INFO] against the deployed Gateway schema before activating any permit."
exit 0
