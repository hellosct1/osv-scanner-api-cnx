#!/usr/bin/env bash
set -euo pipefail

PROJECT_PATH="${1:-.}"
OUTPUT_DIR="${OUTPUT_DIR:-./rapport}"
EUVD_API_URL="${EUVD_API_URL:-https://euvdservices.enisa.eu/api/v1/vulnerabilities}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OSV_REPORT="${OUTPUT_DIR}/osv-report-${TIMESTAMP}.json"
EUVD_REPORT="${OUTPUT_DIR}/euvd-report-${TIMESTAMP}.json"
COMBINED_REPORT="${OUTPUT_DIR}/osv-euvd-report-${TIMESTAMP}.json"

for cmd in osv-scanner jq curl; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "[ERROR] Required command not found: $cmd" >&2
    exit 1
  }
done

[[ -d "$PROJECT_PATH" ]] || {
  echo "[ERROR] Project directory not found: $PROJECT_PATH" >&2
  exit 1
}

mkdir -p "$OUTPUT_DIR"

echo "[INFO] Scanning project with OSV-Scanner: $PROJECT_PATH"

OSV_STATUS=0
osv-scanner scan source \
  --recursive \
  --format json \
  --output-file "$OSV_REPORT" \
  "$PROJECT_PATH" || OSV_STATUS=$?

[[ -s "$OSV_REPORT" ]] || {
  echo "[ERROR] OSV report is missing or empty: $OSV_REPORT" >&2
  exit 1
}

jq -e . "$OSV_REPORT" >/dev/null || {
  echo "[ERROR] OSV report is not valid JSON: $OSV_REPORT" >&2
  exit 1
}

mapfile -t CVE_IDS < <(
  jq -r '
    [
      .results[]?.packages[]?.vulnerabilities[]?.aliases[]?
      | select(test("^CVE-[0-9]{4}-[0-9]+$"))
    ]
    | unique
    | .[]
  ' "$OSV_REPORT"
)

printf '[]\n' > "$EUVD_REPORT"

for cve_id in "${CVE_IDS[@]}"; do
  echo "[INFO] Querying EUVD for $cve_id"

  response="$(
    curl --fail --silent --show-error --location \
      --get "$EUVD_API_URL" \
      --data-urlencode "cveId=$cve_id" \
      --header "Accept: application/json" \
      || true
  )"

  if [[ -z "$response" ]] || ! jq -e . >/dev/null 2>&1 <<<"$response"; then
    echo "[WARN] No valid EUVD response for $cve_id" >&2
    continue
  fi

  jq --arg cve_id "$cve_id" \
    '. + [{cve_id: $cve_id, data: .}]' \
    "$EUVD_REPORT" > "${EUVD_REPORT}.tmp"
  mv "${EUVD_REPORT}.tmp" "$EUVD_REPORT"

  jq --arg cve_id "$cve_id" --argjson data "$response" \
    '. + [{cve_id: $cve_id, data: $data}]' \
    "$EUVD_REPORT" > "${EUVD_REPORT}.tmp"
  mv "${EUVD_REPORT}.tmp" "$EUVD_REPORT"
done

jq -n \
  --slurpfile osv "$OSV_REPORT" \
  --slurpfile euvd "$EUVD_REPORT" \
  '{
    generated_at: (now | todate),
    osv: $osv[0],
    euvd: $euvd[0]
  }' > "$COMBINED_REPORT"

echo "[INFO] OSV report: $OSV_REPORT"
echo "[INFO] EUVD report: $EUVD_REPORT"
echo "[INFO] Combined report: $COMBINED_REPORT"

if [[ "$OSV_STATUS" -ne 0 ]]; then
  echo "[WARN] OSV-Scanner detected vulnerabilities." >&2
fi

exit "$OSV_STATUS"