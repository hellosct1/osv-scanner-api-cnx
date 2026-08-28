#!/usr/bin/env bash
set -euo pipefail

PROJECT_PATH="/var/www/html/osv-scanner/drupal-10.2"
OUTPUT_DIR="/var/www/html/osv-scanner/rapport"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OSV_REPORT="${OUTPUT_DIR}/osv-drupal-scanner-${TIMESTAMP}.json"

for cmd in osv-scanner jq; do
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

echo "[INFO] Scan récursif du projet Drupal : $PROJECT_PATH"

SCAN_STATUS=0
osv-scanner scan source \
  --recursive \
  --format json \
  --output-file "$OSV_REPORT" \
  "$PROJECT_PATH" || SCAN_STATUS=$?

[[ -s "$OSV_REPORT" ]] || {
  echo "[ERROR] Rapport OSV absent ou vide : $OSV_REPORT" >&2
  exit 1
}

jq -e . "$OSV_REPORT" >/dev/null || {
  echo "[ERROR] Le rapport OSV n'est pas un JSON valide : $OSV_REPORT" >&2
  exit 1
}

# Expose les identifiants CVE dans des champs dédiés, tout en conservant
# les alias et l'identifiant OSV fournis par OSV-Scanner.
jq '(.results[]?.packages[]?.vulnerabilities[]? |=
  (. + {
    cve_ids: [(.aliases // [])[] | select(test("^CVE-[0-9]{4}-[0-9]+$"))],
    cve_id: ([ (.aliases // [])[] | select(test("^CVE-[0-9]{4}-[0-9]+$")) ] | first // null)
  }))' "$OSV_REPORT" > "${OSV_REPORT}.tmp"
mv "${OSV_REPORT}.tmp" "$OSV_REPORT"

echo "[INFO] Rapport JSON généré : $OSV_REPORT"

FINAL_SCAN_STATUS=0
osv-scanner scan -r "$PROJECT_PATH" || FINAL_SCAN_STATUS=$?

if [[ "$SCAN_STATUS" -ne 0 || "$FINAL_SCAN_STATUS" -ne 0 ]]; then
  echo "[WARN] OSV-Scanner a détecté des vulnérabilités."
fi
