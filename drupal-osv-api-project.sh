#!/usr/bin/env bash
# =============================================================================
# osv-api-drupal-project.sh — Scan a Drupal project with the OSV API
# Drupal packages are published in the Packagist OSV ecosystem.
# =============================================================================

set -euo pipefail

OSV_API="https://api.osv.dev/v1"
PROJECT_PATH="/var/www/html/osv-scanner/drupal-10.2"
OUTPUT_DIR="/var/www/html/osv-scanner/rapport"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

die()  { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[INFO]  $*"; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }
require_cmd curl
require_cmd jq
require_cmd find

usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Scan recursively the Drupal project with the OSV API.
The project is read from:
  $PROJECT_PATH

Drupal advisories use the OSV Packagist ecosystem and DRUPAL-* identifiers.

OPTIONS
  -o <file>        Output JSON file (default: OUTPUT_DIR/osv-drupal-project-TIMESTAMP.json)
  -h, --help       Show this help

EXAMPLES
  $0
  $0 -o /tmp/drupal-osv.json
EOF
  exit 0
}

OUTFILE=""

[[ "${1:-}" == "--help" ]] && usage

while getopts ":o:h" opt; do
  case "$opt" in
    o) OUTFILE="$OPTARG" ;;
    h) usage ;;
    :) die "Option -$OPTARG requires an argument." ;;
    \?) die "Unknown option: -$OPTARG" ;;
  esac
done

[[ -d "$PROJECT_PATH" ]] || die "Project directory not found: $PROJECT_PATH"

mkdir -p "$OUTPUT_DIR"
OUTFILE="${OUTFILE:-${OUTPUT_DIR}/osv-drupal-project-${TIMESTAMP}.json}"

mapfile -d '' -t LOCKFILES < <(find "$PROJECT_PATH" -type f -name composer.lock -print0)
[[ ${#LOCKFILES[@]} -gt 0 ]] || die "No composer.lock found recursively in: $PROJECT_PATH"

info "Scanning Drupal project recursively: $PROJECT_PATH"
info "Found ${#LOCKFILES[@]} composer.lock file(s)"

PAYLOAD=$(jq -s \
  '[.[].packages[]?, .[]."packages-dev"[]?]
   | map(select((.name // "") != "" and (.version // "") != ""))
   | unique_by([.name, .version])
   | {queries: map({package: {name: .name, ecosystem: "Packagist"}, version: .version})}' \
  "${LOCKFILES[@]}") \
  || die "Unable to parse composer.lock files"

QUERY_COUNT=$(echo "$PAYLOAD" | jq '.queries | length')
[[ "$QUERY_COUNT" -gt 0 ]] || die "No package with a name and version found in composer.lock files"

RESPONSE=$(curl --fail --silent --show-error --location \
  --connect-timeout 10 --max-time 120 \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "User-Agent: osv-api-drupal-project/1.0" \
  --data "$PAYLOAD" \
  "${OSV_API}/querybatch") || die "OSV API request failed"

echo "$RESPONSE" | jq -e . >/dev/null || die "Invalid JSON response from OSV API"
echo "$RESPONSE" | jq . > "$OUTFILE"

VULN_COUNT=$(echo "$RESPONSE" | jq '[.results[]?.vulns[]?] | length')
info "Sent $QUERY_COUNT package queries to OSV"
info "Found $VULN_COUNT vulnerability/vulnerabilities"
info "JSON report saved: $OUTFILE"
