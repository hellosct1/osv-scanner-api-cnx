#!/usr/bin/env bash
# =============================================================================
# Scan a Drupal project with the OSV API
# Drupal packages are published in the Packagist OSV ecosystem.
# =============================================================================

set -euo pipefail

OSV_API="${OSV_API:-https://api.osv.dev/v1}"
PROJECT_PATH=""
OUTPUT_DIR="rapport-projet"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

die()  { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[INFO]  $*"; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }
require_cmd curl
require_cmd jq
require_cmd find

usage() {
  cat <<EOF
Usage: $0 PROJECT_PATH [OPTIONS]
       $0 --project PROJECT_PATH [OPTIONS]

Scan recursively the Drupal project with the OSV API.
PROJECT_PATH is the Drupal project directory to scan.

Drupal advisories use the OSV Packagist ecosystem and DRUPAL-* identifiers.

OPTIONS
  -p, --project <directory>  Drupal project directory (alternative to positional argument)
  -o <file>        Output JSON file (default: OUTPUT_DIR/osv-drupal-project-TIMESTAMP.json)
  -h, --help       Show this help

EXAMPLES
  $0 /var/www/html/drupal
  $0 --project /var/www/html/drupal -o /tmp/drupal-osv.json
EOF
  exit 0
}

OUTFILE=""

[[ "${1:-}" == "--help" ]] && usage

while (($#)); do
  case "$1" in
    -p|--project)
      (($# >= 2)) || die "Option $1 requires a project directory."
      PROJECT_PATH="$2"
      shift 2
      ;;
    -o)
      (($# >= 2)) || die "Option -o requires an output file."
      OUTFILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    --)
      shift
      (($# == 1)) || die "Provide exactly one project directory."
      [[ -z "$PROJECT_PATH" ]] || die "Project directory was provided more than once."
      PROJECT_PATH="$1"
      shift
      ;;
    -*)
      die "Unknown option: $1"
      ;;
    *)
      [[ -z "$PROJECT_PATH" ]] || die "Project directory was provided more than once."
      PROJECT_PATH="$1"
      shift
      ;;
  esac
done

[[ -n "$PROJECT_PATH" ]] || die "Project directory required. Use: $0 PROJECT_PATH"
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
