#!/usr/bin/env bash
# =============================================================================
# 1-osv-api-drupal.sh — Query the OSV.dev API for Drupal vulnerabilities
# API  : https://google.github.io/osv.dev/api/
# Ecosystem : Packagist (Composer)
# Drupal packages follow the pattern  drupal/<module>  (e.g. drupal/core)
# IDs follow the pattern DRUPAL-CORE-YYYY-NNN or DRUPAL-SA-CONTRIB-YYYY-NNN
# =============================================================================

set -euo pipefail

OSV_API="https://api.osv.dev/v1"
OUTPUT_DIR="."
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
die()  { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[INFO]  $*"; }

require_cmd() { command -v "$1" &>/dev/null || die "Required command not found: $1"; }
require_cmd curl
require_cmd jq

usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Query OSV.dev for known vulnerabilities in Drupal modules and core.

Drupal packages are tracked in the Packagist (Composer) ecosystem.
Package names follow the pattern  drupal/<module>  (e.g. drupal/core,
drupal/views, drupal/webform).

OPTIONS
  -p <package>     Drupal package name (e.g. drupal/core, drupal/views)
                   The  drupal/  prefix is added automatically if omitted.
  -v <version>     Version string (required unless -c/-g is used)
  -c <commit>      Git commit hash (alternative to -p/-v)
  -g <vuln-id>     Fetch a specific OSV vulnerability by ID
                   (e.g. DRUPAL-CORE-2023-001 or GHSA-xxxx)
  -o <file>        Output JSON file  (default: auto-generated)
  -b               Batch mode: read "package version" pairs from stdin
  -l               List well-known Drupal modules and exit
  -h               Show this help

EXAMPLES
  # Query Drupal core
  $0 -p drupal/core -v 9.5.0

  # Short syntax: prefix drupal/ added automatically
  $0 -p core -v 10.1.0

  # Query a contributed module
  $0 -p views -v 8.x-3.0
  $0 -p drupal/webform -v 6.1.0

  # Query by commit hash
  $0 -c 6879efc2c1596d11a6a6ad296f80063b558d5e0f

  # Fetch a specific Drupal advisory
  $0 -g DRUPAL-CORE-2023-001

  # Batch query (stdin)
  printf "drupal/core 9.5.0\ndrupal/views 8.x-3.0\n" | $0 -b

  # Save to a custom file
  $0 -p core -v 10.0.0 -o drupal-core-10-vulns.json
EOF
  exit 0
}

list_known_modules() {
  cat <<EOF
Well-known Drupal packages (use with -p, prefix drupal/ added automatically):

  Core
    drupal/core                 — Drupal CMS core

  Content & Fields
    drupal/views                — Views (content listing)
    drupal/paragraphs           — Paragraphs (structured content)
    drupal/field_group          — Field Group
    drupal/metatag              — Meta Tag
    drupal/token                — Token

  Forms & Workflow
    drupal/webform              — Webform
    drupal/workflow             — Workflow
    drupal/content_moderation   — Content Moderation

  Media & Files
    drupal/media                — Media
    drupal/media_library        — Media Library
    drupal/file_entity          — File Entity

  Commerce
    drupal/commerce             — Drupal Commerce
    drupal/commerce_stripe      — Commerce Stripe

  Security & Access
    drupal/captcha              — CAPTCHA
    drupal/recaptcha            — reCAPTCHA
    drupal/two_factor_auth      — Two-Factor Authentication
    drupal/seckit               — Security Kit

  SEO & Performance
    drupal/pathauto             — Pathauto
    drupal/redirect             — Redirect
    drupal/xmlsitemap           — XML Sitemap
    drupal/cache_control_policy — Cache Control Policy

  Development
    drupal/devel                — Devel
    drupal/ctools               — CTools

NOTE: Package names must match exactly on Packagist (drupal/<module>).
      See https://www.drupal.org/project/project_module for all modules.
EOF
  exit 0
}

# ---------------------------------------------------------------------------
# Normalize package name: add drupal/ prefix if missing
# ---------------------------------------------------------------------------
normalize_package() {
  local pkg="$1"
  if [[ "$pkg" != drupal/* && "$pkg" != */* ]]; then
    echo "drupal/${pkg}"
  else
    echo "$pkg"
  fi
}

# ---------------------------------------------------------------------------
# Single query — package + version in Packagist ecosystem
# ---------------------------------------------------------------------------
query_package() {
  local package="$1" version="$2" outfile="$3"

  info "Querying OSV.dev → Drupal package: $package  version: $version"

  local payload
  payload=$(jq -nc \
    --arg name    "$package" \
    --arg version "$version" \
    '{"package": {"name": $name, "ecosystem": "Packagist"}, "version": $version}')

  local response
  response=$(curl -sSL \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -H "User-Agent: osv-api-drupal/1.0" \
    -d "$payload" \
    "${OSV_API}/query")

  echo "$response" | jq -e . > /dev/null 2>&1 || die "Invalid JSON response from OSV API"

  local count
  count=$(echo "$response" | jq '.vulns | length // 0')
  info "Found $count vulnerability/vulnerabilities for $package@$version"

  echo "$response" | jq . > "$outfile"
  info "Results saved → $outfile"

  if [[ "$count" -gt 0 ]]; then
    echo ""
    echo "=== Vulnerability summary for Drupal: $package@$version ==="
    echo "$response" | jq -r '
      .vulns[]? |
      "  ID       : \(.id)",
      "  Summary  : \(.details // "N/A" | gsub("\n";" ") | .[0:120])",
      "  Published: \(.published)",
      "  Modified : \(.modified)",
      "  Aliases  : \((.aliases // []) | join(", "))",
      "  Fixed in : \([ .affected[]?.ranges[]?.events[]? | .fixed? // empty ] | unique | join(", ") | if . == "" then "N/A" else . end)",
      "  Ref      : \((.references // []) | map(.url) | first // "N/A")",
      "  ---"
    '
    echo ""
    echo "Total: $count vulnerabilities"
  else
    info "No vulnerabilities found for $package@$version"
  fi
}

# ---------------------------------------------------------------------------
# Query by commit hash
# ---------------------------------------------------------------------------
query_commit() {
  local commit="$1" outfile="$2"

  info "Querying OSV.dev → commit: $commit"

  local payload
  payload=$(jq -nc --arg commit "$commit" '{"commit": $commit}')

  local response
  response=$(curl -sSL \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -H "User-Agent: osv-api-drupal/1.0" \
    -d "$payload" \
    "${OSV_API}/query")

  echo "$response" | jq -e . > /dev/null 2>&1 || die "Invalid JSON response from OSV API"

  local count
  count=$(echo "$response" | jq '.vulns | length // 0')
  info "Found $count vulnerability/vulnerabilities for commit $commit"

  echo "$response" | jq . > "$outfile"
  info "Results saved → $outfile"

  if [[ "$count" -gt 0 ]]; then
    echo ""
    echo "=== Vulnerability summary for commit $commit ==="
    echo "$response" | jq -r '
      .vulns[]? |
      "  ID      : \(.id)",
      "  Summary : \(.details // "N/A" | gsub("\n";" ") | .[0:120])",
      "  Ecosystem: \(.affected[0].package.ecosystem // "N/A")",
      "  Modified: \(.modified)",
      "  ---"
    '
  fi
}

# ---------------------------------------------------------------------------
# Fetch a single vulnerability record by OSV ID
# ---------------------------------------------------------------------------
get_vuln_by_id() {
  local vuln_id="$1"
  local outfile="${OUTPUT_DIR}/osv-drupal-${vuln_id}-${TIMESTAMP}.json"

  info "Fetching vulnerability record → $vuln_id"

  local response
  response=$(curl -sSL \
    -H "Accept: application/json" \
    -H "User-Agent: osv-api-drupal/1.0" \
    "${OSV_API}/vulns/${vuln_id}")

  echo "$response" | jq -e . > /dev/null 2>&1 || die "Invalid JSON response from OSV API"

  echo "$response" | jq . > "$outfile"
  info "Vulnerability record saved → $outfile"

  echo ""
  echo "=== $vuln_id ==="
  echo "$response" | jq -r '
    "ID        : \(.id)",
    "Details   : \(.details // "N/A" | gsub("\n";" ") | .[0:400])",
    "Published : \(.published)",
    "Modified  : \(.modified)",
    "Aliases   : \((.aliases // []) | join(", "))",
    "Ecosystem : \(.affected[0].package.ecosystem // "N/A")",
    "Package   : \(.affected[0].package.name // "N/A")"
  '
  echo ""
  echo "Affected version ranges:"
  echo "$response" | jq -r '
    .affected[]?.ranges[]?.events[]? |
    if .introduced then "  introduced: \(.introduced)"
    elif .fixed then "  fixed     : \(.fixed)"
    else empty end
  '
  echo ""
  echo "References:"
  echo "$response" | jq -r '.references[]? | "  [\(.type)] \(.url)"'
}

# ---------------------------------------------------------------------------
# Batch query — POST /v1/querybatch
# Reads "package version" pairs from stdin
# ---------------------------------------------------------------------------
batch_query() {
  info "Batch mode: reading Drupal package-version pairs from stdin…"

  local queries=()
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    local package version
    read -r package version <<< "$line"
    [[ -z "$package" || -z "$version" ]] && { echo "[WARN]  Skipping malformed line: $line" >&2; continue; }
    package=$(normalize_package "$package")
    queries+=("$(jq -nc --arg n "$package" --arg v "$version" \
      '{"package":{"name":$n,"ecosystem":"Packagist"},"version":$v}')")
  done

  [[ ${#queries[@]} -eq 0 ]] && die "No valid queries found in stdin"

  info "Sending batch query for ${#queries[@]} Drupal packages…"

  local payload
  payload=$(printf '%s\n' "${queries[@]}" | jq -sc '{"queries": .}')

  local outfile="${OUTPUT_DIR}/osv-drupal-batch-${TIMESTAMP}.json"

  local response
  response=$(curl -sSL \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -H "User-Agent: osv-api-drupal/1.0" \
    -d "$payload" \
    "${OSV_API}/querybatch")

  echo "$response" | jq -e . > /dev/null 2>&1 || die "Invalid JSON response from OSV API"

  echo "$response" | jq . > "$outfile"
  info "Batch results saved → $outfile"

  echo ""
  echo "=== Batch Drupal vulnerability summary ==="
  echo "$response" | jq -r '
    .results[]? |
    if (.vulns | length) > 0 then
      "  Package : \(.vulns[0].affected[0].package.name // "unknown")",
      "  Vulns   : \(.vulns | length)",
      (.vulns[]? | "    - \(.id): \(.details // "N/A" | gsub("\n";" ") | .[0:80])"),
      "  ---"
    else empty end
  '
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
PACKAGE=""
VERSION=""
COMMIT=""
OUTFILE=""
GET_ID=""
BATCH=false

while getopts ":p:v:c:g:o:blh" opt; do
  case "$opt" in
    p) PACKAGE="$OPTARG" ;;
    v) VERSION="$OPTARG" ;;
    c) COMMIT="$OPTARG" ;;
    g) GET_ID="$OPTARG" ;;
    o) OUTFILE="$OPTARG" ;;
    b) BATCH=true ;;
    l) list_known_modules ;;
    h) usage ;;
    :) die "Option -$OPTARG requires an argument." ;;
    \?) die "Unknown option: -$OPTARG" ;;
  esac
done

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
if $BATCH; then
  batch_query

elif [[ -n "$GET_ID" ]]; then
  get_vuln_by_id "$GET_ID"

elif [[ -n "$COMMIT" ]]; then
  OUTFILE="${OUTFILE:-${OUTPUT_DIR}/osv-drupal-commit-${COMMIT:0:8}-${TIMESTAMP}.json}"
  query_commit "$COMMIT" "$OUTFILE"

elif [[ -n "$PACKAGE" && -n "$VERSION" ]]; then
  PACKAGE=$(normalize_package "$PACKAGE")
  safe_name="${PACKAGE//\//-}"
  OUTFILE="${OUTFILE:-${OUTPUT_DIR}/osv-drupal-${safe_name}-${VERSION}-${TIMESTAMP}.json}"
  query_package "$PACKAGE" "$VERSION" "$OUTFILE"

else
  echo ""
  echo "No query specified. Running a demo query: drupal/core 9.5.0"
  echo ""
  PACKAGE="drupal/core"
  VERSION="9.5.0"
  OUTFILE="${OUTPUT_DIR}/osv-drupal-core-${VERSION}-${TIMESTAMP}.json"
  query_package "$PACKAGE" "$VERSION" "$OUTFILE"
fi
