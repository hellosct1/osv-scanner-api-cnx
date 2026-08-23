#!/usr/bin/env bash
# =============================================================================
# 2-osv-api-ossfuzz.sh — Query the OSV.dev API for OSS-Fuzz vulnerabilities
# API  : https://google.github.io/osv.dev/api/
# Ecosystem : OSS-Fuzz
# OSS-Fuzz integrates C/C++ (and other) projects; packages are identified by
# the name used in their OSS-Fuzz integration (e.g. "ffmpeg", "curl", "libpng")
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

Query OSV.dev for OSS-Fuzz vulnerabilities (fuzzing-discovered bugs in
C/C++ and other open-source projects integrated with OSS-Fuzz).

OPTIONS
  -p <project>     OSS-Fuzz project name (required unless -c/-g/-b is used)
  -v <version>     Version string (optional; omit to list all vulns for project)
  -c <commit>      Git commit hash (alternative to -p/-v)
  -g <vuln-id>     Fetch a specific OSV/OSS-Fuzz vulnerability by ID (e.g. OSV-2020-744)
  -o <file>        Output JSON file  (default: auto-generated)
  -b               Batch mode: read "project version" pairs from stdin (one per line)
  -l               List well-known OSS-Fuzz project names and exit
  -h               Show this help

EXAMPLES
  # All vulnerabilities for the curl project
  $0 -p curl

  # Vulnerabilities for a specific libpng version
  $0 -p libpng -v 1.6.37

  # Query by commit hash
  $0 -c 6879efc2c1596d11a6a6ad296f80063b558d5e0f

  # Fetch a specific OSV vulnerability record
  $0 -g OSV-2020-744

  # Batch query (stdin)
  printf "curl 7.88.0\nffmpeg 6.0\n" | $0 -b
EOF
  exit 0
}

list_known_projects() {
  cat <<EOF
Well-known OSS-Fuzz project names (use with -p):

  C / C++
    curl           ffmpeg          libpng          libjpeg-turbo
    openssl        libxml2         sqlite3         zlib
    freetype2      lcms            libtiff         harfbuzz
    icu             poppler         ghostscript     wireshark

  Rust (integrated via OSS-Fuzz)
    rust-url       rust-regex      rust-lexical    nom

  Python
    pillow         pycparser

  Others
    mruby          lua             php             openjpeg

NOTE: The exact string must match the OSS-Fuzz integration name.
      See https://github.com/google/oss-fuzz/tree/master/projects
EOF
  exit 0
}

# ---------------------------------------------------------------------------
# Single query — project (+ optional version) in OSS-Fuzz ecosystem
# ---------------------------------------------------------------------------
query_project() {
  local project="$1" version="$2" outfile="$3"

  local payload
  if [[ -n "$version" ]]; then
    info "Querying OSV.dev → OSS-Fuzz project: $project  version: $version"
    payload=$(jq -nc \
      --arg name    "$project" \
      --arg version "$version" \
      '{"package": {"name": $name, "ecosystem": "OSS-Fuzz"}, "version": $version}')
  else
    info "Querying OSV.dev → OSS-Fuzz project: $project  (all versions)"
    payload=$(jq -nc \
      --arg name "$project" \
      '{"package": {"name": $name, "ecosystem": "OSS-Fuzz"}}')
  fi

  local response
  response=$(curl -sSL \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -H "User-Agent: osv-api-ossfuzz/1.0" \
    -d "$payload" \
    "${OSV_API}/query")

  echo "$response" | jq -e . > /dev/null 2>&1 || die "Invalid JSON response from OSV API"

  local count
  count=$(echo "$response" | jq '.vulns | length // 0')
  info "Found $count OSS-Fuzz vulnerability/vulnerabilities for $project"

  echo "$response" | jq . > "$outfile"
  info "Results saved → $outfile"

  if [[ "$count" -gt 0 ]]; then
    echo ""
    echo "=== OSS-Fuzz vulnerability summary: $project ==="
    echo "$response" | jq -r '
      .vulns[]? |
      "  ID       : \(.id)",
      "  Summary  : \(.summary // "N/A")",
      "  Severity : \(.database_specific.severity // .severity // "N/A")",
      "  Published: \(.published)",
      "  Modified : \(.modified)",
      "  Aliases  : \((.aliases // []) | join(", "))",
      "  Ref      : \((.references // []) | map(.url) | first // "N/A")",
      "  ---"
    '
    echo ""
    echo "Total: $count vulnerabilities"
  else
    info "No vulnerabilities found for $project${version:+ @ $version}"
  fi
}

# ---------------------------------------------------------------------------
# Query by commit hash (cross-ecosystem, works for OSS-Fuzz Git-tracked repos)
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
    -H "User-Agent: osv-api-ossfuzz/1.0" \
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
      "  Summary : \(.summary // "N/A")",
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
  local outfile="${OUTPUT_DIR}/osv-ossfuzz-${vuln_id}-${TIMESTAMP}.json"

  info "Fetching vulnerability record → $vuln_id"

  local response
  response=$(curl -sSL \
    -H "Accept: application/json" \
    -H "User-Agent: osv-api-ossfuzz/1.0" \
    "${OSV_API}/vulns/${vuln_id}")

  echo "$response" | jq -e . > /dev/null 2>&1 || die "Invalid JSON response from OSV API"

  echo "$response" | jq . > "$outfile"
  info "Vulnerability record saved → $outfile"

  echo ""
  echo "=== $vuln_id ==="
  echo "$response" | jq -r '
    "ID        : \(.id)",
    "Summary   : \(.summary // "N/A")",
    "Details   : \(.details // "N/A" | .[0:400])",
    "Published : \(.published)",
    "Modified  : \(.modified)",
    "Aliases   : \((.aliases // []) | join(", "))",
    "Severity  : \(.database_specific.severity // "N/A")",
    "Ecosystem : \(.affected[0].package.ecosystem // "N/A")",
    "Package   : \(.affected[0].package.name // "N/A")"
  '
  echo ""
  echo "References:"
  echo "$response" | jq -r '.references[]? | "  [\(.type)] \(.url)"'
}

# ---------------------------------------------------------------------------
# Batch query — POST /v1/querybatch
# Reads "project version" pairs from stdin
# ---------------------------------------------------------------------------
batch_query() {
  info "Batch mode: reading OSS-Fuzz project-version pairs from stdin…"

  local queries=()
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    local project version
    read -r project version <<< "$line"
    [[ -z "$project" ]] && { echo "[WARN]  Skipping malformed line: $line" >&2; continue; }
    if [[ -n "$version" ]]; then
      queries+=("$(jq -nc --arg n "$project" --arg v "$version" \
        '{"package":{"name":$n,"ecosystem":"OSS-Fuzz"},"version":$v}')")
    else
      queries+=("$(jq -nc --arg n "$project" \
        '{"package":{"name":$n,"ecosystem":"OSS-Fuzz"}}')")
    fi
  done

  [[ ${#queries[@]} -eq 0 ]] && die "No valid queries found in stdin"

  info "Sending batch query for ${#queries[@]} projects…"

  local payload
  payload=$(printf '%s\n' "${queries[@]}" | jq -sc '{"queries": .}')

  local outfile="${OUTPUT_DIR}/osv-ossfuzz-batch-${TIMESTAMP}.json"

  local response
  response=$(curl -sSL \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -H "User-Agent: osv-api-ossfuzz/1.0" \
    -d "$payload" \
    "${OSV_API}/querybatch")

  echo "$response" | jq -e . > /dev/null 2>&1 || die "Invalid JSON response from OSV API"

  echo "$response" | jq . > "$outfile"
  info "Batch results saved → $outfile"

  echo ""
  echo "=== Batch OSS-Fuzz vulnerability summary ==="
  echo "$response" | jq -r '
    .results[]? |
    if (.vulns | length) > 0 then
      "  Project : \(.vulns[0].affected[0].package.name // "unknown")",
      "  Vulns   : \(.vulns | length)",
      (.vulns[]? | "    - \(.id): \(.summary // "N/A")"),
      "  ---"
    else empty end
  '
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
PROJECT=""
VERSION=""
COMMIT=""
OUTFILE=""
GET_ID=""
BATCH=false

while getopts ":p:v:c:g:o:blh" opt; do
  case "$opt" in
    p) PROJECT="$OPTARG" ;;
    v) VERSION="$OPTARG" ;;
    c) COMMIT="$OPTARG" ;;
    g) GET_ID="$OPTARG" ;;
    o) OUTFILE="$OPTARG" ;;
    b) BATCH=true ;;
    l) list_known_projects ;;
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
  OUTFILE="${OUTFILE:-${OUTPUT_DIR}/osv-ossfuzz-commit-${COMMIT:0:8}-${TIMESTAMP}.json}"
  query_commit "$COMMIT" "$OUTFILE"

elif [[ -n "$PROJECT" ]]; then
  local_name="${PROJECT}${VERSION:+-$VERSION}"
  OUTFILE="${OUTFILE:-${OUTPUT_DIR}/osv-ossfuzz-${local_name}-${TIMESTAMP}.json}"
  query_project "$PROJECT" "$VERSION" "$OUTFILE"

else
  echo ""
  echo "No query specified. Running a demo query: OSS-Fuzz project 'mruby'"
  echo ""
  PROJECT="mruby"
  VERSION=""
  OUTFILE="${OUTPUT_DIR}/osv-ossfuzz-${PROJECT}-${TIMESTAMP}.json"
  query_project "$PROJECT" "$VERSION" "$OUTFILE"
fi
