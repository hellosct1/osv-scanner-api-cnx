#!/usr/bin/env bash
# =============================================================================
# osv-api-rust.sh — Query the OSV.dev API for Rust vulnerabilities
# API  : https://google.github.io/osv.dev/api/
# Ecosystem : crates.io
# Packages are identified by their crate name on crates.io (e.g., serde, tokio)
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

Query OSV.dev for known vulnerabilities in Rust (crates.io) packages.

Packages are identified by their crate name from https://crates.io

OPTIONS
  -c <crate>       Crate name (required unless -h/-g/-b/-C is used)
  -v <version>     Version string (required unless -C is used)
  -C <commit>      Git commit hash (alternative to -c/-v)
  -g <vuln-id>     Fetch a specific OSV vulnerability by ID (e.g. GHSA-xxxx)
  -o <file>        Output JSON file  (default: auto-generated)
  -b               Batch mode: read "crate version" pairs from stdin
  -l               List well-known Rust crates and exit
  -h               Show this help

EXAMPLES
  # Query a specific crate version
  $0 -c serde -v 1.0.160

  # Query another Rust crate
  $0 -c tokio -v 1.28.0

  # Query by commit hash
  $0 -C 6879efc2c1596d11a6a6ad296f80063b558d5e0f

  # Fetch a specific vulnerability
  $0 -g GHSA-fxjv-4453-4f89

  # Batch query (stdin)
  printf "serde 1.0.160\ntokio 1.28.0\n" | $0 -b

  # Query with custom output file
  $0 -c openssl -v 0.10.55 -o openssl-vulns.json
EOF
  exit 0
}

list_known_crates() {
  cat <<EOF
Well-known Rust crates (use with -c):

  Serialization
    serde              serde_json         bincode
    protobuf           thiserror

  Async & Concurrency
    tokio              async-std          futures
    crossbeam          parking_lot

  HTTP & Web
    reqwest            hyper              actix-web
    axum               rocket             warp

  Cryptography & Security
    openssl            rustls             sha2
    hmac               bcrypt             argon2

  Database
    sqlx               sqlx-postgres      mongodb
    diesel             rusqlite           redis

  JSON & Serialization
    serde_json         toml               yaml
    ron                msgpack-rs

  Logging & Monitoring
    log                tracing            slog
    env_logger         fern

  Utilities & Tools
    clap               anyhow             thiserror
    regex              chrono             uuid

NOTE: The crate name must match exactly on crates.io
      See https://crates.io for the complete list.
EOF
  exit 0
}

# ---------------------------------------------------------------------------
# Single query — crate + version in crates.io ecosystem
# ---------------------------------------------------------------------------
query_crate() {
  local crate="$1" version="$2" outfile="$3"

  info "Querying OSV.dev → Rust crate: $crate  version: $version"

  local payload
  payload=$(jq -nc \
    --arg name    "$crate" \
    --arg version "$version" \
    '{"package": {"name": $name, "ecosystem": "crates.io"}, "version": $version}')

  local response
  response=$(curl -sSL \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -H "User-Agent: osv-api-rust/1.0" \
    -d "$payload" \
    "${OSV_API}/query")

  echo "$response" | jq -e . > /dev/null 2>&1 || die "Invalid JSON response from OSV API"

  local count
  count=$(echo "$response" | jq '.vulns | length // 0')
  info "Found $count vulnerability/vulnerabilities for $crate@$version"

  echo "$response" | jq . > "$outfile"
  info "Results saved → $outfile"

  if [[ "$count" -gt 0 ]]; then
    echo ""
    echo "=== Vulnerability summary for Rust crate: $crate@$version ==="
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
    info "No vulnerabilities found for $crate@$version"
  fi
}

# ---------------------------------------------------------------------------
# Query by commit hash (cross-ecosystem, works for Rust Git repos)
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
    -H "User-Agent: osv-api-rust/1.0" \
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
  local outfile="${OUTPUT_DIR}/osv-rust-${vuln_id}-${TIMESTAMP}.json"

  info "Fetching vulnerability record → $vuln_id"

  local response
  response=$(curl -sSL \
    -H "Accept: application/json" \
    -H "User-Agent: osv-api-rust/1.0" \
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
# Reads "crate version" pairs from stdin
# ---------------------------------------------------------------------------
batch_query() {
  info "Batch mode: reading Rust crate-version pairs from stdin…"

  local queries=()
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    local crate version
    read -r crate version <<< "$line"
    [[ -z "$crate" || -z "$version" ]] && { echo "[WARN]  Skipping malformed line: $line" >&2; continue; }
    queries+=("$(jq -nc --arg n "$crate" --arg v "$version" \
      '{"package":{"name":$n,"ecosystem":"crates.io"},"version":$v}')")
  done

  [[ ${#queries[@]} -eq 0 ]] && die "No valid queries found in stdin"

  info "Sending batch query for ${#queries[@]} Rust crates…"

  local payload
  payload=$(printf '%s\n' "${queries[@]}" | jq -sc '{"queries": .}')

  local outfile="${OUTPUT_DIR}/osv-rust-batch-${TIMESTAMP}.json"

  local response
  response=$(curl -sSL \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -H "User-Agent: osv-api-rust/1.0" \
    -d "$payload" \
    "${OSV_API}/querybatch")

  echo "$response" | jq -e . > /dev/null 2>&1 || die "Invalid JSON response from OSV API"

  echo "$response" | jq . > "$outfile"
  info "Batch results saved → $outfile"

  echo ""
  echo "=== Batch Rust vulnerability summary ==="
  echo "$response" | jq -r '
    .results[]? |
    if (.vulns | length) > 0 then
      "  Crate   : \(.vulns[0].affected[0].package.name // "unknown")",
      "  Vulns   : \(.vulns | length)",
      (.vulns[]? | "    - \(.id): \(.summary // "N/A")"),
      "  ---"
    else empty end
  '
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
CRATE=""
VERSION=""
COMMIT=""
OUTFILE=""
GET_ID=""
BATCH=false

while getopts ":c:v:C:g:o:blh" opt; do
  case "$opt" in
    c) CRATE="$OPTARG" ;;
    v) VERSION="$OPTARG" ;;
    C) COMMIT="$OPTARG" ;;
    g) GET_ID="$OPTARG" ;;
    o) OUTFILE="$OPTARG" ;;
    b) BATCH=true ;;
    l) list_known_crates ;;
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
  OUTFILE="${OUTFILE:-${OUTPUT_DIR}/osv-rust-commit-${COMMIT:0:8}-${TIMESTAMP}.json}"
  query_commit "$COMMIT" "$OUTFILE"

elif [[ -n "$CRATE" && -n "$VERSION" ]]; then
  OUTFILE="${OUTFILE:-${OUTPUT_DIR}/osv-rust-${CRATE}-${VERSION}-${TIMESTAMP}.json}"
  query_crate "$CRATE" "$VERSION" "$OUTFILE"

else
  echo ""
  echo "No query specified. Running a demo query: serde 1.0.160"
  echo ""
  CRATE="serde"
  VERSION="1.0.160"
  OUTFILE="${OUTPUT_DIR}/osv-rust-${CRATE}-${VERSION}-${TIMESTAMP}.json"
  query_crate "$CRATE" "$VERSION" "$OUTFILE"
fi
