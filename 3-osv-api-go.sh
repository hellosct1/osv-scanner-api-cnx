#!/usr/bin/env bash
# =============================================================================
# 3-osv-api-go.sh — Query the OSV.dev API for Go vulnerabilities
# API  : https://google.github.io/osv.dev/api/
# Ecosystem : Go
# Packages are identified by their import path (e.g., github.com/gin-gonic/gin)
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

Query OSV.dev for known vulnerabilities in Go (golang) packages.

The Go ecosystem in OSV.dev includes packages from go.pkg.dev and other
Go module repositories. Packages are identified by their import path
(e.g., github.com/gin-gonic/gin).

OPTIONS
  -p <import-path>  Go package import path (required unless -c/-g/-b is used)
  -v <version>      Version string (required unless -c/-g is used)
  -c <commit>       Git commit hash (alternative to -p/-v)
  -g <vuln-id>      Fetch a specific OSV vulnerability by ID (e.g. GHSA-xxxx)
  -o <file>         Output JSON file  (default: auto-generated)
  -b                Batch mode: read "import-path version" pairs from stdin
  -l                List well-known Go packages and exit
  -h                Show this help

EXAMPLES
  # Query a specific Go module version
  $0 -p github.com/gin-gonic/gin -v 1.8.1

  # Query another Go package
  $0 -p gorm.io/gorm -v 1.24.0

  # Query by commit hash
  $0 -c 6879efc2c1596d11a6a6ad296f80063b558d5e0f

  # Fetch a specific vulnerability
  $0 -g GHSA-fxjv-4453-4f89

  # Batch query (stdin)
  printf "github.com/gin-gonic/gin 1.8.1\ngorm.io/gorm 1.24.0\n" | $0 -b

  # Query with custom output file
  $0 -p github.com/ethereum/go-ethereum -v 1.11.0 -o eth-vulns.json
EOF
  exit 0
}

list_known_packages() {
  cat <<EOF
Well-known Go packages (use with -p):

  Web & API Frameworks
    github.com/gin-gonic/gin
    github.com/gorilla/mux
    github.com/labstack/echo
    github.com/valyala/fasthttp

  Database & ORM
    gorm.io/gorm
    github.com/go-sql-driver/mysql
    github.com/lib/pq
    github.com/mongodb/mongo-go-driver

  Cryptography & Security
    golang.org/x/crypto
    golang.org/x/net
    github.com/golang-jwt/jwt

  Blockchain & Crypto
    github.com/ethereum/go-ethereum
    github.com/solana-labs/solana-web3.go
    github.com/cosmos/cosmos-sdk

  Networking & HTTP
    github.com/go-resty/resty
    github.com/hashicorp/go-retryablehttp
    github.com/go-http-utils/headers

  JSON & Serialization
    github.com/json-iterator/go
    github.com/mitchellh/mapstructure

  Utilities
    github.com/sirupsen/logrus
    github.com/urfave/cli
    github.com/spf13/cobra

NOTE: The import path must match exactly. See pkg.go.dev for full list.
EOF
  exit 0
}

# ---------------------------------------------------------------------------
# Single query — package + version in Go ecosystem
# ---------------------------------------------------------------------------
query_package() {
  local package="$1" version="$2" outfile="$3"

  info "Querying OSV.dev → Go package: $package  version: $version"

  local payload
  payload=$(jq -nc \
    --arg name    "$package" \
    --arg version "$version" \
    '{"package": {"name": $name, "ecosystem": "Go"}, "version": $version}')

  local response
  response=$(curl -sSL \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -H "User-Agent: osv-api-go/1.0" \
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
    echo "=== Vulnerability summary for $package@$version ==="
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
    info "No vulnerabilities found for $package@$version"
  fi
}

# ---------------------------------------------------------------------------
# Query by commit hash (cross-ecosystem, works for Go Git repos)
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
    -H "User-Agent: osv-api-go/1.0" \
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
  local outfile="${OUTPUT_DIR}/osv-go-${vuln_id}-${TIMESTAMP}.json"

  info "Fetching vulnerability record → $vuln_id"

  local response
  response=$(curl -sSL \
    -H "Accept: application/json" \
    -H "User-Agent: osv-api-go/1.0" \
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
# Reads "import-path version" pairs from stdin
# ---------------------------------------------------------------------------
batch_query() {
  info "Batch mode: reading Go package-version pairs from stdin…"

  local queries=()
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    local package version
    read -r package version <<< "$line"
    [[ -z "$package" || -z "$version" ]] && { echo "[WARN]  Skipping malformed line: $line" >&2; continue; }
    queries+=("$(jq -nc --arg n "$package" --arg v "$version" \
      '{"package":{"name":$n,"ecosystem":"Go"},"version":$v}')")
  done

  [[ ${#queries[@]} -eq 0 ]] && die "No valid queries found in stdin"

  info "Sending batch query for ${#queries[@]} Go packages…"

  local payload
  payload=$(printf '%s\n' "${queries[@]}" | jq -sc '{"queries": .}')

  local outfile="${OUTPUT_DIR}/osv-go-batch-${TIMESTAMP}.json"

  local response
  response=$(curl -sSL \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -H "User-Agent: osv-api-go/1.0" \
    -d "$payload" \
    "${OSV_API}/querybatch")

  echo "$response" | jq -e . > /dev/null 2>&1 || die "Invalid JSON response from OSV API"

  echo "$response" | jq . > "$outfile"
  info "Batch results saved → $outfile"

  echo ""
  echo "=== Batch Go vulnerability summary ==="
  echo "$response" | jq -r '
    .results[]? |
    if (.vulns | length) > 0 then
      "  Package : \(.vulns[0].affected[0].package.name // "unknown")",
      "  Vulns   : \(.vulns | length)",
      (.vulns[]? | "    - \(.id): \(.summary // "N/A")"),
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
    l) list_known_packages ;;
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
  OUTFILE="${OUTFILE:-${OUTPUT_DIR}/osv-go-commit-${COMMIT:0:8}-${TIMESTAMP}.json}"
  query_commit "$COMMIT" "$OUTFILE"

elif [[ -n "$PACKAGE" && -n "$VERSION" ]]; then
  local_name="${PACKAGE##*/}"
  OUTFILE="${OUTFILE:-${OUTPUT_DIR}/osv-go-${local_name}-${VERSION}-${TIMESTAMP}.json}"
  query_package "$PACKAGE" "$VERSION" "$OUTFILE"

else
  echo ""
  echo "No query specified. Running a demo query: gorm.io/gorm 1.24.0"
  echo ""
  PACKAGE="gorm.io/gorm"
  VERSION="1.24.0"
  OUTFILE="${OUTPUT_DIR}/osv-go-gorm-${VERSION}-${TIMESTAMP}.json"
  query_package "$PACKAGE" "$VERSION" "$OUTFILE"
fi
