#!/usr/bin/env bash
# =============================================================================
# osv-api-euvd.sh — Query the ENISA EUVD API for vulnerability information
# API  : https://euvdservices.enisa.europa.eu/api/
# EUVD : European Vulnerability Database (ENISA)
#
# Endpoints used:
#   GET /api/enisaid?id=<EUVD-ID|CVE-ID>   — lookup by ID
#   GET /api/search?text=<keyword>&page=0&pageSize=N — full-text search
# =============================================================================

set -euo pipefail

EUVD_API="https://euvdservices.enisa.europa.eu/api"
OUTPUT_DIR="/var/www/html/osv-scanner/rapport"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PAGE_SIZE=20

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

Query the ENISA European Vulnerability Database (EUVD) API.

OPTIONS
  -i <id>          Lookup by EUVD or CVE ID (e.g. EUVD-2024-45012 or CVE-2021-44228)
  -s <keyword>     Full-text search (product name, keyword, vendor, etc.)
  -n <pageSize>    Number of results for search (default: $PAGE_SIZE, max: 100)
  -P <page>        Page number for search (0-based, default: 0)
  -o <file>        Output JSON file (default: auto-generated)
  -b               Batch mode: read CVE/EUVD IDs from stdin (one per line)
  -l               Show example IDs and keywords
  -h               Show this help

EXAMPLES
  # Lookup a CVE
  $0 -i CVE-2021-44228

  # Lookup by EUVD ID
  $0 -i EUVD-2024-45012

  # Search by keyword
  $0 -s log4j

  # Search for a vendor/product
  $0 -s "openssl heartbleed"

  # Search with more results
  $0 -s django -n 50

  # Batch lookup from stdin
  printf "CVE-2021-44228\nCVE-2021-23337\n" | $0 -b

  # Save results to a custom file
  $0 -s "apache struts" -o struts-euvd.json
EOF
  exit 0
}

list_examples() {
  cat <<EOF
Example EUVD / CVE IDs and keywords:

  Lookup by ID (-i)
    CVE-2021-44228          Log4Shell (Apache Log4j)
    CVE-2022-22965          Spring4Shell
    CVE-2021-23337          Lodash command injection
    CVE-2014-0160           Heartbleed (OpenSSL)
    CVE-2017-5638           Apache Struts RCE
    CVE-2019-0708           BlueKeep (Windows RDP)
    CVE-2023-44487          HTTP/2 Rapid Reset
    EUVD-2024-45012         ENISA EUVD record
    EUVD-2021-34768         Apache Log4j   

  Search keywords (-s)
    log4j        log4shell       openssl        heartbleed
    struts       spring          django         flask
    wordpress    apache          nginx          kubernetes
    docker       redis           mongodb        postgresql
    libssl       libcurl         libc           glibc
EOF
  exit 0
}

# ---------------------------------------------------------------------------
# Lookup a single vulnerability by EUVD or CVE ID
# ---------------------------------------------------------------------------
lookup_id() {
  local id="$1" outfile="$2"

  info "Looking up EUVD record → $id"

  local response
  response=$(curl -sSL \
    --connect-timeout 10 \
    --max-time 30 \
    -H "Accept: application/json" \
    -H "User-Agent: osv-api-euvd/1.0" \
    "${EUVD_API}/enisaid?id=${id}")

  echo "$response" | jq -e . > /dev/null 2>&1 || die "Invalid JSON response from EUVD API"

  # Check if record was found (non-empty object)
  local found
  found=$(echo "$response" | jq 'if . == {} or . == null then false else true end')

  echo "$response" | jq . > "$outfile"
  info "Results saved → $outfile"

  if [[ "$found" == "true" ]]; then
    echo ""
    echo "## EUVD Record: $id"
    echo ""
    # Main info table
    echo "| Champ | Valeur |"
    echo "|---|---|"
    echo "$response" | jq -r '
      "| ID | \(.id // "N/A") |",
      "| CVSS Score | \(.baseScore // "N/A") (v\(.baseScoreVersion // "N/A")) |",
      "| CVSS Vector | `\(.baseScoreVector // "N/A")` |",
      "| EPSS | \(.epss // "N/A")% |",
      "| Published | \(.datePublished // "N/A") |",
      "| Updated | \(.dateUpdated // "N/A") |",
      "| Assigner | \(.assigner // "N/A") |",
      "| Aliases | \(.aliases // "N/A" | gsub("\n"; ", ") | rtrimstr(", ")) |",
      "| Exploited since | \(.exploitedSince // "N/A") |"
    '
    echo ""
    echo "**Description :**"
    echo ""
    echo "$response" | jq -r '.description // "N/A" | .[0:500]'
    echo ""
    # Affected products table
    local prod_count
    prod_count=$(echo "$response" | jq '.enisaIdProduct | length // 0')
    if [[ "$prod_count" -gt 0 ]]; then
      echo "### Produits affectés"
      echo ""
      echo "| Vendeur | Produit | Version |"
      echo "|---|---|---|"
      echo "$response" | jq -r '
        .enisaIdProduct[]? |
        "| \(.product.vendor.name // "unknown") | \(.product.name // "unknown") | \(.product_version // "N/A") |"
      '
      echo ""
    fi
    # References table
    local ref_count
    ref_count=$(echo "$response" | jq '(.references // "") | split("\n") | map(select(. != "")) | length')
    if [[ "$ref_count" -gt 0 ]]; then
      echo "### Références"
      echo ""
      echo "| # | URL |"
      echo "|---|---|"
      echo "$response" | jq -r '
        .references // "" |
        split("\n") |
        to_entries[] |
        select(.value != "") |
        "| \(.key + 1) | \(.value) |"
      ' 2>/dev/null || true
      echo ""
    fi
  else
    info "No EUVD record found for ID: $id"
  fi
}

# ---------------------------------------------------------------------------
# Full-text search
# ---------------------------------------------------------------------------
search_keyword() {
  local keyword="$1" page="$2" size="$3" outfile="$4"

  info "Searching EUVD → \"$keyword\"  (page $page, size $size)"

  local encoded_keyword
  encoded_keyword=$(printf '%s' "$keyword" | jq -sRr @uri)

  local response
  response=$(curl -sSL \
    --connect-timeout 10 \
    --max-time 30 \
    -H "Accept: application/json" \
    -H "User-Agent: osv-api-euvd/1.0" \
    "${EUVD_API}/search?text=${encoded_keyword}&page=${page}&pageSize=${size}")

  echo "$response" | jq -e . > /dev/null 2>&1 || die "Invalid JSON response from EUVD API"

  local total count
  total=$(echo "$response" | jq '.total // 0')
  count=$(echo "$response" | jq '.items | length // 0')

  info "Found $count results (total: $total) for \"$keyword\""

  echo "$response" | jq . > "$outfile"
  info "Results saved → $outfile"

  if [[ "$count" -gt 0 ]]; then
    echo ""
    echo "## Résultats EUVD — \"$keyword\" ($count / $total)  |  Page $page"
    echo ""
    echo "| ID | Description | CVSS | CVSS v | EPSS (%) | Publié | Aliases |"
    echo "|---|---|---|---|---|---|---|"
    echo "$response" | jq -r '
      .items[]? |
      "| \(.id // "N/A") | \(.description // "N/A" | gsub("[|\n\r]"; " ") | .[0:100]) | \(.baseScore // "N/A") | v\(.baseScoreVersion // "?") | \(.epss // "N/A") | \(.datePublished // "N/A") | \(.aliases // "" | gsub("\n"; ", ") | rtrimstr(", ") | .[0:60]) |"
    '
    echo ""
    echo "> Total disponible : **$total**  |  Affichés : **$count**  |  Page : **$page**"
    if [[ "$total" -gt "$(( ( page + 1 ) * size))" ]]; then
      echo "> Suite disponible avec : \`-P $((page + 1))\`"
    fi
    echo ""
  else
    info "No results found for \"$keyword\""
  fi
}

# ---------------------------------------------------------------------------
# Batch lookup — reads CVE/EUVD IDs from stdin
# ---------------------------------------------------------------------------
batch_lookup() {
  info "Batch mode: reading CVE/EUVD IDs from stdin…"

  local ids=()
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    ids+=("$(echo "$line" | tr -d '[:space:]')")
  done

  [[ ${#ids[@]} -eq 0 ]] && die "No valid IDs found in stdin"

  info "Processing ${#ids[@]} IDs…"

  local outfile="${OUTPUT_DIR}/euvd-batch-${TIMESTAMP}.jsonl"
  rm -f "$outfile"

  local found=0 not_found=0
  local batch_rows=()

  for id in "${ids[@]}"; do
    info "Looking up → $id"

    local response
    response=$(curl -sSL \
      --connect-timeout 10 \
      --max-time 30 \
      -H "Accept: application/json" \
      -H "User-Agent: osv-api-euvd/1.0" \
      "${EUVD_API}/enisaid?id=${id}")

    if echo "$response" | jq -e . > /dev/null 2>&1; then
      jq -Rs --arg id "$id" \
        '{id: $id, euvd_response: (fromjson? // {})}' \
        <<< "$response" >> "$outfile"

      local has_data
      has_data=$(echo "$response" | jq 'if . == {} or . == null then false else true end')
      if [[ "$has_data" == "true" ]]; then
        found=$((found + 1))
        batch_rows+=("$(echo "$response" | jq -r \
          '"| \(.id // "N/A") | \(.description // "N/A" | gsub("[|\n\r]"; " ") | .[0:100]) | \(.baseScore // "N/A") | \(.baseScoreVersion // "N/A") | \(.epss // "N/A") | \(.exploitedSince // "N/A") |"' \
        )")
      else
        not_found=$((not_found + 1))
        batch_rows+=("| $id | *Aucun enregistrement EUVD* | N/A | N/A | N/A | N/A |")
      fi
    else
      not_found=$((not_found + 1))
      echo "  [$id] Invalid response"
    fi

    sleep 0.2
  done

  # Print Markdown table
  echo ""
  echo "## Résultats EUVD — Batch ($found trouvés, $not_found introuvables)"
  echo ""
  echo "| ID EUVD | Description | CVSS | CVSS v | EPSS (%) | Exploité depuis |"
  echo "|---|---|---|---|---|---|"
  for row in "${batch_rows[@]}"; do
    echo "$row"
  done
  echo ""

  info "Batch complete: $found found, $not_found not found"
  info "Results saved → $outfile"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
LOOKUP_ID=""
SEARCH=""
PAGE=0
OUTFILE=""
BATCH=false

for arg in "$@"; do
  if [[ "$arg" == "--help" ]]; then
    usage
  fi
done

if [[ $# -eq 0 ]]; then
  echo "No arguments provided. Use --help (or -h) to see usage."
  echo ""
  usage
fi

while getopts ":i:s:n:P:o:blh" opt; do
  case "$opt" in
    i) LOOKUP_ID="$OPTARG" ;;
    s) SEARCH="$OPTARG" ;;
    n) PAGE_SIZE="$OPTARG" ;;
    P) PAGE="$OPTARG" ;;
    o) OUTFILE="$OPTARG" ;;
    b) BATCH=true ;;
    l) list_examples ;;
    h) usage ;;
    :) die "Option -$OPTARG requires an argument." ;;
    \?) die "Unknown option: -$OPTARG" ;;
  esac
done

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
if $BATCH; then
  batch_lookup

elif [[ -n "$LOOKUP_ID" ]]; then
  OUTFILE="${OUTFILE:-${OUTPUT_DIR}/euvd-${LOOKUP_ID}-${TIMESTAMP}.json}"
  lookup_id "$LOOKUP_ID" "$OUTFILE"

elif [[ -n "$SEARCH" ]]; then
  safe_name=$(echo "$SEARCH" | tr ' /' '--' | tr -dc '[:alnum:]-_')
  OUTFILE="${OUTFILE:-${OUTPUT_DIR}/euvd-search-${safe_name}-${TIMESTAMP}.json}"
  search_keyword "$SEARCH" "$PAGE" "$PAGE_SIZE" "$OUTFILE"

else
  echo "No valid query specified. Use --help (or -h) to see usage."
  exit 1
fi
