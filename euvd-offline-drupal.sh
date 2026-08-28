#!/usr/bin/env bash
# =============================================================================
# euvd-offline-drupal.sh — Scan hors ligne (offline) d'un projet Drupal avec
# OSV-Scanner en utilisant la base EUVD locale (ENISA) au format OSV.
#
# Source   : /var/www/html/osv-scanner/euvd-osv       (fichiers OSV EUVD-*.json)
# Projet   : /var/www/html/osv-scanner/drupal-10.2
# Rapports : /var/www/html/osv-scanner/rapport/EUVD-*.json et EUVD-*.html
#
# Les enregistrements EUVD utilisent l'écosystème "EUVD" (vendeur/produit), qui
# n'est pas reconnu par OSV-Scanner. Ce script les réécrit dans les écosystèmes
# scannables (Packagist, npm) afin qu'OSV-Scanner fasse la correspondance de
# versions lui-même, entièrement hors ligne.
# =============================================================================

set -euo pipefail

SOURCE_DIR="/var/www/html/osv-scanner/euvd-osv"
PROJECT_PATH="/var/www/html/osv-scanner/drupal-10.2"
OUTPUT_DIR="/var/www/html/osv-scanner/rapport"
ECOSYSTEMS=("Packagist" "npm")
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DB_DIR=""
KEEP_DB=0

die()  { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[INFO]  $*"; }

usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Scanne un projet hors ligne avec OSV-Scanner à partir de la base EUVD locale.

OPTIONS
  -s <dir>     Dossier des advisories EUVD au format OSV (défaut: $SOURCE_DIR)
  -t <dir>     Projet à scanner (défaut: $PROJECT_PATH)
  -r <dir>     Dossier des rapports (défaut: $OUTPUT_DIR)
  -e <eco>     Écosystèmes cibles séparés par des virgules (défaut: ${ECOSYSTEMS[*]})
  -k           Conserver la base locale générée (sinon supprimée en fin de scan)
  -h, --help   Affiche cette aide

EXEMPLES
  $0
  $0 -t /var/www/html/mon-drupal -e Packagist -k
EOF
  exit 0
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Commande requise introuvable: $1"; }

[[ "${1:-}" == "--help" ]] && usage
while getopts ":s:t:r:e:kh" opt; do
  case "$opt" in
    s) SOURCE_DIR="$OPTARG" ;;
    t) PROJECT_PATH="$OPTARG" ;;
    r) OUTPUT_DIR="$OPTARG" ;;
    e) IFS=',' read -r -a ECOSYSTEMS <<< "$OPTARG" ;;
    k) KEEP_DB=1 ;;
    h) usage ;;
    :) die "L'option -$OPTARG requiert un argument." ;;
    \?) die "Option inconnue: -$OPTARG" ;;
  esac
done

require_cmd osv-scanner
require_cmd jq
require_cmd zip

[[ -d "$SOURCE_DIR" ]]   || die "Dossier source EUVD introuvable: $SOURCE_DIR"
[[ -d "$PROJECT_PATH" ]] || die "Projet introuvable: $PROJECT_PATH"

mapfile -d '' -t EUVD_FILES < <(find "$SOURCE_DIR" -type f -name '*.json' -print0)
[[ ${#EUVD_FILES[@]} -gt 0 ]] || die "Aucun fichier OSV EUVD dans: $SOURCE_DIR"

mkdir -p "$OUTPUT_DIR"
JSON_REPORT="${OUTPUT_DIR}/EUVD-offline-drupal-${TIMESTAMP}.json"
HTML_REPORT="${OUTPUT_DIR}/EUVD-offline-drupal-${TIMESTAMP}.html"

DB_DIR="$(mktemp -d -t euvd-osv-db-XXXXXX)"
cleanup() { [[ "$KEEP_DB" -eq 1 ]] || rm -rf "$DB_DIR"; }
trap cleanup EXIT

info "Advisories EUVD trouvées : ${#EUVD_FILES[@]}"
info "Base locale OSV-Scanner  : $DB_DIR"

# ---------------------------------------------------------------------------
# Conversion EUVD -> écosystèmes scannables
# Un enregistrement sans information de version (ni ranges, ni versions) est
# ignoré pour éviter de marquer toutes les versions comme vulnérables.
# ---------------------------------------------------------------------------
CONVERT_JQ='
  def vers($a):
    [ ($a.database_specific.raw_product_version // "")
      | scan("[0-9]+(?:\\.[0-9]+)+(?:-[A-Za-z0-9.]+)?") ] | unique;
  . as $adv
  | [ $adv.affected[]?
      | . as $a
      | (($a.database_specific.vendor // "") | ascii_downcase | gsub("\\s+"; "-")) as $vendor
      | (($a.package.name // "")            | ascii_downcase | gsub("\\s+"; "-")) as $prod
      | select($prod != "")
      | ([$prod] + (if $vendor != "" then [$vendor + "/" + $prod] else [] end)) as $names
      | ($a.ranges // []) as $ranges
      | (vers($a) + ($a.versions // []) | unique) as $versions
      | select(($ranges | length) > 0 or ($versions | length) > 0)
      | $names[]
      | { package: { ecosystem: $eco, name: . } }
        + (if ($ranges | length) > 0 then { ranges: $ranges } else {} end)
        + (if ($versions | length) > 0 then { versions: $versions } else {} end)
        + { database_specific: (($a.database_specific // {}) + { euvd_ecosystem: "EUVD" }) }
    ]
  | select(length > 0)
  | { schema_version: ($adv.schema_version // "1.5.0"),
      id: $adv.id,
      aliases: ($adv.aliases // []),
      published: $adv.published,
      modified: $adv.modified,
      summary: ($adv.summary // ($adv.details // "" | .[0:120])),
      details: ($adv.details // ""),
      severity: ($adv.severity // []),
      references: ($adv.references // []),
      database_specific: (($adv.database_specific // {}) + { source: "EUVD", euvd_id: $adv.id }),
      affected: .
    }
'

# OSV-Scanner v2.5+ lit la base dans <dir>/osv-scalibr/<eco>/all.zip,
# les versions antérieures dans <dir>/osv-scanner/<eco>/all.zip : on alimente les deux.
DB_LAYOUTS=("osv-scalibr" "osv-scanner")

TOTAL_CONVERTED=0
for eco in "${ECOSYSTEMS[@]}"; do
  STAGE_DIR="${DB_DIR}/stage/${eco}"
  mkdir -p "$STAGE_DIR"
  count=0
  for advisory in "${EUVD_FILES[@]}"; do
    converted=$(jq -c --arg eco "$eco" "$CONVERT_JQ" "$advisory" 2>/dev/null || true)
    [[ -n "$converted" ]] || continue
    id=$(jq -r '.id' <<<"$converted")
    printf '%s' "$converted" > "${STAGE_DIR}/${id//\//_}.json"
    count=$((count + 1))
  done

  if [[ "$count" -eq 0 ]]; then
    info "Écosystème $eco : aucune advisory convertible, ignoré"
    continue
  fi

  for layout in "${DB_LAYOUTS[@]}"; do
    mkdir -p "${DB_DIR}/${layout}/${eco}"
    ( cd "$STAGE_DIR" && zip -q -r -X "${DB_DIR}/${layout}/${eco}/all.zip" . -i '*.json' ) \
      || die "Création de la base locale $eco ($layout) échouée"
  done
  info "Écosystème $eco : $count advisories EUVD converties"
  TOTAL_CONVERTED=$((TOTAL_CONVERTED + count))
done

[[ "$TOTAL_CONVERTED" -gt 0 ]] || die "Aucune advisory EUVD exploitable (pas d'information de version)"

# ---------------------------------------------------------------------------
# Scan hors ligne
# ---------------------------------------------------------------------------
info "Scan hors ligne du projet : $PROJECT_PATH"

SCAN_STATUS=0
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$DB_DIR" \
osv-scanner scan source \
  --recursive \
  --offline \
  --format json \
  --output-file "$JSON_REPORT" \
  "$PROJECT_PATH" || SCAN_STATUS=$?

[[ -s "$JSON_REPORT" ]] || die "Rapport JSON absent ou vide : $JSON_REPORT"
jq -e . "$JSON_REPORT" >/dev/null || die "Rapport JSON invalide : $JSON_REPORT"

# Expose l'identifiant EUVD et les CVE associés dans des champs dédiés.
jq '(.results[]?.packages[]?.vulnerabilities[]? |=
  (. + {
    euvd_id: (if (.id // "") | startswith("EUVD-") then .id
              else ([(.aliases // [])[] | select(startswith("EUVD-"))] | first // null) end),
    cve_ids: ([.id] + (.aliases // []) | map(select(test("^CVE-[0-9]{4}-[0-9]+$"))) | unique)
  }))
  | . + {euvd_scan: {source: "EUVD", mode: "offline", generated: (now | todate)}}' \
  "$JSON_REPORT" > "${JSON_REPORT}.tmp" && mv "${JSON_REPORT}.tmp" "$JSON_REPORT"

VULN_COUNT=$(jq '[.results[]?.packages[]?.vulnerabilities[]?] | length' "$JSON_REPORT")
PKG_COUNT=$(jq '[.results[]?.packages[]?] | length' "$JSON_REPORT")
CVE_COUNT=$(jq '[.results[]?.packages[]?.vulnerabilities[]?.cve_ids[]?] | unique | length' "$JSON_REPORT")

# ---------------------------------------------------------------------------
# Rapport HTML
# ---------------------------------------------------------------------------
{
  cat <<HTML_HEAD
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport EUVD hors ligne — $(printf '%s' "$TIMESTAMP")</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; color: #1b1b1b; }
  h1 { font-size: 1.5rem; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; }
  th, td { border: 1px solid #ccc; padding: .45rem .6rem; text-align: left; vertical-align: top; font-size: .9rem; }
  th { background: #f0f2f5; }
  tr:nth-child(even) td { background: #fafafa; }
  .meta td:first-child { width: 16rem; font-weight: 600; }
  .empty { padding: 1rem; background: #eef7ee; border: 1px solid #bcd9bc; }
  code { background: #f4f4f4; padding: 0 .2rem; }
</style>
</head>
<body>
<h1>Rapport EUVD hors ligne (offline)</h1>
<table class="meta">
  <tr><td>Projet analysé</td><td><code>$(printf '%s' "$PROJECT_PATH")</code></td></tr>
  <tr><td>Source EUVD</td><td><code>$(printf '%s' "$SOURCE_DIR")</code></td></tr>
  <tr><td>Entrées de base générées</td><td>${TOTAL_CONVERTED} (advisories × écosystèmes)</td></tr>
  <tr><td>Écosystèmes ciblés</td><td>$(printf '%s' "${ECOSYSTEMS[*]}")</td></tr>
  <tr><td>Paquets vulnérables</td><td>${PKG_COUNT}</td></tr>
  <tr><td>Vulnérabilités détectées</td><td>${VULN_COUNT}</td></tr>
  <tr><td>CVE uniques</td><td>${CVE_COUNT}</td></tr>
  <tr><td>Rapport JSON</td><td><code>$(printf '%s' "$JSON_REPORT")</code></td></tr>
  <tr><td>Généré le</td><td>$(date '+%Y-%m-%d %H:%M:%S')</td></tr>
</table>
HTML_HEAD

  if [[ "$VULN_COUNT" -gt 0 ]]; then
    echo '<h2>Vulnérabilités</h2>'
    echo '<table><thead><tr><th>EUVD</th><th>CVE</th><th>Paquet</th><th>Version</th><th>Écosystème</th><th>Sévérité</th><th>Résumé</th><th>Fichier source</th></tr></thead><tbody>'
    jq -r '
      .results[]? as $r
      | $r.packages[]? as $p
      | $p.vulnerabilities[]?
      | "<tr><td>\(.euvd_id // .id // "" | @html)</td>"
        + "<td>\((.cve_ids // []) | join(", ") | @html)</td>"
        + "<td>\($p.package.name // "" | @html)</td>"
        + "<td>\($p.package.version // "" | @html)</td>"
        + "<td>\($p.package.ecosystem // "" | @html)</td>"
        + "<td>\([(.severity // [])[] | "\(.type): \(.score)"] | join("<br>"))</td>"
        + "<td>\((.summary // .details // "") | .[0:300] | @html)</td>"
        + "<td>\($r.source.path // "" | @html)</td></tr>"
    ' "$JSON_REPORT"
    echo '</tbody></table>'
  else
    echo '<p class="empty">Aucune vulnérabilité EUVD ne correspond aux dépendances du projet analysé.</p>'
  fi

  echo '</body></html>'
} > "$HTML_REPORT"

info "Paquets vulnérables : $PKG_COUNT"
info "Vulnérabilités détectées : $VULN_COUNT"
info "CVE uniques : $CVE_COUNT"
info "Rapport JSON : $JSON_REPORT"
info "Rapport HTML : $HTML_REPORT"
[[ "$KEEP_DB" -eq 1 ]] && info "Base locale conservée : $DB_DIR"

[[ "$SCAN_STATUS" -ne 0 ]] && echo "[WARN] OSV-Scanner a retourné le code $SCAN_STATUS (vulnérabilités détectées)."
exit 0
