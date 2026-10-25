#!/usr/bin/env bash
# =============================================================================
# Extrait les failles Drupal du schéma OSV (ecosystem Packagist) 
# et les convertit en identifiants CVE dans le dossier ./osv-drupal
#
# Sorties :
#   osv-drupal/advisories/<OSV-ID>.json   advisories OSV brutes (drupal/*)
#   osv-drupal/drupal-cve.json            mapping OSV/DRUPAL -> CVE
#   osv-drupal/drupal-cve.csv             idem, format CSV
#   osv-drupal/cves.txt                   liste plate des CVE uniques
# =============================================================================

set -euo pipefail

OSV_BUCKET="https://osv-vulnerabilities.storage.googleapis.com"
ECOSYSTEM="Packagist"
OUTPUT_DIR="osv-drupal"
PACKAGE_PREFIX="drupal/"

die()  { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[INFO]  $*"; }

usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Télécharge les advisories OSV de l'écosystème $ECOSYSTEM, ne garde que les
paquets Drupal (${PACKAGE_PREFIX}*) et produit la correspondance OSV -> CVE.

OPTIONS
  -d <dir>     Dossier de sortie (défaut: $OUTPUT_DIR)
  -p <valeur>  Dossier projet avec composer.lock ou préfixe de paquet
               (défaut: $PACKAGE_PREFIX)
  -k           Conserver all.zip dans le dossier de sortie pour réutilisation hors ligne
  -h, --help   Affiche cette aide

EXEMPLES
  $0
  $0 -p /var/www/html/osv-scanner/drupal-10.2/
  $0 -d osv-drupal
EOF
  exit 0
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Commande requise introuvable: $1"; }

KEEP_ZIP=0
PROJECT_PATH=""
PROJECT_PACKAGE_NAMES=""
[[ "${1:-}" == "--help" ]] && usage
while getopts ":d:p:kh" opt; do
  case "$opt" in
    d) OUTPUT_DIR="$OPTARG" ;;
    p) PACKAGE_PREFIX="$OPTARG" ;;
    k) KEEP_ZIP=1 ;;
    h) usage ;;
    :) die "L'option -$OPTARG requiert un argument." ;;
    \?) die "Option inconnue: -$OPTARG" ;;
  esac
done

require_cmd jq
require_cmd unzip

ADVISORY_DIR="${OUTPUT_DIR}/advisories"
if [[ ! -s "${OUTPUT_DIR}/all.zip" ]]; then
  require_cmd curl
fi

WORK_DIR="$(mktemp -d)"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

mkdir -p "$ADVISORY_DIR"

# Si -p désigne un dossier, lire ses dépendances Composer pour filtrer les
# avis du projet au lieu de traiter cette valeur comme un préfixe de package.
if [[ -d "$PACKAGE_PREFIX" ]]; then
  PROJECT_PATH="$PACKAGE_PREFIX"
  PACKAGE_PREFIX=""

  mapfile -d '' -t LOCKFILES < <(find "$PROJECT_PATH" -type f -name composer.lock -print0)
  [[ ${#LOCKFILES[@]} -gt 0 ]] || die "Aucun composer.lock trouvé dans le projet: $PROJECT_PATH"

  PROJECT_PACKAGE_NAMES=$(jq -s '
    map([.packages[]?, .["packages-dev"][]?] | map(.name? // empty))
    | add
    | unique
  ' "${LOCKFILES[@]}") || die "Impossible de lire les composer.lock du projet"

  [[ $(jq 'length' <<< "$PROJECT_PACKAGE_NAMES") -gt 0 ]] ||
    die "Aucun package Composer trouvé dans: $PROJECT_PATH"

  info "Packages Composer du projet : $(jq 'length' <<< "$PROJECT_PACKAGE_NAMES")"
elif [[ "$PACKAGE_PREFIX" == /* || "$PACKAGE_PREFIX" == ./* || "$PACKAGE_PREFIX" == ../* ]]; then
  die "Projet introuvable: $PACKAGE_PREFIX"
fi

ZIP_FILE="${WORK_DIR}/all.zip"
if [[ -s "${OUTPUT_DIR}/all.zip" ]]; then
  cp "${OUTPUT_DIR}/all.zip" "$ZIP_FILE"
  info "Utilisation de l'archive locale : ${OUTPUT_DIR}/all.zip"
else
  info "Téléchargement des advisories OSV : ${OSV_BUCKET}/${ECOSYSTEM}/all.zip"
  curl --fail --silent --show-error --location \
    --connect-timeout 10 --max-time 600 \
    -H "User-Agent: osv-drupal-to-cve/1.0" \
    -o "$ZIP_FILE" \
    "${OSV_BUCKET}/${ECOSYSTEM}/all.zip" || die "Téléchargement OSV échoué (conserver all.zip avec -k pour le mode hors ligne)"
fi

[[ -s "$ZIP_FILE" ]] || die "Archive OSV vide : $ZIP_FILE"

EXTRACT_DIR="${WORK_DIR}/extract"
mkdir -p "$EXTRACT_DIR"
unzip -q -o "$ZIP_FILE" -d "$EXTRACT_DIR" || die "Extraction de all.zip échouée"

if [[ -n "$PROJECT_PATH" ]]; then
  info "Filtrage des advisories selon les packages de $PROJECT_PATH"
else
  info "Filtrage des advisories concernant ${PACKAGE_PREFIX}*"
fi
rm -f "${ADVISORY_DIR}"/*.json 2>/dev/null || true

MATCHED=0
while IFS= read -r -d '' advisory; do
  MATCHES_ADVISORY=0

  if [[ -n "$PROJECT_PATH" ]]; then
    if jq -e --argjson packages "$PROJECT_PACKAGE_NAMES" \
        'any(.affected[]?.package?.name // ""; . as $name | $packages | index($name) != null)' \
        "$advisory" >/dev/null 2>&1; then
      MATCHES_ADVISORY=1
    fi
  else
    if jq -e --arg prefix "$PACKAGE_PREFIX" \
        'any(.affected[]?.package?.name // ""; startswith($prefix))' \
        "$advisory" >/dev/null 2>&1; then
      MATCHES_ADVISORY=1
    fi
  fi

  if [[ "$MATCHES_ADVISORY" -eq 1 ]]; then
    cp "$advisory" "${ADVISORY_DIR}/$(basename "$advisory")"
    MATCHED=$((MATCHED + 1))
  fi
done < <(find "$EXTRACT_DIR" -type f -name '*.json' -print0)

if [[ "$MATCHED" -eq 0 ]]; then
  if [[ -n "$PROJECT_PATH" ]]; then
    die "Aucune advisory OSV trouvée pour les packages Composer de: $PROJECT_PATH"
  fi
  die "Aucune advisory Drupal trouvée dans l'écosystème $ECOSYSTEM"
fi
info "$MATCHED advisories Drupal extraites dans : $ADVISORY_DIR"

MAP_JSON="${OUTPUT_DIR}/drupal-cve.json"
MAP_CSV="${OUTPUT_DIR}/drupal-cve.csv"
CVE_LIST="${OUTPUT_DIR}/cves.txt"

# Conversion : chaque advisory OSV (DRUPAL-*, GHSA-*, ...) est reliée aux CVE
# présents dans son champ id ou dans ses aliases.
jq -s '
  map({
    osv_id: .id,
    drupal_id: ([.id] + (.aliases // []) | map(select(startswith("DRUPAL-"))) | first // null),
    summary: (.summary // ""),
    published: (.published // null),
    modified: (.modified // null),
    severity: ([.database_specific.severity? // empty] | first // null),
    packages: ([.affected[]?.package?.name // empty] | unique),
    cve_ids: ([.id] + (.aliases // []) | map(select(test("^CVE-[0-9]{4}-[0-9]+$"))) | unique)
  })
  | map(. + {cve_id: (.cve_ids | first // null)})
  | sort_by(.osv_id)
' "${ADVISORY_DIR}"/*.json > "$MAP_JSON" || die "Génération du mapping JSON échouée"

{
  echo "osv_id,drupal_id,cve_ids,packages,summary"
  jq -r '.[] | [
      .osv_id,
      (.drupal_id // ""),
      (.cve_ids | join(" ")),
      (.packages | join(" ")),
      (.summary | gsub("[\r\n]+"; " "))
    ] | @csv' "$MAP_JSON"
} > "$MAP_CSV"

jq -r '.[].cve_ids[]' "$MAP_JSON" | sort -u > "$CVE_LIST"

TOTAL=$(jq 'length' "$MAP_JSON")
WITH_CVE=$(jq '[.[] | select((.cve_ids | length) > 0)] | length' "$MAP_JSON")
CVE_TOTAL=$(wc -l < "$CVE_LIST" | tr -d ' ')

if [[ "$KEEP_ZIP" -eq 1 ]]; then
  cp "$ZIP_FILE" "${OUTPUT_DIR}/all.zip"
  info "Archive conservée : ${OUTPUT_DIR}/all.zip"
fi

info "Advisories Drupal traitées : $TOTAL"
info "Advisories avec au moins un CVE : $WITH_CVE"
info "CVE uniques : $CVE_TOTAL"
info "Mapping JSON : $MAP_JSON"
info "Mapping CSV  : $MAP_CSV"
info "Liste CVE    : $CVE_LIST"
