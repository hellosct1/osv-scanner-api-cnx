#!/usr/bin/env bash
# =============================================================================
# osv-offline-drupal.sh — Scan OSV-Scanner en mode hors ligne (offline) en
# utilisant comme source locale les advisories du dossier ./osv-drupal
# généré par osv-drupal-to-cve.sh
#
# OSV-Scanner attend une base locale de la forme :
#   <db-path>/osv-scanner/<Ecosystem>/all.zip
# =============================================================================

set -euo pipefail


SOURCE_DIR="osv-drupal"
PROJECT_PATH=""
OUTPUT_DIR="rapport"
ECOSYSTEM="Packagist"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTFILE=""

die()  { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[INFO]  $*"; }

usage() {
  cat <<EOF
Usage: $0 PROJECT_PATH [OPTIONS]
      $0 --project PROJECT_PATH [OPTIONS]

Lance OSV-Scanner totalement hors ligne à partir des advisories JSON locaux.
Par défaut, les avis sont lus dans $SOURCE_DIR/advisories.

OPTIONS
  -s <dir>     Racine contenant advisories/ ou dossier advisories lui-même
               (défaut: $SOURCE_DIR)
  -p, --project <dir> Projet Drupal à scanner (-t reste accepté)
  -o <file>    Rapport JSON de sortie (défaut: $OUTPUT_DIR/osv-offline-drupal-TIMESTAMP.json)
  -h, --help   Affiche cette aide

EXEMPLES
  ./osv-drupal-to-cve.sh && $0 -p /var/www/html/mon-drupal
  $0 -p /var/www/html/mon-drupal -s ./osv-drupal/advisories
  $0 -p /var/www/html/mon-drupal -o /tmp/offline.json
EOF
  exit 0
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Commande requise introuvable: $1"; }

[[ "${1:-}" == "--help" ]] && usage
while (($#)); do
  case "$1" in
    -s)
      (($# >= 2)) || die "L'option -s requiert un dossier source."
      SOURCE_DIR="$2"
      shift 2
      ;;
    -p|-t|--project)
      (($# >= 2)) || die "L'option $1 requiert un dossier projet."
      [[ -z "$PROJECT_PATH" ]] || die "Le dossier projet a été indiqué plusieurs fois."
      PROJECT_PATH="$2"
      shift 2
      ;;
    -o)
      (($# >= 2)) || die "L'option -o requiert un fichier de sortie."
      OUTFILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    --)
      shift
      (($# == 1)) || die "Indiquer un seul dossier projet."
      [[ -z "$PROJECT_PATH" ]] || die "Le dossier projet a été indiqué plusieurs fois."
      PROJECT_PATH="$1"
      shift
      ;;
    -*)
      die "Option inconnue: $1"
      ;;
    *)
      [[ -z "$PROJECT_PATH" ]] || die "Le dossier projet a été indiqué plusieurs fois."
      PROJECT_PATH="$1"
      shift
      ;;
  esac
done

[[ -n "$PROJECT_PATH" ]] || die "Dossier projet requis. Utilisation : $0 -p /chemin/vers/drupal"

require_cmd osv-scanner
require_cmd jq
require_cmd zip

if [[ "$(basename "${SOURCE_DIR%/}")" == "advisories" ]]; then
  SOURCE_DIR="$(dirname "${SOURCE_DIR%/}")"
fi

[[ -d "$SOURCE_DIR" ]] || die "Dossier source introuvable : $SOURCE_DIR"
SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd)"
ADVISORY_DIR="${SOURCE_DIR}/advisories"
[[ -d "$ADVISORY_DIR" ]] || die "Dossier d'advisories introuvable: $ADVISORY_DIR (lancer d'abord osv-drupal-to-cve.sh)"
ADVISORY_COUNT=$(find "$ADVISORY_DIR" -type f -name '*.json' | wc -l | tr -d ' ')
[[ "$ADVISORY_COUNT" -gt 0 ]] || die "Aucune advisory JSON dans: $ADVISORY_DIR"
[[ -d "$PROJECT_PATH" ]] || die "Projet introuvable: $PROJECT_PATH"

mkdir -p "$OUTPUT_DIR"
OUTFILE="${OUTFILE:-${OUTPUT_DIR}/osv-offline-drupal-${TIMESTAMP}.json}"

# ---------------------------------------------------------------------------
# Construction de la base locale attendue par OSV-Scanner
# ---------------------------------------------------------------------------
DB_ROOT="${SOURCE_DIR}/db"
DB_ECOSYSTEM_DIR="${DB_ROOT}/osv-scanner/${ECOSYSTEM}"
mkdir -p "$DB_ECOSYSTEM_DIR"

info "Construction de la base locale : ${DB_ECOSYSTEM_DIR}/all.zip ($ADVISORY_COUNT advisories)"
rm -f "${DB_ECOSYSTEM_DIR}/all.zip"
( cd "$ADVISORY_DIR" && zip -q -r -X "${DB_ECOSYSTEM_DIR}/all.zip" . -i '*.json' ) \
  || die "Création de all.zip échouée"

# ---------------------------------------------------------------------------
# Détection des options offline selon la version d'OSV-Scanner
# v2 : --offline + variable OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY
# v1 : --experimental-offline + --experimental-local-db-path
# ---------------------------------------------------------------------------
HELP_TEXT="$(osv-scanner scan source --help 2>&1 || true)"
if grep -q -- '--experimental-local-db-path' <<<"$HELP_TEXT"; then
  OFFLINE_FLAGS=(--experimental-offline --experimental-local-db-path "$DB_ROOT")
elif grep -q -- '--offline' <<<"$HELP_TEXT"; then
  OFFLINE_FLAGS=(--offline)
else
  die "Cette version d'OSV-Scanner ne propose pas de mode hors ligne compatible"
fi

info "Scan hors ligne du projet : $PROJECT_PATH"
info "Options offline : ${OFFLINE_FLAGS[*]}"

SCAN_STATUS=0
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$DB_ROOT" osv-scanner scan source \
  --recursive \
  "${OFFLINE_FLAGS[@]}" \
  --format json \
  --output-file "$OUTFILE" \
  "$PROJECT_PATH" || SCAN_STATUS=$?

[[ -s "$OUTFILE" ]] || die "Rapport absent ou vide : $OUTFILE"
jq -e . "$OUTFILE" >/dev/null || die "Rapport JSON invalide : $OUTFILE"

# Ajout des identifiants CVE dans des champs dédiés.
jq '(.results[]?.packages[]?.vulnerabilities[]? |=
  (. + {
    cve_ids: ([.id] + (.aliases // []) | map(select(test("^CVE-[0-9]{4}-[0-9]+$"))) | unique),
    cve_id: ([[.id] + (.aliases // []) | .[] | select(test("^CVE-[0-9]{4}-[0-9]+$"))] | first // null)
  }))' "$OUTFILE" > "${OUTFILE}.tmp" && mv "${OUTFILE}.tmp" "$OUTFILE"

VULN_COUNT=$(jq '[.results[]?.packages[]?.vulnerabilities[]?] | length' "$OUTFILE")
CVE_COUNT=$(jq '[.results[]?.packages[]?.vulnerabilities[]?.cve_ids[]?] | unique | length' "$OUTFILE")

info "Vulnérabilités détectées : $VULN_COUNT"
info "CVE uniques : $CVE_COUNT"
info "Rapport JSON : $OUTFILE"

[[ "$SCAN_STATUS" -ne 0 ]] && echo "[WARN] OSV-Scanner a détecté des vulnérabilités (code $SCAN_STATUS)."
exit 0
