#!/usr/bin/env bash
# ==============================================================================
# euvd-download.sh - Telechargement pagine de la base EUVD, avec filtre facultatif
#
# Usage :
#   ./euvd-download.sh
#   ./euvd-download.sh -s drupal
#   ./euvd-download.sh -s "Drupal core" -o ./resultats
#
# Options :
#   -s TERME   Filtre texte transmis a l'API EUVD, par exemple drupal
#   -o DOSSIER Repertoire de sortie, par defaut euvd-data
#   -p TAILLE  Nombre d'elements par page, de 1 a 100, par defaut 100
#   -d DELAI   Delai entre les requetes en secondes, par defaut 1
#   -h         Afficher l'aide
#
# Sorties :
#   <dossier>/euvd_<filtre>_AAAA-MM-JJ.json
#   <dossier>/euvd_<filtre>_AAAA-MM-JJ.csv
#   <dossier>/pages_<filtre>/page_XXXX.json
#
# Dependances : curl, jq
# ==============================================================================
# Recherche composée
./euvd-download.sh -s "Drupal core"

# Répertoire de sortie personnalisé
./euvd-download.sh -s drupal -o ./resultats-drupal

# Taille des pages et délai personnalisés
./euvd-download.sh -s drupal -p 50 -d 2

# Télécharger toute la base, sans filtre
./euvd-download.sh

# Afficher l’aide
./euvd-download.sh -h


set -euo pipefail

readonly BASE_URL="https://euvdservices.enisa.europa.eu"
SEARCH_TERM=""
OUTPUT_DIR="euvd-data"
PAGE_SIZE=100
DELAY=1

usage() {
  sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
}

log() {
  printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

fail() {
  printf 'Erreur : %s\n' "$*" >&2
  exit 1
}

while getopts ':s:o:p:d:h' opt; do
  case "$opt" in
    s) SEARCH_TERM="$OPTARG" ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    p) PAGE_SIZE="$OPTARG" ;;
    d) DELAY="$OPTARG" ;;
    h) usage; exit 0 ;;
    :) fail "l'option -$OPTARG attend une valeur" ;;
    \?) fail "option inconnue : -$OPTARG. Utilisez -h pour l'aide" ;;
  esac
done
shift $((OPTIND - 1))

[[ $# -eq 0 ]] || fail "argument inattendu : $1"

for cmd in curl jq sed tr date mkdir mv rm printf; do
  command -v "$cmd" >/dev/null 2>&1 || fail "commande manquante : $cmd"
done

[[ "$PAGE_SIZE" =~ ^[0-9]+$ ]] || fail "-p doit etre un entier"
(( PAGE_SIZE >= 1 && PAGE_SIZE <= 100 )) || fail "-p doit etre compris entre 1 et 100"
[[ "$DELAY" =~ ^[0-9]+([.][0-9]+)?$ ]] || fail "-d doit etre un nombre positif"

DATE_VALUE=$(date +%Y-%m-%d)
if [[ -n "$SEARCH_TERM" ]]; then
  SLUG=$(printf '%s' "$SEARCH_TERM" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//')
  [[ -n "$SLUG" ]] || SLUG="recherche"
else
  SLUG="complet"
fi

PAGES_DIR="${OUTPUT_DIR}/pages_${SLUG}"
FINAL_FILE="${OUTPUT_DIR}/euvd_${SLUG}_${DATE_VALUE}.json"
CSV_FILE="${OUTPUT_DIR}/euvd_${SLUG}_${DATE_VALUE}.csv"
FIRST_PAGE="${PAGES_DIR}/page_0000.json"
TMP_FILE="${FINAL_FILE}.tmp"

mkdir -p "$PAGES_DIR"
rm -f "$PAGES_DIR"/page_*.json "$TMP_FILE"

fetch_page() {
  local page="$1"
  local output="$2"
  local http_code
  local curl_args=(
    --silent --show-error --location
    --connect-timeout 10 --max-time 60
    --retry 3 --retry-delay 2 --retry-all-errors
    --get "${BASE_URL}/api/search"
    --data-urlencode "page=${page}"
    --data-urlencode "size=${PAGE_SIZE}"
    --header 'Accept: application/json'
    --output "$output"
    --write-out '%{http_code}'
  )

  if [[ -n "$SEARCH_TERM" ]]; then
    curl_args+=(--data-urlencode "text=${SEARCH_TERM}")
  fi

  if ! http_code=$(curl "${curl_args[@]}"); then
    rm -f "$output"
    return 1
  fi

  if [[ ! "$http_code" =~ ^2 ]]; then
    printf 'Erreur HTTP %s pour la page %s\n' "$http_code" "$page" >&2
    rm -f "$output"
    return 1
  fi

  if ! jq -e 'type == "object" and (.items | type == "array")' "$output" >/dev/null 2>&1; then
    printf 'Reponse JSON EUVD invalide pour la page %s\n' "$page" >&2
    rm -f "$output"
    return 1
  fi
}

if [[ -n "$SEARCH_TERM" ]]; then
  log "Recherche EUVD : $SEARCH_TERM"
else
  log "Telechargement complet de la base EUVD"
fi

log "Interrogation initiale pour obtenir le total..."
fetch_page 0 "$FIRST_PAGE" || fail "impossible de recuperer la premiere page EUVD"

total=$(jq -er '.total | numbers' "$FIRST_PAGE") \
  || fail "le champ total est absent ou invalide dans la reponse EUVD"
pages=$(( (total + PAGE_SIZE - 1) / PAGE_SIZE ))
log "Total annonce par l'API : $total vulnerabilite(s), $pages page(s)"

if (( total == 0 )); then
  printf '[]\n' > "$FINAL_FILE"
else
  for ((page=1; page<pages; page++)); do
    page_file=$(printf '%s/page_%04d.json' "$PAGES_DIR" "$page")
    log "Telechargement page $((page + 1))/$pages"
    fetch_page "$page" "$page_file" || fail "echec du telechargement de la page $page"
    sleep "$DELAY"
  done

  log "Fusion des pages..."
  jq -s '[.[].items[]]' "$PAGES_DIR"/page_*.json > "$TMP_FILE"
  mv "$TMP_FILE" "$FINAL_FILE"
fi

final_count=$(jq 'length' "$FINAL_FILE")
if (( final_count != total )); then
  log "Avertissement : l'API annonce $total entree(s), mais $final_count ont ete fusionnees"
fi

log "Generation du CSV..."
jq -r '
  (["euvd_id", "aliases", "base_score", "epss", "exploited_since", "date_published", "date_updated", "description"] | @csv),
  (.[] |
    [
      (.id // ""),
      ((.aliases // "") | tostring | gsub("\\r?\\n"; " ") | sub(" +$"; "")),
      (.baseScore // ""),
      (.epss // ""),
      (.exploitedSince // ""),
      (.datePublished // ""),
      (.dateUpdated // ""),
      ((.description // "") | tostring | gsub("\\r?\\n"; " "))
    ] | @csv
  )
' "$FINAL_FILE" > "$CSV_FILE"

log "Termine : $final_count entree(s)"
printf 'Fichiers produits :\n'
printf ' - %s\n' "$FINAL_FILE"
printf ' - %s\n' "$CSV_FILE"
printf ' - %s\n' "$PAGES_DIR"
