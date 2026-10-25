#!/usr/bin/env bash
# =============================================================================
# euvd-download.sh — Téléchargement complet de la base EUVD
#
# Ce script itère sur toutes les pages de l'API EUVD et sauvegarde
# les données dans des fichiers JSON, puis les fusionne en un seul fichier.
#
# Usage  : ./euvd-download.sh [répertoire_sortie]
# Sortie : <dir>/euvd_YYYY-MM-DD.json  (base complète fusionnée)
#          <dir>/pages/page_XXXX.json  (pages individuelles)
#
# Dépendances : curl, jq
# =============================================================================

set -euo pipefail

readonly BASE_URL="https://euvdservices.enisa.europa.eu"
readonly PAGE_SIZE=100
readonly OUTPUT_DIR="${1:-euvd-data}"
readonly DATE=$(date +%Y-%m-%d)
readonly PAGES_DIR="${OUTPUT_DIR}/pages"
readonly FINAL_FILE="${OUTPUT_DIR}/euvd_${DATE}.json"
readonly DELAY=1   # secondes entre chaque requête (respect du serveur)

mkdir -p "$PAGES_DIR"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# Obtenir le nombre total de vulnérabilités
log "Interrogation initiale pour obtenir le total..."
first_page=$(curl -sf "${BASE_URL}/api/search?size=1&page=0")
total=$(echo "$first_page" | jq -r '.total')
pages=$(( (total + PAGE_SIZE - 1) / PAGE_SIZE ))
log "Total : ${total} vulnérabilités — ${pages} pages à télécharger"

# Téléchargement page par page
downloaded=0
for ((page=0; page<pages; page++)); do
    page_file="${PAGES_DIR}/page_$(printf '%04d' $page).json"

    if [[ -f "$page_file" ]]; then
        log "Page ${page} déjà présente, ignorée."
        continue
    fi

    log "Téléchargement page $((page+1))/${pages}..."
    curl -sf "${BASE_URL}/api/search?size=${PAGE_SIZE}&page=${page}" \
        -o "$page_file"

    count=$(jq '.items | length' "$page_file")
    log "  -> ${count} entrées sauvegardées dans ${page_file}"
    downloaded=$((downloaded + count))

    sleep "$DELAY"
done

log "Téléchargement terminé. Fusion des pages..."

# Fusion de toutes les pages en un seul fichier JSON
jq -s '[.[].items[]]' "${PAGES_DIR}"/page_*.json > "$FINAL_FILE"

final_count=$(jq 'length' "$FINAL_FILE")
log "Fichier final : ${FINAL_FILE} (${final_count} entrées)"
log "Terminé."
