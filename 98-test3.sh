#!/usr/bin/env bash
set -euo pipefail

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

PROJECT_PATH="/var/www/html/osv-scanner/demo"
OSV_REPORT="rapport-json.json"
CVE_LIST="cves-osv.txt"
EUVD_JSONL="rapport-euvd.json"
EUVD_JSON="rapport-euvd-complet.json"
EUVD_CSV="rapport-euvd.csv"
EUVD_API="https://euvdservices.enisa.europa.eu/api/search"

# -------------------------------------------------------------------
# Verification des dependances
# -------------------------------------------------------------------

for cmd in osv-scanner jq curl grep sort sed; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Erreur : la commande '$cmd' est manquante."
    exit 1
  fi
done

# -------------------------------------------------------------------
# 1. Execution OSV-Scanner
# -------------------------------------------------------------------

echo "[1/5] Scan OSV du projet : ${PROJECT_PATH}"

osv-scanner scan \
  --format json \
  --output-file "${OSV_REPORT}" \
  "${PROJECT_PATH}" || true

if [ ! -s "${OSV_REPORT}" ]; then
  echo "Erreur : le rapport OSV '${OSV_REPORT}' est vide ou absent."
  exit 1
fi

echo "Rapport OSV genere : ${OSV_REPORT}"

# -------------------------------------------------------------------
# 2. Extraction des CVE depuis le rapport OSV
# -------------------------------------------------------------------

echo "[2/5] Extraction des CVE depuis ${OSV_REPORT}"

jq -r '
  ..
  | objects
  | .aliases? // empty
  | .[]?
' "${OSV_REPORT}" \
  | grep -E '^CVE-[0-9]{4}-[0-9]+' \
  | sort -u \
  > "${CVE_LIST}" || true

NB_CVE=$(wc -l < "${CVE_LIST}" | tr -d ' ')

echo "Nombre de CVE trouvees : ${NB_CVE}"

if [ "${NB_CVE}" -eq 0 ]; then
  echo "Aucune CVE trouvee dans le rapport OSV."
  echo "Creation d'un rapport vide."

  echo "[]" > "${EUVD_JSON}"
  echo "cve,euvd_id,base_score,epss,exploited_since,aliases,description" > "${EUVD_CSV}"

  exit 0
fi

# -------------------------------------------------------------------
# 3. Correlation CVE avec l'API EUVD
# -------------------------------------------------------------------

echo "[3/5] Correlation avec l'API EUVD"

rm -f "${EUVD_JSONL}"

while read -r CVE; do
  echo "Recherche EUVD pour ${CVE}"

  RESPONSE=$(curl -s \
    --connect-timeout 10 \
    --max-time 30 \
    "${EUVD_API}?text=${CVE}&page=0&size=10")

  # On produit une ligne JSON par CVE pour faciliter le debug
  jq -n \
    --arg cve "${CVE}" \
    --argjson euvd "${RESPONSE:-{}}" \
    '{
      cve: $cve,
      euvd_response: $euvd
    }' >> "${EUVD_JSONL}"

  # Petite pause pour eviter de solliciter trop rapidement l'API
  sleep 0.2

done < "${CVE_LIST}"

echo "Rapport JSONL genere : ${EUVD_JSONL}"

# -------------------------------------------------------------------
# 4. Conversion JSONL vers JSON complet
# -------------------------------------------------------------------

echo "[4/5] Generation du rapport JSON complet"

jq -s '.' "${EUVD_JSONL}" > "${EUVD_JSON}"

echo "Rapport JSON complet genere : ${EUVD_JSON}"

# -------------------------------------------------------------------
# 5. Generation d'un rapport CSV simplifie
# -------------------------------------------------------------------

echo "[5/5] Generation du rapport CSV"

echo "cve,euvd_id,base_score,epss,exploited_since,aliases,description" > "${EUVD_CSV}"

jq -r '
  .[]
  | .cve as $cve
  | (
      .euvd_response.items // .euvd_response // []
    )
  | if type == "array" then . else [] end
  | .[]
  | [
      $cve,
      (.id // ""),
      (.baseScore // ""),
      (.epss // ""),
      (.exploitedSince // ""),
      ((.aliases // "") | tostring | gsub("\n"; " ")),
      ((.description // "") | tostring | gsub("\n"; " ") | gsub("\""; "'"))
    ]
  | @csv
' "${EUVD_JSON}" >> "${EUVD_CSV}" || true

echo "Rapport CSV genere : ${EUVD_CSV}"

echo ""
echo "Traitement termine."
echo "Fichiers produits :"
echo " - ${OSV_REPORT}"
echo " - ${CVE_LIST}"
echo " - ${EUVD_JSONL}"
echo " - ${EUVD_JSON}"
echo " - ${EUVD_CSV}"
