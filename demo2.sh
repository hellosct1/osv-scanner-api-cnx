#!/usr/bin/env bash
set -euo pipefail

#######################################
# CONFIGURATION
#######################################

PROJECT_DIR="${1:-.}"

DATE=$(date +%Y%m%d-%H%M%S)

WORKDIR="./reports-${DATE}"

OSV_REPORT="${WORKDIR}/osv-report.json"
CSV_REPORT="${WORKDIR}/osv-euvd-report.csv"

EUVD_API="https://euvdservices.enisa.europa.eu/api/search?text="

mkdir -p "${WORKDIR}"

#######################################
# VERIFICATION
#######################################

command -v osv-scanner >/dev/null || {
    echo "[ERREUR] osv-scanner non installé"
    exit 1
}

command -v jq >/dev/null || {
    echo "[ERREUR] jq non installé"
    exit 1
}

command -v curl >/dev/null || {
    echo "[ERREUR] curl non installé"
    exit 1
}

#######################################
# SCAN OSV
#######################################

echo "[INFO] Scan du projet ${PROJECT_DIR}"

osv-scanner scan \
    -r "${PROJECT_DIR}" \
    --format json \
    > "${OSV_REPORT}"

#######################################
# EXTRACTION DES CVE
#######################################

echo "[INFO] Extraction des vulnérabilités"

echo \
"package,cve,severity,euvd_id,exploited,last_modified" \
> "${CSV_REPORT}"

jq -r '
.results[]
| .packages[]? as $pkg
| $pkg.vulnerabilities[]?
| [
    $pkg.package.name,
    .id,
    (.severity[0].score // "")
  ]
| @tsv
' "${OSV_REPORT}" \
| sort -u \
| while IFS=$'\t' read -r PACKAGE CVE SCORE
do

    echo "[INFO] Recherche EUVD : ${CVE}"

    EUVD_JSON=$(curl -s \
        "${EUVD_API}${CVE}")

    EUVD_ID=$(echo "${EUVD_JSON}" | jq -r '
        .content[0].enisaId // ""
    ')

    EXPLOITED=$(echo "${EUVD_JSON}" | jq -r '
        .content[0].exploited // ""
    ')

    LASTMOD=$(echo "${EUVD_JSON}" | jq -r '
        .content[0].lastModified // ""
    ')

    echo "\"${PACKAGE}\",\"${CVE}\",\"${SCORE}\",\"${EUVD_ID}\",\"${EXPLOITED}\",\"${LASTMOD}\"" \
    >> "${CSV_REPORT}"

done

#######################################
# SYNTHESE
#######################################

echo
echo "======================================="
echo "RAPPORT TERMINE"
echo "======================================="
echo "OSV JSON : ${OSV_REPORT}"
echo "CSV      : ${CSV_REPORT}"

awk 'END{print NR-1}' "${CSV_REPORT}" \
| xargs echo "Vulnérabilités analysées :"

