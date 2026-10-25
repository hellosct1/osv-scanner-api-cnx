#!/usr/bin/env bash
# =============================================================================
# Client Bash de l'API OSV.dev pour Drupal et les autres ecosystemes OSV.
#
# Documentation API : https://google.github.io/osv.dev/api/
# Schema des avis   : https://ossf.github.io/osv-schema/
# Aide et exemples  : ./drupal-2-osv-api.sh --help
#
# Deroulement : arguments -> validation -> requetes -> collecte -> exports.
# Les filtres de date et de schema sont appliques localement apres la collecte.
# Les rapports sont places dans un sous-dossier unique de rapport-drupal.
#
# Prerequis : Bash, curl avec --fail-with-body, jq, GNU date, mkdir et mktemp.
# Tout echec HTTP ou JSON interrompt le traitement avec un code non nul.
# Les fichiers deja produits restent disponibles pour faciliter le diagnostic.
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# 1. Configuration par defaut
# -----------------------------------------------------------------------------

# La variable d'environnement OSV_API peut remplacer l'URL par defaut.
# L'option --api-url reste prioritaire sur cette variable.
OSV_API="${OSV_API:-https://api.osv.dev/v1}"
OUTPUT_DIR="rapport-drupal"

PACKAGE=""
ECOSYSTEM="Packagist"
VERSION=""
COMMIT=""
PURL=""
GET_ID=""
PROJECT=""
BATCH=""
REQUEST=""
PAGE_TOKEN=""
REPOSITORY=""

FROM=""
TO=""
DATE_FIELD="published"
SCHEMA_VERSION=""
RANGE_TYPE=""
INCLUDE_DEV=true

CONNECT_TIMEOUT=10
MAX_TIME=120
RETRIES=3

# Distingue l'ecosysteme par defaut d'un choix explicite de l'utilisateur.
ECOSYSTEM_SET=false

# -----------------------------------------------------------------------------
# 2. Messages et aide en ligne
# -----------------------------------------------------------------------------

die() {
  printf '[ERREUR] %s\n' "$*" >&2
  exit 1
}

info() {
  printf '[INFO] %s\n' "$*" >&2
}

usage() {
  cat <<'EOF'
Usage: ./drupal-2-osv-api.sh MODE [OPTIONS]

API OSV.dev (ce script n'appelle pas le binaire OSV-Scanner).

MODES (un seul a la fois)
  -p, -s, --package NOM   Package, ex. drupal/core (core devient drupal/core
                          uniquement avec l'ecosysteme Packagist)
      --purl PURL         Package URL, ex. pkg:composer/drupal/core@9.5.0
  -c, --commit HASH       Commit Git ; peut etre associe a --package ou --purl
      --repo URL          Depot Git, associe a --version pour un tag (GIT)
  -g, --id ID             Avis OSV complet via GET /vulns/{id}
                  Exemple : DRUPAL-CORE-2023-001
                  Sans --package ni --version ; l'ID doit exister
                  dans OSV, sinon l'API renvoie une erreur HTTP.
                  Le prefixe SA- est remplace par DRUPAL- automatiquement.
      --project CHEMIN    Dossier Composer ou fichier composer.lock
  -b, --batch FICHIER     JSON {"queries":[...]} via POST /querybatch
      --request FICHIER   Objet JSON brut via POST /query
                          FICHIER peut etre - pour lire stdin

PARAMETRES /query ET /querybatch
  -e, --ecosystem NOM     Packagist par defaut ; PyPI, npm, GIT, etc.
  -v, --version VERSION   Version exacte ou tag ; incompatible avec --commit
                          Ne pas doubler une version deja incluse dans un PURL
      --page-token JETON  Premiere page a lire (mode requete simple seulement)
                          Les pages suivantes sont recuperees automatiquement
      Sans version : tous les avis connus pour le package, pas une detection
      des vulnerabilites d'une installation particuliere.
      JSON brut : champs commit, version, package {name, ecosystem OU purl},
      page_token. Les schemas OSV des avis sont conserves dans les exports.

PROJET ET FILTRES LOCAUX
      --no-dev            Exclure packages-dev du fichier composer.lock
      --from AAAA-MM-JJ    Debut de periode inclusif (UTC)
      --to AAAA-MM-JJ      Fin de periode inclusive (UTC)
      --date-field CHAMP  published (defaut) ou modified
      --schema-version V  Version du schema des avis, ex. 1.6.0
      --range-type TYPE   GIT, SEMVER ou ECOSYSTEM dans affected[].ranges[]
      Les filtres s'appliquent aux avis recus, pas a une recherche globale
      par date sur toute la base OSV. Avis sans date exclus si periode fournie.

EXPORTS ET RESEAU
  -o, --output-dir DIR    rapport-drupal par defaut, sous-dossier par execution
      --api-url URL       https://api.osv.dev/v1 par defaut
      --connect-timeout N Delai connexion en secondes (defaut 10)
      --max-time N        Delai par appel en secondes (defaut 120)
      --retries N         Nouvelles tentatives curl (defaut 3)
  -h, --help              Afficher cette aide sans effectuer de requete

Exports : queries.json, responses.jsonl (reponses brutes), vulnerabilities.json,
vulnerabilities.jsonl, vulnerabilities.csv et metadata.json (filtres/comptages).
Les lots sont decoupes en groupes de 1000 ; leurs avis sont ensuite recuperes
par ID pour obtenir les details complets. Aucun secret du projet n'est envoye,
seuls les noms et versions de ses dependances sont transmis a OSV.
Un echec HTTP/JSON arrete le traitement ; le dossier partiel reste disponible.

EXEMPLES
  ./drupal-2-osv-api.sh -p core -v 7.103
  ./drupal-2-osv-api.sh -p core -v 10.6.15
  # Module Views : formes courte et complete equivalentes (Packagist).
  ./drupal-2-osv-api.sh -p views -v 8.x-3.0
  ./drupal-2-osv-api.sh -p drupal/views -v 8.x-3.0
  ./drupal-2-osv-api.sh -p drupal/core --from 2023-01-01 --to 2025-12-31
  ./drupal-2-osv-api.sh -p requests -e PyPI -v 2.31.0
  ./drupal-2-osv-api.sh -s drupal/block_attributes -v 2.1.0
  ./drupal-2-osv-api.sh --purl pkg:composer/drupal/core@10.5.0
  ./drupal-2-osv-api.sh --repo https://github.com/drupal/drupal.git -v 7.98
  ./drupal-2-osv-api.sh --commit HASH
  ./drupal-2-osv-api.sh --id DRUPAL-CORE-2023-001
  ./drupal-2-osv-api.sh --id GHSA-xxxx-yyyy-zzzz
  ./drupal-2-osv-api.sh --id SA-CONTRIB-2026-232
  ./drupal-2-osv-api.sh --project /var/www/drupal --no-dev
  ./drupal-2-osv-api.sh --batch queries.json --date-field modified --from 2025-01-01
  printf '%s\n' '{"package":{"name":"drupal/core","ecosystem":"Packagist"}}' |
    ./drupal-2-osv-api.sh --request -
EOF
}

# -----------------------------------------------------------------------------
# 3. Lecture des arguments
# -----------------------------------------------------------------------------

# L'aide est accessible sans verifier les dependances et sans appel reseau.
# Les options avec valeur partagent le meme controle avant leur affectation.
while (($#)); do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;

    --no-dev)
      INCLUDE_DEV=false
      shift
      continue
      ;;

    -p|-s|--package|-e|--ecosystem|-v|--version|-c|--commit|--purl|--repo|-g|--id|--project|-b|--batch|--request|--page-token|--from|--to|--date-field|--schema-version|--range-type|-o|--output-dir|--api-url|--connect-timeout|--max-time|--retries)
      if (($# < 2)) || [[ -z "$2" ]]; then
        die "Valeur manquante pour $1"
      fi

      case "$1" in
        -p|-s|--package)
          PACKAGE="$2"
          ;;
        -e|--ecosystem)
          ECOSYSTEM="$2"
          ECOSYSTEM_SET=true
          ;;
        -v|--version)
          VERSION="$2"
          ;;
        -c|--commit)
          COMMIT="$2"
          ;;
        --purl)
          PURL="$2"
          ;;
        --repo)
          REPOSITORY="$2"
          ;;
        -g|--id)
          GET_ID="$2"
          ;;
        --project)
          PROJECT="$2"
          ;;
        -b|--batch)
          BATCH="$2"
          ;;
        --request)
          REQUEST="$2"
          ;;
        --page-token)
          PAGE_TOKEN="$2"
          ;;
        --from)
          FROM="$2"
          ;;
        --to)
          TO="$2"
          ;;
        --date-field)
          DATE_FIELD="$2"
          ;;
        --schema-version)
          SCHEMA_VERSION="$2"
          ;;
        --range-type)
          RANGE_TYPE="$2"
          ;;
        -o|--output-dir)
          OUTPUT_DIR="$2"
          ;;
        --api-url)
          OSV_API="$2"
          ;;
        --connect-timeout)
          CONNECT_TIMEOUT="$2"
          ;;
        --max-time)
          MAX_TIME="$2"
          ;;
        --retries)
          RETRIES="$2"
          ;;
      esac

      shift 2
      ;;

    *)
      die "Argument inconnu : $1 (voir --help)"
      ;;
  esac
done

# -----------------------------------------------------------------------------
# 4. Verification des dependances, des valeurs et des modes compatibles
# -----------------------------------------------------------------------------

for command_name in curl jq date mkdir mktemp; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    die "Commande manquante : $command_name"
  fi
done

for number in "$CONNECT_TIMEOUT" "$MAX_TIME"; do
  if [[ ! "$number" =~ ^[1-9][0-9]*$ ]]; then
    die "Les delais doivent etre des entiers positifs"
  fi
done

if [[ ! "$RETRIES" =~ ^[0-9]+$ ]]; then
  die "--retries doit etre un entier positif ou nul"
fi

if [[ "$DATE_FIELD" != published && "$DATE_FIELD" != modified ]]; then
  die "Champ de date invalide"
fi

if [[ -n "$RANGE_TYPE" && "$RANGE_TYPE" != GIT &&
      "$RANGE_TYPE" != SEMVER && "$RANGE_TYPE" != ECOSYSTEM ]]; then
  die "Type de plage invalide"
fi

# GNU date verifie le calendrier, pas seulement la forme AAAA-MM-JJ.
for date_value in "$FROM" "$TO"; do
  if [[ -n "$date_value" ]]; then
    if [[ ! "$date_value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
      die "Date attendue : AAAA-MM-JJ"
    fi

    if ! normalized=$(date -u -d "$date_value" +%F); then
      die "Date invalide : $date_value"
    fi

    if [[ "$normalized" != "$date_value" ]]; then
      die "Date invalide : $date_value"
    fi
  fi
done

if [[ -n "$FROM" && -n "$TO" && "$FROM" > "$TO" ]]; then
  die "Periode inversee"
fi

# Package, PURL, commit et depot constituent le meme mode de requete simple.
# Un commit peut etre restreint a un package, mais pas associe a une version.
mode_count=0

for mode_value in "$GET_ID" "$PROJECT" "$BATCH" "$REQUEST"; do
  if [[ -n "$mode_value" ]]; then
    mode_count=$((mode_count + 1))
  fi
done

if [[ -n "$PACKAGE$PURL$COMMIT$REPOSITORY" ]]; then
  mode_count=$((mode_count + 1))
fi

if ((mode_count != 1)); then
  die "Choisir un seul mode de recherche (voir --help)"
fi

if [[ -n "$GET_ID$PROJECT$BATCH$REQUEST" ]]; then
  if [[ -n "$VERSION$PAGE_TOKEN" || "$ECOSYSTEM_SET" != false ]]; then
    die "Version, ecosysteme et jeton doivent etre dans les requetes JSON ou le mode package"
  fi
fi

if [[ "$INCLUDE_DEV" != true && -z "$PROJECT" ]]; then
  die "--no-dev necessite --project"
fi

if [[ -n "$PURL" && ( -n "$PACKAGE" || "$ECOSYSTEM_SET" != false ) ]]; then
  die "PURL incompatible avec package/ecosysteme"
fi

if [[ -n "$COMMIT" && -n "$VERSION" ]]; then
  die "Commit et version sont incompatibles"
fi

if [[ -n "$PURL" && -n "$VERSION" && "$PURL" == *@* ]]; then
  die "Version deja incluse dans le PURL"
fi

if [[ -n "$REPOSITORY" ]]; then
  if [[ -n "$PACKAGE$PURL$COMMIT" || -z "$VERSION" || "$ECOSYSTEM_SET" != false ]]; then
    die "--repo necessite --version, sans package, PURL, commit ou ecosysteme"
  fi

  PACKAGE="$REPOSITORY"
  ECOSYSTEM="GIT"
fi

if [[ -n "$GET_ID" && ! "$GET_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]]; then
  die "Identifiant OSV invalide"
fi

# Le flux OSV identifie les avis Drupal contrib avec DRUPAL-CONTRIB-...
# Accepter aussi l'identifiant Drupal.org SA-CONTRIB-... en entree.
if [[ "$GET_ID" == SA-* ]]; then
  GET_ID="DRUPAL-${GET_ID#SA-}"
  info "Identifiant Drupal normalise : $GET_ID"
fi

# -----------------------------------------------------------------------------
# 5. Construction du tableau de requetes OSV
# -----------------------------------------------------------------------------

# Tous les modes de recherche sont convertis en tableau JSON, meme lorsqu'il
# ne contient qu'une requete. Le mode --id n'a pas de corps de requete.
QUERIES='[]'

if [[ -n "$PROJECT" ]]; then
  LOCKFILE="$PROJECT"

  if [[ -d "$PROJECT" ]]; then
    LOCKFILE="${PROJECT%/}/composer.lock"
  fi

  if [[ ! -r "$LOCKFILE" ]]; then
    die "composer.lock introuvable : $LOCKFILE"
  fi

  # composer.lock fournit les versions installees, contrairement aux contraintes
  # de composer.json. Seuls le nom et la version des packages sont transmis.
  QUERIES=$(jq -ce \
    --argjson dev "$INCLUDE_DEV" \
    '
      if (.packages | type) != "array" then
        error("packages doit etre un tableau")
      else
        [
          .packages[],
          (if $dev then .["packages-dev"][]? else empty end)
          | {
              package: {
                name: .name,
                ecosystem: "Packagist"
              },
              version: .version
            }
        ]
      end
    ' "$LOCKFILE") || die "Fichier Composer invalide"

elif [[ -n "$BATCH$REQUEST" ]]; then
  INPUT_FILE="${BATCH:-$REQUEST}"

  # -s permet aussi de refuser plusieurs documents JSON dans le meme fichier.
  if [[ -n "$BATCH" ]]; then
    QUERIES=$(jq -sce '
      if length == 1 and (.[0].queries | type) == "array" then
        .[0].queries
      else
        error("objet queries attendu")
      end
    ' "$INPUT_FILE") || die "Lot JSON invalide"
  else
    QUERIES=$(jq -sce '
      if length == 1 and (.[0] | type) == "object" then
        .
      else
        error("objet query attendu")
      end
    ' "$INPUT_FILE") || die "Requete JSON invalide"
  fi

elif [[ -z "$GET_ID" ]]; then
  if [[ "$ECOSYSTEM" == Packagist && -n "$PACKAGE" && "$PACKAGE" != */* ]]; then
    PACKAGE="drupal/$PACKAGE"
  fi

  QUERIES=$(jq -nc \
    --arg name "$PACKAGE" \
    --arg ecosystem "$ECOSYSTEM" \
    --arg purl "$PURL" \
    --arg version "$VERSION" \
    --arg commit "$COMMIT" \
    --arg token "$PAGE_TOKEN" \
    '
      [
        {}
        | if $name != "" then
            .package = {name: $name, ecosystem: $ecosystem}
          else . end
        | if $purl != "" then .package = {purl: $purl} else . end
        | if $version != "" then .version = $version else . end
        | if $commit != "" then .commit = $commit else . end
        | if $token != "" then .page_token = $token else . end
      ]
    ')
fi

# Les entrees JSON et Composer passent par les memes controles que les options :
# package identifie par nom + ecosysteme OU par PURL, version OU commit.
jq -e '
  def text:
    type == "string" and length > 0;

  type == "array" and all(.[];
    type == "object"
    and ((keys - ["package", "version", "commit", "page_token"]) | length == 0)
    and (
      if has("package") then
        .package
        | type == "object" and (
            (has("purl") and (keys == ["purl"]) and (.purl | text))
            or (
              (keys == ["ecosystem", "name"])
              and (.name | text)
              and (.ecosystem | text)
            )
          )
      else
        has("commit")
      end
    )
    and (
      if has("version") then
        (.version | text) and (has("commit") | not)
      else true end
    )
    and (if has("commit") then (.commit | text) else true end)
    and (if has("page_token") then (.page_token | text) else true end)
    and (
      if has("version") and (.package | has("purl")) then
        .package.purl | contains("@") | not
      else true end
    )
  )
' <<< "$QUERIES" >/dev/null || die "Schema de requete OSV invalide"

# -----------------------------------------------------------------------------
# 6. Dossier de travail et conservation des requetes/reponses
# -----------------------------------------------------------------------------

mkdir -p -- "$OUTPUT_DIR"
RUN_DIR=$(mktemp -d "${OUTPUT_DIR%/}/osv-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")

printf '%s\n' "$QUERIES" | jq . > "$RUN_DIR/queries.json"
: > "$RUN_DIR/responses.jsonl"
: > "$RUN_DIR/records.jsonl"

info "Rapports : $RUN_DIR"

# -----------------------------------------------------------------------------
# 7. Fonctions de communication avec l'API
# -----------------------------------------------------------------------------

# Usage : api_call ENDPOINT [CORPS_JSON]
# Sans corps : GET. Avec corps : POST. stdout contient uniquement la reponse.
# Chaque appel reussi est journalise avant de rendre la reponse a l'appelant.
api_call() {
  local endpoint="$1"
  local payload="${2:-}"
  local response

  local curl_args=(
    --silent
    --show-error
    --fail-with-body
    --location
    --connect-timeout "$CONNECT_TIMEOUT"
    --max-time "$MAX_TIME"
    --retry "$RETRIES"
    -H 'Accept: application/json'
    -H 'User-Agent: drupal-7-osv/1.0'
  )

  if [[ -n "$payload" ]]; then
    curl_args+=(-H 'Content-Type: application/json' --data-binary "$payload")
  fi

  response=$(curl "${curl_args[@]}" "${OSV_API%/}/$endpoint") ||
    die "Echec HTTP/reseau : $endpoint"

  printf '%s\n' "$response" | jq -se '
    length == 1
    and (.[0] | type) == "object"
    and (.[0] | has("error") | not)
  ' >/dev/null || die "Reponse JSON invalide : $endpoint"

  jq -nc \
    --arg endpoint "$endpoint" \
    --argjson request "${payload:-null}" \
    --argjson response "$response" \
    '{
      endpoint: $endpoint,
      request: $request,
      response: $response
    }' >> "$RUN_DIR/responses.jsonl"

  printf '%s\n' "$response"
}

# Usage : query_all_pages REQUETE_JSON
# OSV peut renvoyer un jeton sans avis : continuer tant que ce jeton existe.
# Le suivi des jetons empeche une boucle infinie si le serveur les repete.
query_all_pages() {
  local query="$1"
  local response
  local token
  local previous_token
  local seen_tokens='[]'

  while :; do
    response=$(api_call query "$query")
    jq -c '.vulns[]?' <<< "$response" >> "$RUN_DIR/records.jsonl"

    token=$(jq -r '.next_page_token // empty' <<< "$response")

    if [[ -z "$token" ]]; then
      break
    fi

    previous_token=$(jq -r '.page_token // empty' <<< "$query")

    if [[ "$token" == "$previous_token" ]]; then
      die "Jeton de pagination repete"
    fi

    jq -e --arg token "$token" 'index($token) == null' \
      <<< "$seen_tokens" >/dev/null || die "Cycle de pagination"

    seen_tokens=$(jq -c --arg token "$token" '. + [$token]' <<< "$seen_tokens")
    query=$(jq -c --arg token "$token" '.page_token = $token' <<< "$query")
  done
}

# Usage : fetch_record IDENTIFIANT_OSV
# /querybatch ne renvoie que les ID et dates modified ; /vulns fournit l'avis
# complet necessaire aux filtres de publication et aux exports detailles.
fetch_record() {
  local identifier="$1"
  local response
  local encoded

  encoded=$(jq -nr --arg identifier "$identifier" '$identifier | @uri')
  response=$(api_call "vulns/$encoded")

  jq -e --arg identifier "$identifier" '.id == $identifier' \
    <<< "$response" >/dev/null || die "Avis OSV incomplet : $identifier"

  jq -c . <<< "$response" >> "$RUN_DIR/records.jsonl"
}

# -----------------------------------------------------------------------------
# 8. Collecte selon le mode choisi
# -----------------------------------------------------------------------------

if [[ -n "$GET_ID" ]]; then
  fetch_record "$GET_ID"

elif [[ -n "$BATCH$PROJECT" ]]; then
  TOTAL=$(jq length <<< "$QUERIES")

  # Les indices des resultats correspondent aux indices des requetes du lot.
  for ((offset = 0; offset < TOTAL; offset += 1000)); do
    payload=$(jq -c \
      --argjson offset "$offset" \
      '{queries: .[$offset:($offset + 1000)]}' <<< "$QUERIES")

    response=$(api_call querybatch "$payload")
    expected=$(jq '.queries | length' <<< "$payload")

    jq -e --argjson expected "$expected" '
      (.results | type) == "array"
      and (.results | length) == $expected
    ' <<< "$response" >/dev/null || die "Resultats du lot incomplets"

    jq -c '.results[].vulns[]?' <<< "$response" >> "$RUN_DIR/records.jsonl"

    # Seules les requetes ayant un jeton necessitent des pages supplementaires.
    for ((index = 0; index < expected; index++)); do
      token=$(jq -r \
        --argjson index "$index" \
        '.results[$index].next_page_token // empty' <<< "$response")

      if [[ -n "$token" ]]; then
        query=$(jq -c \
          --argjson index "$index" \
          --arg token "$token" \
          '.queries[$index] | .page_token = $token' <<< "$payload")

        query_all_pages "$query"
      fi
    done
  done

  # Un avis peut concerner plusieurs dependances : ne le telecharger qu'une fois.
  # records.jsonl est ensuite remplace par les avis complets, sans les resumes.
  jq -sr 'unique_by(.id)[] | .id' "$RUN_DIR/records.jsonl" > "$RUN_DIR/ids.txt"
  : > "$RUN_DIR/records.jsonl"

  while IFS= read -r identifier; do
    fetch_record "$identifier"
  done < "$RUN_DIR/ids.txt"

else
  query_all_pages "$(jq -c '.[0]' <<< "$QUERIES")"
fi

# -----------------------------------------------------------------------------
# 9. Deduplication et filtres locaux
# -----------------------------------------------------------------------------

# Les dates OSV sont en UTC. Leur partie AAAA-MM-JJ permet une comparaison
# inclusive par jour, sans perdre les avis publies en fin de journee.
# Sans periode demandee, un avis sans date reste eligible a l'export.
jq -s \
  --arg from "$FROM" \
  --arg to "$TO" \
  --arg field "$DATE_FIELD" \
  --arg schema "$SCHEMA_VERSION" \
  --arg range "$RANGE_TYPE" \
  '
    unique_by(.id)
    | map(
        select(
          ($from == "" or ((.[$field] // "")[0:10] >= $from))
          and ($to == "" or ((.[$field] // "")[0:10] <= $to))
          and (($from == "" and $to == "") or ((.[$field] // "") != ""))
          and ($schema == "" or .schema_version == $schema)
          and (
            $range == ""
            or any(.affected[]?.ranges[]?; .type == $range)
          )
        )
      )
  ' "$RUN_DIR/records.jsonl" > "$RUN_DIR/vulnerabilities.json"

# -----------------------------------------------------------------------------
# 10. Exports JSONL, CSV et metadonnees de l'execution
# -----------------------------------------------------------------------------

# JSON et JSONL conservent les objets OSV complets. Le CSV est une vue resumee :
# les listes sont reunies avec "; " et jq @csv protege guillemets et virgules.
jq -c '.[]' "$RUN_DIR/vulnerabilities.json" > "$RUN_DIR/vulnerabilities.jsonl"

jq -r '
  [
    "id",
    "schema_version",
    "published",
    "modified",
    "withdrawn",
    "aliases",
    "packages",
    "fixed",
    "severity",
    "summary",
    "references"
  ],
  (
    .[]
    | [
        .id,
        .schema_version,
        .published,
        .modified,
        .withdrawn,
        ((.aliases // []) | join("; ")),
        ([.affected[]?.package | "\(.ecosystem):\(.name)"] | unique | join("; ")),
        ([.affected[]?.ranges[]?.events[]?.fixed // empty] | unique | join("; ")),
        ([.severity[]? | "\(.type):\(.score)"] | join("; ")),
        (.summary // .details // "" | gsub("[\r\n]"; " ")),
        ([.references[]?.url] | join("; "))
      ]
  )
  | @csv
' "$RUN_DIR/vulnerabilities.json" > "$RUN_DIR/vulnerabilities.csv"

# Les comptages avant/apres filtrage permettent de distinguer une recherche
# sans resultat d'une recherche dont tous les avis ont ete exclus localement.
jq -n \
  --arg api "$OSV_API" \
  --arg created "$(date -u +%FT%TZ)" \
  --arg project "$PROJECT" \
  --arg id "$GET_ID" \
  --arg from "$FROM" \
  --arg to "$TO" \
  --arg field "$DATE_FIELD" \
  --arg schema "$SCHEMA_VERSION" \
  --arg range "$RANGE_TYPE" \
  --argjson include_dev "$INCLUDE_DEV" \
  --slurpfile queries "$RUN_DIR/queries.json" \
  --slurpfile records "$RUN_DIR/records.jsonl" \
  --slurpfile filtered "$RUN_DIR/vulnerabilities.json" \
  '{
    api: $api,
    created: $created,
    project: $project,
    id: $id,
    include_dev: $include_dev,
    queries: ($queries[0] | length),
    retrieved: ($records | unique_by(.id) | length),
    exported: ($filtered[0] | length),
    filters: {
      from: $from,
      to: $to,
      date_field: $field,
      schema_version: $schema,
      range_type: $range
    }
  }' > "$RUN_DIR/metadata.json"

info "Termine : $(jq length "$RUN_DIR/vulnerabilities.json") avis exportes dans $RUN_DIR"