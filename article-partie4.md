# Partie 4 - Interroger l'API OSV Scanner: un exemple simple qui change la routine securite

La securite des dependances n'est plus un sujet reserve aux grands groupes. Aujourd'hui, meme un petit projet web peut integrer des dizaines de bibliotheques externes, parfois sans que l'equipe en ait une vision complete. Dans ce contexte, verifier l'exposition aux vulnerabilites n'est pas un luxe: c'est devenu un reflexe d'hygiene logicielle.

C'est exactement la que l'API OSV entre en jeu. Elle permet de poser une question tres directe et tres utile:

> Cette version de package est-elle connue comme vulnerable?

Dans cette partie, on garde une approche volontairement simple. Pas d'usine a gaz, pas d'outillage complexe: juste une requete HTTP bien formee avec `curl`, puis une lecture propre de la reponse JSON avec `jq`.

## OSV en une phrase

OSV (Open Source Vulnerabilities) est une base de vulnerabilites open source, concue pour des requetes precises sur des packages et des versions, avec un format exploitable en automatisation.

Documentation officielle: https://google.github.io/osv.dev/

## Pourquoi passer par l'API, meme pour un besoin basique

Beaucoup d'equipes commencent par des scans ponctuels. C'est utile, mais l'API ajoute une dimension operationnelle immediate:

- Controler une version precise avant une mise en production
- Ajouter une verification rapide dans un script ou une pipeline CI/CD
- Obtenir des donnees structurees, faciles a transformer en rapport

En clair, l'API OSV permet de passer d'une verification manuelle a un controle repetable.

## Prerequis minimaux

Il suffit de deux outils tres courants:

- `curl`
- `jq`

Avec cela, vous pouvez deja interroger OSV et lire les resultats proprement.

## Endpoint principal a connaitre

https://api.osv.dev/v1/query

Cet endpoint attend un objet JSON decrivant le package, son ecosysteme et la version ciblee.

## Exemple simple: verifier `drupal/core` en version `9.5.0`

Voici une commande minimale, proche de ce que vous utilisez deja dans ce projet:

```bash
curl -s -H "Content-Type: application/json" \
	-d '{"package":{"name":"drupal/core","ecosystem":"Packagist"},"version":"9.5.0"}' \
	"https://api.osv.dev/v1/query" | jq .
```

Cette requete pose une question claire a OSV: existe-t-il des vulnerabilites connues pour `drupal/core` en `9.5.0` dans l'ecosysteme `Packagist`?

## Comment lire la reponse sans se perdre

Le JSON retourne peut sembler dense au premier regard. En pratique, concentrez-vous sur quelques points:

- La presence de `vulnerabilities`
- Les identifiants des vulnerabilites (`CVE`, `GHSA`, etc.)
- Le resume et les details
- Les references externes (advisories, commits, pages officielles)

Si `vulnerabilities` contient des entrees, la version interrogee est concernee par des vulnerabilites connues.
Si la liste est absente ou vide, OSV n'a pas de vulnerabilite correspondante pour cette version au moment de la requete.

> Important: absence de resultat ne veut pas dire absence absolue de risque. Cela signifie uniquement qu'aucune vulnerabilite correspondante n'a ete trouvee dans les donnees OSV disponibles a cet instant.

## Scripts d'exemple prets a copier

Cette section ajoute des scripts courts pour passer rapidement du test manuel a un usage automatisable.

### Script 1: verifier un package/version (OSV query)

Ce script prend 3 arguments: ecosysteme, package, version.

```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
	echo "Usage: $0 <ecosysteme> <package> <version>"
	echo "Exemple: $0 Packagist drupal/core 9.5.0"
	exit 1
fi

ECOSYSTEM="$1"
PACKAGE="$2"
VERSION="$3"

curl -sS -H "Content-Type: application/json" \
	-d "{\"package\":{\"name\":\"${PACKAGE}\",\"ecosystem\":\"${ECOSYSTEM}\"},\"version\":\"${VERSION}\"}" \
	"https://api.osv.dev/v1/query" | jq .
```

Exemple d'execution:

```bash
bash osv-query.sh Packagist drupal/core 9.5.0
```

### Script 2: verifier plusieurs dependances en une fois (OSV querybatch)

Ce script utilise l'endpoint batch pour envoyer plusieurs requetes en une seule fois.

```bash
#!/usr/bin/env bash
set -euo pipefail

curl -sS -H "Content-Type: application/json" \
	-d '{
		"queries": [
			{"package": {"name": "drupal/core", "ecosystem": "Packagist"}, "version": "9.5.0"},
			{"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.20"},
			{"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.19.1"}
		]
	}' \
	"https://api.osv.dev/v1/querybatch" | jq .
```

### Script 3: extraire seulement les IDs de vulnerabilites

Ce script affiche uniquement les identifiants, ce qui est pratique pour des logs CI simples.

```bash
#!/usr/bin/env bash
set -euo pipefail

curl -sS -H "Content-Type: application/json" \
	-d '{"package":{"name":"drupal/core","ecosystem":"Packagist"},"version":"9.5.0"}' \
	"https://api.osv.dev/v1/query" \
	| jq -r '.vulnerabilities[]?.id'
```

## Exemple d'utilisation de l'API EUVD (ENISA)

En complement d'OSV, l'API EUVD permet de chercher des informations sur des CVE et des entrees EUVD.

Base API:

https://euvdservices.enisa.europa.eu/api

### Exemple A: recherche par identifiant (CVE ou EUVD ID)

```bash
curl -sS -H "Accept: application/json" \
	"https://euvdservices.enisa.europa.eu/api/enisaid?id=CVE-2021-44228" \
	| jq .
```

### Exemple B: recherche plein texte

```bash
curl -sS -H "Accept: application/json" \
	"https://euvdservices.enisa.europa.eu/api/search?text=log4j&page=0&pageSize=10" \
	| jq .
```

Astuce: dans un workflow, vous pouvez d'abord detecter via OSV, puis enrichir chaque CVE avec EUVD pour obtenir plus de contexte (references, score, metadonnees).

## Ce que cet exemple apporte concretement

Cet exemple est volontairement simple, mais il couvre deja des besoins reels:

- Validation rapide d'une dependance critique
- Controle pre-deploiement
- Verification ad hoc pendant un incident ou un audit

Et surtout, il sert de brique de base pour une automatisation plus large.

## Vers une integration CI/CD pragmatique

Une fois la requete validee localement, l'etape suivante consiste a l'industrialiser:

- Interroger les dependances prioritaires dans un job CI
- Filtrer les resultats sur la severite ou la criticite metier
- Echouer le pipeline si un seuil de risque est depasse
- Publier un rapport lisible pour l'equipe

Meme sans plateforme complexe, vous pouvez deja produire un premier garde-fou securite efficace.

## Limites a garder en tete

Pour eviter les faux sentiments de securite, gardez ces points en memoire:

- Une requete API verifie ce que vous lui demandez: package, ecosysteme, version
- Le resultat depend de la qualite et de la fraicheur des donnees agregees
- La securite ne se resume pas a un seul signal: combinez OSV avec vos autres controles

OSV est un excellent detecteur, pas un substitut a une strategie complete.

## Conclusion

L'API OSV est un point d'entree ideal pour rendre la securite des dependances concrete, rapide et automatisable. Avec une simple commande `curl`, vous obtenez une reponse directement exploitable pour decider, corriger ou bloquer un deploiement a temps.

C'est exactement le type de geste simple qui, repete a chaque cycle de livraison, ameliore durablement le niveau de securite d'un projet.

## Ressources utiles

- OSV: https://google.github.io/osv.dev/
- Exemple de workflow scan-source: https://google.github.io/osv-scanner/usage/scan-source
- API EUVD (enrichissement): https://rud.is/euvd-api/


