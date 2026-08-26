# osv-scanner-api-cnx

> connexion to API OSV Scanner


## Required

 `curl` et `jq`.


## Introduction

https://google.github.io/osv.dev/

### Utilisation workflow

Exemple de workflow automatisé

https://google.github.io/osv-scanner/usage/scan-source


## Scripts


### osv-api-drupal.sh

Utilisation de la fonctionnalité expérimentale de l'API OSV avec Drupal

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"package": {"name": "drupal/core", "ecosystem": "Packagist"}, "version": "9.5.0"}' \
  "https://api.osv.dev/v1/query" | jq .
```

| Script | Technologie | Ecosystème OSV |
|--------|------------|----------------|
| `osv-api-drupal.sh` | Drupal / Composer | Packagist |



### osv-api-euvd.sh

Utilisation de la fonctionnalité expérimentale de l'API OSV avec EUVD


| Script | Technologie | Ecosystème OSV |
|--------|------------|----------------|
| `osv-api-euvd.sh` | Toutes (enrichissement) | EUVD / ENISA |





#### API EUVD
https://rud.is/euvd-api/


