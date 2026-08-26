# osv-scanner-api-cnx

> connexion to API OSV Scanner


## Required

 `curl` et `jq`.


## Introduction

https://google.github.io/osv.dev/




## Script


### 1-osv-api-drupal.sh

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"package": {"name": "drupal/core", "ecosystem": "Packagist"}, "version": "9.5.0"}' \
  "https://api.osv.dev/v1/query" | jq .
```

2-osv-api-ossfuzz.sh
3-osv-api-go.sh
4-osv-api-rust.sh
5-osv-api-pypi.sh

6-osv-api-euvd.sh



| Script | Technologie | Ecosystème OSV |
|--------|------------|----------------|
| `1-osv-api-drupal.sh` | Drupal / Composer | Packagist |
| `2-osv-api-ossfuzz.sh` | C/C++, Rust, Python fuzés | OSS-Fuzz |
| `3-osv-api-go.sh` | Golang | Go |
| `6-osv-api-euvd.sh` | Toutes (enrichissement) | EUVD / ENISA |



Exemple de workflow automatisé
https://google.github.io/osv-scanner/usage/scan-source

# API EUVD
https://rud.is/euvd-api/
