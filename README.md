# osv-scanner-api-cnx

> connexion to API OSV Scanner




## Required

 `curl` et `jq`.


## Introduction

https://google.github.io/osv.dev/

### Utilisation workflow

Exemple de workflow automatisé

https://google.github.io/osv-scanner/usage/scan-source


### Liste des scripts

| Fichier | Description |
|---|---|
| osv.sh | Vérification du fonctionnement OSV |
| drupal-osv-api.sh | fonctionnalité expérimentale de l'API OSV avec Drupal |
| drupal-osv.sh | Utilisation de API OSV via Drupal |
| drupal-osv-api-project.sh | Validation d'un projet drupal avec l'API OSV |
| drupal-to-cve-osv.sh | Convertir les vulnérabilités `Drupal` pour etre compatble avec OSV  |
| drupal-offline-osv.sh |API OSV Hors ligne via Drupal |
| euvd-1-download.sh |  |
| euvd-api.sh | Utilisation de la fonctionnalité expérimentale de l'API EUVD |
| euvd-download.sh |  |
| euvd-api-list-vulnerabilite.sh| Retourne seulement les vulnérabilités via API OSV |



## Open Source Vulnerabilities (OSV)

Vérification du fonctionnement OSV


```bash
./osv.sh
```


## OSV API

### osv api drupal

Utilisation de la fonctionnalité expérimentale de l'API OSV avec Drupal

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"package": {"name": "drupal/core", "ecosystem": "Packagist"}, "version": "9.5.0"}' \
  "https://api.osv.dev/v1/query" | jq .
```

| Script | Technologie | Ecosystème OSV |
|--------|------------|----------------|
| `drupal-osv-api.sh` | Drupal / Composer | Packagist |



### osv drupal

Utilisation de API OSV via Drupal

Voir les CVE pour les dossiers et sous dossiers



| Script | Technologie | Ecosystème OSV |
|--------|------------|----------------|
| `drupal-osv.sh` | Drupal / Composer | Packagist |



### OSV API drupal project

Validation d'un projet drupal avec l'API OSV


| Script | Technologie | Ecosystème OSV |
|--------|------------|----------------|
| `drupal-osv-api-project.sh` | Drupal / Composer | Packagist |




### OSV offline drupal

L'utilisation du mode offline d'OSV s'effectue en plusieurs étapes

#### Méthode 1 : mode Assisté

Utilisation de la base de données disponible par OSV


```
mkdir -p /opt/osv-db/osv-scanner/Packagist

wget -O /opt/osv-db/osv-scanner/Packagist/all.zip \
  https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip
`

```


* Déclarer l'emplacement des vulnérabilités en local


```bash
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-db

```

* affiche le chemin par defaut

```bash
printenv OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY

```


* Utilisation du mode offline


```bash

osv-scanner \
  --offline \
  -r /var/www/html/osv-scanner/drupal-10.2/

```

* exporter un rapport en HTML
  

```
osv-scanner \
  --offline \
  -r /var/www/html/osv-scanner/drupal \
  --format html \
  --output drupal-security-report.html 

  
```



* Mise à jour
La mise à jour de la base de données doit avoir accés à internet


```
wget https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip
unzip all.zip
git commit -m "Update OSV DB"
```
Puis synchronisation vers la zone isolée.

```
osv_scan:
  stage: security
  script:
    - export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-db
    - osv-scanner --offline \
        --format html \
        --output report.html \
        --lockfile composer.lock
  artifacts:
    paths:
      - report.html
``

```


#### Méthode 2 : personnaliser data source

changer le chemin en local


```

osv-scanner --offline \
  --local-db-path /var/www/html/osv-scanner/osv-db \
  -r /var/www/html/osv-scanner/drupal-10.2/


* Avec le rapport


```
osv-scanner \
  --offline \
  -r /var/www/html/osv-scanner/drupal \
  --format html \
  --output drupal-security-report.html 

  
```

osv-scanner --download-offline-databases -r /var/www/html/osv-scanner/drupal-10.2/
  
```



#### Méthode 3 : Compilation manuelle

* Etape 1

Convertir la source des vulnérabilités `Drupal` en  CVE pour etre compatble avec OSV 

```bash
./drupal-to-cve-osv.sh
```

* Etape 2


```bash
drupal-offline-osv.sh
```



| Script | Technologie | Ecosystème OSV |
|--------|------------|----------------|
| `osv-offline-drupal.sh` | Drupal / Composer | Packagist |






## EUVD connexion


### EUVD API

Utilisation de la fonctionnalité expérimentale de l'API EUVD


| Script | Technologie | Ecosystème OSV |
|--------|------------|----------------|
| `euvd-api.sh` | Toutes (enrichissement) | EUVD / ENISA |


### mode offiline

#### methode 1

utilisation du projet `òsv-schema`

[](https://github.com/hellosct1/osv-schema)

```
cd osv-schema/tools/euvd
./dump_euvd.sh --vendor nodejs --fromDate 2026-01-01 --toDate 2026-31-12 euvd-data

mkdir osv
./convert_euvd.sh -o osv euvd-data/*.json

```




### Utilisation autre projet
./convert_euvd.sh -o osv euvd-data/*.json
./dump_euvd.sh --vendor drupal --fromDate 2026-01-01 --toDate 2026-31-12 euvd-data
./convert_euvd.sh -o osv-data data/*.json

./7-euvd-download.sh


### ./euvd-offline-drupal.sh 
./euvd-offline-drupal.sh
./euvd-offline-drupal.sh -t /chemin/projet -e Packagist -k


### Returne seulement les vulnerabilités via API OSV

Retourne seulement les vulnérabilités via API OSV

```
euvd-api-list-vulnerabilite.sh
```

## test EUVD avec les vulnérabilités Drupal

fonctionnalité en espérimental 

```bash
euvd-offline-drupal.sh
```







