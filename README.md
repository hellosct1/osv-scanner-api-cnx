# osv-scanner-api-cnx

> connexion to API OSV Scanner
> https://google.github.io/osv.dev/




## Required

### Installation de `curl` et `jq`.

```
sudo apt-get install jq
sudo apt-get install curl
```



### Installation GO


* Option A : Avec le gestionnaire de paquets
  
```
sudo apt update
sudo apt install golang-go
```

* Option B : Installation manuelle (version plus récente)

```
# Télécharger la dernière version
wget https://go.dev/dl/go1.27.3.linux-amd64.tar.gz

# Extraire dans /usr/local
sudo tar -C /usr/local -xzf go1.27.3.linux-amd64.tar.gz

# Ajouter au PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

Vérification :

```
go version
```


### Installation osv-scanner

```

go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
osv-scanner --version
```






* déroulement
```
./osv.sh
```



## Liste des scripts

| Fichier | Description |
|---|---|
| 1-osv.sh | Vérification du fonctionnement OSV |
| drupal-1-osv.sh | Scan des vulnérabilités connues pour un projet Drupal via OSV-Scanner |
| drupal-2-osv-api.sh | Client Bash de l'API OSV.dev pour Drupal |
| drupal-3-osv-api-project.sh | Scan a Drupal project with the OSV API |
| drupal-4-download.sh | Extrait les failles Drupal du schéma OSV et les convertit en identifiants CVE |
| drupal-5-offline.sh | Scan OSV-Scanner en mode hors ligne (offline) |
| euvd-1-api-list-vulnerabilite.sh| Retourne seulement les vulnérabilités via API OSV |
| euvd-2-api.sh | Utilisation de la fonctionnalité expérimentale de l'API EUVD |
| euvd-3-download.sh |  |
| euvd-download.sh |  |







## USE TO SCRIPTS


```
./osv-scanner scan --filter-type=EUVD -r /var/www/html/osv-scanner/drupal-10.2/
```
./osv-scanner scan -r --filter-type=EUVD /var/www/html/osv-scanner/drupal-10.2/
./osv-scanner scan --filter-type=EUVD -r /var/www/html/osv-scanner/drupal-10.2/

### Utilisation workflow

Exemple de workflow automatisé

https://google.github.io/osv-scanner/usage/scan-source



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









## ------------------------------------------------




## A TRIER

```
git clone https://github.com/hellosct1/osv-scanner.git

./scripts/run_formatters.sh
./scripts/build.sh
```

* Verification

```
./osv-scanner --help

```
