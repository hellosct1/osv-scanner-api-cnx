#!/usr/bin/env bash

# Scan le dossier de démonstration avec osv-scanner pour détecter les vulnérabilités connues (OSV)
echo "Scan le dossier de démonstration avec osv-scanner pour détecter les vulnérabilités connues (OSV)"

osv-scanner scan /var/www/html/osv-scanner/demo


