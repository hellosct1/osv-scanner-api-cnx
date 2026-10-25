#!/usr/bin/env bash
# =============================================================================
# Scan le dossier de démonstration avec osv-scanner pour détecter les vulnérabilités connues (OSV)
# Usage : ./1-osv.sh 
# =============================================================================


echo "Scan le dossier de démonstration avec osv-scanner pour détecter les vulnérabilités connues (OSV)"

osv-scanner scan -r /var/www/html/osv-scanner/demo-symfony/


