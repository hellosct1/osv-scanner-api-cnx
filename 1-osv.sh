#!/usr/bin/env bash
# =============================================================================
# Scan le dossier de démonstration avec osv-scanner pour détecter les vulnérabilités connues (OSV)
# Usage : ./1-osv.sh /var/www/html/osv-scanner/demo-symfony/
# =============================================================================


echo "Scan le dossier de démonstration avec osv-scanner pour détecter les vulnérabilités connues (OSV)"

osv-scanner scan -r "$1"


