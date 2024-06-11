#!/bin/bash

# Configuration
REMOTE_USER='utilisateur'
REMOTE_HOST='adresse_ip_pfsense'
REMOTE_PATH='/etc/snort/rules'
LOCAL_RULES_PATH='/chemin/vers/src/snort_rules.rules'

# Transfert des règles
scp $LOCAL_RULES_PATH $REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH