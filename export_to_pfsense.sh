#!/bin/bash

# Configuration
REMOTE_USER='root'
REMOTE_HOST='192.168.2.1'
REMOTE_PATH=''
LOCAL_RULES_PATH='/home/user/misp-export/apt41.rules'

# Transfert des règles
scp $LOCAL_RULES_PATH $REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH