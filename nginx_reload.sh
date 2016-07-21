#!/bin/bash

if [ -n "${SEALKEY}" ]; then
	/certctl.py open_keypair -sealKey ${SEALKEY} -dir /etc/nginx/ssl
fi

/usr/sbin/nginx -t -c ${TMP_CONF}