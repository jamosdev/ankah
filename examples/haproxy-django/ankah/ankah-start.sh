#!/bin/sh
set -eu
mkdir -p /run/ankah
openssl rand -hex 32 > /run/ankah/secret
exec ankah --listen 0.0.0.0:8080 --upstream 172.30.72.10:8000 \
  --public-origin https://localhost:8443 --secret-file /run/ankah/secret \
  --assets-dir /assets --trusted-proxy 172.30.71.10/32 \
  --allow-prefix /health --allow-prefix /upload --proxy-abuse-profile conservative
