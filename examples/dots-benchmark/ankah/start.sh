#!/bin/sh
# Ankah in front of Django, with the optional DOTS client enabled. Every
# DOTS_* value can be overridden from compose.yaml or the environment.
set -eu
C=/run/demo-certs
exec ankah \
  --listen 0.0.0.0:8080 \
  --upstream 172.30.1.31:8000 \
  --public-origin http://ankah.test \
  --secret-file "$C/ankah-secret" \
  --assets-dir /assets \
  --trusted-proxy 172.30.1.10/32 \
  --proxy-abuse-profile=off \
  --allow-prefix /healthz \
  --ankah-livez \
  --dashboard-listen 0.0.0.0:9101 \
  --dashboard-token-file "$C/ankah-dashboard-token" \
  --no-stats-file \
  --dots-server "${DOTS_SERVER:-172.30.1.10:4443}" \
  --dots-server-name "${DOTS_SERVER_NAME:-edge-dots.demo.test}" \
  --dots-ca-file "$C/ca.crt" \
  --dots-cert-file "$C/ankah-dots-client.crt" \
  --dots-key-file "$C/ankah-dots-client.key" \
  --dots-cuid "${DOTS_CUID:-ankah-demo}" \
  --dots-protected-network "${DOTS_PROTECTED_NETWORK:-172.30.0.11/32}" \
  --dots-protected-port "${DOTS_PROTECTED_PORT:-80}" \
  --dots-threshold "${DOTS_THRESHOLD:-10}" \
  --dots-window-seconds "${DOTS_WINDOW_SECONDS:-5}" \
  --dots-block-seconds "${DOTS_BLOCK_SECONDS:-45}"
