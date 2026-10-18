#!/bin/sh
set -eu
cd "$(dirname "$0")"
test "$(id -u)" = 0 || { echo 'Run with sudo sh deploy/compose/setup.sh' >&2; exit 1; }
python3 ../credentials.py credentials
chown root:10001 credentials credentials/gateway.secret credentials/dashboard.token
chmod 750 credentials
chmod 640 credentials/gateway.secret credentials/dashboard.token
install -d -m 700 -o 10001 -g 10001 state
