#!/bin/sh
set -eu
mkdir -p /run/haproxy
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout /run/haproxy/localhost.key -out /run/haproxy/localhost.crt \
  -subj /CN=localhost -addext 'subjectAltName=DNS:localhost' >/dev/null 2>&1
cat /run/haproxy/localhost.crt /run/haproxy/localhost.key > /run/haproxy/localhost.pem
if [ "${1:-}" = "--check" ]; then
  exec haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg
fi
exec haproxy -f /usr/local/etc/haproxy/haproxy.cfg -db
