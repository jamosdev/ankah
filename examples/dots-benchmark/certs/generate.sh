#!/bin/sh
# Generate demo-only credentials into $OUT (default /out, the demo-certs volume).
# Idempotent: existing files are kept, so restarts reuse the same identity.
# Nothing here is suitable for production use.
set -eu
OUT=${OUT:-/out}
mkdir -p "$OUT"
cd "$OUT"

days=825
if [ ! -s ca.crt ] || [ ! -s ca.key ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout ca.key -out ca.crt -days "$days" -sha256 \
        -subj "/CN=dots-benchmark demo CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    rm -f edge-dots.crt ankah-dots-client.crt
    echo "created demo CA"
fi

issue() { # name subject extensions
    name=$1
    if [ -s "$name.crt" ] && [ -s "$name.key" ]; then
        return
    fi
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$name.key" -out "$name.csr" -subj "$2" 2>/dev/null
    printf '%s\n' "$3" > "$name.ext"
    openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "$name.crt" -days "$days" -sha256 -extfile "$name.ext" 2>/dev/null
    rm -f "$name.csr" "$name.ext"
    echo "issued $name"
}

# DOTS server (edge data channel). Ankah verifies this name.
issue edge-dots "/CN=edge-dots.demo.test" \
"basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:edge-dots.demo.test,IP:172.30.1.10"

# DOTS client (Ankah). go-dots maps the subject CN to its customer table.
issue ankah-dots-client "/CN=ankah-demo-client" \
"basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth"

secret() { # file bytes
    [ -s "$1" ] || { openssl rand -hex "$2" > "$1"; echo "created $1"; }
}
secret ankah-secret 32
secret ankah-dashboard-token 32
secret anubis-ed25519.hex 32

rm -f ca.srl
# Readable by the unprivileged service users in the other containers. These
# are throwaway demo keys in a gitignored directory.
chmod 0644 ./*
echo "demo credentials ready in $OUT"
