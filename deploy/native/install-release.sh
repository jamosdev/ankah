#!/bin/sh
# Download and install, but do not activate, a versioned Linux x86-64 package.
set -eu
test "$#" = 2 || { echo "usage: $0 VERSION SHA256" >&2; exit 2; }
version=$1
checksum=$2
printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'
printf '%s\n' "$checksum" | grep -Eq '^[a-fA-F0-9]{64}$'
test "$(uname -sm)" = 'Linux x86_64'
test "$(id -u)" = 0
destination=/opt/ankah/$version
test ! -e "$destination"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
curl -fsSL "https://github.com/jamosdev/ankah/releases/download/$version/ankah-linux-musl-x64.tar.gz" \
  -o "$temporary/package.tar.gz"
printf '%s  %s\n' "$checksum" "$temporary/package.tar.gz" | sha256sum -c -
tar -xzf "$temporary/package.tar.gz" -C "$temporary"
test -x "$temporary/ankah-linux-musl-x64/ankah"
test -d "$temporary/ankah-linux-musl-x64/assets/dashboard"
install -d -m 755 /opt/ankah
mv "$temporary/ankah-linux-musl-x64" "$destination"
chown -R root:root "$destination"
chmod -R go-w "$destination"
