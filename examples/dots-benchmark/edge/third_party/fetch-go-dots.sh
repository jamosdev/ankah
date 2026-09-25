#!/bin/sh
# Fetch go-dots at the pinned commit into third_party/go-dots and apply the
# local patch series. Used by the edge Dockerfile; also usable by hand.
set -eu
GO_DOTS_REPO=https://github.com/nttdots/go-dots.git
GO_DOTS_COMMIT=4e631d1257fd6a5d1f7201c2d06d63c7ace88940

here=$(cd "$(dirname "$0")" && pwd)
dest="$here/go-dots"
rm -rf "$dest"
git init -q "$dest"
git -C "$dest" fetch -q --depth 1 "$GO_DOTS_REPO" "$GO_DOTS_COMMIT"
git -C "$dest" -c advice.detachedHead=false checkout -q FETCH_HEAD
actual=$(git -C "$dest" rev-parse HEAD)
if [ "$actual" != "$GO_DOTS_COMMIT" ]; then
    echo "go-dots commit mismatch: $actual" >&2
    exit 1
fi
for patch in "$here"/patches/*.patch; do
    git -C "$dest" apply --whitespace=nowarn "$patch"
    echo "applied $(basename "$patch")"
done
