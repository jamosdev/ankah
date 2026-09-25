#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 vMAJOR.MINOR.PATCH" >&2
  exit 2
fi

tag=$1
case "$tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "expected vMAJOR.MINOR.PATCH" >&2; exit 2 ;;
esac
if ! printf '%s\n' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
  echo "expected vMAJOR.MINOR.PATCH" >&2
  exit 2
fi

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
test "$(git branch --show-current)" = main || {
  echo "check out main before tagging" >&2
  exit 1
}
test -z "$(git status --porcelain)" || {
  echo "the checkout must be clean" >&2
  exit 1
}
git fetch origin +refs/heads/main:refs/remotes/origin/main
sha=$(git rev-parse HEAD)
test "$sha" = "$(git rev-parse origin/main)" || {
  echo "HEAD must equal published origin/main" >&2
  exit 1
}
if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
  echo "tag $tag already exists" >&2
  exit 1
fi

glab api projects/:id/repository/tags --method POST \
  --raw-field "tag_name=$tag" --raw-field "ref=$sha" >/dev/null
echo "Created $tag at $sha"
glab ci run --branch mastah --variables-env "RELEASE_TAG:$tag"
