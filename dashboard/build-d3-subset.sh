#!/bin/sh
# Rebuild d3-subset.min.js from pinned D3 modules. Needs Node and npm.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
npm init -y >/dev/null
npm install --no-audit --no-fund --save-exact esbuild@0.28.2 \
  d3-array@3.2.4 d3-axis@3.0.0 d3-color@3.1.0 d3-format@3.1.2 \
  d3-interpolate@3.0.1 d3-path@3.1.0 d3-scale@4.0.2 d3-selection@3.0.0 \
  d3-shape@3.2.0 d3-time@3.1.0 d3-time-format@4.1.0 internmap@2.0.3 >/dev/null
cat > entry.js <<'ENTRY'
export { bisector, extent, max } from "d3-array";
export { axisBottom, axisLeft } from "d3-axis";
export { format } from "d3-format";
export { scaleBand, scaleLinear, scaleTime } from "d3-scale";
export { pointer, select } from "d3-selection";
export { area, curveMonotoneX, line } from "d3-shape";
export { timeFormat, utcFormat } from "d3-time-format";
ENTRY
./node_modules/.bin/esbuild entry.js --bundle --minify --format=iife \
  --global-name=d3 --legal-comments=none --outfile="$here/d3-subset.min.js"
for module in d3-array d3-axis d3-color d3-format d3-interpolate d3-path \
    d3-scale d3-selection d3-shape d3-time d3-time-format internmap; do
  printf '%s %s\n' "$module" "$(node -p "require('./node_modules/$module/package.json').version")"
done
