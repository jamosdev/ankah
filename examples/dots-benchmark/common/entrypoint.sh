#!/bin/sh
# Start the metrics exporter next to the application server. The multiprocess
# directory must be empty at start so stale worker files are not counted.
set -eu
: "${PROMETHEUS_MULTIPROC_DIR:=/tmp/prometheus-multiproc}"
export PROMETHEUS_MULTIPROC_DIR
rm -rf "$PROMETHEUS_MULTIPROC_DIR"
mkdir -p "$PROMETHEUS_MULTIPROC_DIR"
python /app/common/metrics_server.py &
exec "$@"
