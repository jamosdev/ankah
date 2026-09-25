#!/bin/sh
# Edge container entrypoint.
#
# Docker Compose gives a container one address per network, but the demo
# needs two frontend destination addresses on the same network so that a
# DOTS ACL can be scoped to one of them. This script is the only user of
# CAP_NET_ADMIN: it adds the secondary address, then drops every capability
# and privilege before starting the proxy. Filtering is done in the edge
# process, never with NET_ADMIN.
set -eu
PRIMARY=${EDGE_PRIMARY_VIP:-172.30.0.10}
SECONDARY=${EDGE_SECONDARY_VIP:-172.30.0.11}
PREFIX_LEN=${EDGE_FRONT_PREFIX_LEN:-24}

dev=$(ip -o -4 addr show | awk -v ip="$PRIMARY" '{split($4, a, "/"); if (a[1] == ip) print $2}' | head -n 1)
if [ -z "$dev" ]; then
    echo "no interface owns $PRIMARY" >&2
    exit 1
fi
if ! ip -o -4 addr show dev "$dev" | grep -q " $SECONDARY/"; then
    ip addr add "$SECONDARY/$PREFIX_LEN" dev "$dev"
    echo "added secondary frontend address $SECONDARY on $dev"
fi

exec setpriv --reuid=65534 --regid=65534 --clear-groups \
    --inh-caps=-all --bounding-set=-all --no-new-privs \
    /usr/local/bin/edge "$@"
