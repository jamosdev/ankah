"""Prometheus metrics shared by both backends.

Both run two worker processes, so the counters use prometheus_client's
multiprocess mode. A separate exporter process (metrics_server.py) serves
them on a port that is not proxied, so /metrics is never public.
"""
from prometheus_client import Counter, Histogram

REQUESTS = Counter(
    "pi_requests_total", "Pi endpoint requests by backend, client class and status.",
    ["backend", "client", "status"])
SECONDS = Histogram(
    "pi_request_seconds", "Pi computation time by backend and client class.",
    ["backend", "client"],
    buckets=(.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10))
