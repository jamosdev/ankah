"""Serves the multiprocess Prometheus registry on METRICS_PORT."""
import os

from prometheus_client import CollectorRegistry, start_http_server
from prometheus_client import multiprocess

registry = CollectorRegistry()
multiprocess.MultiProcessCollector(registry)
_, thread = start_http_server(int(os.environ.get("METRICS_PORT", "9102")), registry=registry)
thread.join()
