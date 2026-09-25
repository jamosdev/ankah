import os
import threading
import time

import pytest

from clients import client_for


class RequestPacer:
    def __init__(self, interval=0.075):
        self.interval = interval
        self.next_at = 0.0
        self.lock = threading.Lock()

    def wait(self, count=1):
        with self.lock:
            now = time.monotonic()
            ready_at = max(now, self.next_at) + (count - 1) * self.interval
            self.next_at = ready_at + self.interval
        if ready_at > now:
            time.sleep(ready_at - now)


class MatrixClient:
    def __init__(self, client, pacer):
        self.client = client
        self.pacer = pacer

    def close(self):
        self.client.close()

    def request(self, method, path, headers=None, content=None):
        self.pacer.wait()
        return self.client.request(method, path, headers, content)

    def concurrent(self, requests):
        self.pacer.wait(len(requests))
        return self.client.concurrent(requests)


def pytest_addoption(parser):
    group = parser.getgroup("protocol-matrix")
    group.addoption("--profile", choices=("edge", "native", "all"), default="all")
    group.addoption("--protocol", choices=("h1", "h2", "h3", "all"), default="all")
    group.addoption("--edge-url", default=os.environ.get("ANKAH_EDGE_URL"))
    group.addoption("--native-url", default=os.environ.get("ANKAH_NATIVE_URL"))
    group.addoption("--ca-file", default=os.environ.get("ANKAH_CA_FILE"))


def pytest_generate_tests(metafunc):
    if "endpoint_protocol" not in metafunc.fixturenames:
        return
    profile = metafunc.config.getoption("profile")
    protocol = metafunc.config.getoption("protocol")
    profiles = ("edge", "native") if profile == "all" else (profile,)
    protocols = ("h1", "h2", "h3") if protocol == "all" else (protocol,)
    values = [(item_profile, item_protocol)
              for item_profile in profiles for item_protocol in protocols]
    metafunc.parametrize("endpoint_protocol", values,
                         ids=[f"{left}-{right}" for left, right in values],
                         scope="session")


@pytest.fixture(scope="session")
def matrix_config(pytestconfig):
    ca_file = pytestconfig.getoption("ca_file")
    if not ca_file:
        pytest.fail("--ca-file is required")
    values = {
        "edge": pytestconfig.getoption("edge_url"),
        "native": pytestconfig.getoption("native_url"),
        "ca_file": ca_file,
    }
    profile = pytestconfig.getoption("profile")
    for name in ("edge", "native"):
        if profile in (name, "all") and not values[name]:
            pytest.fail(f"--{name}-url is required for profile {profile}")
    return values


@pytest.fixture
def endpoint(endpoint_protocol, matrix_config):
    profile, protocol = endpoint_protocol
    return {
        "profile": profile,
        "protocol": protocol,
        "url": matrix_config[profile],
        "ca_file": matrix_config["ca_file"],
    }


@pytest.fixture
def client(endpoint, request_pacer):
    value = MatrixClient(client_for(endpoint["url"], endpoint["protocol"],
                                    endpoint["ca_file"]), request_pacer)
    try:
        yield value
    finally:
        value.close()


@pytest.fixture(scope="session")
def request_pacer():
    # All matrix clients share the native proxy's anonymous per-IP rate bucket.
    return RequestPacer()
