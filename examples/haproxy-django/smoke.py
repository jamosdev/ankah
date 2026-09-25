"""Build and exercise the complete HTTPS example with two source IPs."""
import os
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMPOSE = ["docker", "compose", "-f", str(HERE / "compose.yml")]


def run(*args):
    subprocess.run([*COMPOSE, *args], cwd=HERE, check=True)


def client(name, phase):
    run("exec", "-T", name, "python", "/smoke.py", phase)


def ready():
    for _ in range(60):
        try:
            client("client_a", "health")
            return
        except subprocess.CalledProcessError:
            time.sleep(1)
    raise RuntimeError("HTTPS stack did not become ready")


def main():
    try:
        run("build")
        run("run", "--rm", "--no-deps", "haproxy", "--check")
        run("up", "-d")
        ready()
        client("client_a", "slow_headers")
        client("client_a", "health")
        host = "docker" if os.environ.get("DOCKER_HOST", "").startswith("tcp://docker:") else "localhost"
        public_request = urllib.request.Request(
            f"https://{host}:8443/health", headers={"Host": "localhost:8443"})
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
        with opener.open(public_request, timeout=8) as reply:
            assert reply.status == 200 and b"Django through Ankah" in reply.read()
        client("client_b", "health")
        time.sleep(11)
        client("client_a", "scan")
        client("client_b", "health")
        time.sleep(62)
        client("client_a", "health")
        client("client_a", "flood")
        client("client_b", "health")
        time.sleep(62)
        client("client_a", "health")
        client("client_a", "stalls")
        client("client_b", "health")
        time.sleep(62)
        client("client_a", "health")
    finally:
        run("down", "--volumes", "--remove-orphans")


if __name__ == "__main__":
    sys.exit(main())
