"""Compose topology shared by all visitor-availability scenarios."""
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEMO = ROOT / "examples/dots-benchmark"


def topology(arm):
    backend = {"backend": {"ipv4_address": "172.30.1.31"}}
    gateway = {"backend": {"ipv4_address": "172.30.1.21"}}
    if arm == "direct":
        backend["front"] = {"ipv4_address": "172.30.0.11"}
    elif arm == "ankah":
        gateway["front"] = {"ipv4_address": "172.30.0.11"}
    services = {
        "app": {
            "image": "ankah-availability-app:local",
            "build": {"context": str(DEMO), "dockerfile": "django/Dockerfile"},
            "cpus": "1.0", "mem_limit": "256m", "networks": backend,
            "command": ["gunicorn", "app:application", "--bind", "0.0.0.0:80",
                        "--workers", "2", "--worker-class", "sync", "--access-logfile", "-",
                        "--access-logformat",
                        'BENCH {"id":"%({x-availability-id}i)s","status":%(s)s,"seconds":%(L)s}'],
            "healthcheck": {"test": ["CMD", "python", "-c",
                "import urllib.request; urllib.request.urlopen('http://localhost/healthz',timeout=2)"],
                "interval": "1s", "timeout": "3s", "retries": 60},
        },
    }
    for role, ip in (("visitors", "21"), ("attacker", "20")):
        services[role] = {
            "image": "ankah-availability-clients:local",
            "build": {"context": str(HERE), "dockerfile": "Dockerfile.clients"},
            "init": True, "command": ["sleep", "infinity"],
            "cpus": "2.0", "mem_limit": "2g", "shm_size": "1g",
            "extra_hosts": ["ankah.test:172.30.0.11"],
            "networks": {"front": {"ipv4_address": "172.30.0." + ip}},
        }
    if arm != "direct":
        services["certs"] = {"image": "ankah-availability-certs:local",
            "build": {"context": str(DEMO / "certs")}, "network_mode": "none",
            "volumes": ["credentials:/out"], "restart": "no"}
        command = ["--listen", "0.0.0.0:80", "--upstream", "172.30.1.31:80",
                   "--public-origin", "http://ankah.test", "--assets-dir", "/assets",
                   "--secret-file", "/run/demo-certs/ankah-secret",
                   "--stats-file", "/tmp/availability.stats",
                   "--session-state-file", "/tmp/availability.sessions",
                   "--dashboard-listen", "0.0.0.0:9101",
                   "--dashboard-token-file", "/run/demo-certs/ankah-dashboard-token"]
        services["ankah"] = {
            "image": "ankah-availability-gateway:local",
            "build": {"context": str(ROOT), "dockerfile": "examples/visitor-availability/Dockerfile.ankah"},
            "entrypoint": ["/usr/local/bin/ankah"], "command": command,
            "working_dir": "/tmp", "cpus": "1.0", "mem_limit": "256m",
            "volumes": ["credentials:/run/demo-certs:ro"], "networks": gateway,
            "depends_on": {"certs": {"condition": "service_completed_successfully"},
                           "app": {"condition": "service_healthy"}},
            "healthcheck": {"test": ["CMD", "nc", "-z", "-w", "1", "127.0.0.1", "80"],
                            "interval": "1s", "timeout": "2s", "retries": 20},
        }
    if arm == "dots":
        services["mysql"] = {"image": "ankah-availability-mysql:local",
            "build": {"context": str(DEMO / "mysql")},
            "environment": {"MYSQL_RANDOM_ROOT_PASSWORD": "yes", "MYSQL_DATABASE": "dots",
                            "MYSQL_USER": "dots", "MYSQL_PASSWORD": "dots-demo-only"},
            "tmpfs": ["/var/lib/mysql"], "cpus": "1.0", "mem_limit": "512m",
            "command": ["--innodb-buffer-pool-size=64M"],
            "networks": {"backend": {"ipv4_address": "172.30.1.40"}},
            "healthcheck": {"test": ["CMD-SHELL", "mysql -udots -pdots-demo-only -h127.0.0.1 -e 'SELECT id FROM dots.blocker' >/dev/null 2>&1"],
                            "interval": "2s", "timeout": "3s", "retries": 90}}
        services["edge"] = {"image": "ankah-availability-edge:local",
            "build": {"context": str(DEMO / "edge")}, "cap_add": ["NET_ADMIN"],
            "cpus": "2.0", "mem_limit": "256m",
            "command": ["--ankah-upstream", "http://ankah:80"],
            "volumes": ["credentials:/run/demo-certs:ro"],
            "networks": {"front": {"ipv4_address": "172.30.0.10"},
                         "backend": {"ipv4_address": "172.30.1.10"}},
            "depends_on": {"mysql": {"condition": "service_healthy"},
                           "certs": {"condition": "service_completed_successfully"}},
            "healthcheck": {"test": ["CMD", "curl", "-fsS", "http://172.30.1.10:9100/readyz"],
                            "interval": "1s", "timeout": "3s", "retries": 90}}
        services["ankah"]["depends_on"]["edge"] = {"condition": "service_healthy"}
        services["ankah"]["command"] += [
            "--trusted-proxy", "172.30.1.10/32", "--dots-server", "172.30.1.10:4443",
            "--dots-server-name", "edge-dots.demo.test", "--dots-ca-file", "/run/demo-certs/ca.crt",
            "--dots-cert-file", "/run/demo-certs/ankah-dots-client.crt",
            "--dots-key-file", "/run/demo-certs/ankah-dots-client.key", "--dots-cuid", "ankah-demo",
            "--dots-protected-network", "172.30.0.11/32", "--dots-protected-port", "80"]
    return {"services": services, "networks": {
        "front": {"internal": True, "ipam": {"config": [{"subnet": "172.30.0.0/24", "ip_range": "172.30.0.128/25"}]}},
        "backend": {"internal": True, "ipam": {"config": [{"subnet": "172.30.1.0/24", "ip_range": "172.30.1.128/25"}]}},
    }, "volumes": {"credentials": {}}}
