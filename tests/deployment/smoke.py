#!/usr/bin/env python3
"""Exercise deployment templates without modifying host services."""
import argparse
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import time
import zlib

ROOT = Path(__file__).resolve().parents[2]
PYTHON = "python:3.12-alpine3.20"
GATEWAY = "ankah:deployment-test"
NATIVE = "ankah-deployment-native:test"
BROWSER = "ankah-deployment-browser:test"
NGINX = "nginx:1.31.3-alpine"
HAPROXY = "haproxy:3.2.23-alpine"
APP_COMMAND = ["sh", "-c", "python3 /app.py & echo $! >/tmp/application.pid; wait; sleep infinity"]


def run(*args, check=True):
    with (evidence / "commands.jsonl").open("a") as output:
        output.write(json.dumps(list(map(str, args))) + "\n")
    result = subprocess.run(list(map(str, args)), text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=1200)
    with (evidence / "commands.log").open("a") as output:
        output.write(result.stdout)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {args}\n{result.stdout[-8192:]}")
    return result.stdout.strip()


def ready(port):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return
        except OSError:
            time.sleep(.05)
    raise RuntimeError(f"TCP startup timeout: {port}")


def request(directory, path, expected, headers=None, direct=False, method="GET", body=None):
    if direct:
        connection = http.client.HTTPConnection("127.0.0.1", gateway_port, timeout=10)
    else:
        connection = http.client.HTTPSConnection("127.0.0.1", proxy_port, timeout=10,
                                                 context=ssl._create_unverified_context())
    row = {"path": path, "status": None, "headers": {}, "body": ""}
    try:
        connection.request(method, path, body=body, headers={"Host": HOST, **(headers or {})})
        response = connection.getresponse()
        row.update(status=response.status, headers=dict(response.getheaders()))
        body = response.read()
        row["body"] = body[:1024].decode(errors="replace")
    except Exception as error:
        row["error"] = str(error)
        raise
    finally:
        with (directory / "responses.jsonl").open("a") as output:
            output.write(json.dumps(row) + "\n")
        connection.close()
    assert response.status == expected, row
    return body


def browser(directory, mode, network):
    run("docker", "run", "--rm", "--network", network, "--ip", "172.30.83.20",
        "-v", f"{ROOT / 'tests/deployment/browser.cjs'}:/bench/deployment.cjs:ro",
        "-v", f"{directory}:/evidence", BROWSER, "node", "/bench/deployment.cjs",
        mode, ORIGIN, "/evidence")


def scenario(kind):
    directory = evidence / kind
    directory.mkdir()
    project = "ankah-deploy-" + kind + "-" + str(os.getpid())
    gateway, application, proxy = (project + "-" + role for role in ("gateway", "app", "proxy"))
    client_network = project + "-browser"
    deploy = directory / "deploy"
    shutil.copytree(ROOT / "deploy", deploy,
                    ignore=shutil.ignore_patterns(".env", "credentials", "state", "ankah.conf"))
    # Native configuration has the same basename as the generated Compose file.
    shutil.copy2(ROOT / "deploy/native/ankah.conf", deploy / "native/ankah.conf")
    compose_dir = deploy / "compose"
    config = ((ROOT / "deploy/compose/ankah.conf.example") if kind == "compose" else
              ROOT / "deploy/native/ankah.conf").read_text().replace("https://example.com", ORIGIN)
    if kind == "native":
        config = config.replace("127.0.0.1:8000", f"127.0.0.1:{gateway_port}")
        config = config.replace("127.0.0.1:8001", f"127.0.0.1:{application_port}")
    compose_file = compose_dir / "compose.yml"
    compose_file.write_text(compose_file.read_text().replace(
        "127.0.0.1:8000:8000", f"127.0.0.1:{gateway_port}:8000"))
    config_file = compose_dir / "ankah.conf"
    config_file.write_text(config)
    config_file.chmod(0o644)
    compose = ["docker", "compose", "--project-name", project, "-f", str(compose_dir / "compose.yml"),
               "-f", str(compose_dir / "test.yml")]
    try:
        run("docker", "network", "create", "--subnet", "172.30.83.0/24", "--gateway", "172.30.83.1",
            client_network)
        run("docker", "run", "--rm", "-v", f"{deploy}:/deploy", PYTHON,
            "sh", "/deploy/compose/setup.sh")
        # Running setup twice must not rotate either credential.
        digest = run("docker", "run", "--rm", "-v", f"{compose_dir / 'credentials'}:/credentials:ro",
                     PYTHON, "sh", "-c", "sha256sum /credentials/*")
        run("docker", "run", "--rm", "-v", f"{deploy}:/deploy", PYTHON,
            "sh", "/deploy/compose/setup.sh")
        assert digest == run("docker", "run", "--rm", "-v",
                             f"{compose_dir / 'credentials'}:/credentials:ro", PYTHON,
                             "sh", "-c", "sha256sum /credentials/*")
        if kind == "native":
            run("docker", "run", "--rm", "--user", "root", "--entrypoint", "sh",
                "-v", f"{compose_dir / 'credentials'}:/credentials",
                "-v", f"{compose_dir / 'state'}:/state", NATIVE, "-c",
                "chown root:ankah /credentials /credentials/*; chown ankah:ankah /state")
        token = run("docker", "run", "--rm", "-v", f"{compose_dir / 'credentials'}:/credentials:ro",
                    PYTHON, "cat", "/credentials/dashboard.token")
        # Remove the credential read from the general command-output log.
        log = evidence / "commands.log"
        log.write_text(log.read_text().replace(token, "[dashboard credential]"))
        if kind == "compose":
            (compose_dir / ".env").write_text(f"APP_IMAGE={PYTHON}\nANKAH_IMAGE={GATEWAY}\n")
            (compose_dir / "test.yml").write_text(json.dumps({"services": {
                "ankah": {"container_name": gateway},
                "application": {"container_name": application,
                                "command": APP_COMMAND, "volumes": [
                                    f"{ROOT / 'tests/deployment/app.py'}:/app.py:ro"]}}}))
            run(*compose, "config", "--quiet")
            run(*compose, "up", "-d", "--no-build")
        else:
            run("docker", "run", "-d", "--name", application, "--network", "host",
                "-e", "APP_BIND=127.0.0.1", "-v",
                f"{ROOT / 'tests/deployment/app.py'}:/app.py:ro", "-e", f"APP_PORT={application_port}",
                PYTHON, *APP_COMMAND)

        def native_start(version="current"):
            run("docker", "run", "-d", "--name", gateway, "--network", "host",
                "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges",
                "--stop-timeout", "120", "--entrypoint", f"/opt/ankah/{version}/ankah",
                "-v", f"{config_file}:/etc/ankah/ankah.conf:ro",
                "-v", f"{compose_dir / 'credentials'}:/etc/ankah/credentials:ro",
                "-v", f"{compose_dir / 'state'}:/var/lib/ankah", NATIVE,
                "--config", "/etc/ankah/ankah.conf")

        if kind == "native":
            native_start()
        ready(gateway_port)
        request(directory, "/ankah/livez", 200, direct=True)
        request(directory, "/ankah/livez", 421, {"Host": "incorrect.test"}, direct=True)
        # Self-signed local TLS terminates at the proxy, as with the existing site.
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=deployment.test", "-keyout", directory / "key.pem",
            "-out", directory / "cert.pem")
        if kind == "native":
            proxy_config = directory / "nginx.conf"
            proxy_config.write_text(f"events {{}}\nhttp {{ server {{ listen 127.0.0.1:{proxy_port} ssl;\n"
                f"listen 172.30.83.1:{proxy_port} ssl;\n"
                "ssl_certificate /cert.pem; ssl_certificate_key /key.pem;\n" +
                (ROOT / "deploy/proxy/nginx.conf").read_text().replace(
                    "127.0.0.1:8000", f"127.0.0.1:{gateway_port}") + "\n} }\n")
            proxy_config.chmod(0o644)
            proxy_args = ["-v", f"{proxy_config}:/etc/nginx/nginx.conf:ro",
                          "-v", f"{directory / 'key.pem'}:/key.pem:ro",
                          "-v", f"{directory / 'cert.pem'}:/cert.pem:ro", NGINX]
            run("docker", "run", "--rm", "--network", "host", *proxy_args, "nginx", "-t")
        else:
            pem = directory / "combined.pem"
            pem.write_text((directory / "cert.pem").read_text() + (directory / "key.pem").read_text())
            pem.chmod(0o644)
            proxy_config = directory / "haproxy.cfg"
            proxy_config.write_text("global\n    maxconn 100\ndefaults\n    mode http\n"
                "    timeout connect 5s\n    timeout client 120s\n    timeout server 120s\n"
                f"frontend https\n    bind 127.0.0.1:{proxy_port} ssl crt /combined.pem\n"
                f"    bind 172.30.83.1:{proxy_port} ssl crt /combined.pem\n"
                "    default_backend ankah\n" + (ROOT / "deploy/proxy/haproxy.cfg").read_text().replace(
                    "127.0.0.1:8000", f"127.0.0.1:{gateway_port}"))
            proxy_config.chmod(0o644)
            proxy_args = ["-v", f"{proxy_config}:/usr/local/etc/haproxy/haproxy.cfg:ro",
                          "-v", f"{pem}:/combined.pem:ro", HAPROXY]
            run("docker", "run", "--rm", "--network", "host", *proxy_args,
                "haproxy", "-c", "-f", "/usr/local/etc/haproxy/haproxy.cfg")
        run("docker", "run", "-d", "--name", proxy, "--network", "host", *proxy_args)
        ready(proxy_port)
        browser(directory, "fresh", client_network)
        cookies = json.loads((directory / "browser-state.json").read_text())["cookies"]
        authorized = {"Cookie": "; ".join(c["name"] + "=" + c["value"] for c in cookies)}
        body = request(directory, "/headers", 200, {**authorized, "Forwarded": "for=198.51.100.77",
            "X-Forwarded-For": "198.51.100.78", "X-Real-IP": "198.51.100.79",
            "X-Forwarded-Proto": "spoofed", "X-Forwarded-Host": "spoofed",
            "X-Forwarded-Extra": "spoofed"})
        headers = {k.lower(): v for k, v in json.loads(body)["headers"].items()}
        assert headers["x-forwarded-for"] == "127.0.0.1", headers
        assert headers["x-forwarded-proto"] == "https", headers
        assert headers["x-forwarded-host"] == HOST, headers
        assert not any(k in headers for k in ("forwarded", "x-real-ip", "x-forwarded-extra")), headers
        admin = {"Authorization": "Bearer " + token}
        request(directory, "/ankah-admin/stats/live", 401)
        before = json.loads(request(directory, "/ankah-admin/stats/live", 200, admin))
        schema = json.loads(request(directory, "/ankah-admin/stats/schema", 200, admin))
        solved_index = schema["fields"].index("challenges_solved")
        (directory / "stats-before.json").write_text(json.dumps(before))
        def chunk(kind, content):
            return (struct.pack(">I", len(content)) + kind + content +
                    struct.pack(">I", zlib.crc32(kind + content)))
        mascot = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)) +
                  chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00\xff")) + chunk(b"IEND", b""))
        request(directory, "/ankah-admin/settings/mascot", 204,
                {**admin, "Content-Type": "image/png"}, method="PUT", body=mascot)
        # Application outage does not change liveness. One failing application request only.
        # Keep its network namespace present so failure is a refused connection,
        # rather than waiting for an unreachable container address to time out.
        run("docker", "exec", application, "sh", "-c", "kill $(cat /tmp/application.pid)")
        request(directory, "/ankah/livez", 200)
        request(directory, "/unavailable", 502, authorized)
        run("docker", "exec", "-d", application, "python3", "/app.py")
        run("docker", "exec", application, "python3", "-c",
            "import socket,time\nfor i in range(200):\n try:\n  socket.create_connection(('127.0.0.1', " +
            str(application_port if kind == "native" else 8001) + "), .1).close(); break\n"
            " except OSError: time.sleep(.02)\nelse: raise RuntimeError('application did not listen')")
        # Establish an in-flight request before stopping; no rate retries are used.
        with concurrent.futures.ThreadPoolExecutor() as executor:
            slow = executor.submit(request, directory, "/slow", 200, authorized)
            deadline = time.monotonic() + 5
            while run("docker", "exec", application, "sh", "-c",
                      "if test -e /tmp/slow-started; then echo yes; else echo no; fi") != "yes":
                assert time.monotonic() < deadline, "application did not receive slow request"
                time.sleep(.05)
            run("docker", "stop", "--time", "120", gateway)
            slow.result()
        assert run("docker", "inspect", "-f", "{{.State.ExitCode}}", gateway) == "0"
        files = run("docker", "run", "--rm", "-v", f"{compose_dir / 'state'}:/state:ro",
                    PYTHON, "ls", "-la", "/state")
        (directory / "persistent-files.txt").write_text(files)
        # A consumption journal is created only when a saved POST is consumed.
        assert all(name in files for name in ("ankah.sessions.", "ankah.stats.",
                                              "ankah.mascot.png")), files
        # Recreate, then select another retained installation and roll back. The
        # two versions intentionally contain the same build: this checks selection
        # and retained state, not cross-release format compatibility.
        for index, version in enumerate(("current", "test-next", "test-first")):
            (directory / f"gateway-{index}.log").write_text(run("docker", "logs", gateway))
            if kind == "compose":
                tag = GATEWAY + ("-next" if index == 1 else "")
                run("docker", "tag", GATEWAY, tag)
                (compose_dir / ".env").write_text(f"APP_IMAGE={PYTHON}\nANKAH_IMAGE={tag}\n")
                run(*compose, "up", "-d", "--no-deps", "--no-build", "--force-recreate", "ankah")
            else:
                run("docker", "rm", gateway)
                native_start(version)
            ready(gateway_port)
            browser(directory, "restored-" + str(index), client_network)
            after = json.loads(request(directory, "/ankah-admin/stats/live", 200, admin))
            assert request(directory, "/ankah-admin/settings/mascot", 200, admin).startswith(b"\x89PNG")
            assert after["epoch"] == before["epoch"], (before, after)
            # Compare cumulative counters, not just a coincidentally equal epoch.
            assert after["cumulative"][0] >= before["cumulative"][0] > 0, (before, after)
            assert after["cumulative"][solved_index] == before["cumulative"][solved_index] > 0
            assert digest == run("docker", "run", "--rm", "-v",
                f"{compose_dir / 'credentials'}:/credentials:ro", PYTHON,
                "sh", "-c", "sha256sum /credentials/*")
            run("docker", "stop", "--time", "120", gateway)
        # Restore the original proxy route while the gateway is stopped.
        protected_config = proxy_config.read_text()
        old_backend = ("172.30.82.10:8001" if kind == "compose" else f"127.0.0.1:{application_port}")
        proxy_config.write_text(protected_config.replace(f"127.0.0.1:{gateway_port}", old_backend))
        run("docker", "restart", proxy)
        ready(proxy_port)
        assert json.loads(request(directory, "/routing-rollback", 200))["application"]
        proxy_config.write_text(protected_config)
        run("docker", "start", gateway)
        ready(gateway_port)
        run("docker", "restart", proxy)
        ready(proxy_port)
        request(directory, "/restored-route", 200, authorized)
        print(f"{kind}: deployment acceptance passed", flush=True)
    finally:
        for name in (gateway, application, proxy):
            (directory / (name + ".log")).write_text(run("docker", "logs", name, check=False))
            run("docker", "rm", "-f", name, check=False)
        if kind == "compose":
            run(*compose, "down", "--remove-orphans", check=False)
        run("docker", "network", "rm", client_network, check=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--skip-build", action="store_true", help="Use previously built acceptance images")
    parser.add_argument("--kind", choices=("compose", "native", "both"), default="both")
    args = parser.parse_args()
    evidence = args.artifacts.resolve()
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.umask(0o077)
    # Allocate isolated host ports; retain the template's container port 8000.
    probes = [socket.socket() for _ in range(3)]
    for probe in probes:
        probe.bind(("127.0.0.1", 0))
    gateway_port, application_port, proxy_port = [probe.getsockname()[1] for probe in probes]
    for probe in probes:
        probe.close()
    HOST = f"deployment.test:{proxy_port}"
    ORIGIN = "https://" + HOST
    metadata = {"commit": run("git", "-C", ROOT, "rev-parse", "HEAD"),
                "configuration": "Release", "systemd_lifecycle": "pending",
                "ports": {"gateway": gateway_port, "application": application_port, "proxy": proxy_port}}
    if not args.skip_build:
        for dockerfile, tag in (("deploy/Dockerfile", GATEWAY),
                                ("tests/deployment/Dockerfile.native", NATIVE)):
            run("docker", "build", "-f", ROOT / dockerfile, "-t", tag, ROOT)
        run("docker", "build", "-f", ROOT / "examples/visitor-availability/Dockerfile.clients",
            "-t", BROWSER, ROOT / "examples/visitor-availability")
    gateway_images = ((GATEWAY,) if args.kind == "compose" else
                      (NATIVE,) if args.kind == "native" else (GATEWAY, NATIVE))
    for image in (*gateway_images, BROWSER, PYTHON, NGINX, HAPROXY):
        if not run("docker", "image", "inspect", "--format", "{{.Id}}", image,
                   check=False).startswith("sha256:"):
            run("docker", "pull", image)
        run("docker", "image", "inspect", image)
    for image in gateway_images:
        metadata[image] = run("docker", "run", "--rm", "--entrypoint", "sha256sum",
                              image, "/opt/ankah/ankah" if image == GATEWAY else "/opt/ankah/current/ankah")
    (evidence / "metadata.json").write_text(json.dumps(metadata, indent=2))
    for kind in (("compose", "native") if args.kind == "both" else (args.kind,)):
        scenario(kind)
