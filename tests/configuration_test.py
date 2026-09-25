"""Exercise file, environment, and command-line configuration layers."""

import http.client
import http.server
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

from process_support import gateway_command


CONFIGURATION_VARIABLES = {
    "ANKAH_LISTEN", "ANKAH_UPSTREAM", "ANKAH_PUBLIC_ORIGIN",
    "ANKAH_SECRET_FILE", "ANKAH_ASSETS_DIR", "ANKAH_STATIC_BUNDLE",
    "ANKAH_STATIC_CACHE_MB", "ANKAH_MAX_UPLOAD_MB",
    "ANKAH_STATIC_THROTTLE_PREFIX", "ANKAH_STATIC_THROTTLE_GLOBAL_CONNECTIONS",
    "ANKAH_STATIC_THROTTLE_CLIENT_CONNECTIONS",
    "ANKAH_STATIC_THROTTLE_GLOBAL_MBPS", "ANKAH_STATIC_THROTTLE_CLIENT_MBPS",
    "ANKAH_HEALTHZ", "ANKAH_LIVEZ", "ANKAH_READYZ", "ANKAH_TLS_CERT",
    "ANKAH_TLS_KEY", "ANKAH_TRUSTED_PROXY", "ANKAH_PROXY_ABUSE_PROFILE",
    "ANKAH_DASHBOARD_LISTEN", "ANKAH_DASHBOARD_PUBLIC_ROUTE",
    "ANKAH_DASHBOARD_TOKEN_FILE", "ANKAH_STATS_FILE", "ANKAH_NO_STATS_FILE",
    "ANKAH_LOG_UNKNOWN_LANGUAGES", "ANKAH_ALLOW_PREFIX",
}


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def environment(**values):
    result = os.environ.copy()
    for name in CONFIGURATION_VARIABLES:
        result.pop(name, None)
    result.update(values)
    return result


def request(port, path):
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    client.request("GET", path, headers={"Host": f"localhost:{port}"})
    reply = client.getresponse()
    result = reply.status, reply.read()
    client.close()
    return result


def wait_for(process, port):
    for _ in range(250):
        if process.poll() is not None:
            raise RuntimeError("gateway exited: " + process.stderr.read().decode())
        try:
            request(port, "/health")
            return
        except OSError:
            time.sleep(.02)
    raise RuntimeError("gateway did not listen")


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def main():
    executable, assets = sys.argv[1:]
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        config_dir = root / "configuration"
        work_dir = root / "working"
        log_dir = config_dir / "logs"
        config_dir.mkdir()
        work_dir.mkdir()
        log_dir.mkdir()
        (config_dir / "secret").write_text("a" * 64)
        (config_dir / "dashboard-token").write_text("b" * 64)

        upstream_port = free_port()
        public_port = free_port()

        class App(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = ("upstream " + self.path + "\n").encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", upstream_port), App)
        threading.Thread(target=server.serve_forever, daemon=True).start()

        assets_relative = os.path.relpath(Path(assets).absolute(), config_dir)
        config_path = config_dir / "ankah.conf"
        config_path.write_bytes((
            "  # values may be spaced and use CRLF\r\n"
            f"listen = 127.0.0.1:{public_port}\r\n"
            f"upstream=127.0.0.1:{upstream_port}\r\n"
            "public-origin=http://config.test\r\n"
            "secret-file=folder/../secret\r\n"
            f"assets-dir={assets_relative}\r\n"
            "allow-prefix=/from-config\r\n"
            "dashboard-public-route=/from-config-dashboard/\r\n"
            "dashboard-token-file=dashboard-token\r\n"
            "ankah-healthz=/from-config-health\r\n"
            "no-stats-file=false\r\n"
            "proxy-abuse-profile=off\r\n"
            "log-unknown-languages=logs/languages=unknown.log\r\n"
        ).encode())

        process = subprocess.Popen(
            gateway_command(executable, [
                "--config", str(config_path),
                "--public-origin", f"http://localhost:{public_port}",
                "--allow-prefix", "/from-command",
                "--dashboard-public-route=/from-command-dashboard/",
                "--ankah-healthz=/health",
                "--proxy-abuse-profile=conservative",
            ]),
            cwd=work_dir,
            env=environment(ANKAH_PUBLIC_ORIGIN="http://environment.test",
                            ANKAH_ALLOW_PREFIX="/from-environment",
                            ANKAH_DASHBOARD_PUBLIC_ROUTE="/from-environment-dashboard/",
                            ANKAH_HEALTHZ="/from-environment-health",
                            ANKAH_NO_STATS_FILE="0",
                            ANKAH_PROXY_ABUSE_PROFILE="strict"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            wait_for(process, public_port)
            check(request(public_port, "/health") == (200, b"ok\n"),
                  "command-line health option did not override lower layers")
            check(request(public_port, "/from-command-dashboard/stats/live")[0] == 401,
                  "command-line public dashboard route did not override lower layers")
            for path in ("/from-config", "/from-environment", "/from-command"):
                check(request(public_port, path) ==
                      (200, ("upstream " + path + "\n").encode()),
                      "repeatable option was not accumulated: " + path)
            for path in ("/from-config-health", "/from-environment-health"):
                check(request(public_port, path)[1] != b"ok\n",
                      "a lower-layer scalar option was not replaced: " + path)
            check((log_dir / "languages=unknown.log").exists(),
                  "relative output path was not based on the config directory")
        finally:
            stop(process)
            server.shutdown()

        invalid_files = {
            "missing-equals.conf": "listen 127.0.0.1:1\n",
            "unknown.conf": "not-an-option=value\n",
            "boolean.conf": "no-stats-file=yes\n",
            "abuse-profile.conf": "proxy-abuse-profile=fast\n",
            "duplicate-health.conf": "ankah-healthz=/one\nankah-healthz=/two\n",
            "stats-conflict.conf": "stats-file=stats\nno-stats-file=true\n",
            "long.conf": "#" + "x" * 4097 + "\n",
        }
        for name, contents in invalid_files.items():
            path = config_dir / name
            path.write_text(contents)
            result = subprocess.run(
                gateway_command(executable, ["--config", str(path)]),
                cwd=work_dir, env=environment(), stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, timeout=30)
            check(result.returncode == 2, "invalid config was accepted: " + name)
            check(str(name).encode() in result.stderr,
                  "config diagnostic did not identify the file: " + name)

        result = subprocess.run(
            gateway_command(executable, ["--config", str(config_path),
                                         "--config", str(config_path)]),
            cwd=work_dir, env=environment(), stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=30)
        check(result.returncode == 2, "duplicate --config was accepted")

        missing = config_dir / "missing.conf"
        result = subprocess.run(
            gateway_command(executable, ["--config", str(missing)]),
            cwd=work_dir, env=environment(), stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, timeout=30)
        check(result.returncode == 2 and b"could not read configuration" in result.stderr,
              "missing config did not produce a useful error")

        result = subprocess.run(
            gateway_command(executable, ["--config", str(config_path)]),
            cwd=work_dir, env=environment(ANKAH_NO_STATS_FILE="yes"),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        check(result.returncode == 2 and b"ANKAH_NO_STATS_FILE" in result.stderr,
              "invalid environment value did not identify its variable")


if __name__ == "__main__":
    main()
