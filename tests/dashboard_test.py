"""Exercise the operator dashboard listener and its statistics endpoints."""

import hashlib
import hmac
import http.client
import http.server
import csv
import io
import json
import os
import struct
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

from process_support import gateway_command, start_gateway


TOKEN = "b" * 64


def dashboard_code(step, token=TOKEN):
    secret = hmac.new(bytes.fromhex(token), b"ankah dashboard totp v1",
                      hashlib.sha256).digest()[:20]
    digest = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000:06d}"


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(port, path, method="GET", headers=None, body=None):
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    client.request(method, path, body=body,
                   headers={"Host": f"localhost:{port}", **(headers or {})})
    reply = client.getresponse()
    result = reply.status, dict(reply.getheaders()), reply.read()
    client.close()
    return result


def main():
    executable, root = sys.argv[1:]
    executable = str(pathlib.Path(executable).resolve())
    root = str(pathlib.Path(root).resolve())
    public, dashboard, app = free_port(), free_port(), free_port()
    authorized = {"Authorization": "Bearer " + TOKEN}

    class App(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/app/delay":
                time.sleep(.05)
            payload = self.path.encode()
            self.send_response(404 if self.path.endswith("/missing") else 200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", app), App)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def stats(path):
        status, headers, body = request(dashboard, path, headers=authorized)
        check(status == 200, f"{path} returned {status}")
        check(headers["Content-Type"] == "application/json", f"{path} content type")
        check(headers["Cache-Control"] == "no-store", f"{path} cache control")
        return json.loads(body)

    with tempfile.TemporaryDirectory() as temp:
        secret = pathlib.Path(temp) / "secret"
        secret.write_text("a" * 64)
        token = pathlib.Path(temp) / "token"
        token.write_text(TOKEN + "\n")
        stats_file = pathlib.Path(temp) / "statistics"
        mascot_file = pathlib.Path(temp) / "mascot.png"
        pathlib.Path(str(stats_file) + ".0").write_bytes(b"corrupt")
        public_route = "/ankah-admin/"
        base = ["--listen", f"127.0.0.1:{public}", "--upstream", f"127.0.0.1:{app}",
                "--public-origin", f"http://localhost:{public}",
                "--secret-file", str(secret), "--assets-dir", root,
                "--mascot-file", str(mascot_file),
                "--allow-prefix", "/app", "--allow-prefix", "/ankah-admin"]
        listen = ["--dashboard-listen", f"127.0.0.1:{dashboard}"]
        public_route_option = ["--dashboard-public-route=" + public_route]

        for extra, reason in ((["--dashboard-public-route", "/", "--dashboard-token-file",
                                str(token)], "root public dashboard route"),
                              (["--dashboard-public-route", "/without-slash",
                                "--dashboard-token-file", str(token)],
                               "unterminated public dashboard route"),
                              (["--dashboard-public-route", "/health/",
                                "--dashboard-token-file", str(token),
                                "--ankah-healthz=/health/check"],
                               "public dashboard health route conflict"),
                              (listen + ["--dashboard-token-file", str(secret)],
                               "token equal to the secret"),
                              (["--no-dashboard", "--dashboard-listen",
                                f"127.0.0.1:{dashboard}"], "disabled dashboard with listener"),
                              (["--no-dashboard", "--dashboard-token-file", str(token)],
                               "disabled dashboard with token"),
                              (["--no-dashboard", "--stats-file", str(stats_file)],
                               "disabled dashboard with statistics"),
                              (["--mascot-file", str(pathlib.Path(root) / "ankah.png")],
                               "mascot override replacing the bundled asset"),
                              (listen + ["--dashboard-token-file", str(token),
                                         "--stats-file", str(stats_file), "--no-stats-file"],
                               "conflicting statistics options")):
            result = subprocess.run(gateway_command(executable, base + extra),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=30)
            check(result.returncode == 2, f"started with {reason}")

        generated = pathlib.Path(temp) / "ankah.dashboard.token"
        default_args = base + ["--no-stats-file"]
        for first in (True, False):
            default_process = start_gateway(
                executable, default_args, cwd=temp,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                for _ in range(250):
                    if default_process.poll() is not None:
                        raise RuntimeError("default dashboard exited: " +
                                           default_process.stderr.read().decode())
                    try:
                        if request(public, public_route + "stats/live")[0] == 401:
                            break
                    except OSError:
                        pass
                    time.sleep(.02)
                else:
                    raise RuntimeError("default public dashboard did not start")
                ephemeral = not generated.exists()
                if ephemeral:
                    check(os.environ.get("ANKAH_TEST_WINDOWS_PATHS") == "1",
                          "native token file was created")
                    line = default_process.stderr.readline().decode()
                    match = re.search(r"temporary token for this run: ([0-9a-f]{64})", line)
                    check(match is not None, "unsupported ACL uses temporary token")
                    value = match.group(1)
                else:
                    value = generated.read_text().strip()
                check(re.fullmatch(r"[0-9a-f]{64}", value) is not None,
                      "generated token format")
                if first:
                    initial_token = value
                    if ephemeral:
                        pass  # No secret may be persisted with an unverifiable ACL.
                    elif os.name == "nt" or os.environ.get("ANKAH_TEST_WINDOWS_PATHS") == "1":
                        from process_support import windows_path
                        checker = str(pathlib.Path(executable).with_name("ankah-private-file.exe"))
                        path = windows_path(generated) if os.name != "nt" else str(generated)
                        subprocess.run(gateway_command(checker, [path]), check=True)
                    else:
                        check(generated.stat().st_mode & 0o077 == 0,
                              "generated token has private permissions")
                else:
                    if ephemeral:
                        check(value != initial_token, "temporary token rotates on restart")
                        check(request(public, public_route + "stats/live", headers={
                            "Authorization": "Bearer " + initial_token})[0] == 401,
                            "previous temporary token no longer authorizes")
                        check(not generated.exists(), "unprotected token is never persisted")
                    else:
                        check(value == initial_token, "generated token survives restart")
                check(request(public, public_route + "stats/live",
                              headers={"Authorization": "Bearer " + value})[0] == 200,
                      "generated token authorizes default dashboard")
                if first:
                    code = dashboard_code(int(time.time()) // 30, value)
                    status, _, body = request(public, public_route + "auth/login", "POST",
                                              {"X-Ankah-Code": code})
                    check(status == 200, "generated token supports authenticator login")
                    session = json.loads(body)["token"]
                    check(request(public, public_route + "settings/disable", "POST",
                                  {"Authorization": "Bearer " + session})[0] == 204,
                          "authenticator session can disable default dashboard")
                    check(request(public, public_route + "stats/live")[0] == 410,
                          "disabled default dashboard API is gone")
                    check(request(public, public_route)[0] == 410,
                          "disabled default dashboard page is gone")
                    check(request(public, "/app/after-disable")[0] == 200,
                          "gateway stays available after live disable")
            finally:
                default_process.terminate()
                default_process.wait(timeout=10)

        generated.write_text("invalid")
        result = subprocess.run(gateway_command(executable, default_args), cwd=temp,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=10)
        check(result.returncode == 2, "malformed generated token is not replaced")

        if sys.platform.startswith("linux") and pathlib.Path("/proc").is_dir():
            temporary_process = start_gateway(
                executable, default_args, cwd="/proc",
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                line = temporary_process.stderr.readline().decode()
                match = re.search(r"temporary token for this run: ([0-9a-f]{64})", line)
                check(match is not None, "read-only working directory emits a temporary token")
                for _ in range(250):
                    if temporary_process.poll() is not None:
                        raise RuntimeError("temporary-token dashboard exited")
                    try:
                        if request(public, public_route + "stats/live", headers={
                                "Authorization": "Bearer " + match.group(1)})[0] == 200:
                            break
                    except OSError:
                        pass
                    time.sleep(.02)
                else:
                    raise RuntimeError("temporary token did not authorize the dashboard")
            finally:
                temporary_process.terminate()
                temporary_process.wait(timeout=10)

        no_dashboard_dir = pathlib.Path(temp) / "no-dashboard"
        no_dashboard_dir.mkdir()
        disabled_process = start_gateway(
            executable, base + ["--no-dashboard"], cwd=no_dashboard_dir,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(250):
                if disabled_process.poll() is not None:
                    raise RuntimeError("disabled dashboard exited: " +
                                       disabled_process.stderr.read().decode())
                try:
                    if request(public, public_route + "stats/live")[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(.02)
            else:
                raise RuntimeError("gateway did not serve with --no-dashboard")
            check(not (no_dashboard_dir / "ankah.dashboard.token").exists(),
                  "--no-dashboard skips token creation")
        finally:
            disabled_process.terminate()
            disabled_process.wait(timeout=10)

        no_dashboard_config = no_dashboard_dir / "disabled.conf"
        no_dashboard_config.write_text("no-dashboard=true\n")
        for options, environment, label in (
                (["--config", str(no_dashboard_config)], os.environ.copy(), "config file"),
                ([], {**os.environ, "ANKAH_NO_DASHBOARD": "true"}, "environment")):
            disabled_process = start_gateway(
                executable, base + options, cwd=no_dashboard_dir,
                env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                for _ in range(250):
                    if disabled_process.poll() is not None:
                        raise RuntimeError(f"{label} disabled gateway exited: " +
                                           disabled_process.stderr.read().decode())
                    try:
                        if request(public, public_route + "stats/live")[0] == 200:
                            break
                    except OSError:
                        pass
                    time.sleep(.02)
                else:
                    raise RuntimeError(f"{label} did not disable the dashboard")
                check(not (no_dashboard_dir / "ankah.dashboard.token").exists(),
                      f"{label} disable skips token creation")
            finally:
                disabled_process.terminate()
                disabled_process.wait(timeout=10)

        process = start_gateway(
            executable, base + listen + public_route_option +
                            ["--dashboard-token-file", str(token),
                            "--stats-file", str(stats_file)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(250):
                if process.poll() is not None:
                    raise RuntimeError("gateway exited: " + process.stderr.read().decode())
                try:
                    if request(dashboard, "/stats/live")[0] == 401:
                        break
                except OSError:
                    pass
                time.sleep(.02)
            else:
                raise RuntimeError("dashboard did not listen")

            status, headers, _ = request(dashboard, "/stats/live")
            check(status == 401 and headers["WWW-Authenticate"].startswith("Bearer"),
                  "missing token is refused")
            for value in ("Bearer " + "c" * 64, "Bearer " + TOKEN[:-1], "Basic " + TOKEN,
                          "Bearer " + TOKEN.upper()):
                status, _, _ = request(dashboard, "/stats/live", headers={"Authorization": value})
                check(status == 401, "wrong token is refused: " + value[:12])
            status, _, _ = request(dashboard, "/stats/live",
                                   headers={"Authorization": "bearer " + TOKEN})
            check(status == 200, "scheme is case insensitive")

            check(request(dashboard, "/auth/qr")[0] == 401,
                  "setup QR requires the dashboard token")
            status, headers, qr = request(dashboard, "/auth/qr", headers=authorized)
            check(status == 200 and headers["Content-Type"] == "image/png" and
                  qr.startswith(b"\x89PNG\r\n\x1a\n"), "setup QR is served")
            check(request(dashboard, "/auth/login", "POST",
                          {"X-Ankah-Code": "123"})[0] == 401,
                  "short authenticator codes are refused")
            code = dashboard_code(int(time.time()) // 30)
            status, _, body = request(dashboard, "/auth/login", "POST",
                                      {"X-Ankah-Code": code})
            check(status == 200, "valid authenticator code is accepted")
            session = json.loads(body)["token"]
            check(re.fullmatch("[0-9a-f]{64}", session) and session != TOKEN,
                  "login returns a distinct session token")
            session_auth = {"Authorization": "Bearer " + session}
            check(request(dashboard, "/stats/live", headers=session_auth)[0] == 200,
                  "session opens statistics")
            check(request(dashboard, "/auth/qr", headers=session_auth)[0] == 401,
                  "session cannot reveal the setup QR")
            check(request(dashboard, "/auth/login", "POST",
                          {"X-Ankah-Code": code})[0] == 401,
                  "authenticator code cannot be reused")
            for _ in range(4):
                check(request(dashboard, "/auth/login", "POST",
                              {"X-Ankah-Code": "xxxxxx"})[0] == 401,
                      "invalid code is refused")
            check(request(dashboard, "/auth/login", "POST",
                          {"X-Ankah-Code": "xxxxxx"})[0] == 429,
                  "code attempts are limited")

            status, headers, _ = request(dashboard, "/metrics")
            check(status == 401 and headers["WWW-Authenticate"].startswith("Bearer"),
                  "metrics require a token")
            status, headers, _ = request(dashboard, "/metrics", "POST", authorized)
            check(status == 405 and headers.get("Allow") == "GET",
                  "metrics reject unsupported methods")
            status, headers, _ = request(dashboard, "/stats/export.csv")
            check(status == 401 and headers["WWW-Authenticate"].startswith("Bearer"),
                  "export requires a token")
            status, headers, _ = request(dashboard, "/stats/export.csv", "POST", authorized)
            check(status == 405 and headers.get("Allow") == "GET",
                  "export rejects unsupported methods")

            def metrics():
                status, headers, body = request(dashboard, "/metrics?source=test",
                                                headers=authorized)
                check(status == 200, "metrics returned " + str(status))
                check(headers["Content-Type"] ==
                      "text/plain; version=0.0.4; charset=utf-8", "metrics content type")
                check(headers["Cache-Control"] == "no-store", "metrics cache control")
                check(body.endswith(b"\n"), "metrics final newline")
                text = body.decode("ascii")
                samples = [line for line in text.splitlines() if line and not line.startswith("#")]
                check(len(samples) == len({line.split(" ", 1)[0] for line in samples}),
                      "metrics contain duplicate samples")
                values = {line.split(" ", 1)[0]: float(line.rsplit(" ", 1)[1])
                          for line in samples}
                types = {line.split()[2]: line.split()[3] for line in text.splitlines()
                         if line.startswith("# TYPE ")}
                return text, values, types

            metric_text, metric_before, metric_types = metrics()
            check(metric_types["ankah_http_requests_total"] == "counter" and
                  metric_types["ankah_connections_current"] == "gauge" and
                  metric_types["ankah_upstream_response_latency_seconds"] == "summary" and
                  metric_types["ankah_static_throttle_queue_wait_seconds"] == "summary",
                  "metrics types")
            classes = {name for name in metric_before
                       if name.startswith("ankah_http_responses_total{")}
            check(classes == {f'ankah_http_responses_total{{class="{kind}"}}'
                              for kind in ("2xx", "3xx", "4xx", "5xx")},
                  "response class labels are bounded")
            check(metric_before["ankah_connections_limit"] == 256 and
                  metric_before["ankah_tls_connections_limit"] == 0 and
                  metric_before["ankah_sessions_limit"] == 4096 and
                  metric_before["ankah_static_cache_bytes_limit"] == 64 * 1024 * 1024 and
                  metric_before["ankah_static_throttle_connections_limit"] == 0 and
                  metric_before["ankah_static_throttle_queue_current"] == 0,
                  "metrics limits")
            check("127.0.0.1" not in metric_text and "/app/" not in metric_text,
                  "metrics exclude addresses and paths")
            status, _, _ = request(public, "/app/delay")
            check(status == 200, "metric delay request")
            _, metric_after, _ = metrics()
            check(metric_after["ankah_http_requests_total"] ==
                  metric_before["ankah_http_requests_total"] + 1,
                  "request counter changes")
            check(metric_after["ankah_upstream_response_latency_seconds_count"] ==
                  metric_before["ankah_upstream_response_latency_seconds_count"] + 1,
                  "latency count changes")
            check(metric_after["ankah_upstream_response_latency_seconds_sum"] >=
                  metric_before["ankah_upstream_response_latency_seconds_sum"] + .04 and
                  metric_after["ankah_upstream_response_latency_peak_seconds"] >= .04,
                  "latency milliseconds convert to seconds")
            _, metric_quiet, _ = metrics()
            check(metric_quiet["ankah_http_requests_total"] ==
                  metric_after["ankah_http_requests_total"],
                  "metric scrapes are not counted")

            schema = stats("/stats/schema")
            fields = schema["fields"]
            check(schema["v"] == 3 and len(fields) == 45 and
                  len(schema["kinds"]) == 45, "schema has 45 fields")
            check(fields[0] == "client_bytes_in" and schema["kinds"][fields.index(
                "peak_connections")] == "max", "schema names and kinds")
            check(schema["hour_capacity"] == 720 and schema["day_capacity"] == 4096,
                  "schema ring sizes")
            check(schema["limits"]["connections"] == 256 and
                  schema["limits"]["tls_connections"] == 0 and
                  schema["limits"]["sessions"] == 4096 and
                  schema["limits"]["throttle_connections"] == 0 and
                  schema["limits"]["throttle_queue"] == 0, "schema limits")
            field = {name: index for index, name in enumerate(fields)}

            status, headers, page = request(dashboard, "/",
                                            headers={"Accept-Language": "fr-CA, en;q=0.5"})
            policy = headers.get("Content-Security-Policy", "")
            check(status == 200 and headers["Content-Type"].startswith("text/html") and
                  b"dashboard/dashboard.js" in page, "page is served without a token")
            check(headers.get("Content-Language") == "en" and
                  "Accept-Language" in headers.get("Vary", ""),
                  "page language is negotiated")
            check(b"<!--#" not in page and b'<html lang="en">' in page and
                  b"Ankah dashboard" in page and
                  b'id="export"' in page and
                  b'id="disable-dialog"' in page and
                  b'Disable dashboard' in page and
                  b'Restarting Ankah turns it back on' in page and
                  b"Rates between polls, last five minutes." in page,
                  "dashboard SSI is rendered")
            english_etag = headers["ETag"]
            for preference, tag, title, disable_text in (
                ("ja-JP, es;q=0.5", "ja", "Ankah ダッシュボード", "統計収集が停止します"),
                ("es-MX, ja;q=0.5", "es", "Panel de Ankah",
                 "detiene sus estadísticas"),
            ):
                localized_status, localized_headers, localized_page = request(
                    dashboard, "/", headers={"Accept-Language": preference})
                check(localized_status == 200 and
                      localized_headers.get("Content-Language") == tag and
                      "Accept-Language" in localized_headers.get("Vary", "") and
                      localized_headers["ETag"] != english_etag and
                      f'<html lang="{tag}">'.encode() in localized_page and
                      title.encode() in localized_page and
                      disable_text.encode() in localized_page and
                      b"<!--#" not in localized_page,
                      f"{tag} dashboard translation and metadata")
                cached_status, cached_headers, _ = request(
                    dashboard, "/", headers={"Accept-Language": tag,
                                             "If-None-Match": localized_headers["ETag"]})
                check(cached_status == 304 and
                      cached_headers.get("Content-Language") == tag,
                      f"{tag} dashboard revalidation")
            page_names = re.findall(rb'data-name="([^"]+)"', page)
            script = (pathlib.Path(root) / "dashboard/dashboard.js").read_text()
            script_names = {name.encode() for name in
                            re.findall(r'text\("([^"]+)"', script)}
            check(len(page_names) == len(set(page_names)) and
                  set(page_names) == script_names,
                  "runtime dashboard text catalog is complete")
            check("default-src 'none'" in policy and "script-src 'self'" in policy and
                  "unsafe" not in policy and "frame-ancestors 'none'" in policy, "page policy")
            status, revalidated, _ = request(
                dashboard, "/", headers={"If-None-Match": headers["ETag"],
                                          "Accept-Language": "en"})
            check(status == 304 and revalidated.get("Content-Language") == "en" and
                  "Accept-Language" in revalidated.get("Vary", ""),
                  "page revalidates with language metadata")
            for name, kind in (("dashboard.js", "application/javascript"),
                               ("dashboard.css", "text/css"),
                               ("d3-subset.min.js", "application/javascript"),
                               ("particles.min.js", "application/javascript"),
                               ("particlejs.json", "application/json")):
                status, headers, body = request(dashboard, "/dashboard/" + name)
                source = pathlib.Path(root) / ("dashboard/" + name
                                               if name.startswith(("dashboard", "d3")) else name)
                check(status == 200 and headers["Content-Type"].startswith(kind) and
                      body == source.read_bytes(), name + " is served")
            status, headers, _ = request(public, public_route[:-1])
            check(status == 308 and headers.get("Location") == public_route,
                  "public dashboard adds its trailing slash")
            status, headers, page = request(public, public_route)
            check(status == 200 and b'dashboard/dashboard.js' in page and
                  "connect-src 'self'" in headers.get("Content-Security-Policy", ""),
                  "public dashboard page is served through normal public routing")
            for name, kind in (("dashboard.js", "application/javascript"),
                               ("dashboard.css", "text/css"),
                               ("d3-subset.min.js", "application/javascript"),
                               ("particles.min.js", "application/javascript"),
                               ("particlejs.json", "application/json")):
                status, headers, body = request(public, public_route + "dashboard/" + name)
                source = pathlib.Path(root) / ("dashboard/" + name
                                               if name.startswith(("dashboard", "d3")) else name)
                check(status == 200 and headers["Content-Type"].startswith(kind) and
                      body == source.read_bytes(), "public " + name + " is served")
            default_mascot = (pathlib.Path(root) / "ankah.png").read_bytes()
            replacement = (pathlib.Path(root) / "phone-scan.png").read_bytes()
            status, headers, body = request(dashboard, "/settings/mascot", headers=authorized)
            check(status == 200 and headers.get("X-Ankah-Mascot-Source") == "default" and
                  body == default_mascot, "dashboard shows the default mascot")
            check(request(dashboard, "/settings/mascot")[0] == 401,
                  "mascot settings require a token")
            upload_headers = {**authorized, "Content-Type": "image/png"}
            check(request(dashboard, "/settings/mascot", "PUT", upload_headers,
                          b"invalid")[0] == 400, "invalid PNG is refused")
            check(request(dashboard, "/settings/mascot", "PUT",
                          {**upload_headers, "Content-Length": str(4 * 1024 * 1024 + 1)},
                          b"")[0] == 413,
                  "oversized mascot is refused")
            check(request(dashboard, "/settings/mascot", "POST", authorized)[0] == 405,
                  "unsupported mascot method is refused")
            with socket.create_connection(("127.0.0.1", public), timeout=10) as slow:
                slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
                slow.sendall((f"GET /ankah/mascot.png HTTP/1.1\r\n"
                              f"Host: localhost:{public}\r\nConnection: close\r\n\r\n").encode())
                time.sleep(.05)
                check(request(public, public_route + "settings/mascot", "PUT",
                              upload_headers, replacement)[0] == 204,
                      "public dashboard route accepts the image")
                response = bytearray()
                while True:
                    part = slow.recv(65536)
                    if not part:
                        break
                    response.extend(part)
                check(response.split(b"\r\n\r\n", 1)[1] == default_mascot,
                      "an image response in progress keeps its original bytes")
            check(mascot_file.read_bytes() == replacement,
                  "uploaded mascot is saved")
            status, headers, body = request(dashboard, "/settings/mascot", headers=authorized)
            check(status == 200 and headers.get("X-Ankah-Mascot-Source") == "custom" and
                  body == replacement, "dashboard shows the uploaded mascot")
            status, headers, body = request(public, "/ankah/mascot.png")
            check(status == 200 and headers.get("Content-Type") == "image/png" and
                  headers.get("Cache-Control") == "no-store" and body == replacement,
                  "challenge mascot changes immediately")
            check(request(public, public_route + "settings/mascot")[0] == 401,
                  "public mascot settings require a token")
            check(request(dashboard, "/settings/mascot", "DELETE", authorized)[0] == 204 and
                  not mascot_file.exists(), "restore removes the override")
            check(request(public, "/ankah/mascot.png")[2] == default_mascot,
                  "restore changes the challenge image")
            before_public_api = stats("/stats/live")
            status, headers, _ = request(public, public_route + "stats/live")
            check(status == 401 and headers["WWW-Authenticate"].startswith("Bearer"),
                  "public statistics require a token")
            public_live = request(public, public_route + "stats/live", headers=authorized)
            check(public_live[0] == 200 and json.loads(public_live[2])["v"] == 3,
                  "public statistics accept a token")
            check(request(public, public_route + "stats/live", headers=session_auth)[0] == 200,
                  "public statistics accept an authenticator session")
            check(request(public, public_route + "auth/logout", "POST", session_auth)[0] == 204,
                  "session can sign out through the public route")
            check(request(dashboard, "/stats/live", headers=session_auth)[0] == 401,
                  "signed-out session is revoked")
            after_public_api = stats("/stats/live")
            check(after_public_api["cumulative"] == before_public_api["cumulative"],
                  "public dashboard API traffic is excluded from statistics")
            digest = hashlib.sha256((pathlib.Path(root) / "dashboard/dashboard.js")
                                    .read_bytes()).hexdigest()
            for path in ("/dashboard/dashboard.js", f"/ankah/assets/{digest}/dashboard.js"):
                status, _, body = request(public, path)
                check(status in (404, 428) and b"particlesJS" not in body,
                      "public listener never serves page files: " + path)

            for path, method, body, expected in (
                    ("/nowhere", "GET", None, 404),
                    ("/", "POST", b"", 405),
                    ("/stats/nowhere", "GET", None, 404),
                    ("/stats/reset", "GET", None, 405),
                    ("/stats/live", "POST", b"", 405),
                    ("/stats/reset", "POST", b"x", 400),
                    ("/stats/history?hours=x", "GET", None, 400)):
                status, _, _ = request(dashboard, path, method, authorized, body)
                check(status == expected, f"{method} {path} returned {status}")

            time.sleep(.3)
            before = stats("/stats/live")
            check(before["gauges"]["tls_connections"] == 0, "no TLS sockets")
            check(before["gauges"]["throttle_connections"] == 0 and
                  before["gauges"]["throttle_queue"] == 0, "throttle gauges are idle")
            for _ in range(5):
                status, _, body = request(public, "/app/ok")
                check(status == 200 and body == b"/app/ok", "forwarded request")
            status, _, _ = request(public, "/app/missing")
            check(status == 404, "upstream 404 passes through")
            status, _, page = request(public, "/blocked")
            check(status == 428 and b"phone-panel" in page and
                  b"<img id=mascot src='/ankah/mascot.png'" in page,
                  "browser challenge displays the mascot")
            status, _, _ = request(public, "/blocked", headers={"User-Agent": "curl/8.0"})
            check(status == 302, "command line challenge")
            status, _, page = request(public, "/stats/live", headers=authorized)
            check(status == 428 and b"cumulative" not in page,
                  "public listener never answers statistics paths")
            time.sleep(.3)
            after = stats("/stats/live")

            def delta(name):
                return after["cumulative"][field[name]] - before["cumulative"][field[name]]

            for name, expected in (("accepted", 9), ("requests", 9), ("responses_2xx", 5),
                                   ("responses_3xx", 1), ("responses_4xx", 3),
                                   ("responses_5xx", 0), ("challenges_issued", 3),
                                   ("upstream_requests", 6), ("upstream_responses", 6),
                                   ("upstream_failures", 0)):
                check(delta(name) == expected, f"{name} moved by {delta(name)}, not {expected}")
            for name in ("client_bytes_in", "client_bytes_out", "upstream_bytes_in",
                         "upstream_bytes_out"):
                check(delta(name) > 0, f"{name} did not move")
            check(after["cumulative"][field["peak_connections"]] >= 1, "peak connections")
            if after["hour_index"] == before["hour_index"]:
                check(after["current_hour"][field["requests"]] -
                      before["current_hour"][field["requests"]] == 9, "current hour moves")
            if after["day_index"] == before["day_index"]:
                check(after["current_day"][field["requests"]] -
                      before["current_day"][field["requests"]] == 9, "current day moves")
            check(after["gauges"]["sessions"] >= 2, "challenge sessions are live")
            check(after["top"] == [] and after["top_other"]["count"] == 0, "no live connections")

            time.sleep(.3)
            quiet = stats("/stats/live")
            check(quiet["cumulative"][field["accepted"]] == after["cumulative"][field["accepted"]]
                  and quiet["cumulative"][field["requests"]] ==
                  after["cumulative"][field["requests"]], "dashboard polls are not counted")

            for _ in range(5):
                started = time.monotonic()
                first, second = stats("/stats/live"), stats("/stats/live")
                if time.monotonic() - started < .2:
                    check(first == second, "polls inside the cache window share one body")
                    break
            else:
                raise RuntimeError("could not poll twice inside the cache window")
            time.sleep(.3)
            check(stats("/stats/live")["sample_ms"] != first["sample_ms"], "cache expires")

            with socket.create_connection(("127.0.0.1", public), timeout=5) as sock:
                sock.sendall(b"GET /app/slow HTTP/1.1\r\nHost: loc")
                time.sleep(.3)
                live = stats("/stats/live")
                check(len(live["top"]) == 1, "open connection is listed")
                entry = live["top"][0]
                check(entry["ip"] == "127.0.0.1" and entry["in"] > 0 and
                      entry["state"] == "reading" and entry["ws"] is False,
                      "listed connection details")
                check(set(entry) == {"id", "ip", "age_ms", "in", "out", "ws", "state"},
                      "listed connection carries no request text")

            history = stats("/stats/history")
            for series, index in (("hours", "hour_index"), ("days", "day_index")):
                rows = history[series]["rows"]
                check(len(rows) <= 1 and all(len(row) == 45 for row in rows),
                      f"new process has at most one completed {series[:-1]}")
                check(history[series]["first"] + len(rows) == history[index],
                      f"{series} end at the current bucket")
            check(len(history["evicted"]) == 45 and history["evicted_days"] == 0,
                  "history shape")
            check(stats("/stats/history?hours=1&days=1&other=2")["epoch"] == history["epoch"],
                  "history accepts a range")

            status, headers, body = request(dashboard, "/stats/export.csv", headers=authorized)
            check(status == 200 and headers["Content-Type"] == "text/csv; charset=utf-8",
                  "export content type")
            check(headers["Cache-Control"] == "no-store" and
                  re.fullmatch(r'attachment; filename="ankah-metrics-\d{8}T\d{6}Z\.csv"',
                               headers.get("Content-Disposition", "")),
                  "export download headers")
            check(body.startswith(b"\xef\xbb\xbf") and body.endswith(b"\r\n"),
                  "export spreadsheet encoding")
            export_rows = list(csv.reader(io.StringIO(body.decode("utf-8-sig"), newline="")))
            check(len(export_rows) >= 2 and len(export_rows[0]) == 5 + len(fields) and
                  export_rows[0][5:] == fields, "export columns follow the schema")
            check(export_rows[-1][0] == "current_hour" and export_rows[-1][3] == "1" and
                  len(export_rows[-1]) == len(export_rows[0]), "export has a partial current hour")
            request_column = export_rows[0].index("requests")
            check(sum(int(row[request_column]) for row in export_rows[1:]) ==
                  after["cumulative"][field["requests"]], "export includes current metrics")
            for previous, current in zip(export_rows[1:], export_rows[2:]):
                check(previous[2] == current[1], "export periods are continuous")

            status, _, body = request(dashboard, "/stats/reset", "POST", authorized, b"")
            check(status == 200, "reset accepted")
            reset_reply = json.loads(body)
            epoch = reset_reply["epoch"]
            check(reset_reply["persistence"] == "queued", "reset snapshot is queued")
            check(epoch >= history["epoch"], "reset moves the epoch forward")
            reset = stats("/stats/live")
            check(reset["epoch"] == epoch and reset["cumulative"][field["requests"]] == 0 and
                  reset["cumulative"][field["accepted"]] == 0, "reset clears counters")
            _, reset_metrics, _ = metrics()
            check(reset_metrics["ankah_stats_epoch_seconds"] == epoch and
                  reset_metrics["ankah_http_requests_total"] == 0,
                  "metrics reflect reset counters")
            check(request(dashboard, "/settings/mascot", "PUT", upload_headers,
                          replacement)[0] == 204, "mascot is saved before restart")
            check(request(dashboard, "/settings/disable", "POST")[0] == 401,
                  "dashboard disable requires authorization")
            check(request(dashboard, "/settings/disable", "GET", authorized)[0] == 405,
                  "dashboard disable only accepts POST")
            check(request(dashboard, "/stats/live", headers=authorized)[0] == 200,
                  "cancelled disable leaves dashboard active")
            check(request(dashboard, "/settings/disable", "POST", authorized)[0] == 204,
                  "dashboard token can disable dashboard")
            check(request(public, public_route + "stats/live", headers=authorized)[0] == 410,
                  "public dashboard API closes immediately")
            check(request(public, public_route + "", headers=authorized)[0] == 410,
                  "public dashboard page closes immediately")
            check(request(public, "/app/after-disable")[0] == 200,
                  "gateway keeps serving after dashboard disable")
            try:
                request(dashboard, "/stats/live", headers=authorized)
            except OSError:
                pass
            else:
                raise RuntimeError("private dashboard listener stayed open")
        finally:
            process.terminate()
            process.wait(timeout=10)

        process = start_gateway(
            executable, base + listen + ["--dashboard-token-file", str(token),
                            "--stats-file", str(stats_file)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(250):
                if process.poll() is not None:
                    raise RuntimeError("restarted gateway exited: " +
                                       process.stderr.read().decode())
                try:
                    if request(dashboard, "/stats/live", headers=authorized)[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(.02)
            else:
                raise RuntimeError("restarted dashboard did not listen")
            check(stats("/stats/live")["epoch"] == epoch,
                  "restart restores the statistics epoch")
            _, restored_metrics, _ = metrics()
            check(restored_metrics["ankah_stats_epoch_seconds"] == epoch and
                  restored_metrics["ankah_http_requests_total"] == 0,
                  "metrics reflect restored counters")
            check(request(public, public_route + "stats/live")[0] == 200,
                  "private listener does not enable the default public route")
            check(request(dashboard, "/settings/mascot", headers=authorized)[2] == replacement and
                  request(public, "/ankah/mascot.png")[2] == replacement,
                  "mascot survives restart")
        finally:
            process.terminate()
            process.wait(timeout=10)

        unavailable = pathlib.Path(temp) / "missing" / "statistics"
        process = start_gateway(
            executable, base + listen + ["--dashboard-token-file", str(token),
                            "--stats-file", str(unavailable)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(250):
                if process.poll() is not None:
                    raise RuntimeError("degraded gateway exited: " +
                                       process.stderr.read().decode())
                try:
                    if request(dashboard, "/stats/live", headers=authorized)[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(.02)
            else:
                raise RuntimeError("degraded dashboard did not listen")
            status, _, body = request(dashboard, "/stats/reset", "POST", authorized, b"")
            check(status == 200 and json.loads(body)["persistence"] == "queued",
                  "snapshot write failure does not prevent reset")
        finally:
            process.terminate()
            process.wait(timeout=10)
            check("statistics persistence unavailable" in process.stderr.read().decode(),
                  "snapshot write failure is reported")

        process = start_gateway(
            executable, base + listen + ["--dashboard-token-file", str(token),
                            "--no-stats-file"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(250):
                if process.poll() is not None:
                    raise RuntimeError("memory-only gateway exited: " +
                                       process.stderr.read().decode())
                try:
                    if request(dashboard, "/stats/live", headers=authorized)[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(.02)
            else:
                raise RuntimeError("memory-only dashboard did not listen")
            status, _, body = request(dashboard, "/stats/reset", "POST", authorized, b"")
            check(status == 200 and json.loads(body)["persistence"] == "disabled",
                  "memory-only reset reports disabled persistence")
        finally:
            process.terminate()
            process.wait(timeout=10)
            server.shutdown()


if __name__ == "__main__":
    main()
