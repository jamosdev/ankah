"""Exercise the operator dashboard listener and its statistics endpoints."""

import hashlib
import http.client
import http.server
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

from process_support import gateway_command


TOKEN = "b" * 64


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
    public, dashboard, app = free_port(), free_port(), free_port()
    authorized = {"Authorization": "Bearer " + TOKEN}

    class App(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
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
        base = ["--listen", f"127.0.0.1:{public}", "--upstream", f"127.0.0.1:{app}",
                "--public-origin", f"http://localhost:{public}",
                "--secret-file", str(secret), "--assets-dir", root,
                "--allow-prefix", "/app"]
        listen = ["--dashboard-listen", f"127.0.0.1:{dashboard}"]

        for extra, reason in ((listen, "listen without a token"),
                              (["--dashboard-token-file", str(token)], "token without a listener"),
                              (listen + ["--dashboard-token-file", str(secret)],
                               "token equal to the secret")):
            result = subprocess.run(gateway_command(executable, base + extra),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=30)
            check(result.returncode == 2, f"started with {reason}")

        process = subprocess.Popen(
            gateway_command(executable, base + listen + ["--dashboard-token-file", str(token)]),
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

            schema = stats("/stats/schema")
            fields = schema["fields"]
            check(len(fields) == 32 and len(schema["kinds"]) == 32, "schema has 32 fields")
            check(fields[0] == "client_bytes_in" and schema["kinds"][fields.index(
                "peak_connections")] == "max", "schema names and kinds")
            check(schema["hour_capacity"] == 720 and schema["day_capacity"] == 4096,
                  "schema ring sizes")
            check(schema["limits"]["connections"] == 256 and
                  schema["limits"]["tls_connections"] == 0 and
                  schema["limits"]["sessions"] == 4096, "schema limits")
            field = {name: index for index, name in enumerate(fields)}

            status, headers, page = request(dashboard, "/")
            policy = headers.get("Content-Security-Policy", "")
            check(status == 200 and headers["Content-Type"].startswith("text/html") and
                  b"/dashboard/dashboard.js" in page, "page is served without a token")
            check("default-src 'none'" in policy and "script-src 'self'" in policy and
                  "unsafe" not in policy and "frame-ancestors 'none'" in policy, "page policy")
            status, _, _ = request(dashboard, "/", headers={"If-None-Match": headers["ETag"]})
            check(status == 304, "page revalidates")
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
            for _ in range(5):
                status, _, body = request(public, "/app/ok")
                check(status == 200 and body == b"/app/ok", "forwarded request")
            status, _, _ = request(public, "/app/missing")
            check(status == 404, "upstream 404 passes through")
            status, _, page = request(public, "/blocked")
            check(status == 428 and b"phone-panel" in page, "browser challenge")
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
                check(len(rows) <= 1 and all(len(row) == 32 for row in rows),
                      f"new process has at most one completed {series[:-1]}")
                check(history[series]["first"] + len(rows) == history[index],
                      f"{series} end at the current bucket")
            check(len(history["evicted"]) == 32 and history["evicted_days"] == 0,
                  "history shape")
            check(stats("/stats/history?hours=1&days=1&other=2")["epoch"] == history["epoch"],
                  "history accepts a range")

            status, _, body = request(dashboard, "/stats/reset", "POST", authorized, b"")
            check(status == 200, "reset accepted")
            epoch = json.loads(body)["epoch"]
            check(epoch >= history["epoch"], "reset moves the epoch forward")
            reset = stats("/stats/live")
            check(reset["epoch"] == epoch and reset["cumulative"][field["requests"]] == 0 and
                  reset["cumulative"][field["accepted"]] == 0, "reset clears counters")
        finally:
            process.terminate()
            process.wait(timeout=10)
            server.shutdown()


if __name__ == "__main__":
    main()
