"""Exercise operator-configured public health route overrides."""

import http.client
import http.server
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


def wait_for(process, port):
    for _ in range(250):
        if process.poll() is not None:
            raise RuntimeError("gateway exited: " + process.stderr.read().decode())
        try:
            request(port, "/probe")
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
    executable, builder, assets = sys.argv[1:]
    app_port = free_port()
    calls = []

    class App(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(self.path)
            body = ("upstream " + self.path + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", app_port), App)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        secret = root / "secret"
        secret.write_text("a" * 64)
        token = root / "token"
        token.write_text(TOKEN)
        static = root / "project" / "static"
        static.mkdir(parents=True)
        (static / "file.txt").write_text("static\n")
        bundle = root / "bundle"
        subprocess.run([sys.executable, builder, "--project-root", str(root / "project"),
                        "--output", str(bundle)], check=True, capture_output=True)

        def base(port):
            return ["--listen", f"127.0.0.1:{port}",
                    "--upstream", f"127.0.0.1:{app_port}",
                    "--public-origin", f"http://localhost:{port}",
                    "--secret-file", str(secret), "--assets-dir", assets]

        invalid = [
            ["--ankah-healthz="],
            ["--ankah-healthz=healthz"],
            ["--ankah-healthz=/health?full=1"],
            ["--ankah-healthz=/health#part"],
            ["--ankah-healthz", "--ankah-healthz"],
            ["--ankah-healthz=/same", "--ankah-livez=/same"],
            ["--ankah-healthz", "/separate-value"],
        ]
        for extra in invalid:
            result = subprocess.run(gateway_command(executable, base(free_port()) + extra),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=30)
            check(result.returncode == 2, "invalid health options were accepted: " + str(extra))

        public = free_port()
        process = subprocess.Popen(gateway_command(executable, base(public) +
                                   ["--allow-prefix", "/"]),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            wait_for(process, public)
            calls.clear()
            status, _, body = request(public, "/healthz")
            check(status == 200 and body == b"upstream /healthz\n",
                  "health routes changed without an option")
            check(calls == ["/healthz"], "disabled route did not reach the application")
        finally:
            stop(process)

        public = free_port()
        process = subprocess.Popen(gateway_command(executable, base(public) + [
            "--ankah-healthz", "--ankah-livez", "--ankah-readyz",
            "--trusted-proxy", "127.0.0.1/32"]),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            wait_for(process, public)
            calls.clear()
            for path in ("/healthz", "/livez?from=monitor", "/readyz"):
                status, headers, body = request(public, path)
                check(status == 200 and body == b"ok\n", "default health route failed: " + path)
                check(headers.get("Content-Type") == "text/plain; charset=utf-8" and
                      headers.get("Cache-Control") == "no-store", "health response headers")
            status, headers, body = request(public, "/healthz", "HEAD")
            check(status == 200 and not body and headers.get("Content-Length") == "3",
                  "health HEAD response")
            status, headers, _ = request(public, "/healthz", "PUT")
            check(status == 405 and headers.get("Allow") == "GET, HEAD",
                  "health method policy")
            check(request(public, "/healthz", headers={"Host": "wrong.test"})[0] == 421,
                  "health route bypassed Host validation")
            check(request(public, "/healthz", headers={"X-Forwarded-For": "bad value"})[0] == 400,
                  "health route bypassed trusted proxy parsing")
            check(calls == [], "default health routes contacted the application")
        finally:
            stop(process)

        public, dashboard = free_port(), free_port()
        options = base(public) + [
            "--allow-prefix", "/app", "--static-bundle", str(bundle),
            "--ankah-healthz=/app/health", "--ankah-livez=/ankah/challenge/example",
            "--ankah-readyz=/static/file.txt",
            "--dashboard-listen", f"127.0.0.1:{dashboard}",
            "--dashboard-token-file", str(token), "--no-stats-file"]
        process = subprocess.Popen(gateway_command(executable, options),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        authorized = {"Authorization": "Bearer " + TOKEN}

        def response_counts():
            status, _, body = request(dashboard, "/metrics", headers=authorized)
            check(status == 200, "metrics unavailable during health test")
            result = {}
            for line in body.decode().splitlines():
                for name in ("ankah_http_requests_total",
                             'ankah_http_responses_total{class="2xx"}'):
                    if line.startswith(name + " "):
                        result[name] = int(line.split()[1])
            check(len(result) == 2, "health statistics counters missing")
            return result

        try:
            wait_for(process, public)
            calls.clear()
            before = response_counts()
            for path in ("/app/health?probe=1", "/ankah/challenge/example",
                         "/static/file.txt"):
                status, _, body = request(public, path)
                check(status == 200 and body == b"ok\n",
                      "custom health override failed: " + path)
            after = response_counts()
            check(all(after[name] - before[name] == 3 for name in before),
                  "health responses did not increment public statistics")
            status, _, body = request(public, "/app/health/child")
            check(status == 200 and body == b"upstream /app/health/child\n",
                  "health override was not an exact path")
            check(calls == ["/app/health/child"], "health overrides contacted the application")
        finally:
            stop(process)
            server.shutdown()


if __name__ == "__main__":
    main()
