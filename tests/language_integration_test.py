"""Exercise local response language negotiation and unknown-range logging."""

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


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(port, path, language=None):
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Host": f"localhost:{port}"}
    if language is not None:
        headers["Accept-Language"] = language
    client.request("GET", path, headers=headers)
    response = client.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    client.close()
    return result


def wait_ready(port):
    for _ in range(250):
        try:
            request(port, "/ankah/not-found")
            return
        except OSError:
            time.sleep(.02)
    raise RuntimeError("gateway did not start")


def main():
    executable, root = sys.argv[1:]
    gate_port, app_port = free_port(), free_port()

    class App(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"application response\n"
            self.send_response(418)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Language", "zz")
            self.send_header("Vary", "X-Upstream")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", app_port), App)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory() as temporary:
        directory = pathlib.Path(temporary)
        secret = directory / "secret"
        secret.write_text("a" * 64)
        language_log = directory / "languages.log"
        base = ["--listen", f"127.0.0.1:{gate_port}",
                "--upstream", f"127.0.0.1:{app_port}",
                "--public-origin", f"http://localhost:{gate_port}",
                "--secret-file", str(secret), "--assets-dir", root,
                "--allow-prefix", "/upstream"]
        process = subprocess.Popen(gateway_command(executable, [
            *base, "--log-unknown-languages", str(language_log)]),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            wait_ready(gate_port)
            status, headers, body = request(
                gate_port, "/ankah/not-found",
                "FR-ca, en-AU;q=0.5, *;q=0.1, de;q=0, bad_tag, e1")
            assert status == 404 and body == b"Unknown Ankah endpoint\n"
            assert headers["Content-Language"] == "en"
            assert "Accept-Language" in headers["Vary"]
            assert headers["Content-Type"] == "text/plain; charset=utf-8"
            status, headers, body = request(
                gate_port, "/ankah/not-found", "ja-JP, es-MX;q=0.5")
            assert status == 404 and headers["Content-Language"] == "ja"
            assert "不明な Ankah".encode() in body
            status, headers, body = request(
                gate_port, "/ankah/not-found", "es-MX, ja;q=0.5")
            assert status == 404 and headers["Content-Language"] == "es"
            assert b"Punto de acceso" in body
            status, headers, body = request(gate_port, "/upstream", "ES-mx")
            assert status == 418 and body == b"application response\n"
            assert headers["Content-Language"] == "zz"
            assert headers["Vary"] == "X-Upstream"
            assert language_log.read_text().splitlines() == ["fr-ca"]
        finally:
            process.terminate()
            process.wait(timeout=5)

        for arguments, expected in ((["--log-unknown-languages", ""], 2),
                                    (["--log-unknown-languages", str(language_log),
                                      "--log-unknown-languages", str(language_log)], 2),
                                    (["--log-unknown-languages", str(directory)], 1)):
            result = subprocess.run(gateway_command(executable, [*base, *arguments]),
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=10)
            assert result.returncode == expected

        language_log.write_bytes(b"x" * (1024 * 1024))
        gate_port = free_port()
        base[1] = f"127.0.0.1:{gate_port}"
        base[5] = f"http://localhost:{gate_port}"
        capped = subprocess.Popen(gateway_command(executable, [
            *base, "--log-unknown-languages", str(language_log)]),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            wait_ready(gate_port)
            request(gate_port, "/upstream", "one")
            request(gate_port, "/upstream", "two")
        finally:
            capped.terminate()
            capped.wait(timeout=5)
        output = capped.stderr.read().decode(errors="replace")
        assert output.count("unknown-language log reached its 1 MiB limit") == 1
        assert language_log.stat().st_size == 1024 * 1024
    server.shutdown()


if __name__ == "__main__":
    main()
