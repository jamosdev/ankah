"""Exercise a resumable TUS upload through the gateway."""

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


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    executable, root = sys.argv[1:]
    gate_port, app_port = port(), port()
    expected = b"first chunk\x00\xffsecond chunk"
    uploaded = bytearray()
    seen = []
    errors = []

    class App(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def empty_response(self, status, *headers):
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def reject(self, message):
            errors.append(message)
            self.empty_response(400)

        def do_OPTIONS(self):
            seen.append(("OPTIONS", self.path))
            self.empty_response(
                204,
                ("Tus-Resumable", "1.0.0"),
                ("Tus-Version", "1.0.0"),
                ("Tus-Extension", "creation"),
            )

        def do_POST(self):
            seen.append(("POST", self.path))
            if (self.path != "/files" or
                    self.headers.get("Tus-Resumable") != "1.0.0" or
                    self.headers.get("Upload-Length") != str(len(expected)) or
                    self.headers.get("Content-Length") != "0"):
                self.reject("invalid creation request")
                return
            self.empty_response(
                201,
                ("Location", "/files/1"),
                ("Tus-Resumable", "1.0.0"),
            )

        def do_HEAD(self):
            seen.append(("HEAD", self.path))
            if (self.path != "/files/1" or
                    self.headers.get("Tus-Resumable") != "1.0.0"):
                self.reject("invalid offset request")
                return
            self.empty_response(
                200,
                ("Upload-Offset", str(len(uploaded))),
                ("Upload-Length", str(len(expected))),
                ("Tus-Resumable", "1.0.0"),
                ("Cache-Control", "no-store"),
            )

        def do_PATCH(self):
            seen.append(("PATCH", self.path))
            try:
                offset = int(self.headers["Upload-Offset"])
                length = int(self.headers["Content-Length"])
            except (KeyError, TypeError, ValueError):
                self.reject("invalid upload framing")
                return
            if (self.path != "/files/1" or
                    self.headers.get("Tus-Resumable") != "1.0.0" or
                    self.headers.get("Content-Type") !=
                    "application/offset+octet-stream" or
                    offset != len(uploaded)):
                self.reject("invalid patch request")
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self.reject("incomplete patch body")
                return
            uploaded.extend(body)
            self.empty_response(
                204,
                ("Upload-Offset", str(len(uploaded))),
                ("Tus-Resumable", "1.0.0"),
            )

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", app_port), App)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()

    def request(method, path, body=None, headers=None):
        client = http.client.HTTPConnection("127.0.0.1", gate_port, timeout=5)
        client.request(method, path, body=body, headers={
            "Host": f"localhost:{gate_port}",
            **(headers or {}),
        })
        reply = client.getresponse()
        result = reply.status, dict(reply.getheaders()), reply.read()
        client.close()
        return result

    with tempfile.TemporaryDirectory() as temp:
        secret = pathlib.Path(temp) / "secret"
        secret.write_text("a" * 64)
        process = subprocess.Popen(gateway_command(executable, [
            "--listen", f"127.0.0.1:{gate_port}",
            "--upstream", f"127.0.0.1:{app_port}",
            "--public-origin", f"http://localhost:{gate_port}",
            "--secret-file", str(secret),
            "--assets-dir", root,
            "--allow-prefix", "/files",
        ]), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(250):
                try:
                    status, headers, _ = request("OPTIONS", "/files")
                    if status == 204:
                        break
                except OSError:
                    pass
                time.sleep(.02)
            else:
                raise RuntimeError("gateway did not start")

            seen.clear()
            status, headers, body = request("OPTIONS", "/files")
            assert status == 204 and not body
            assert headers["Tus-Resumable"] == "1.0.0"
            assert headers["Tus-Version"] == "1.0.0"
            assert headers["Tus-Extension"] == "creation"

            tus = {"Tus-Resumable": "1.0.0"}
            status, headers, body = request(
                "POST", "/files", b"", {**tus, "Upload-Length": str(len(expected))})
            assert status == 201 and not body
            assert headers["Location"] == "/files/1"
            assert headers["Tus-Resumable"] == "1.0.0"

            first = expected[:8]
            status, headers, body = request("PATCH", headers["Location"], first, {
                **tus,
                "Content-Type": "application/offset+octet-stream",
                "Upload-Offset": "0",
            })
            assert status == 204 and not body
            assert headers["Upload-Offset"] == str(len(first))

            status, headers, body = request("HEAD", "/files/1", headers=tus)
            assert status == 200 and not body
            assert headers["Upload-Offset"] == str(len(first))
            assert headers["Upload-Length"] == str(len(expected))
            assert headers["Cache-Control"] == "no-store"

            status, headers, body = request("PATCH", "/files/1", expected[len(first):], {
                **tus,
                "Content-Type": "application/offset+octet-stream",
                "Upload-Offset": str(len(first)),
            })
            assert status == 204 and not body
            assert headers["Upload-Offset"] == str(len(expected))

            status, headers, body = request("HEAD", "/files/1", headers=tus)
            assert status == 200 and not body
            assert headers["Upload-Offset"] == str(len(expected))
            assert bytes(uploaded) == expected
            assert not errors, errors
            assert seen == [
                ("OPTIONS", "/files"),
                ("POST", "/files"),
                ("PATCH", "/files/1"),
                ("HEAD", "/files/1"),
                ("PATCH", "/files/1"),
                ("HEAD", "/files/1"),
            ]
        finally:
            process.terminate()
            process.wait(timeout=3)
            server.shutdown()


if __name__ == "__main__":
    main()
