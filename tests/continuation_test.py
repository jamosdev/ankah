"""Exercise two-device challenge completion and exact request replay."""

import hashlib
import http.client
import http.server
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def solve(challenge):
    nonce, _, bits, *_ = challenge.split(".")
    bits = int(bits)
    for counter in range(4_000_000):
        digest = hashlib.sha256(f"{nonce}:{counter}".encode()).digest()
        if int.from_bytes(digest, "big") >> (256 - bits) == 0:
            return counter
    raise RuntimeError("answer not found")


def main():
    executable, root = sys.argv[1:]
    gate_port, app_port = port(), port()
    seen = []

    class App(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(("GET", self.path, b"", dict(self.headers)))
            payload = self.path.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            seen.append(("POST", self.path, body, dict(self.headers)))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", app_port), App)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()

    def request(path, method="GET", body=None, headers=None):
        client = http.client.HTTPConnection("127.0.0.1", gate_port, timeout=5)
        client.request(method, path, body=body,
                       headers={"Host": f"localhost:{gate_port}", **(headers or {})})
        reply = client.getresponse()
        result = reply.status, dict(reply.getheaders()), reply.read()
        client.close()
        return result

    with tempfile.TemporaryDirectory() as temp:
        secret = pathlib.Path(temp) / "secret"
        secret.write_text("a" * 64)
        process = subprocess.Popen(
            [executable, "--listen", f"127.0.0.1:{gate_port}",
             "--upstream", f"127.0.0.1:{app_port}",
             "--public-origin", f"http://localhost:{gate_port}",
             "--secret-file", str(secret), "--assets-dir", root],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                try:
                    status, _, _ = request("/ready")
                    if status == 428:
                        break
                except OSError:
                    pass
                time.sleep(.02)
            else:
                raise RuntimeError("gateway did not start")

            with socket.create_connection(("127.0.0.1", gate_port), timeout=5) as sock:
                sock.sendall((f"GET /socket HTTP/1.1\r\nHost: localhost:{gate_port}\r\n"
                              "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n").encode())
                assert sock.recv(1024).startswith(b"HTTP/1.1 428")

            status, _, _ = request("/ankah/open-extra?challenge=x&answer=0", "POST", b"")
            assert status == 404

            with socket.create_connection(("127.0.0.1", gate_port), timeout=5) as sock:
                sock.sendall((f"POST /expectation HTTP/1.1\r\nHost: localhost:{gate_port}\r\n"
                              "Content-Length: 3\r\nExpect: something-else\r\n\r\n").encode())
                assert sock.recv(1024).startswith(b"HTTP/1.1 417")

            status, headers, page = request("/report?x=1&y=2")
            assert status == 428 and b"phone-panel" in page and b"Finished" in page
            assert "worker-src 'self'" in headers["Content-Security-Policy"]
            assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
            assert headers["X-Content-Type-Options"] == "nosniff"
            assert headers["Referrer-Policy"] == "no-referrer"
            gate_headers = headers
            assert b"setTimeout(() => { panel.hidden = false; }, 10000)" in pathlib.Path(root, "challenge.js").read_bytes()
            worker_path = re.search(rb"data-worker='([^']*)'", page).group(1).decode()
            wasm_path = re.search(rb"data-wasm='([^']*)'", page).group(1).decode()
            if worker_path and wasm_path:
                status, headers, worker = request(worker_path)
                assert status == 200 and b"search_batch" in worker
                assert headers["Content-Type"].startswith("application/javascript")
                status, headers, module = request(wasm_path)
                assert status == 200 and headers["Content-Type"] == "application/wasm"
                assert headers["Cache-Control"] == "public, max-age=31536000, immutable"
                assert module.startswith(b"\x00asm")
                assert hashlib.sha256(module).hexdigest() in wasm_path
            sid = re.search(rb"data-session='([a-f0-9]{32})'", page).group(1).decode()
            challenge = re.search(rb"data-challenge='([^']+)'", page).group(1).decode()
            cookie = gate_headers["Set-Cookie"].split(";", 1)[0]
            status, headers, png = request(f"/ankah/qr/{sid}.png")
            assert status == 200 and headers["Content-Type"] == "image/png"
            assert png.startswith(b"\x89PNG\r\n\x1a\n")
            status, _, phone = request(f"/ankah/solve/{sid}")
            assert status == 200 and b"original page" in phone
            status, headers, _ = request(f"/ankah/answer/{sid}?answer={solve(challenge)}", "POST")
            assert status == 200 and "Set-Cookie" not in headers
            status, headers, _ = request(f"/ankah/finish/{sid}", headers={"Cookie": cookie})
            assert status == 303 and headers["Location"] == "/report?x=1&y=2"

            status, redirect_headers, redirect_page = request("//elsewhere.example/path")
            assert status == 428
            redirect_sid = re.search(
                rb"data-session='([a-f0-9]{32})'", redirect_page).group(1).decode()
            redirect_challenge = re.search(
                rb"data-challenge='([^']+)'", redirect_page).group(1).decode()
            redirect_cookie = redirect_headers["Set-Cookie"].split(";", 1)[0]
            status, _, _ = request(
                f"/ankah/answer/{redirect_sid}?answer={solve(redirect_challenge)}", "POST")
            assert status == 200
            status, redirect_headers, _ = request(
                f"/ankah/finish/{redirect_sid}", headers={"Cookie": redirect_cookie})
            assert status == 303
            assert redirect_headers["Location"] == (
                f"http://localhost:{gate_port}//elsewhere.example/path")

            status, _, payload = request(headers["Location"], headers={
                "Cookie": cookie,
                "Connection": "X-Remove",
                "X-Remove": "discarded",
                "Keep-Alive": "timeout=30",
                "X-Forwarded-For": "198.51.100.4",
                "X-Forwarded-Proto": "ftp",
                "Forwarded": "for=198.51.100.5"})
            assert status == 200 and payload == b"/report?x=1&y=2"
            forwarded = seen[-1][3]
            assert "X-Remove" not in forwarded and "Keep-Alive" not in forwarded
            assert forwarded["Connection"].lower() == "close"
            assert forwarded["X-Forwarded-For"] == "127.0.0.1"
            assert forwarded["X-Forwarded-Proto"] == "http"
            assert forwarded["X-Forwarded-Host"] == f"localhost:{gate_port}"
            assert "Forwarded" not in forwarded

            with socket.create_connection(("127.0.0.1", gate_port), timeout=5) as sock:
                sock.sendall((f"GET /socket HTTP/1.1\r\nHost: localhost:{gate_port}\r\n"
                              f"Cookie: {cookie}\r\nConnection: Upgrade, X-Remove\r\n"
                              "Upgrade: websocket\r\nX-Remove: discarded\r\n\r\n").encode())
                assert sock.recv(1024).startswith(b"HTTP/1.0 200")
            forwarded = seen[-1][3]
            assert forwarded["Connection"].lower() == "upgrade"
            assert forwarded["Upgrade"].lower() == "websocket"
            assert "X-Remove" not in forwarded

            multipart = (b"--boundary\r\nContent-Disposition: form-data; name=\"file\"; "
                         b"filename=\"a.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                         b"\x00original=bytes&x\xff\r\n--boundary--\r\n")
            original_headers = {"Content-Type": "multipart/form-data; boundary=boundary",
                                "X-Test-Replay": "exact"}
            status, headers, page = request("/upload?mode=fast", "POST", multipart, original_headers)
            assert status == 428 and b"method=post" in page
            sid = re.search(rb"data-session='([a-f0-9]{32})'", page).group(1).decode()
            token = re.search(rb"name=ankah_continue value='([a-f0-9]{32})'", page).group(1)
            challenge = re.search(rb"data-challenge='([^']+)'", page).group(1).decode()
            cookie = headers["Set-Cookie"].split(";", 1)[0]
            assert not seen[-1][0] == "POST"
            status, _, _ = request(f"/ankah/answer/{sid}?answer={solve(challenge)}", "POST")
            assert status == 200
            form = b"ankah_continue=" + token
            status, _, payload = request("/upload?mode=fast", "POST", form,
                                         {"Cookie": cookie,
                                          "Content-Type": "application/x-www-form-urlencoded"})
            assert status == 200 and payload == b"ok"
            assert seen[-1][0:3] == ("POST", "/upload?mode=fast", multipart)
            assert seen[-1][3]["Content-Type"] == original_headers["Content-Type"]
            assert seen[-1][3]["X-Test-Replay"] == "exact"
            status, _, _ = request("/upload?mode=fast", "POST", form,
                                   {"Cookie": cookie,
                                    "Content-Type": "application/x-www-form-urlencoded"})
            assert status != 200

            with socket.create_connection(("127.0.0.1", gate_port), timeout=5) as sock:
                sock.sendall((f"POST /expect HTTP/1.1\r\nHost: localhost:{gate_port}\r\n"
                              "Content-Length: 3\r\nExpect: 100-continue\r\n\r\n").encode())
                interim = sock.recv(256)
                assert interim.startswith(b"HTTP/1.1 100 Continue\r\n\r\n")
                sock.sendall(b"abc")
                response = sock.recv(8192)
                assert response.startswith(b"HTTP/1.1 428")

            with socket.create_connection(("127.0.0.1", gate_port), timeout=5) as sock:
                sock.sendall((f"POST /large HTTP/1.1\r\nHost: localhost:{gate_port}\r\n"
                              "Content-Length: 2097153\r\nExpect: 100-continue\r\n\r\n").encode())
                response = sock.recv(1024)
                assert response.startswith(b"HTTP/1.1 413")
        finally:
            process.terminate()
            process.wait(timeout=3)
            server.shutdown()


if __name__ == "__main__":
    main()
