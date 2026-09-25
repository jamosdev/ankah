"""Exercise the unlock route, refusals of request bodies, and large uploads."""

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

from process_support import gateway_command


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


def exchange(gate_port, head, body=b"", timeout=10):
    """Send one raw request and return every byte until the gateway closes."""
    chunks = []
    with socket.create_connection(("127.0.0.1", gate_port), timeout=timeout) as sock:
        try:
            sock.sendall(head.encode("latin-1") + body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        while True:
            try:
                chunk = sock.recv(65536)
            except ConnectionResetError:
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def parse(reply):
    head, _, body = reply.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ")[1])
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return status, headers, body


def main():
    executable, root = sys.argv[1:]
    gate_port, app_port = port(), port()
    sized_port, capped_port = port(), port()
    origin = f"http://localhost:{gate_port}"
    seen = []
    early_started = threading.Event()
    early_body_release = threading.Event()
    chunked_final_release = threading.Event()
    chunked_final_stalled = threading.Event()
    early_body = b"split response body\n" * 4096

    class App(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(("GET", self.path))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def do_POST(self):
            if self.path == "/upload/early-reply":
                self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                early_started.set()
                self.wfile.write(b"HTTP/1.1 409 Conflict\r\n"
                                 b"Content-Length: %d\r\n"
                                 b"Connection: close\r\n\r\n" % len(early_body))
                self.wfile.flush()
                early_body_release.wait(5)
                self.wfile.write(early_body)
                self.wfile.flush()
                self.connection.shutdown(socket.SHUT_WR)
                self.connection.settimeout(5)
                try:
                    while self.connection.recv(65536):
                        pass
                except (ConnectionResetError, socket.timeout):
                    pass
                self.close_connection = True
                return
            if self.path == "/upload/interim-reply":
                self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                self.wfile.flush()
            if self.path == "/upload/chunked-final":
                self.wfile.write(b"HTTP/1.1 409 Conflict\r\n"
                                 b"Content-Length: 0\r\n"
                                 b"Connection: close\r\n\r\n")
                self.wfile.flush()
                self.connection.settimeout(.1)
                received = 0
                while not chunked_final_release.is_set():
                    try:
                        data = self.connection.recv(65536)
                        if not data:
                            break
                        received += len(data)
                    except socket.timeout:
                        if received >= (16 << 20) - (128 << 10):
                            chunked_final_stalled.set()
                self.close_connection = True
                return
            digest = hashlib.sha256()
            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                while True:
                    size = int(self.rfile.readline().split(b";", 1)[0], 16)
                    if not size:
                        while self.rfile.readline() not in (b"\r\n", b""):
                            pass
                        break
                    digest.update(self.rfile.read(size))
                    assert self.rfile.read(2) == b"\r\n"
            else:
                remaining = int(self.headers["Content-Length"])
                while remaining:
                    chunk = self.rfile.read(min(remaining, 1 << 20))
                    if not chunk:
                        break
                    digest.update(chunk)
                    remaining -= len(chunk)
            seen.append(("POST", self.path))
            payload = digest.hexdigest().encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", app_port), App)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()

    def request(path, method="GET", body=None, headers=None, target=None, timeout=5):
        target = target or gate_port
        client = http.client.HTTPConnection("127.0.0.1", target, timeout=timeout)
        client.request(method, path, body=body,
                       headers={"Host": f"localhost:{target}", **(headers or {})})
        reply = client.getresponse()
        result = reply.status, dict(reply.getheaders()), reply.read()
        client.close()
        return result

    def head(method, path, *lines, target=None):
        target = target or gate_port
        return "".join([f"{method} {path} HTTP/1.1\r\n", f"Host: localhost:{target}\r\n",
                        *(line + "\r\n" for line in lines), "\r\n"])

    def upload(path, size, target):
        """Send a body of size bytes and check the upstream hashed all of it."""
        body = bytes(range(256)) * (size // 256)
        expected = hashlib.sha256(body).hexdigest().encode()
        status, _, digest = request(path, "POST", body, target=target, timeout=60)
        assert status == 200 and digest == expected, (path, size, status)

    def refused(path, size, target):
        reply = exchange(target, head("POST", path, f"Content-Length: {size}", target=target))
        return parse(reply)

    def gate_parts(page, headers):
        sid = re.search(rb"data-session='([a-f0-9]{32})'", page).group(1).decode()
        challenge = re.search(rb"data-challenge='([^']+)'", page).group(1).decode()
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        return sid, challenge, cookie

    def unlock(path, headers=None):
        """Solve the challenge an unlock page issues and return the redirect."""
        status, gate_headers, page = request(path, headers=headers)
        assert status == 428, (path, status)
        sid, challenge, cookie = gate_parts(page, gate_headers)
        answer = solve(challenge)
        status, _, _ = request(f"/ankah/answer/{sid}?answer={answer}", "POST")
        assert status == 200
        status, finish_headers, _ = request(f"/ankah/finish/{sid}", headers={"Cookie": cookie})
        assert status == 303
        return sid, cookie, finish_headers

    with tempfile.TemporaryDirectory() as temp:
        secret = pathlib.Path(temp) / "secret"
        secret.write_text("a" * 64)

        def arguments(listen, *extra):
            return ["--listen", f"127.0.0.1:{listen}", "--upstream", f"127.0.0.1:{app_port}",
                    "--public-origin", f"http://localhost:{listen}",
                    "--secret-file", str(secret), "--assets-dir", root, *extra]

        for extra in [["--max-upload-mb", "abc"], ["--max-upload-mb", "8"],
                      ["--max-upload-mb", "1048577"]]:
            result = subprocess.run(gateway_command(executable, arguments(port(), *extra)),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=30)
            assert result.returncode == 2, extra

        gateways = {
            gate_port: ["--allow-prefix", "/upload", "--ankah-healthz=/healthz"],
            sized_port: ["--allow-prefix", "/upload", "--max-upload-mb", "32"],
            capped_port: ["--allow-prefix", "/upload", "--max-upload-mb", "0"],
        }
        processes = [subprocess.Popen(gateway_command(executable, arguments(listen, *extra)),
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                     for listen, extra in gateways.items()]
        try:
            for listen in gateways:
                for _ in range(250):
                    try:
                        status, _, _ = request("/ready", target=listen)
                        if status == 428:
                            break
                    except OSError:
                        pass
                    time.sleep(.02)
                else:
                    raise RuntimeError("gateway did not start")

            # A local reply is sent once even while the body keeps arriving.
            body = b"x" * 65536
            reply = exchange(gate_port, head("POST", "/ankah/nowhere",
                                             f"Content-Length: {len(body)}"), body)
            status_lines = reply.count(b"HTTP/1.1 ")
            assert reply.startswith(b"HTTP/1.1 404"), reply[:200]
            assert status_lines == 1, reply

            # The upstream replies in two writes without reading the upload.
            # The gateway must flush the complete reply before closing its socket.
            with socket.create_connection(("127.0.0.1", gate_port), timeout=5) as sock:
                sock.settimeout(.25)
                sock.sendall(head("POST", "/upload/early-reply",
                                  "Content-Length: 67108864").encode())
                assert early_started.wait(3), "early-reply application did not start"
                block = b"x" * 65536
                sent = 0
                while sent < (16 << 20):
                    try:
                        sent += sock.send(block)
                    except socket.timeout:
                        break
                sock.settimeout(5)
                reply = bytearray()
                try:
                    while b"\r\n\r\n" not in reply:
                        chunk = sock.recv(65536)
                        assert chunk, "early reply ended before its headers"
                        reply.extend(chunk)
                    early_body_release.set()
                    while len(reply.partition(b"\r\n\r\n")[2]) < len(early_body):
                        chunk = sock.recv(65536)
                        assert chunk, "early reply ended before its body"
                        reply.extend(chunk)
                    sock.shutdown(socket.SHUT_WR)
                    while True:
                        try:
                            chunk = sock.recv(65536)
                        except socket.timeout as error:
                            raise AssertionError(f"early reply stalled after {len(reply)} bytes") from error
                        if not chunk:
                            break
                        reply.extend(chunk)
                finally:
                    early_body_release.set()
            status, headers, text = parse(reply)
            assert status == 409 and int(headers["content-length"]) == len(early_body)
            assert text == early_body, (len(text), len(early_body))

            # The unlock page issues a challenge and returns to / by default.
            first_sid, cookie, finish = unlock("/ankah/unlock")
            assert finish["Location"] == "/"
            status, _, payload = request("/app", headers={"Cookie": cookie})
            assert status == 200 and payload == b"ok"

            # An allowed client still gets a fresh challenge.
            status, headers, page = request("/ankah/unlock", headers={"Cookie": cookie})
            assert status == 428
            fresh_sid, _, fresh_cookie = gate_parts(page, headers)
            assert fresh_sid != first_sid and fresh_cookie != cookie

            _, _, finish = unlock("/ankah/unlock?return=/report?x=1&y=2")
            assert finish["Location"] == "/report?x=1&y=2"
            _, _, finish = unlock("/ankah/unlock?return=/a%0d%0aX-Injected:1")
            assert finish["Location"] == "/a%0d%0aX-Injected:1"
            assert "X-Injected" not in finish

            # Returning to the unlock page itself repeats the proof of work.
            loop_sid, loop_cookie, finish = unlock("/ankah/unlock?return=/ankah/unlock")
            assert finish["Location"] == "/ankah/unlock"
            status, headers, page = request(finish["Location"], headers={"Cookie": loop_cookie})
            assert status == 428
            next_sid, _, _ = gate_parts(page, headers)
            assert next_sid != loop_sid

            for query in ["?return=", "?return=rel", "?return=//evil.example/",
                          "?return=/\\evil", "?next=/x", "?a=1&return=/x"]:
                status, _, _ = request("/ankah/unlock" + query)
                assert status == 400, (query, status)
            reply = exchange(gate_port, head("GET", "/ankah/unlock?return=/\xff"))
            assert reply.startswith(b"HTTP/1.1 400"), reply[:100]
            status, _, _ = request("/ankah/unlockx")
            assert status == 404
            status, _, _ = request("/ankah/unlock", "POST", b"")
            assert status == 404

            status, headers, text = request("/ankah/unlock", headers={"User-Agent": "curl/8.5.0"})
            assert status == 302
            assert headers["Location"].startswith("/ankah/blocked/run-ankah-challenge-")
            assert b"curl -fsSL" in text

            # A blocked upload links a browser back through the unlock page.
            declared = "Content-Length: 3145728"
            referer = f"Referer: {origin}/form?a=1&b='x'"
            reply = exchange(gate_port, head("POST", "/api/upload", declared, referer,
                                             "Accept: text/html,*/*;q=0.8"))
            status, headers, page = parse(reply)
            status_lines = reply.count(b"HTTP/1.1 ")
            assert status == 413 and status_lines == 1
            assert headers["content-type"] == "text/html; charset=utf-8"
            assert "default-src 'none'" in headers["content-security-policy"]
            link = f"{origin}/ankah/unlock?return=/form?a=1&amp;b=&#39;x&#39;"
            assert f"<a href='{link}'>Unlock</a>".encode() in page, page

            reply = exchange(gate_port, head("POST", "/api/upload", declared, referer))
            status, headers, text = parse(reply)
            assert status == 413 and headers["content-type"].startswith("text/plain")
            assert text == (b"Unlock, then retry this upload.\n"
                            + f"Unlock: {origin}/ankah/unlock?return=/form?a=1&b='x'\n".encode())

            reply = exchange(gate_port, head("POST", "/api/upload", declared,
                                             "Referer: http://elsewhere.example/form"))
            status, _, text = parse(reply)
            assert status == 413 and text.endswith(f"Unlock: {origin}/ankah/unlock\n".encode())

            reply = exchange(gate_port, head("POST", "/api/upload", declared,
                                             "User-Agent: curl/8.5.0"))
            status, headers, text = parse(reply)
            assert status == 413 and "location" not in headers
            assert text.startswith(b"Unlock, then retry this upload.\n")
            assert b"curl -fsSL" in text

            status, headers, text = request("/api/item", "PUT", b"abc")
            assert status == 405 and headers["Allow"] == "GET, POST"
            assert text == (b"Unlock, then retry this method.\n"
                            + f"Unlock: {origin}/ankah/unlock\n".encode())

            # Allowed clients may forward bodies past the 16 MiB local limit.
            upload("/upload/default", 17 << 20, gate_port)
            status, _, text = refused("/upload/default", (1 << 30) + 1, gate_port)
            assert status == 413 and text == b"Request body too large\n"
            for path in ["/ankah/x", "/healthz"]:
                status, _, text = refused(path, 20 << 20, gate_port)
                assert status == 413 and text == b"Request body too large\n", path
            reply = exchange(gate_port, head("POST", "/upload/chunked",
                                             "Transfer-Encoding: chunked"), b"0\r\n\r\n")
            status, _, text = parse(reply)
            assert status == 200 and text == hashlib.sha256(b"").hexdigest().encode()
            status, _, text = refused("/api/large", 20 << 20, gate_port)
            assert status == 413 and text.startswith(b"Unlock, then retry this upload.\n")
            assert f"Unlock: {origin}/ankah/unlock\n".encode() in text

            upload("/upload/sized", 20 << 20, sized_port)
            status, _, _ = refused("/upload/sized", (32 << 20) + 1, sized_port)
            assert status == 413
            status, _, _ = refused("/upload/capped", 17 << 20, capped_port)
            assert status == 413

            oversized_chunk = (16 << 20) + 1
            oversized_body = (f"{oversized_chunk:x}\r\n".encode() +
                              b"x" * oversized_chunk)
            reply = exchange(capped_port,
                             head("POST", "/upload/chunked",
                                  "Transfer-Encoding: chunked", target=capped_port),
                             oversized_body)
            status, _, text = parse(reply)
            assert status == 413 and text == b"Request body too large\n"
            reply = exchange(capped_port,
                             head("POST", "/upload/interim-reply",
                                  "Transfer-Encoding: chunked", target=capped_port),
                             oversized_body)
            assert reply.startswith(b"HTTP/1.1 100 Continue\r\n\r\n"), reply[:100]
            status, _, text = parse(reply.split(b"\r\n\r\n", 1)[1])
            assert status == 413 and text == b"Request body too large\n"

            with socket.create_connection(("127.0.0.1", capped_port), timeout=10) as sock:
                sock.settimeout(10)
                sock.sendall(head("POST", "/upload/chunked",
                                  "Transfer-Encoding: chunked",
                                  target=capped_port).encode() + oversized_body)
                reply = bytearray()
                while (b"\r\n\r\n" not in reply or
                       len(reply.partition(b"\r\n\r\n")[2]) <
                       len(b"Request body too large\n")):
                    chunk = sock.recv(65536)
                    assert chunk, "413 ended before its complete body"
                    reply.extend(chunk)
                status, _, text = parse(reply)
                assert status == 413 and text == b"Request body too large\n"
                sock.sendall(b"x" * 65536)
                sock.shutdown(socket.SHUT_WR)
                assert sock.recv(65536) == b"", "413 connection did not close cleanly"

            with socket.create_connection(("127.0.0.1", capped_port), timeout=10) as sock:
                sock.settimeout(10)
                sock.sendall(head("POST", "/upload/chunked-final",
                                  "Transfer-Encoding: chunked",
                                  target=capped_port).encode())
                reply = bytearray()
                while b"\r\n\r\n" not in reply:
                    chunk = sock.recv(65536)
                    assert chunk, "upstream 409 ended before its headers"
                    reply.extend(chunk)
                assert parse(reply)[0] == 409, reply[:100]
                sock.sendall(oversized_body)
                assert chunked_final_stalled.wait(5), \
                    "upload did not reach the 16 MiB limit"
                sock.shutdown(socket.SHUT_WR)
                chunked_final_release.set()
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    reply.extend(chunk)
                assert reply.count(b"HTTP/1.1 ") == 1, reply[:200]

            forwarded = [path for method, path in seen if method == "POST"]
            assert forwarded == ["/upload/default", "/upload/chunked", "/upload/sized"], forwarded
            leaked = [path for _, path in seen if path.startswith("/ankah/")]
            assert not leaked, leaked
        finally:
            chunked_final_release.set()
            for process in processes:
                process.terminate()
            for process in processes:
                process.wait(timeout=3)
            server.shutdown()


if __name__ == "__main__":
    main()
