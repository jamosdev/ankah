"""Exercise TLS, HTTP/2, credential reload, and trusted proxy handling."""

import hashlib
import http.server
import os
import pathlib
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from process_support import gateway_command


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def certificate(directory, name, common_name):
    key = directory / f"{name}-key.pem"
    cert = directory / f"{name}-cert.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-subj", f"/CN={common_name}", "-keyout", str(key), "-out", str(cert),
        "-days", "1",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


def peer_certificate(gate_port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection(("127.0.0.1", gate_port), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as wrapped:
            return hashlib.sha256(wrapped.getpeercert(binary_form=True)).digest(), \
                   wrapped.selected_alpn_protocol()


def curl(gate_port, path, version="--http2", method="GET", body=None, headers=(), extra=()):
    command = [
        "curl", "--silent", "--show-error", "--insecure", "--noproxy", "*",
        version, f"https://127.0.0.1:{gate_port}{path}",
        "--header", f"Host: localhost:{gate_port}",
        "--write-out", "\nANKAH_RESULT:%{http_code}:%{http_version}",
    ]
    command.extend(extra)
    for header in headers:
        command.extend(["--header", header])
    if method != "GET":
        command.extend(["--request", method, "--data-binary", "@-"])
    result = subprocess.run(command, input=body, capture_output=True, timeout=8)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    payload, marker = result.stdout.rsplit(b"\nANKAH_RESULT:", 1)
    status, protocol = marker.decode().split(":", 1)
    return int(status), protocol, payload


def main():
    executable, root = sys.argv[1:]
    gate_port, app_port = port(), port()
    seen = []

    class App(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            seen.append(dict(self.headers))
            if self.path.startswith("/allowed/parallel/"):
                time.sleep(.05)
            if self.path == "/allowed/chunked":
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("X-Upstream", "chunked")
                self.end_headers()
                self.wfile.write(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
            else:
                payload = self.path.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        def do_POST(self):
            payload = self.rfile.read(int(self.headers["Content-Length"]))
            seen.append(dict(self.headers))
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", app_port), App)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()

    with tempfile.TemporaryDirectory() as temporary:
        directory = pathlib.Path(temporary)
        secret = directory / "secret"
        secret.write_text("a" * 64)
        static_source = directory / "static"
        static_source.mkdir()
        static_payload = (b"0123456789abcdefghijklmnopqrstuvwxyz" * 256)
        (static_source / "large.txt").write_bytes(static_payload)
        static_bundle = directory / "bundle"
        subprocess.run([
            sys.executable, str(pathlib.Path(root) / "build_static_bundle.py"),
            "--project-root", str(directory), "--source", "static",
            "--output", str(static_bundle),
        ], check=True)
        active_cert, active_key = certificate(directory, "active", "first.local")
        first_key = active_key.read_bytes()
        _, unrelated_key = certificate(directory, "unrelated", "unrelated.local")
        base_options = [
            "--listen", f"127.0.0.1:{gate_port}",
            "--upstream", f"127.0.0.1:{app_port}",
            "--public-origin", f"https://localhost:{gate_port}",
            "--secret-file", str(secret), "--assets-dir", root,
        ]
        incomplete = subprocess.run(
            gateway_command(executable, [*base_options, "--tls-cert", str(active_cert)]),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        assert incomplete.returncode == 2
        mismatch = subprocess.run(gateway_command(executable, [
            *base_options, "--tls-cert", str(active_cert),
            "--tls-key", str(unrelated_key),
        ]), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        assert mismatch.returncode == 1
        process = subprocess.Popen(gateway_command(executable, [
            *base_options,
            "--static-bundle", str(static_bundle),
            "--tls-cert", str(active_cert), "--tls-key", str(active_key),
            "--trusted-proxy", "127.0.0.0/8", "--trusted-proxy", "10.0.0.0/8",
            "--allow-prefix", "/allowed",
        ]), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(300):
                try:
                    first_hash, protocol = peer_certificate(gate_port)
                    break
                except OSError:
                    time.sleep(.02)
            else:
                raise RuntimeError("TLS gateway did not start")
            assert protocol == "h2"

            status, protocol, payload = curl(
                gate_port, "/blocked", "--http1.1",
                headers=("User-Agent: Mozilla/5.0",))
            assert status == 428 and protocol.startswith("1.") and b"phone-panel" in payload

            status, protocol, page = curl(
                gate_port, "/blocked-h2", headers=("User-Agent: Mozilla/5.0",))
            assert status == 428 and protocol == "2" and b"phone-panel" in page
            worker_path = re.search(rb"data-worker='([^']*)'", page).group(1).decode()
            if worker_path:
                status, protocol, worker_script = curl(gate_port, worker_path)
                assert status == 200 and protocol == "2" and b"search_batch" in worker_script

            status, protocol, payload = curl(
                gate_port, "/static/large.txt", extra=("--compressed",))
            assert status == 200 and protocol == "2" and payload == static_payload
            status, protocol, payload = curl(
                gate_port, "/static/large.txt", headers=("Range: bytes=10-29",))
            assert status == 206 and protocol == "2" and payload == static_payload[10:30]

            status, protocol, payload = curl(gate_port, "/allowed/chunked")
            assert status == 200 and protocol == "2" and payload == b"hello world"

            posted = b"multipart-looking\x00body\xff"
            status, protocol, payload = curl(
                gate_port, "/allowed/post", method="POST", body=posted)
            assert status == 200 and protocol == "2" and payload == posted

            status, _, payload = curl(gate_port, "/allowed/proxy", headers=(
                "Forwarded: for=198.51.100.7;proto=https, for=10.2.3.4",
                "X-Forwarded-For: 203.0.113.9",
            ))
            assert status == 200 and payload == b"/allowed/proxy"
            assert seen[-1]["X-Forwarded-For"] == "198.51.100.7"
            assert seen[-1]["X-Forwarded-Proto"] == "https"
            assert seen[-1]["X-Forwarded-Host"] == f"localhost:{gate_port}"
            assert "Forwarded" not in seen[-1]

            parallel = [
                "curl", "--silent", "--show-error", "--insecure", "--noproxy", "*",
                "--http2", "--parallel", "--parallel-max", "8",
                "--header", f"Host: localhost:{gate_port}",
                "--write-out", "MUX:%{http_code}:%{http_version}:%{num_connects}\n",
            ]
            for number in range(8):
                parallel.extend([
                    "--output", os.devnull,
                    f"https://127.0.0.1:{gate_port}/allowed/parallel/{number}",
                ])
            multiplexed = subprocess.run(
                parallel, capture_output=True, check=True, timeout=8).stdout.decode().splitlines()
            assert len(multiplexed) == 8
            fields = [line.split(":") for line in multiplexed]
            assert all(parts[:3] == ["MUX", "200", "2"] for parts in fields)
            assert sum(int(parts[3]) for parts in fields) == 1

            active_key.write_text("invalid key\n")
            if os.environ.get("ANKAH_TEST_WINDOWS_PATHS") != "1":
                process.send_signal(signal.SIGHUP)
            time.sleep(.8)
            retained_hash, _ = peer_certificate(gate_port)
            assert retained_hash == first_hash
            active_key.write_bytes(first_key)

            second_cert, second_key = certificate(directory, "replacement", "second.local")
            shutil.copyfile(second_cert, active_cert)
            shutil.copyfile(second_key, active_key)
            if os.environ.get("ANKAH_TEST_WINDOWS_PATHS") != "1":
                process.send_signal(signal.SIGHUP)
            for _ in range(100):
                time.sleep(.05)
                try:
                    second_hash, _ = peer_certificate(gate_port)
                    if second_hash != first_hash:
                        break
                except OSError:
                    pass
            else:
                raise AssertionError("TLS credentials were not reloaded")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            server.shutdown()
            if process.returncode not in (0, -15, 1):
                raise RuntimeError(process.stderr.read().decode(errors="replace"))


if __name__ == "__main__":
    main()
