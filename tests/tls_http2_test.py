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

from http2_client import Client as Http2Client
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
    drain_started = threading.Event()
    drain_release = threading.Event()
    upload_started = threading.Event()
    upload_release = threading.Event()
    upload_result = {}
    early_started = {}
    early_abandoned = set()
    early_response = threading.Event()
    early_body_release = threading.Event()
    early_closed = threading.Event()
    early_body = b"early response body\n"
    held_started = [threading.Event() for _ in range(8)]
    held_release = threading.Event()
    probe_finished = threading.Event()

    class App(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            seen.append(dict(self.headers))
            if self.path.startswith("/allowed/parallel/"):
                time.sleep(.05)
            if self.path == "/allowed/drain":
                drain_started.set()
                drain_release.wait(10)
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
            if self.path == "/allowed/drop-upload":
                self.connection.shutdown(socket.SHUT_RDWR)
                self.close_connection = True
                return
            if self.path == "/allowed/early-limit":
                self.send_response(409)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                if os.environ.get("ANKAH_TEST_WINDOWS_PATHS") == "1":
                    # Let Wine deliver the reply before closing with unread input.
                    self.wfile.flush()
                    time.sleep(.5)
                self.close_connection = True
                return
            if self.path.startswith("/allowed/early-response/"):
                attempt = int(self.path.rsplit("/", 1)[1])
                self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                early_started[attempt].set()
                early_response.wait(30)
                if attempt in early_abandoned:
                    self.close_connection = True
                    return
                self.wfile.write(b"HTTP/1.1 409 Conflict\r\n"
                                 b"Content-Length: %d\r\n"
                                 b"Connection: close\r\n\r\n" % len(early_body))
                self.wfile.flush()
                early_body_release.wait(5)
                self.wfile.write(early_body)
                self.wfile.flush()
                self.connection.shutdown(socket.SHUT_WR)
                early_closed.set()
                self.connection.settimeout(5)
                try:
                    while self.connection.recv(65536):
                        pass
                except (ConnectionResetError, socket.timeout):
                    pass
                self.close_connection = True
                return
            if self.path.startswith("/allowed/held/"):
                number = int(self.path.rsplit("/", 1)[1])
                self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                held_started[number].set()
                held_release.wait(30)
                self.close_connection = True
                return
            if self.path == "/allowed/stalled-upload":
                time.sleep(4)
                remaining = int(self.headers["Content-Length"])
                digest = hashlib.sha256()
                while remaining:
                    chunk = self.rfile.read(min(remaining, 1 << 20))
                    if not chunk:
                        break
                    digest.update(chunk)
                    remaining -= len(chunk)
                payload = digest.hexdigest().encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if self.path == "/allowed/delayed-reply":
                remaining = int(self.headers["Content-Length"])
                while remaining:
                    chunk = self.rfile.read(min(remaining, 1 << 20))
                    if not chunk:
                        return
                    remaining -= len(chunk)
                self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                self.wfile.flush()
                time.sleep(32)
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            payload = self.rfile.read(int(self.headers["Content-Length"]))
            if self.path == "/allowed/latency-upload":
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/allowed/probe":
                probe_finished.set()
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            seen.append(dict(self.headers))
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_PATCH(self):
            if self.path == "/allowed/reject-upload":
                self.send_response(409)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            remaining = int(self.headers["Content-Length"])
            digest = hashlib.sha256()
            first = self.rfile.read(min(remaining, 65536))
            digest.update(first)
            remaining -= len(first)
            upload_started.set()
            upload_release.wait(10)
            while remaining:
                chunk = self.rfile.read(min(remaining, 1 << 20))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
            upload_result["digest"] = digest.hexdigest()
            upload_result["size"] = int(self.headers["Content-Length"]) - remaining
            self.send_response(204)
            self.send_header("Tus-Resumable", "1.0.0")
            self.send_header("Upload-Offset", str(upload_result["size"]))
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", app_port), App)
    server.daemon_threads = True
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
        (static_source / "downloads").mkdir()
        (static_source / "downloads" / "protected.bin").write_bytes(static_payload)
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
            "--static-throttle-prefix", "/static/downloads/",
            "--static-throttle-global-connections", "2",
            "--static-throttle-client-connections", "1",
            "--static-throttle-global-mbps", "50",
            "--tls-cert", str(active_cert), "--tls-key", str(active_key),
            "--trusted-proxy", "127.0.0.0/8", "--trusted-proxy", "10.0.0.0/8",
            "--allow-prefix", "/allowed", "--max-upload-mb", "64",
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
            status, protocol, localized_page = curl(
                gate_port, "/blocked-h2-ja",
                headers=("User-Agent: Mozilla/5.0", "Accept-Language: ja-JP"))
            assert status == 428 and protocol == "2"
            assert b"<html lang=ja>" in localized_page
            assert "ブラウザーを確認しています".encode() in localized_page
            worker_path = re.search(rb"data-worker='([^']*)'", page).group(1).decode()
            if worker_path:
                status, protocol, worker_script = curl(gate_port, worker_path)
                assert status == 200 and protocol == "2" and b"search_batch" in worker_script

            status, protocol, payload = curl(
                gate_port, "/static/large.txt", extra=("--compressed",))
            assert status == 200 and protocol == "2" and payload == static_payload
            status, protocol, payload = curl(
                gate_port, "/static/downloads/protected.bin",
                headers=("User-Agent: Mozilla/5.0",))
            assert status == 428 and protocol == "2" and b"phone-panel" in payload
            status, protocol, payload = curl(
                gate_port, "/static/large.txt", headers=("Range: bytes=10-29",))
            assert status == 206 and protocol == "2" and payload == static_payload[10:30]

            status, protocol, payload = curl(gate_port, "/allowed/chunked")
            assert status == 200 and protocol == "2" and payload == b"hello world"

            posted = b"multipart-looking\x00body\xff"
            status, protocol, payload = curl(
                gate_port, "/allowed/post", method="POST", body=posted)
            assert status == 200 and protocol == "2" and payload == posted

            status, protocol, payload = curl(
                gate_port, "/allowed/post", method="POST", body=posted,
                headers=("Content-Length:",))
            assert status == 200 and protocol == "2" and payload == posted

            large_upload = bytes(range(256)) * (17 * 4096 + 1)
            upload_headers = directory / "upload-headers"
            command = [
                "curl", "--silent", "--show-error", "--insecure", "--noproxy", "*",
                "--http2", "--request", "PATCH", "--upload-file", "-",
                "--header", f"Host: localhost:{gate_port}",
                "--header", f"Content-Length: {len(large_upload)}",
                "--header", "Tus-Resumable: 1.0.0",
                "--header", "Content-Type: application/offset+octet-stream",
                "--dump-header", str(upload_headers), "--output", os.devnull,
                "--write-out", "%{http_code}:%{http_version}",
                f"https://127.0.0.1:{gate_port}/allowed/tus",
            ]
            uploading = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            try:
                first = 65536
                uploading.stdin.write(large_upload[:first])
                uploading.stdin.flush()
                assert upload_started.wait(8), \
                    "application did not receive the partial streaming body"
                upload_release.set()
                stdout, stderr = uploading.communicate(
                    input=large_upload[first:], timeout=30)
            except BaseException:
                upload_release.set()
                if uploading.poll() is None:
                    uploading.kill()
                uploading.communicate()
                raise
            assert uploading.returncode == 0, stderr.decode(errors="replace")
            assert stdout == b"204:2", stdout
            response_headers = upload_headers.read_text().lower()
            assert f"upload-offset: {len(large_upload)}\n" in response_headers
            assert upload_result == {
                "digest": hashlib.sha256(large_upload).hexdigest(),
                "size": len(large_upload),
            }

            h2 = Http2Client("127.0.0.1", gate_port)
            try:
                h2.wait_for(lambda: h2.connection_window >= 16 << 20, 3,
                            "16 MiB connection receive window")
                assert h2.initial_stream_window == 512 << 10
                h2.window_update_delay = 4
                amount = 2 << 20
                h2.request(1, "POST", "/allowed/latency-upload",
                           f"localhost:{gate_port}", amount)
                sent = 0
                after_initial_window = None
                deadline = time.monotonic() + 35
                block = b"x" * 16384
                while sent < amount and time.monotonic() < deadline:
                    size = min(len(block), amount - sent)
                    count = h2.send_data(1, block[:size],
                                         end_stream=sent + size == amount)
                    if count:
                        sent += count
                        if sent == h2.initial_stream_window:
                            after_initial_window = time.monotonic()
                    else:
                        h2.receive(.05)
                assert sent == amount, f"sent {sent} of {amount} bytes"
                assert after_initial_window is not None
                sustained = ((amount - h2.initial_stream_window) /
                             (time.monotonic() - after_initial_window))
                assert sustained > 65536, f"{sustained / 1024:.1f} KiB/s"
                h2.wait_for(lambda: 1 in h2.ended, 5, "latency upload response")
                assert 1 not in h2.resets, h2.resets
            finally:
                h2.close()

            h2 = Http2Client("127.0.0.1", gate_port)
            try:
                h2.request(1, "POST", "/allowed/drop-upload",
                           f"localhost:{gate_port}", 17 << 20)
                h2.send_body(1, 512 << 10, 5, end_stream=False)
                h2.wait_for(lambda: 1 in h2.ended, 5,
                            "upstream close without a response")
                assert h2.received.get(1, 0) > 0, h2.response_headers[1]
                h2.request(3, "GET", "/allowed/after-drop",
                           f"localhost:{gate_port}")
                h2.wait_for(lambda: 3 in h2.ended, 5,
                            "request after failed upload")
                assert 3 not in h2.resets, h2.resets
            finally:
                h2.close()

            h2 = Http2Client("127.0.0.1", gate_port)
            try:
                h2.request(1, "POST", "/allowed/delayed-reply",
                           f"localhost:{gate_port}", 17 << 20)
                h2.send_body(1, 17 << 20, 30)
                h2.wait_for(lambda: 1 in h2.ended, 40,
                            "large upload final reply after interim response")
                assert h2.response_headers[1][0].startswith(b"\x89"), \
                    h2.response_headers[1]
                assert 1 not in h2.resets, h2.resets
            finally:
                h2.close()

            if os.environ.get("ANKAH_TEST_WINDOWS_PATHS") == "1":
                # Wine loses an immediate upstream reply when the fixture closes
                # with the large request body unread.
                status, protocol, payload = curl(gate_port, "/allowed/reject-upload",
                                                 method="PATCH", body=b"")
                assert (status, protocol, payload) == (409, "2", b"")
                status, protocol, payload = curl(gate_port, "/allowed/concurrent")
                assert (status, protocol, payload) == (200, "2", b"/allowed/concurrent")
            else:
                rejected_body = directory / "rejected-body"
                concurrent_body = directory / "concurrent-body"
                rejected = subprocess.run([
                    "curl", "--silent", "--show-error", "--insecure", "--noproxy", "*",
                    "--parallel", "--parallel-max", "2",
                    "--http2", "--request", "PATCH", "--data-binary", "@-",
                    "--header", f"Host: localhost:{gate_port}",
                    "--output", str(rejected_body),
                    "--write-out", "REJECT:%{http_code}:%{http_version}:%{num_connects}\n",
                    f"https://127.0.0.1:{gate_port}/allowed/reject-upload",
                    "--next", "--silent", "--show-error", "--insecure", "--noproxy", "*",
                    "--http2", "--header", f"Host: localhost:{gate_port}",
                    "--output", str(concurrent_body),
                    "--write-out", "OTHER:%{http_code}:%{http_version}:%{num_connects}\n",
                    f"https://127.0.0.1:{gate_port}/allowed/concurrent",
                ], input=large_upload, capture_output=True, timeout=8)
                assert rejected.returncode == 0, rejected.stderr.decode(errors="replace")
                results = rejected.stdout.decode().splitlines()
                assert "REJECT:409:2:1" in results, results
                assert "OTHER:200:2:0" in results, results
                assert rejected_body.read_bytes() == b""
                assert concurrent_body.read_bytes() == b"/allowed/concurrent"

            authority = f"localhost:{gate_port}"
            h2 = Http2Client("127.0.0.1", gate_port)
            try:
                h2.request(1, "POST", "/allowed/early-limit", authority,
                           end_stream=False)
                h2.send_body(1, 16 << 20, 30)
                h2.wait_for(lambda: 1 in h2.ended, 3,
                            "accepted 16 MiB unknown-length upload")
                assert h2.response_status[1] == b"409", h2.response_status[1]
                assert 1 not in h2.resets, h2.resets

                h2.request(3, "POST", "/allowed/early-limit", authority,
                           end_stream=False)
                h2.receive_window(0)
                h2.ping(b"limit-00")
                h2.wait_for(lambda: b"limit-00" in h2.pings, 3,
                            "zero response window")
                h2.send_body(3, (16 << 20) + 1, 30, end_stream=False)
                h2.wait_for(lambda: 3 in h2.responses, 3,
                            "413 without request END_STREAM")
                assert h2.response_status[3] == b"413", h2.response_status[3]
                assert 3 not in h2.resets, h2.resets
                h2.receive_window(65535)
                h2.wait_for(lambda: 3 in h2.ended, 3, "complete 413 response")
                h2.wait_for(lambda: 3 in h2.resets, 3, "oversized upload reset")
                assert h2.resets[3] == 0, h2.resets
                events = [event[1:] for event in h2.events if event[0] == 3]
                assert events.index((0, True)) < events.index((3, False)), events

                h2.request(5, "GET", "/allowed/after-oversized", authority)
                h2.wait_for(lambda: 5 in h2.ended, 3,
                            "request after oversized upload")
                assert 5 not in h2.resets, h2.resets
            finally:
                h2.close()

            h2 = Http2Client("127.0.0.1", gate_port)
            try:
                for stream_id in (1, 3, 5, 7):
                    h2.request(stream_id, "POST", "/allowed/early-limit",
                               authority, end_stream=False)
                    h2.send_body(stream_id, 16 << 20, 30, end_stream=False)
                h2.request(9, "POST", "/allowed/early-limit", authority,
                           end_stream=False)
                h2.send_data(9, b"x")
                h2.wait_for(lambda: 9 in h2.ended, 3,
                            "503 at shared buffer cap")
                assert h2.response_status[9] == b"503", h2.response_status[9]
                h2.wait_for(lambda: 9 in h2.resets, 3,
                            "shared buffer rejection reset")
                assert h2.resets[9] == 0, h2.resets
                events = [event[1:] for event in h2.events if event[0] == 9]
                assert events.index((0, True)) < events.index((3, False)), events
                for stream_id in (1, 3, 5, 7):
                    h2.reset(stream_id)
                h2.request(11, "GET", "/allowed/after-shared-cap", authority)
                h2.wait_for(lambda: 11 in h2.ended, 3,
                            "request after shared buffer rejection")
                assert 11 not in h2.resets, h2.resets
            finally:
                h2.close()

            h2 = Http2Client("127.0.0.1", gate_port)
            try:
                # Upstream buffering is host-dependent and keeps growing slowly
                # after a stall, so each attempt declares a length from the last
                # and keeps the stream only if part of its body is still queued
                # or in flight upstream. Leave the request stream open.
                early_length = 64 << 20
                for attempt in range(8):
                    early_stream = 1 + 2 * attempt
                    early_started[attempt] = threading.Event()
                    h2.request(early_stream, "POST",
                               f"/allowed/early-response/{attempt}", authority,
                               early_length)
                    started = early_started[attempt].wait(3)
                    assert started, "early-response application did not start"
                    sent = h2.send_until_stalled(early_stream, early_length)
                    if sent == early_length:
                        ping = b"body-%02d." % attempt
                        h2.ping(ping)
                        h2.wait_for(lambda: ping in h2.pings, 3,
                                    "PING after queued request body")
                        if h2.delivered(early_stream) < early_length:
                            break
                        early_length += 32768
                    else:
                        early_length = sent
                    early_abandoned.add(attempt)
                    h2.reset(early_stream)
                else:
                    raise AssertionError("request body never stayed pending upstream")

                # A zero response window keeps the stream open while upstream
                # closes over the pending request body.
                h2.receive_window(0)
                early_response.set()
                h2.wait_for(lambda: early_stream in h2.responses, 3,
                            "early upload response headers")
                early_body_release.set()
                closed = early_closed.wait(3)
                assert closed, "early-response application did not close"
                h2.ping(b"closed-1")
                h2.wait_for(lambda: b"closed-1" in h2.pings, 3,
                            "PING after upstream close")
                settle = time.monotonic() + .5
                while time.monotonic() < settle and early_stream not in h2.resets:
                    h2.receive(.05)
                assert early_stream not in h2.resets, h2.resets
                h2.receive_window(65535)
                h2.wait_for(lambda: early_stream in h2.ended or early_stream in h2.resets,
                            3, "early upload response")
                assert early_stream in h2.ended, h2.resets
                assert h2.received[early_stream] == len(early_body)
                h2.wait_for(lambda: early_stream in h2.resets, 3,
                            "reset after early upload response")
                assert h2.resets[early_stream] == 0, h2.resets

                after_stream = early_stream + 2
                h2.ping(b"early-ok")
                h2.request(after_stream, "GET", "/allowed/after-early", authority)
                h2.wait_for(lambda: b"early-ok" in h2.pings, 3,
                            "PING after early response")
                h2.wait_for(lambda: after_stream in h2.ended, 3,
                            "request after early response")
                assert after_stream not in h2.resets, h2.resets
            finally:
                early_response.set()
                early_body_release.set()
                h2.close()

            h2 = Http2Client("127.0.0.1", gate_port)
            try:
                abandoned = list(range(1, 65, 2))
                for stream_id in abandoned:
                    h2.request(stream_id, "POST", "/allowed/early-limit",
                               authority, 1)
                    h2.wait_for(lambda: stream_id in h2.ended or stream_id in h2.resets,
                                3, f"early response on stream {stream_id}")
                    assert stream_id in h2.ended, h2.resets
                h2.request(65, "GET", "/allowed/after-early-limit", authority)
                h2.wait_for(lambda: 65 in h2.ended or 65 in h2.resets,
                            3, "request after 32 early responses")
                assert 65 in h2.ended and 65 not in h2.resets, h2.resets
                h2.wait_for(lambda: all(stream_id in h2.resets for stream_id in abandoned),
                            3, "resets for 32 abandoned uploads")
                assert all(h2.resets[stream_id] == 0 for stream_id in abandoned), h2.resets
            finally:
                h2.close()

            h2 = Http2Client("127.0.0.1", gate_port)
            held_streams = list(range(1, 16, 2))
            try:
                for number, stream_id in enumerate(held_streams):
                    h2.request(stream_id, "POST", f"/allowed/held/{number}",
                               authority, 64 << 20,
                               headers={"x-forwarded-for": f"198.51.100.{number + 1}"})
                for event in held_started:
                    assert event.wait(3), "held upload application did not start"
                for stream_id in held_streams:
                    h2.fill_until_stalled(stream_id)

                h2.ping(b"blocked8")
                h2.request(17, "POST", "/allowed/probe", authority, 256 << 10)
                h2.wait_for(lambda: b"blocked8" in h2.pings, 3,
                            "PING with eight pending writes")
                h2.send_body(17, 256 << 10, 3)
                assert probe_finished.wait(3), "ninth request body was blocked"
                h2.wait_for(lambda: 17 in h2.ended, 3, "ninth response")

                h2.reset(held_streams[0])
                for stream_id in held_streams[1:]:
                    h2.reset(stream_id)
                h2.ping(b"reset-ok")
                h2.request(19, "GET", "/allowed/after-reset", authority)
                h2.wait_for(lambda: b"reset-ok" in h2.pings, 3,
                            "PING after eight resets")
                h2.wait_for(lambda: 19 in h2.ended, 3, "request after eight resets")
                assert 19 not in h2.resets, h2.resets
            finally:
                held_release.set()
                h2.close()

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

            # An HTTP/1.1 upload waits while the application is not reading,
            # well past the point where the gateway's buffers fill.
            block = bytes(range(256)) * 4096
            blocks = 48
            expected = hashlib.sha256(block * blocks).hexdigest().encode()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(["http/1.1"])
            reply = b""
            with socket.create_connection(("127.0.0.1", gate_port), timeout=60) as raw:
                with context.wrap_socket(raw, server_hostname="localhost") as tls:
                    tls.sendall((f"POST /allowed/stalled-upload HTTP/1.1\r\n"
                                 f"Host: localhost:{gate_port}\r\n"
                                 f"Content-Length: {len(block) * blocks}\r\n\r\n").encode())
                    for _ in range(blocks):
                        tls.sendall(block)
                    while True:
                        try:
                            chunk = tls.recv(65536)
                        except ssl.SSLEOFError:
                            break
                        if not chunk:
                            break
                        reply += chunk
            assert reply.startswith(b"HTTP/1.1 200") or reply.startswith(b"HTTP/1.0 200"), reply[:200]
            assert reply.endswith(expected), reply[-200:]

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

            if os.environ.get("ANKAH_TEST_WINDOWS_PATHS") != "1":
                drained = {}

                def existing_stream():
                    try:
                        drained["response"] = curl(gate_port, "/allowed/drain")
                    except Exception as error:
                        drained["error"] = error

                draining = threading.Thread(target=existing_stream)
                draining.start()
                assert drain_started.wait(5)
                process.terminate()
                time.sleep(.15)
                status, protocol, payload = curl(
                    gate_port, "/allowed/new-http1-after-drain", "--http1.1")
                assert status == 503 and protocol.startswith("1.")
                assert payload == b"Service shutting down\n"
                refused = subprocess.run([
                    "curl", "--silent", "--show-error", "--insecure", "--noproxy", "*",
                    "--http2", "--max-time", "2",
                    "--header", f"Host: localhost:{gate_port}",
                    f"https://127.0.0.1:{gate_port}/allowed/new-after-drain",
                ], capture_output=True, timeout=4)
                assert refused.returncode != 0, refused.stdout
                drain_release.set()
                draining.join(timeout=8)
                assert not draining.is_alive() and "error" not in drained, drained
                assert drained["response"] == (200, "2", b"/allowed/drain")
                process.wait(timeout=5)
                assert process.returncode == 0
        finally:
            if process.poll() is None:
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
