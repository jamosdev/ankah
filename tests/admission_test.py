"""Check that unproved traffic cannot spend proved request capacity."""

from contextlib import contextmanager
import hashlib
import http.client
import http.server
import os
import pathlib
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from http2_client import Client as Http2Client, DATA
from process_support import gateway_command


class AdmissionHttp2Client(Http2Client):
    """Keep small response samples without buffering arbitrary response bodies."""

    def __init__(self, *args):
        self.response_bodies = {}
        super().__init__(*args)

    def process_frame(self, kind, flags, stream_id, payload):
        if kind == DATA:
            body = self.response_bodies.get(stream_id, b"")
            self.response_bodies[stream_id] = body + payload[:256 - len(body)]
        return super().process_frame(kind, flags, stream_id, payload)

    def diagnostic(self, stream_id):
        return (self.response_status.get(stream_id),
                self.response_headers.get(stream_id),
                self.received.get(stream_id), self.response_bodies.get(stream_id))

    def assert_ok(self, stream_id):
        diagnostic = self.diagnostic(stream_id)
        assert self.response_status.get(stream_id) == b"200", diagnostic
        assert self.received.get(stream_id) == 2, diagnostic
        assert self.response_bodies.get(stream_id) == b"ok", diagnostic

    def assert_rejected(self, stream_id, status, body):
        diagnostic = self.diagnostic(stream_id)
        assert self.response_status.get(stream_id) == status, diagnostic
        assert self.response_bodies.get(stream_id) == body, diagnostic


def assert_ok(result):
    assert result[0] == 200 and result[2] == b"ok", result


def assert_crawler_busy(result, tls):
    status, headers, body = result
    assert status == 429 and headers.get("Retry-After") == "1", result
    # TLS HTTP/1 currently uses the same body for both rejection causes.
    # Its callers must stay within the initial burst even without any refill.
    expected = b"Rate limit exceeded\n" if tls else b"Crawler concurrency exceeded\n"
    assert body == expected, result


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def solve(challenge):
    nonce, _, bits, *_ = challenge.split(".")
    bits = int(bits)
    for counter in range(4_000_000):
        digest = hashlib.sha256(f"{nonce}:{counter}".encode()).digest()
        if int.from_bytes(digest, "big") >> (256 - bits) == 0:
            return counter
    raise AssertionError("challenge answer not found")


def run_gateway(executable, root, app_port, tls=False):
    root = pathlib.Path(tempfile.mkdtemp(dir=root))
    gate_port = port()
    secret = root / "secret"
    secret.write_text("a" * 64)
    (root / "dashboard-token").write_text("b" * 64)
    options = ["--listen", f"127.0.0.1:{gate_port}",
               "--upstream", f"127.0.0.1:{app_port}",
               "--public-origin", f"{'https' if tls else 'http'}://localhost:{gate_port}",
               "--secret-file", str(secret), "--assets-dir", str(pathlib.Path(__file__).parent.parent),
               "--allow-prefix", "/public", "--trusted-proxy", "127.0.0.1/32",
               "--proxy-abuse-profile=off",
               "--dashboard-token-file", str(root / "dashboard-token"),
               "--session-state-file", str(root / "sessions"),
               "--stats-file", str(root / "stats")]
    if tls:
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-nodes", "-subj", "/CN=localhost", "-keyout", str(key),
                        "-out", str(cert), "-days", "1"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        options += ["--tls-cert", str(cert), "--tls-key", str(key)]
    environment = os.environ.copy()
    if dns_fixture:
        environment["LD_PRELOAD"] = dns_fixture
    process = subprocess.Popen(gateway_command(executable, options), env=environment,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    return gate_port, process


@contextmanager
def gateway(executable, root, app_port, tls):
    gate_port, process = run_gateway(executable, root, app_port, tls)
    context = ssl._create_unverified_context() if tls else None

    def request(path, method="GET", headers=None):
        if tls:
            client = http.client.HTTPSConnection("127.0.0.1", gate_port,
                                                 timeout=5, context=context)
        else:
            client = http.client.HTTPConnection("127.0.0.1", gate_port, timeout=5)
        client.request(method, path,
                       headers={"Host": f"localhost:{gate_port}", **(headers or {})})
        reply = client.getresponse()
        result = reply.status, dict(reply.getheaders()), reply.read()
        client.close()
        return result

    try:
        for _ in range(250):
            if process.poll() is not None:
                raise AssertionError(process.stderr.read().decode())
            try:
                if request("/public/ready")[0] == 200:
                    break
            except OSError:
                time.sleep(.02)
        else:
            raise AssertionError("gateway did not start")

        yield gate_port, request, context
    except BaseException:
        # Preserve the child exit status before cleanup can replace it.
        status = process.poll()
        if status is not None:
            diagnostic = process.stderr.read(8192).decode(errors="replace")
            print(f"gateway exited before cleanup: {status}; stderr={diagnostic!r}", file=sys.stderr)
        else:
            print("gateway still running at test failure", file=sys.stderr)
        raise
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stderr.close()


def known_crawler_can_enter(request, peer, tls):
    # Each probe can spend a token even when the slot is busy. Together with
    # the other requests in check_gateway, two calls use at most ten tokens.
    for attempt in range(3):
        result = request("/private", headers={"X-Forwarded-For": peer})
        if result[0] == 200:
            assert_ok(result)
            return
        assert_crawler_busy(result, tls)
        if attempt < 2:
            time.sleep(.25)
    raise AssertionError(("known crawler could not acquire the released slot", result))


def prove(request):
    status, headers, page = request("/private")
    assert status == 428, status
    sid = re.search(rb"data-session='([^']+)'", page).group(1).decode()
    challenge = re.search(rb"data-challenge='([^']+)'", page).group(1).decode()
    answer = solve(challenge)
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    assert request(f"/ankah/answer/{sid}?answer={answer}", "POST")[0] == 200
    pass_status, pass_headers, _ = request(
        f"/ankah/open?challenge={challenge}&answer={answer}", "POST")
    assert pass_status == 200
    pass_cookie = pass_headers["Set-Cookie"].split(";", 1)[0]
    assert request("/private", headers={"Cookie": cookie})[0] == 200

    return cookie, pass_cookie


def check_google_crawlers(executable, root, app_port, tls):
    with gateway(executable, root, app_port, tls) as (gate_port, request, _):
        hold_started.clear()
        hold_release.clear()
        first = []

        def hold_crawler():
            first.append(request("/crawler-hold", headers={
                "X-Forwarded-For": "192.178.4.1"}))

        worker = threading.Thread(target=hold_crawler)
        worker.start()
        try:
            assert hold_started.wait(5), "known crawler did not reach the application"
            assert_crawler_busy(request("/private", headers={
                "X-Forwarded-For": "192.178.4.2"}), tls)
        finally:
            hold_release.set()
            worker.join(5)
        assert len(first) == 1 and first[0][0] == 200 and first[0][2] == b"ok", first
        assert_ok(request("/private", headers={"X-Forwarded-For": "192.178.4.3"}))
        if tls:
            assert request("/public/ready", headers={
                "X-Ankah-Internal-Crawler-Slot": "1"})[0] == 400
            h2 = Http2Client("127.0.0.1", gate_port)
            try:
                h2.request(1, "GET", "/public/ready", f"localhost:{gate_port}",
                           headers={"x-ankah-internal-crawler-slot": "1"})
                h2.wait_for(lambda: 1 in h2.responses, 3,
                            "internal crawler marker was not rejected")
                assert h2.response_headers[1][0][0] == 0x8c, h2.response_headers[1]
            finally:
                h2.close()


def check_proved_google_crawlers(executable, root, app_port, tls):
    # This scenario can make eight crawler attempts over TLS. It needs its
    # own burst, separate from the three attempts in check_google_crawlers.
    with gateway(executable, root, app_port, tls) as (gate_port, request, _):
        _, pass_cookie = prove(request)

        hold_started.clear()
        hold_release.clear()
        first = []

        def hold_proved_crawler():
            first.append(request("/crawler-hold", headers={
                "X-Forwarded-For": "192.178.4.5", "Cookie": pass_cookie}))

        worker = threading.Thread(target=hold_proved_crawler)
        worker.start()
        try:
            assert hold_started.wait(5), "proved crawler did not reach the application"
            assert_crawler_busy(request("/private", headers={
                "X-Forwarded-For": "192.178.4.6", "Cookie": pass_cookie}), tls)
            assert_crawler_busy(request("/private", headers={"User-Agent": "bingbot"}), tls)
            if tls:
                h2 = AdmissionHttp2Client("127.0.0.1", gate_port)
                try:
                    h2.request(1, "GET", "/private", f"localhost:{gate_port}",
                               headers={"user-agent": "bingbot"})
                    h2.wait_for(lambda: 1 in h2.ended, 3,
                                "HTTP/2 Bing claim was not rejected at capacity")
                    h2.assert_rejected(1, b"429", b"Crawler concurrency exceeded\n")
                finally:
                    h2.close()
                h2 = AdmissionHttp2Client("127.0.0.1", gate_port)
                try:
                    h2.request(1, "GET", "/private", f"localhost:{gate_port}",
                               headers={"x-forwarded-for": "192.178.4.8",
                                        "cookie": pass_cookie})
                    h2.wait_for(lambda: 1 in h2.ended, 3,
                                "HTTP/2 proved crawler was not rejected at capacity")
                    h2.assert_rejected(1, b"429", b"Crawler concurrency exceeded\n")
                finally:
                    h2.close()
        finally:
            hold_release.set()
            worker.join(5)
        assert len(first) == 1 and first[0][0] == 200, first
        assert request("/private", headers={"User-Agent": "bingbot"})[0] == 428
        assert_ok(request("/private", headers={
            "User-Agent": "bingbot", "Cookie": pass_cookie}))
        assert_ok(request("/private", headers={"X-Forwarded-For": "192.178.4.7"}))


def check_verified_bing(executable, root, app_port, tls):
    with gateway(executable, root, app_port, tls) as (_, request, _):
        _, pass_cookie = prove(request)
        bing_headers = {"User-Agent": "bingbot",
                        "X-Forwarded-For": "203.0.113.42"}
        bing_result = request("/private", headers=bing_headers)
        assert_ok(bing_result)
        hold_started.clear()
        hold_release.clear()
        first = []

        def hold_verified_bing():
            first.append(request("/crawler-hold", headers={
                **bing_headers, "Cookie": pass_cookie}))

        worker = threading.Thread(target=hold_verified_bing)
        worker.start()
        try:
            assert hold_started.wait(5), "verified Bing did not reach the application"
            assert_crawler_busy(request("/private", headers={
                "X-Forwarded-For": "192.178.4.9"}), tls)
        finally:
            hold_release.set()
            worker.join(5)
        assert len(first) == 1 and first[0][0] == 200, first

        assert_ok(request("/private", headers=bing_headers))


def check_verified_h2_bing(executable, root, app_port):
    with gateway(executable, root, app_port, True) as (gate_port, request, _):
        h2 = AdmissionHttp2Client("127.0.0.1", gate_port)
        try:
            # Exercise both a cold DNS verification and a cached classification.
            for stream_id in (1, 3):
                h2.request(stream_id, "GET", "/private", f"localhost:{gate_port}",
                           headers={"user-agent": "bingbot",
                                    "x-forwarded-for": "203.0.113.42"})
                h2.wait_for(lambda: stream_id in h2.ended, 3,
                            "verified HTTP/2 Bing request did not finish")
                h2.assert_ok(stream_id)
        finally:
            h2.close()

        hold_started.clear()
        hold_release.clear()
        h2 = AdmissionHttp2Client("127.0.0.1", gate_port)
        try:
            h2.request(1, "GET", "/crawler-hold", f"localhost:{gate_port}",
                       headers={"user-agent": "bingbot",
                                "x-forwarded-for": "203.0.113.42"})
            h2.wait_for(lambda: hold_started.is_set() or 1 in h2.ended, 5,
                        "HTTP/2 Bing did not reach the application")
            assert hold_started.is_set(), h2.diagnostic(1)
            assert_crawler_busy(request("/private", headers={
                "X-Forwarded-For": "192.178.4.9"}), True)
            h2.reset(1)
            # Poll only for asynchronous slot release, not token-bucket refill.
            # At most nine Google/Bing attempts share this fresh crawler budget.
            for attempt in range(5):
                result = request("/private", headers={
                    "X-Forwarded-For": "192.178.4.10"})
                if result[0] == 200:
                    assert_ok(result)
                    break
                assert_crawler_busy(result, True)
                if attempt < 4:
                    time.sleep(.25)
            else:
                raise AssertionError("reset HTTP/2 Bing stream kept crawler slot")
        finally:
            hold_release.set()
            h2.close()


def check_gateway(executable, root, app_port, tls):
    with gateway(executable, root, app_port, tls) as (gate_port, request, context):
        for _ in range(45):
            assert request("/public/scan", headers={"Host": "wrong.test"})[0] == 421
        assert request("/public/scan")[0] == 200
        if tls:
            for _ in range(25):
                assert request("/public/scan")[0] == 200, "TLS request was charged twice"

        cookie, pass_cookie = prove(request)

        if tls:
            h2 = Http2Client("127.0.0.1", gate_port)
            try:
                h2.request(1, "GET", "/private", f"localhost:{gate_port}",
                           headers={"user-agent": "bingbot"})
                h2.wait_for(lambda: 1 in h2.responses, 3,
                            "HTTP/2 Bing claim was not classified")
                assert b"428" in b"".join(h2.response_headers[1])
            finally:
                h2.close()

        limited = False
        for attempt in range(120):
            try:
                status, headers, body = request("/public/scan")
            except Exception as error:
                raise AssertionError(f"anonymous request {attempt}: {error}") from error
            if status == 429:
                limited = True
                assert headers.get("Retry-After") == "1"
                assert body == b"Rate limit exceeded\n", (status, headers, body)
                break
        assert limited, "anonymous requests were not bounded"
        assert_ok(request("/private", headers={"X-Forwarded-For": "192.178.4.4"}))
        assert request("/private", headers={"Cookie": cookie})[0] == 200
        assert request("/private", headers={"Cookie": pass_cookie})[0] == 200
        assert request("/public/scan", headers={"Cookie": cookie})[0] == 200

        def bounded(path, headers):
            for _ in range(20):
                result = request(path, headers=headers)
                if result[0] == 429:
                    assert result[2] == b"Rate limit exceeded\n", result
                    return
            raise AssertionError(f"{path} escaped anonymous capacity")

        bounded("/public/scan", {"Cookie": "ankah_pass=invalid"})
        bounded("/ankah/unlock", {"Cookie": cookie})

        if tls:
            h2 = Http2Client("127.0.0.1", gate_port)
            try:
                streams = list(range(1, 32, 2))
                for stream_id in streams:
                    h2.request(stream_id, "POST", "/public/no-length",
                               f"localhost:{gate_port}", end_stream=False)
                h2.wait_for(lambda: any(i in h2.responses for i in streams), 3,
                            "rate rejection before unknown-length body")
                assert any(b"429" in b"".join(h2.response_headers.get(i, []))
                           for i in streams)
                assert sum(h2.received.get(i, 0) for i in streams) < 2048
            finally:
                h2.close()
            pending = [socket.create_connection(("127.0.0.1", gate_port), timeout=5)
                       for _ in range(32)]
            try:
                extra = socket.create_connection(("127.0.0.1", gate_port), timeout=5)
                extra.settimeout(2)
                try:
                    extra.sendall(b"x")
                    assert not extra.recv(1024), "TLS pending limit did not refuse"
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    extra.close()
            finally:
                for sock in pending:
                    sock.close()
            for _ in range(50):
                try:
                    if request("/private", headers={"Cookie": cookie})[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(.02)
            else:
                raise AssertionError("proved TLS request did not recover after pending sockets closed")

        hold_started.clear()
        raw = socket.create_connection(("127.0.0.1", gate_port), timeout=5)
        sock = context.wrap_socket(raw, server_hostname="localhost") if tls else raw
        try:
            sock.sendall((f"POST /public/scan HTTP/1.1\r\n"
                          f"Host: localhost:{gate_port}\r\n"
                          "User-Agent: bingbot\r\n"
                          "X-Forwarded-For: 203.0.113.88\r\n"
                          "Content-Length: 1\r\n\r\n").encode())
            assert hold_started.wait(5), "unverified Bing did not reach the application"
            known_crawler_can_enter(request, "192.178.4.11", tls)
        finally:
            sock.close()
        if tls:
            time.sleep(.05)
            hold_started.clear()
            h2 = Http2Client("127.0.0.1", gate_port)
            try:
                h2.request(1, "POST", "/public/scan", f"localhost:{gate_port}",
                           length=1, end_stream=False,
                           headers={"user-agent": "bingbot",
                                    "x-forwarded-for": "203.0.113.89"})
                assert hold_started.wait(5), "unverified HTTP/2 Bing did not reach the application"
                known_crawler_can_enter(request, "192.178.4.12", tls)
            finally:
                h2.reset(1)
                h2.close()


def check_connection_capacity(executable, root, app_port, tls=False):
    gate_port, process = run_gateway(executable, root, app_port, tls)
    held = []
    context = ssl._create_unverified_context() if tls else None
    if context:
        context.set_alpn_protocols(["http/1.1"])

    def request(path, headers=None):
        client = (http.client.HTTPSConnection("127.0.0.1", gate_port,
                                            timeout=5, context=context) if tls else
                  http.client.HTTPConnection("127.0.0.1", gate_port, timeout=5))
        client.request("GET", path,
                       headers={"Host": f"localhost:{gate_port}", **(headers or {})})
        reply = client.getresponse()
        result = reply.status, dict(reply.getheaders()), reply.read()
        client.close()
        return result

    try:
        for _ in range(250):
            try:
                if request("/public/ready")[0] == 200:
                    break
            except OSError:
                time.sleep(.02)
        else:
            raise AssertionError("capacity gateway did not start")

        status, headers, page = request("/private")
        assert status == 428
        sid = re.search(rb"data-session='([^']+)'", page).group(1).decode()
        challenge = re.search(rb"data-challenge='([^']+)'", page).group(1).decode()
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        client = (http.client.HTTPSConnection("127.0.0.1", gate_port,
                                            timeout=5, context=context) if tls else
                  http.client.HTTPConnection("127.0.0.1", gate_port, timeout=5))
        client.request("POST", f"/ankah/answer/{sid}?answer={solve(challenge)}",
                       headers={"Host": f"localhost:{gate_port}"})
        reply = client.getresponse()
        assert reply.status == 200
        reply.read()
        client.close()

        if not tls:
            pending = [socket.create_connection(("127.0.0.1", gate_port), timeout=5)
                       for _ in range(32)]
            held.extend(pending)
            extra = socket.create_connection(("127.0.0.1", gate_port), timeout=5)
            extra.settimeout(2)
            try:
                extra.sendall(f"GET /public/extra HTTP/1.1\r\n"
                              f"Host: localhost:{gate_port}\r\n\r\n".encode())
                assert not extra.recv(1024), "pending connection limit did not refuse"
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                extra.close()
            for sock in pending:
                sock.close()
            held.clear()
            for _ in range(50):
                try:
                    if request("/public/ready")[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(.02)
            else:
                raise AssertionError("pending connections did not drain")

        for index in range(192):
            raw = socket.create_connection(("127.0.0.1", gate_port), timeout=5)
            sock = context.wrap_socket(raw, server_hostname="localhost") if tls else raw
            held.append(sock)
            sock.settimeout(5)
            sock.sendall((f"POST /private HTTP/1.1\r\nHost: localhost:{gate_port}\r\n"
                          f"X-Forwarded-For: 198.51.{index // 256}.{index % 256}\r\n"
                          "Content-Length: 1\r\nExpect: 100-continue\r\n\r\n").encode())
            assert sock.recv(1024).startswith(b"HTTP/1.1 100"), index

        status, _, _ = request("/private", headers={"X-Forwarded-For": "203.0.113.1"})
        assert status == 503, status
        assert request("/private", headers={"Cookie": cookie})[0] == 200
        status, _, body = request("/ankah/unlock", headers={"User-Agent": "bingbot"})
        assert status == 503 and body == b"Anonymous connection capacity reached\n", (status, body)
        if tls:
            h2 = AdmissionHttp2Client("127.0.0.1", gate_port)
            try:
                h2.request(1, "GET", "/ankah/unlock", f"localhost:{gate_port}",
                           headers={"user-agent": "bingbot"})
                h2.wait_for(lambda: 1 in h2.ended, 3,
                            "HTTP/2 Bing claim escaped anonymous connection capacity")
                h2.assert_rejected(1, b"503", b"Anonymous connection capacity reached\n")
            finally:
                h2.close()
    finally:
        for sock in held:
            sock.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def check_h2_reused_capacity(executable, root, app_port):
    gate_port, process = run_gateway(executable, root, app_port, True)
    clients = []

    def h2_request(path, peer, expected):
        client = AdmissionHttp2Client("127.0.0.1", gate_port)
        clients.append(client)
        client.request(1, "GET", path, f"localhost:{gate_port}",
                       headers={"x-forwarded-for": peer})
        client.wait_for(lambda: 1 in client.ended, 5, path)
        if expected == 503:
            client.assert_rejected(1, b"503", b"Anonymous connection capacity reached\n")
        elif expected == 200:
            client.assert_ok(1)
        return client

    try:
        for _ in range(250):
            try:
                client = h2_request("/public/ready", "203.0.113.80", 200)
                client.close()
                clients.remove(client)
                break
            except OSError:
                time.sleep(.02)
        else:
            raise AssertionError("HTTP/2 capacity gateway did not start")

        privileged = AdmissionHttp2Client("127.0.0.1", gate_port)
        clients.append(privileged)
        privileged.request(1, "GET", "/private", f"localhost:{gate_port}",
                           headers={"user-agent": "bingbot"})
        privileged.wait_for(lambda: 1 in privileged.ended, 5, "unverified Bing claim")
        assert b"428" in b"".join(privileged.response_headers[1])

        for index in range(191):
            h2_request("/public/ready", f"198.51.100.{index + 1}", 200)

        hold_started.clear()
        hold_release.clear()
        mixed = AdmissionHttp2Client("127.0.0.1", gate_port)
        clients.append(mixed)
        mixed.request(1, "GET", "/public/crawler-hold", f"localhost:{gate_port}",
                      headers={"x-forwarded-for": "203.0.113.81"})
        assert hold_started.wait(5), "anonymous HTTP/2 stream did not reach the application"

        h2_request("/public/ready", "203.0.113.82", 503)
        privileged.request(3, "GET", "/ankah/unlock", f"localhost:{gate_port}",
                           headers={"user-agent": "bingbot",
                                    "x-forwarded-for": "203.0.113.83"})
        privileged.wait_for(lambda: 3 in privileged.ended, 5, "reused Bing claim")
        privileged.assert_rejected(3, b"503", b"Anonymous connection capacity reached\n")

        mixed.request(3, "GET", "/public/ready", f"localhost:{gate_port}",
                      headers={"x-forwarded-for": "192.178.4.20"})
        mixed.wait_for(lambda: 3 in mixed.ended, 5, "privileged mixed stream")
        mixed.assert_ok(3)
        h2_request("/public/ready", "203.0.113.84", 503)

        hold_release.set()
        mixed.wait_for(lambda: 1 in mixed.ended, 5, "anonymous stream completion")
        for _ in range(50):
            client = h2_request("/public/ready", "203.0.113.85", 0)
            if client.response_status.get(1) == b"200":
                client.assert_ok(1)
                break
            client.assert_rejected(1, b"503", b"Anonymous connection capacity reached\n")
            client.close()
            clients.remove(client)
            time.sleep(.02)
        else:
            raise AssertionError("completed anonymous stream kept the capacity slot")
    finally:
        hold_release.set()
        for client in clients:
            client.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main():
    executable = sys.argv[1]
    global dns_fixture
    dns_fixture = sys.argv[2] if len(sys.argv) > 2 else ""
    app_port = port()
    global hold_started, hold_release
    hold_started = threading.Event()
    hold_release = threading.Event()

    class App(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path in ("/crawler-hold", "/public/crawler-hold"):
                hold_started.set()
                assert hold_release.wait(5), "crawler release was not signalled"
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path == "/public/scan":
                hold_started.set()
                if not self.rfile.read(1):
                    return
            self.do_GET()

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", app_port), App)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            # Each scenario owns its rate buckets; unrelated contention checks
            # must not spend the budget of a later successful crawler request.
            for tls in (False, True):
                check_google_crawlers(executable, root, app_port, tls)
                check_proved_google_crawlers(executable, root, app_port, tls)
                if dns_fixture:
                    check_verified_bing(executable, root, app_port, tls)
                check_gateway(executable, root, app_port, tls)
            if dns_fixture:
                check_verified_h2_bing(executable, root, app_port)
            check_connection_capacity(executable, root, app_port)
            check_connection_capacity(executable, root, app_port, True)
            check_h2_reused_capacity(executable, root, app_port)
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
