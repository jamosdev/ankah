"""Exercise the optional RFC 8783 DOTS data channel client against a fake mTLS server."""
import http.client
import http.server
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from process_support import gateway_command


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def openssl(*args):
    subprocess.run(["openssl", *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def credentials(directory):
    d = Path(directory)
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-keyout", d / "ca.key", "-out", d / "ca.crt", "-days", "2",
            "-subj", "/CN=dots test CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign")
    for name, subject, extensions in (
        ("server", "/CN=dots.test",
         "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n"
         "subjectAltName=DNS:dots.test,IP:127.0.0.1\n"),
        ("client", "/CN=ankah-test",
         "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\n"),
    ):
        (d / f"{name}.ext").write_text(extensions)
        openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", d / f"{name}.key", "-out", d / f"{name}.csr", "-subj", subject)
        openssl("x509", "-req", "-in", d / f"{name}.csr", "-CA", d / "ca.crt",
                "-CAkey", d / "ca.key", "-CAcreateserial", "-out", d / f"{name}.crt",
                "-days", "2", "-extfile", d / f"{name}.ext")
    return d


class DotsServer:
    """Records every request; answers like an RFC 8783 server."""

    def __init__(self, certs):
        self.requests = []
        self.lock = threading.Lock()
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def handle_any(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                cert = self.connection.getpeercert()
                subject = dict(item[0] for item in cert["subject"])
                with owner.lock:
                    owner.requests.append({
                        "method": self.command, "path": self.path,
                        "cn": subject.get("commonName"),
                        "content_type": self.headers.get("Content-Type"),
                        "body": body})
                status, reply = 201, b""
                if self.command == "GET":
                    status = 200
                    reply = json.dumps({"ietf-dots-data-channel:acls": {"acl": [
                        {"name": "ankah-203-0-113-50", "aces": {"ace": [{"name": "block"}]}},
                        {"name": "someone-else"}]}}).encode()
                elif self.command == "DELETE":
                    status = 204
                self.send_response(status)
                self.send_header("Content-Type", "application/yang-data+json")
                self.send_header("Content-Length", str(len(reply)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(reply)
                self.close_connection = True

            do_GET = do_PUT = do_POST = do_DELETE = handle_any

            def log_message(self, *_):
                pass

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certs / "server.crt", certs / "server.key")
        context.load_verify_locations(certs / "ca.crt")
        context.verify_mode = ssl.CERT_REQUIRED
        self.port = port()
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def matching(self, method, suffix):
        with self.lock:
            return [r for r in self.requests
                    if r["method"] == method and r["path"].endswith(suffix)]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def request(gate, source=None):
    conn = http.client.HTTPConnection("127.0.0.1", gate, timeout=5)
    headers = {"Host": f"localhost:{gate}", "User-Agent": "dots-test"}
    if source:
        headers["X-Forwarded-For"] = source
    try:
        conn.request("GET", "/pi?n=1", headers=headers)
        reply = conn.getresponse()
        reply.read()
        return reply.status
    finally:
        conn.close()


def metrics(dashboard, token):
    conn = http.client.HTTPConnection("127.0.0.1", dashboard, timeout=5)
    try:
        conn.request("GET", "/metrics", headers={"Authorization": f"Bearer {token}"})
        reply = conn.getresponse()
        return reply.read().decode()
    finally:
        conn.close()


def wait_for(predicate, what, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(.05)
    raise AssertionError(f"timed out waiting for {what}")


def start(binary, assets, tmp, dots_port, trusted, extra=()):
    gate, dashboard, upstream = port(), port(), port()
    args = ["--listen", f"127.0.0.1:{gate}", "--upstream", f"127.0.0.1:{upstream}",
            "--public-origin", f"http://localhost:{gate}",
            "--secret-file", tmp / "secret", "--assets-dir", assets,
            "--proxy-abuse-profile=off", "--trusted-proxy", trusted,
            "--dashboard-listen", f"127.0.0.1:{dashboard}",
            "--dashboard-token-file", tmp / "token", "--no-stats-file",
            "--dots-server", f"127.0.0.1:{dots_port}", "--dots-server-name", "dots.test",
            "--dots-ca-file", tmp / "ca.crt", "--dots-cert-file", tmp / "client.crt",
            "--dots-key-file", tmp / "client.key", "--dots-cuid", "ankah-test",
            "--dots-protected-network", "192.0.2.11/32", "--dots-protected-port", "80",
            "--dots-threshold", "5", "--dots-window-seconds", "10",
            "--dots-block-seconds", "2", *extra]
    process = subprocess.Popen(gateway_command(binary, args),
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(200):
        try:
            request(gate)
            return process, gate, dashboard
        except OSError:
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read().decode())
            time.sleep(.03)
    raise RuntimeError("gateway did not start")


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        raise


def main(binary, assets):
    with tempfile.TemporaryDirectory() as directory:
        tmp = credentials(directory)
        (tmp / "secret").write_text("a" * 64)
        (tmp / "token").write_text("b" * 64)
        token = "b" * 64

        # Invalid configuration: a DOTS server without credentials.
        incomplete = subprocess.run(gateway_command(binary, [
            "--public-origin", "http://localhost", "--secret-file", tmp / "secret",
            "--assets-dir", assets, "--trusted-proxy", "127.0.0.1/32",
            "--dots-server", "127.0.0.1:1"]),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        check(incomplete.returncode == 2, "incomplete DOTS configuration must be rejected")

        server = DotsServer(tmp)
        try:
            process, gate, dashboard = start(binary, assets, tmp, server.port, "127.0.0.1/32")
            try:
                register = wait_for(lambda: server.matching("PUT", "/dots-client=ankah-test"),
                                    "registration")
                check(register[0]["cn"] == "ankah-test", "client certificate identity")
                check(register[0]["content_type"] == "application/yang-data+json",
                      "RESTCONF media type")
                check(json.loads(register[0]["body"]) ==
                      {"ietf-dots-data-channel:dots-client": [{"cuid": "ankah-test"}]},
                      "registration body")
                check(register[0]["path"] == "/v1/restconf/data/ietf-dots-data-channel:"
                      "dots-data/dots-client=ankah-test", register[0]["path"])
                wait_for(lambda: server.matching("DELETE", "/acl=ankah-203-0-113-50"),
                         "withdrawal of a stale ACL listed after registration")
                check(not server.matching("DELETE", "/acl=someone-else"),
                      "ACLs not named by Ankah are left alone")

                # The proxy's own address never becomes a filtering source.
                for _ in range(12):
                    check(request(gate) in (302, 428), "challenge without forwarding")
                # Below the threshold nothing is sent.
                for _ in range(4):
                    check(request(gate, "198.51.100.7") in (302, 428), "challenged")
                time.sleep(.3)
                check(not server.matching("PUT", "/acls/acl=ankah-198-51-100-7"),
                      "no install below the threshold")
                check(not server.matching("PUT", "/acls/acl=ankah-127-0-0-1"),
                      "proxy address never escalated")
                check(request(gate, "198.51.100.7") in (302, 428), "fifth challenged")
                install = wait_for(
                    lambda: server.matching("PUT", "/acls/acl=ankah-198-51-100-7"),
                    "ACL install")
                body = json.loads(install[0]["body"])
                acl = body["ietf-dots-data-channel:acls"]["acl"][0]
                ace = acl["aces"]["ace"][0]
                check(acl["name"] == "ankah-198-51-100-7", acl)
                check(acl["type"] == "ipv4-acl-type", acl)
                check(acl["activation-type"] == "immediate", acl)
                check(ace["matches"]["ipv4"] == {
                    "source-ipv4-network": "198.51.100.7/32",
                    "destination-ipv4-network": "192.0.2.11/32", "protocol": 6}, ace)
                check(ace["matches"]["tcp"] == {"destination-port-range-or-operator":
                                                {"operator": "eq", "port": 80}}, ace)
                check(ace["actions"] == {"forwarding": "drop"}, ace)
                check("pending-lifetime" not in acl, "no nonconfig members sent")

                # Further requests while active do not reinstall.
                for _ in range(10):
                    request(gate, "198.51.100.7")
                text = metrics(dashboard, token)
                check('ankah_dots_operations_total{operation="install",result="ok"} 1' in text,
                      text)
                check("ankah_dots_active_acls 1" in text, text)
                check("ankah_dots_registered 1" in text, text)
                check(len(server.matching("PUT", "/acls/acl=ankah-198-51-100-7")) == 1,
                      "one install while the ACL is active")

                wait_for(lambda: server.matching("DELETE", "/acls/acl=ankah-198-51-100-7"),
                         "withdrawal after the block time", timeout=8)
                text = wait_for(lambda: (lambda t: t if "ankah_dots_active_acls 0" in t
                                         else None)(metrics(dashboard, token)),
                                "active gauge to drop")
                check('ankah_dots_operations_total{operation="withdraw",result="ok"} 2' in text,
                      text)
                check("ankah_dots_escalations_total 1" in text, text)
            finally:
                stop(process)

            # An untrusted direct peer cannot pick the filtering source.
            before = len(server.requests)
            process, gate, _ = start(binary, assets, tmp, server.port, "192.0.2.0/24")
            try:
                wait_for(lambda: len(server.matching("PUT", "/dots-client=ankah-test")) >= 2,
                         "second registration")
                for _ in range(20):
                    request(gate, "198.51.100.8")
                time.sleep(.5)
                check(not server.matching("PUT", "/acls/acl=ankah-198-51-100-8"),
                      "forwarded address from an untrusted peer escalated")
                check(not server.matching("PUT", "/acls/acl=ankah-127-0-0-1"),
                      "untrusted direct peer escalated")
                check(len(server.requests) > before, "second gateway talked to DOTS")
            finally:
                stop(process)
        finally:
            server.close()

        # Fail open: with no DOTS server, ordinary handling continues.
        process, gate, dashboard = start(binary, assets, tmp, port(), "127.0.0.1/32")
        try:
            for _ in range(30):
                check(request(gate, "198.51.100.9") in (302, 428), "request while DOTS is down")
            text = wait_for(lambda: (lambda t: t if 'operation="register",result="error"} 0'
                                     not in t else None)(metrics(dashboard, token)),
                            "registration failure to be counted")
            check("ankah_dots_registered 0" in text, text)
            check("ankah_dots_escalations_total" in text, text)
            check(process.poll() is None, "gateway stayed up")
        finally:
            stop(process)
    print("dots integration ok")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else ".")
