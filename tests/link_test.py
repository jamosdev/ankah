"""Exercise authenticated gateway links and durable POST ownership."""

import hashlib
import http.client
import http.server
import concurrent.futures
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

from process_support import start_gateway


def free_port(ip="127.0.0.1"):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.bind((ip, 0))
        return listener.getsockname()[1]


def request(port, path, method="GET", body=None, headers=None):
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=12)
    client.request(method, path, body=body,
                   headers={"Host": "example.test", **(headers or {})})
    response = client.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    client.close()
    return result


def await_status(port, path, expected, headers=None):
    until = time.monotonic() + 8
    while time.monotonic() < until:
        try:
            result = request(port, path, headers=headers)
            if result[0] == expected:
                return result
        except OSError:
            pass
        time.sleep(.05)
    raise AssertionError(f"{path} did not return {expected}")


def solve(challenge):
    nonce, _, bits, *_ = challenge.split(".")
    bits = int(bits)
    for counter in range(4_000_000):
        digest = hashlib.sha256(f"{nonce}:{counter}".encode()).digest()
        if int.from_bytes(digest, "big") >> (256 - bits) == 0:
            return counter
    raise AssertionError("proof search exhausted")


def gate(port, path, method="GET", body=None):
    status, _, page = request(port, path, method, body, {"Accept": "text/html"})
    assert status == 428, (status, page[:120])
    session = re.search(rb"data-session='([0-9a-f]{32})'", page).group(1).decode()
    challenge = re.search(rb"data-challenge='([^']+)'", page).group(1).decode()
    token = re.search(rb"name=ankah_continue value='([0-9a-f]{32})'", page)
    return session, challenge, token.group(1).decode() if token else None


def main():
    executable, assets = sys.argv[1:]
    app_port = free_port()
    replayed = []

    class App(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            payload = self.rfile.read(int(self.headers["Content-Length"]))
            replayed.append((self.path, payload))
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_):
            pass

    application = http.server.ThreadingHTTPServer(("127.0.0.1", app_port), App)
    threading.Thread(target=application.serve_forever, daemon=True).start()
    processes = []
    with tempfile.TemporaryDirectory() as temporary:
        directory = pathlib.Path(temporary)
        secret = directory / "secret"
        wrong_secret = directory / "wrong"
        secret.write_text("5a" * 32 + "\n")
        wrong_secret.write_text("a5" * 32 + "\n")
        gate_a, gate_b, gate_c = free_port(), free_port(), free_port()
        link_a, link_b, link_c = free_port(), free_port(), free_port()

        def start(gate_port, link_port, other_link, key, state,
                  link_ip="127.0.0.1", peer_host=None):
            peer_host = peer_host or link_ip
            peer = (f"[{peer_host}]:{other_link}" if ":" in peer_host
                    else f"{peer_host}:{other_link}")
            listen = (f"[{link_ip}]:{link_port}" if ":" in link_ip
                      else f"{link_ip}:{link_port}")
            arguments = [
                "--public-origin", "http://example.test",
                "--secret-file", str(key), "--assets-dir", assets,
                "--listen", f"127.0.0.1:{gate_port}",
                "--upstream", f"127.0.0.1:{app_port}",
                "--ankah-link", peer, "--ankah-link-listen", listen,
                "--ankah-healthz", "--trusted-proxy", "127.0.0.1/32",
                "--proxy-abuse-profile=strict",
            ]
            if state:
                arguments += ["--session-state-file", str(state)]
            else:
                arguments += ["--no-session-state-file"]
            log = tempfile.TemporaryFile()
            process = start_gateway(executable, arguments,
                                    stdout=subprocess.DEVNULL, stderr=log)
            process.error_log = log
            processes.append(process)
            await_status(gate_port, "/healthz", 200)
            return process

        def stop(process, abrupt=False):
            if abrupt:
                process.kill()
            else:
                process.terminate()
            process.wait(timeout=12)
            processes.remove(process)
            process.error_log.seek(0)
            output = process.error_log.read().decode()
            process.error_log.close()
            return output

        try:
            state_a = directory / "sessions-a"
            state_b = directory / "sessions-b"
            a = start(gate_a, link_a, link_b, secret, state_a,
                      peer_host="localhost")
            b = start(gate_b, link_b, link_a, secret, state_b)
            time.sleep(1.2)

            session, challenge, _ = gate(gate_a, "/private")
            assert request(gate_b, f"/ankah/qr/{session}.png")[0] == 200
            solve_page = request(gate_b, f"/ankah/solve/{session}")
            assert solve_page[0] == 200 and challenge.encode() in solve_page[2]
            answer = solve(challenge)
            assert request(gate_b, f"/ankah/answer/{session}?answer={answer}",
                           "POST", b"")[0] == 200
            status, headers, _ = await_status(
                gate_b, f"/ankah/finish/{session}", 303,
                {"Cookie": f"ankah_sid={session}"})
            assert headers["Location"] == "/private"
            assert "ankah_pass=" in headers["Set-Cookie"]

            post_id, post_challenge, token = gate(
                gate_a, "/submit?one=1", "POST", b"saved body")
            assert token
            assert request(gate_b, f"/ankah/answer/{post_id}?answer={solve(post_challenge)}",
                           "POST", b"")[0] == 200
            shutdown_log = stop(a)
            assert "draining" in shutdown_log, shutdown_log
            unavailable = request(gate_b, "/submit?one=1", "POST",
                                  f"ankah_continue={token}".encode(), {
                                      "Cookie": f"ankah_sid={post_id}",
                                      "Content-Type": "application/x-www-form-urlencoded",
                                  })
            assert unavailable[0] == 503 and unavailable[1]["Retry-After"] == "1"
            a = start(gate_a, link_a, link_b, secret, state_a)
            time.sleep(1.2)
            continuation = f"ankah_continue={token}".encode()
            continuation_headers = {
                "Cookie": f"ankah_sid={post_id}",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                attempts = list(pool.map(
                    lambda _: request(gate_b, "/submit?one=1", "POST",
                                      continuation, continuation_headers), range(2)))
            assert sorted(attempt[0] for attempt in attempts) == [200, 403], attempts
            status, headers, body = next(
                attempt for attempt in attempts if attempt[0] == 200)
            assert body == b"saved body", body
            assert "ankah_pass=" in headers["Set-Cookie"]
            assert replayed.count(("/submit?one=1", b"saved body")) == 1
            assert request(gate_b, "/submit?one=1", "POST", continuation,
                           continuation_headers)[0] == 403

            stop(a, abrupt=True)
            a = start(gate_a, link_a, link_b, secret, state_a)
            time.sleep(1.2)
            assert request(gate_b, "/submit?one=1", "POST", continuation,
                           continuation_headers)[0] == 403

            malicious = {"X-Forwarded-For": "198.51.100.77"}
            for _ in range(4):
                request(gate_a, "/ankah/answer/" + "0" * 32 + "?answer=0",
                        "POST", b"", malicious)
            await_status(gate_b, "/private", 403, malicious)

            c = start(gate_c, link_c, link_a, wrong_secret, None)
            status = request(gate_c, f"/ankah/answer/{session}?answer={answer}",
                             "POST", b"")[0]
            assert status == 403
            stop(c)

            quiet_source = {"X-Forwarded-For": "198.51.100.90"}
            for _ in range(100):
                request(gate_a, "/flood", headers=quiet_source)
            output = stop(a)
            match = re.search(r"gateway link bytes sent: (\d+)", output)
            assert match and int(match.group(1)) < 64 * 1024, output
            stop(b)

            if socket.has_ipv6:
                try:
                    ipv6_a, ipv6_b = free_port("::1"), free_port("::1")
                except OSError:
                    ipv6_a = ipv6_b = None
                if ipv6_a:
                    http_a, http_b = free_port(), free_port()
                    x = start(http_a, ipv6_a, ipv6_b, secret, None, "::1")
                    y = start(http_b, ipv6_b, ipv6_a, secret, None, "::1")
                    time.sleep(1.2)
                    ipv6_id, ipv6_challenge, _ = gate(http_a, "/ipv6")
                    assert request(http_b, f"/ankah/answer/{ipv6_id}"
                                   f"?answer={solve(ipv6_challenge)}",
                                   "POST", b"")[0] == 200
                    assert await_status(http_a, f"/ankah/finish/{ipv6_id}", 303,
                                        {"Cookie": f"ankah_sid={ipv6_id}"})[0] == 303
                    stop(x)
                    stop(y)

            failed_state = directory / "missing" / "sessions"
            failed_gate = free_port()
            failing = start(failed_gate, free_port(), free_port(),
                            secret, failed_state)
            gate(failed_gate, "/writer-failure")
            assert "session persistence unavailable" in stop(failing)

            repair_state = directory / "repair-sessions"
            repair_journal = directory / "repair-sessions.journal"
            repair_journal.write_bytes(b"incomplete record")
            repairing = start(free_port(), free_port(), free_port(),
                              secret, repair_state)
            deadline = time.monotonic() + 12
            while (repair_journal.stat().st_size and time.monotonic() < deadline):
                time.sleep(.05)
            assert repair_journal.stat().st_size == 0
            assert (directory / "repair-sessions.0").exists()
            assert (directory / "repair-sessions.1").exists()
            stop(repairing)
        finally:
            for process in list(processes):
                stop(process, abrupt=True)
            application.shutdown()


if __name__ == "__main__":
    main()
