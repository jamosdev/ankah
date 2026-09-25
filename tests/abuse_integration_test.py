"""Exercise trusted response signals and timeout behavior over HTTP/1.1."""
import http.client
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from process_support import gateway_command


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(gate, path, source):
    conn = http.client.HTTPConnection("127.0.0.1", gate, timeout=5)
    try:
        conn.request("GET", path, headers={"Host": f"localhost:{gate}",
                                           "X-Forwarded-For": source})
        reply = conn.getresponse()
        return reply.status, dict(reply.getheaders()), reply.read()
    finally:
        conn.close()


def serve(upstream, stop):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", upstream))
    listener.listen()
    listener.settimeout(.2)
    while not stop.is_set():
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        threading.Thread(target=hold, args=(conn,), daemon=True).start()
    listener.close()


def hold(conn):
    with conn:
        conn.settimeout(40)
        try:
            first = conn.recv(4096)
            if first.startswith(b"GET /pass"):
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhi")
            time.sleep(35)
        except OSError:
            pass


def raw(gate, packet, result, index):
    try:
        with socket.create_connection(("127.0.0.1", gate), timeout=4) as sock:
            sock.settimeout(40)
            sock.sendall(packet.replace(b"PORT", str(gate).encode()))
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            result[index] = b"".join(chunks)
    except OSError as error:
        result[index] = repr(error).encode()


def run_gateway(binary, assets, gate, upstream, secret, trusted):
    args = [binary, "--listen", f"127.0.0.1:{gate}", "--upstream", f"127.0.0.1:{upstream}",
            "--public-origin", f"http://localhost:{gate}", "--secret-file", str(secret),
            "--assets-dir", assets, "--proxy-abuse-profile=conservative",
            "--allow-prefix", "/upload", "--allow-prefix", "/pass"]
    if trusted:
        args += ["--trusted-proxy", "127.0.0.1/32"]
    process = subprocess.Popen(gateway_command(binary, args[1:]),
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(100):
        try:
            request(gate, "/ready", "198.51.100.100")
            return process
        except OSError:
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read().decode())
            time.sleep(.03)
    raise RuntimeError("gateway did not start")


def main(binary, assets):
    with tempfile.TemporaryDirectory() as tmp:
        secret = Path(tmp) / "secret"
        secret.write_text("a" * 64)
        gate, upstream = port(), port()
        stop = threading.Event()
        worker = threading.Thread(target=serve, args=(upstream, stop), daemon=True)
        worker.start()
        process = run_gateway(binary, assets, gate, upstream, secret, True)
        try:
            status, headers, _ = request(gate, "/ordinary", "198.51.100.1")
            assert status in (302, 428) and "Ankah-Proxy-Action" not in headers
            for i in range(39):
                status, headers, _ = request(gate, f"/scan/{i}?same=1", "198.51.100.2")
                assert "Ankah-Proxy-Action" not in headers, i
            status, headers, _ = request(gate, "/scan/39", "198.51.100.2")
            assert headers.get("Ankah-Proxy-Action") == "block", (status, headers)
            status, headers, _ = request(gate, "/ordinary", "198.51.100.3")
            assert "Ankah-Proxy-Action" not in headers
            packets = [b"POST /upload HTTP/1.1\r\nHost: localhost:PORT\r\n"
                       b"X-Forwarded-For: 198.51.100.4\r\nContent-Length: 100\r\n\r\n"] * 3
            packets += [b"GET /slow HTTP/1.1\r\nHost: localhost:PORT\r\n",
                        b"GET /pass HTTP/1.1\r\nHost: localhost:PORT\r\n"
                        b"X-Forwarded-For: 198.51.100.5\r\n\r\n"]
            results = [None] * len(packets)
            threads = [threading.Thread(target=raw, args=(gate, packet, results, i))
                       for i, packet in enumerate(packets)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            assert all(reply.startswith(b"HTTP/1.1 408") for reply in results[:3]), results
            assert sum(b"Ankah-Proxy-Action: block" in reply for reply in results[:3]) == 1
            assert results[3] == b"", results[3]
            assert results[4].startswith(b"HTTP/1.1 200") and b"408" not in results[4]
        finally:
            process.terminate()
            process.wait(timeout=5)
        gate = port()
        process = run_gateway(binary, assets, gate, upstream, secret, False)
        try:
            for i in range(80):
                _, headers, _ = request(gate, f"/scan/{i}", "198.51.100.9")
                assert "Ankah-Proxy-Action" not in headers
            result = [None]
            raw(gate, b"POST /upload HTTP/1.1\r\nHost: localhost:PORT\r\n"
                b"Content-Length: 100\r\n\r\n", result, 0)
            assert result[0].startswith(b"HTTP/1.1 429") and \
                   b"Retry-After: 1" in result[0] and \
                   b"Ankah-Proxy-Action" not in result[0], result[0]
        finally:
            process.terminate()
            process.wait(timeout=5)
            stop.set()
            worker.join(timeout=1)


if __name__ == "__main__":
    main(*sys.argv[1:])
