"""Run one smoke phase from a fixed source-IP container."""
import http.client
import socket
import ssl
import sys
import threading

HOST = "haproxy"
PORT = 8443
CONTEXT = ssl._create_unverified_context()


def request(path):
    conn = http.client.HTTPSConnection(HOST, PORT, context=CONTEXT, timeout=8)
    try:
        conn.request("GET", path, headers={"Host": "localhost:8443"})
        reply = conn.getresponse()
        body = reply.read()
        return reply.status, dict(reply.getheaders()), body
    finally:
        conn.close()


def rejected():
    try:
        sock = socket.create_connection((HOST, PORT), timeout=4)
        try:
            with CONTEXT.wrap_socket(sock, server_hostname="localhost"):
                return False
        finally:
            sock.close()
    except (OSError, ssl.SSLError):
        return True


def health():
    status, headers, body = request("/health")
    assert status == 200 and b"Django through Ankah" in body, (status, body)
    assert "ankah-proxy-action" not in {key.lower() for key in headers}


def slow_headers():
    sock = socket.create_connection((HOST, PORT), timeout=5)
    try:
        with CONTEXT.wrap_socket(sock, server_hostname="localhost") as tls:
            tls.settimeout(40)
            tls.sendall(b"GET /health HTTP/1.1\r\nHost: localhost:8443\r\n")
            data = tls.recv(4096)
            assert data.startswith(b"HTTP/1.1 408"), data
    finally:
        sock.close()


def scan():
    for i in range(40):
        status, headers, _ = request(f"/scan/{i}?q=ignored")
        assert status in (302, 428), (i, status)
        assert "ankah-proxy-action" not in {key.lower() for key in headers}
    assert rejected(), "scanner was not rejected at connection time"


def flood():
    for _ in range(51):
        with socket.create_connection((HOST, PORT), timeout=4):
            pass
    assert rejected(), "connection-only flood was not rejected"


def stall_one(results, index):
    try:
        sock = socket.create_connection((HOST, PORT), timeout=5)
        with CONTEXT.wrap_socket(sock, server_hostname="localhost") as tls:
            tls.settimeout(45)
            tls.sendall(b"POST /upload HTTP/1.1\r\nHost: localhost:8443\r\n"
                        b"Content-Length: 1000\r\nConnection: close\r\n\r\n")
            data = tls.recv(4096)
            results[index] = data.startswith(b"HTTP/1.1 408")
    except Exception as error:
        results[index] = repr(error)


def stalls():
    results = [None] * 3
    threads = [threading.Thread(target=stall_one, args=(results, i)) for i in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results == [True] * 3, results
    assert rejected(), "body stalls did not cause a connection-time rejection"


if __name__ == "__main__":
    {"health": health, "slow_headers": slow_headers, "scan": scan,
     "flood": flood, "stalls": stalls,
     "rejected": lambda: None if rejected() else sys.exit("source was admitted")}[sys.argv[1]]()
