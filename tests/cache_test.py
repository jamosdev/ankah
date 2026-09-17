"""Exercise the gateway's versioned asset responses over a real socket."""

import hashlib
import http.client
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import time


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def request(port, path, method="GET", headers=None):
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    client.request(method, path, headers={"Host": "localhost:%d" % port, **(headers or {})})
    reply = client.getresponse()
    result = reply.status, dict(reply.getheaders()), reply.read()
    client.close()
    return result


def main():
    executable = sys.argv[1]
    root = pathlib.Path(sys.argv[2])
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with tempfile.TemporaryDirectory() as temp:
        secret = pathlib.Path(temp) / "secret"
        secret.write_text("a" * 64)
        process = subprocess.Popen(
            [executable, "--listen", "127.0.0.1:%d" % port,
             "--public-origin", "http://localhost:%d" % port,
             "--secret-file", str(secret), "--assets-dir", str(root)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            for _ in range(50):
                if process.poll() is not None:
                    raise RuntimeError("gateway exited: " + process.stderr.read().decode())
                try:
                    request(port, "/")
                    break
                except OSError:
                    time.sleep(0.02)
            else:
                raise RuntimeError("gateway did not listen")

            body = (root / "ankah.png").read_bytes()
            digest = hashlib.sha256(body).hexdigest()
            path = "/ankah/assets/%s/ankah.png" % digest
            status, headers, payload = request(port, path)
            check(status == 200 and payload == body, "asset body differs")
            check(headers.get("Cache-Control") == "public, max-age=31536000, immutable",
                  "immutable cache header missing")
            check(headers.get("ETag") == '"%s"' % digest, "ETag differs")
            modified = headers.get("Last-Modified", "")
            check(re.fullmatch(r"\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} GMT", modified),
                  "Last-Modified missing")
            status, headers, payload = request(port, path, "HEAD")
            check(status == 200 and not payload and int(headers["Content-Length"]) == len(body),
                  "HEAD must report the asset size")
            status, _, payload = request(port, path, headers={"If-None-Match": '"%s"' % digest})
            check(status == 304 and not payload, "ETag revalidation failed")
            status, _, payload = request(port, path, headers={"If-Modified-Since": modified})
            check(status == 304 and not payload, "modification-date revalidation failed")
            status, _, _ = request(port, "/ankah/assets/%s/ankah.png" % ("0" * 64))
            check(status == 404, "stale content hash must not serve the asset")
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
