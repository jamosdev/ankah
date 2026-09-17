"""Exercise packaged static files over a real gateway socket."""

import hashlib
import http.client
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def request(port, path, method="GET", headers=None):
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    client.request(method, path, headers={"Host": f"localhost:{port}", **(headers or {})})
    reply = client.getresponse()
    result = reply.status, dict(reply.getheaders()), reply.read()
    client.close()
    return result


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    executable, builder, assets = sys.argv[1:]
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        static = root / "app" / "static"
        static.mkdir(parents=True)
        body = b"hello from static\n" * 4096
        (static / "large.txt").write_bytes(body)
        (static / "app.abcdef1234.js").write_text("let value = 1;\n")
        bundle = root / "bundle"
        subprocess.run([sys.executable, builder, "--project-root", str(root / "app"),
                        "--output", str(bundle)], check=True, capture_output=True)
        manifest = (bundle / "manifest.tsv").read_text()
        require(manifest.startswith("ANKAH_STATIC_V1\t/static/\n"), "wrong mount")
        secret = root / "secret"
        secret.write_text("a" * 64)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        process = subprocess.Popen(
            [executable, "--listen", f"127.0.0.1:{port}",
             "--public-origin", f"http://localhost:{port}",
             "--secret-file", str(secret), "--assets-dir", assets,
             "--static-bundle", str(bundle)],
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
            status, headers, payload = request(port, "/static/large.txt?x=1")
            require(status == 200 and payload == body, "large static body differs")
            digest = hashlib.sha256(body).hexdigest()
            require(headers.get("ETag") == f'"{digest}"', "wrong static ETag")
            require(headers.get("Cache-Control") == "public, max-age=60", "wrong cache policy")
            status, headers, payload = request(port, "/static/large.txt", "HEAD")
            require(status == 200 and not payload and int(headers["Content-Length"]) == len(body),
                    "HEAD failed")
            status, _, payload = request(port, "/static/large.txt", headers={"If-None-Match": f'"{digest}"'})
            require(status == 304 and not payload, "conditional request failed")
            status, headers, _ = request(port, "/static/app.abcdef1234.js")
            require(status == 200 and headers.get("Cache-Control") ==
                    "public, max-age=31536000, immutable", "hashed cache policy missing")
            require(request(port, "/static/missing.txt")[0] == 404, "missing static file passed upstream")
            require(request(port, "/static/../secret")[0] == 404, "parent path escaped mount")
            require(request(port, "/static/large.txt", "POST")[0] == 405, "method guard failed")
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

        frontend = root / "frontend" / "dist"
        frontend.mkdir(parents=True)
        (frontend / "index.html").write_text("<h1>Ready</h1>\n")
        frontend_bundle = root / "frontend-bundle"
        subprocess.run([sys.executable, builder, "--project-root", str(frontend.parent),
                        "--output", str(frontend_bundle)], check=True, capture_output=True)
        require((frontend_bundle / "manifest.tsv").read_text().startswith(
                "ANKAH_STATIC_V1\t/assets/\n"), "frontend detection failed")
        root_bundle = root / "root-bundle"
        subprocess.run([sys.executable, builder, "--project-root", str(frontend.parent),
                        "--source", "dist", "--url-prefix", "/", "--output", str(root_bundle)],
                       check=True, capture_output=True)
        require("\n/\t" in (root_bundle / "manifest.tsv").read_text(),
                "root index alias missing")

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            root_port = sock.getsockname()[1]
        root_process = subprocess.Popen(
            [executable, "--listen", f"127.0.0.1:{root_port}",
             "--public-origin", f"http://localhost:{root_port}",
             "--secret-file", str(secret), "--assets-dir", assets,
             "--static-bundle", str(root_bundle)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            for _ in range(50):
                if root_process.poll() is not None:
                    raise RuntimeError("root gateway exited: " + root_process.stderr.read().decode())
                try:
                    status, _, payload = request(root_port, "/")
                    break
                except OSError:
                    time.sleep(0.02)
            else:
                raise RuntimeError("root gateway did not listen")
            require(status == 200 and payload == b"<h1>Ready</h1>\n",
                    "root index was not served")
        finally:
            root_process.terminate()
            root_process.wait(timeout=3)

        blob = next((bundle / "files").iterdir())
        blob.write_bytes(b"tampered")
        rejected = subprocess.run(
            [executable, "--listen", "127.0.0.1:0",
             "--public-origin", "http://localhost:8000", "--secret-file", str(secret),
             "--assets-dir", assets, "--static-bundle", str(bundle)],
            capture_output=True, timeout=3,
        )
        require(rejected.returncode != 0, "tampered bundle was accepted")


if __name__ == "__main__":
    main()
