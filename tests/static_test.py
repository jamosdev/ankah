"""Exercise packaged static files over a real gateway socket."""

import hashlib
import http.client
import gzip
import brotli
import shutil
import random
from concurrent.futures import ThreadPoolExecutor
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
        (static / "empty.txt").write_bytes(b"")
        bundle = root / "bundle"
        subprocess.run([sys.executable, builder, "--project-root", str(root / "app"),
                        "--output", str(bundle)], check=True, capture_output=True)
        manifest = (bundle / "manifest.tsv").read_text()
        require(manifest.startswith("ANKAH_STATIC_V2\t/static/\n"), "wrong mount")
        require("\tgzip\t" in manifest and "\tbr\t" in manifest,
                "compressed variants missing")
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
            require(headers.get("Vary") == "Accept-Encoding", "missing Vary")
            require(headers.get("Accept-Ranges") == "bytes", "missing range advertisement")
            status, gzip_headers, zipped = request(port, "/static/large.txt",
                                                   headers={"Accept-Encoding": "gzip"})
            require(status == 200 and gzip_headers.get("Content-Encoding") == "gzip" and
                    gzip.decompress(zipped) == body, "gzip negotiation failed")
            require(gzip_headers["ETag"] != headers["ETag"], "gzip ETag reused identity")
            status, br_headers, packed = request(port, "/static/large.txt",
                                                 headers={"Accept-Encoding": "gzip, br"})
            require(status == 200 and br_headers.get("Content-Encoding") == "br" and
                    brotli.decompress(packed) == body, "Brotli negotiation failed")
            require(br_headers["ETag"] != gzip_headers["ETag"], "Brotli ETag reused gzip")
            status, compressed_head, payload = request(port, "/static/large.txt", "HEAD",
                                                       {"Accept-Encoding": "br"})
            require(status == 200 and not payload and
                    int(compressed_head["Content-Length"]) == len(packed),
                    "compressed HEAD failed")
            require(request(port, "/static/large.txt", headers={
                "Accept-Encoding": "br;q=0, gzip;q=0.5, identity;q=0"})[1].get("Content-Encoding") == "gzip",
                "quality values ignored")
            require(request(port, "/static/large.txt", headers={
                "Accept-Encoding": "identity;q=0, br;q=0, gzip;q=0"})[0] == 406,
                "unacceptable encodings were served")
            status, _, payload = request(port, "/static/large.txt", "HEAD", {
                "Accept-Encoding": "identity;q=0, br;q=0, gzip;q=0"})
            require(status == 406 and not payload, "unacceptable HEAD sent a body")
            status, headers, payload = request(port, "/static/large.txt", "HEAD")
            require(status == 200 and not payload and int(headers["Content-Length"]) == len(body),
                    "HEAD failed")
            status, _, payload = request(port, "/static/large.txt", headers={"If-None-Match": f'"{digest}"'})
            require(status == 304 and not payload, "conditional request failed")
            require(request(port, "/static/large.txt", headers={
                "If-None-Match": f'W/"{digest}"'})[0] == 304,
                "weak conditional tag failed")
            status, _, payload = request(port, "/static/large.txt", headers={
                "Accept-Encoding": "gzip", "If-None-Match": gzip_headers["ETag"],
                "Range": "bytes=0-9"})
            require(status == 304 and not payload, "conditional range failed")
            status, _, payload = request(port, "/static/large.txt", headers={
                "Accept-Encoding": "gzip", "If-None-Match": br_headers["ETag"]})
            require(status == 200 and gzip.decompress(payload) == body,
                    "wrong variant matched conditional request")
            status, range_headers, payload = request(port, "/static/large.txt", headers={
                "Range": "bytes=10-29"})
            require(status == 206 and payload == body[10:30] and
                    range_headers.get("Content-Range") == f"bytes 10-29/{len(body)}",
                    "single range failed")
            status, _, payload = request(port, "/static/large.txt", headers={
                "Range": "bytes=30-"})
            require(status == 206 and payload == body[30:], "open range failed")
            status, _, payload = request(port, "/static/large.txt", headers={
                "Range": "bytes=-20"})
            require(status == 206 and payload == body[-20:], "suffix range failed")
            status, range_headers, payload = request(port, "/static/large.txt", headers={
                "Accept-Encoding": "gzip", "Range": "bytes=0-9"})
            require(status == 206 and payload == zipped[:10] and
                    range_headers.get("Content-Range") == f"bytes 0-9/{len(zipped)}",
                    "compressed range used decoded offsets")
            status, multi_headers, payload = request(port, "/static/large.txt", headers={
                "Range": "bytes=0-4,10-14"})
            require(status == 206 and multi_headers["Content-Type"].startswith(
                "multipart/byteranges; boundary=") and
                b"Content-Range: bytes 0-4/" in payload and
                b"Content-Range: bytes 10-14/" in payload and
                b"\r\n" + body[:5] + b"\r\n" in payload and
                b"\r\n" + body[10:15] + b"\r\n" in payload,
                "multipart ranges failed")
            require(int(multi_headers["Content-Length"]) == len(payload),
                    "multipart length wrong")
            status, multi_headers, payload = request(port, "/static/large.txt", headers={
                "Accept-Encoding": "gzip", "Range": "bytes=0-4,10-14"})
            require(status == 206 and multi_headers.get("Content-Encoding") == "gzip" and
                    zipped[:5] in payload and zipped[10:15] in payload and
                    f"bytes 10-14/{len(zipped)}".encode() in payload,
                    "compressed multipart ranges failed")
            status, headers, payload = request(port, "/static/large.txt", headers={
                "Range": "bytes=999999-"})
            require(status == 416 and not payload and
                    headers.get("Content-Range") == f"bytes */{len(body)}",
                    "unsatisfied range failed")
            status, _, payload = request(port, "/static/large.txt", headers={
                "Range": "bytes=0-4", "If-Range": '"old"'})
            require(status == 200 and payload == body, "stale If-Range was accepted")
            status, _, payload = request(port, "/static/large.txt", headers={
                "Range": "bytes=0-4", "If-Range": f'"{digest}"'})
            require(status == 206 and payload == body[:5], "matching If-Range failed")
            require(request(port, "/static/large.txt", headers={
                "Range": "bytes=0-4", "If-Range": "Wed, 01 Jan 2020 00:00:00 GMT"})[0] == 200,
                "date If-Range was accepted")
            require(request(port, "/static/large.txt", headers={
                "Range": "bytes=" + ",".join(f"{n}-{n}" for n in range(17))})[0] == 200,
                "excessive ranges were accepted")
            status, headers, payload = request(port, "/static/large.txt", "HEAD", {
                "Range": "bytes=0-4"})
            require(status == 206 and not payload and headers["Content-Length"] == "5",
                    "HEAD range failed")
            require(request(port, "/static/empty.txt", headers={
                "Range": "bytes=0-1"})[0] == 416, "empty range failed")
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
                "ANKAH_STATIC_V2\t/assets/\n"), "frontend detection failed")
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

        legacy = root / "legacy-bundle"
        shutil.copytree(bundle / "files", legacy / "files")
        legacy_rows = ["ANKAH_STATIC_V1\t/static/\n"]
        for row in manifest.splitlines()[1:]:
            fields = row.split("\t")
            if fields[1] == "identity":
                legacy_rows.append("\t".join([fields[0], *fields[2:]]) + "\n")
        (legacy / "manifest.tsv").write_text("".join(legacy_rows))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            legacy_port = sock.getsockname()[1]
        legacy_process = subprocess.Popen(
            [executable, "--listen", f"127.0.0.1:{legacy_port}",
             "--public-origin", f"http://localhost:{legacy_port}",
             "--secret-file", str(secret), "--assets-dir", assets,
             "--static-bundle", str(legacy), "--static-cache-mb", "0"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            for _ in range(50):
                if legacy_process.poll() is not None:
                    raise RuntimeError("legacy gateway exited: " +
                                       legacy_process.stderr.read().decode())
                try:
                    status, _, payload = request(legacy_port, "/static/large.txt")
                    break
                except OSError:
                    time.sleep(0.02)
            else:
                raise RuntimeError("legacy gateway did not listen")
            require(status == 200 and payload == body, "version 1 bundle failed")
        finally:
            legacy_process.terminate()
            legacy_process.wait(timeout=3)

        cache_static = root / "cache-app" / "static"
        cache_static.mkdir(parents=True)
        samples = []
        for number in range(3):
            sample = random.Random(number).randbytes(550000) + b"0" * 550000
            samples.append(sample)
            (cache_static / f"file{number}.txt").write_bytes(sample)
        cache_bundle = root / "cache-bundle"
        subprocess.run([sys.executable, builder, "--project-root", str(cache_static.parent),
                        "--output", str(cache_bundle)], check=True, capture_output=True)
        cache_rows = (cache_bundle / "manifest.tsv").read_text().splitlines()
        compressed_sizes = [int(row.split("\t")[3]) for row in cache_rows
                            if row.split("\t")[1] == "gzip"]
        require(len(compressed_sizes) == 3 and
                max(compressed_sizes) < 1024 * 1024 < sum(compressed_sizes),
                "cache fixture does not force eviction")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cache_port = sock.getsockname()[1]
        cache_process = subprocess.Popen(
            [executable, "--listen", f"127.0.0.1:{cache_port}",
             "--public-origin", f"http://localhost:{cache_port}",
             "--secret-file", str(secret), "--assets-dir", assets,
             "--static-bundle", str(cache_bundle), "--static-cache-mb", "1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            for _ in range(50):
                if cache_process.poll() is not None:
                    raise RuntimeError("cache gateway exited: " +
                                       cache_process.stderr.read().decode())
                try:
                    request(cache_port, "/")
                    break
                except OSError:
                    time.sleep(0.02)
            else:
                raise RuntimeError("cache gateway did not listen")
            for number in (0, 1, 2, 0):
                status, headers, payload = request(cache_port, f"/static/file{number}.txt",
                                                   headers={"Accept-Encoding": "gzip, identity;q=0"})
                require(status == 200 and headers.get("Content-Encoding") == "gzip" and
                        gzip.decompress(payload) == samples[number],
                        "cache fill or eviction changed the response")
            with ThreadPoolExecutor(max_workers=3) as workers:
                concurrent = list(workers.map(
                    lambda number: request(cache_port, f"/static/file{number}.txt",
                                           headers={"Accept-Encoding": "gzip, identity;q=0"}),
                    range(3)))
            for number, (status, headers, payload) in enumerate(concurrent):
                require(status == 200 and headers.get("Content-Encoding") == "gzip" and
                        gzip.decompress(payload) == samples[number],
                        "concurrent cache responses differed")
        finally:
            cache_process.terminate()
            cache_process.wait(timeout=3)

        compressed_digest = next(row.split("\t")[2] for row in manifest.splitlines()[1:]
                                 if row.split("\t")[1] == "gzip")
        blob = bundle / "files" / compressed_digest
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
