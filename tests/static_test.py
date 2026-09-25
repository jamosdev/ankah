"""Exercise packaged static files over a real gateway socket."""

import hashlib
import http.client
import gzip
import brotli
import json
import os
import shutil
import random
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse

from process_support import gateway_command


def request(port, path, method="GET", headers=None, timeout=3):
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    client.request(method, path, headers={"Host": f"localhost:{port}", **(headers or {})})
    reply = client.getresponse()
    result = reply.status, dict(reply.getheaders()), reply.read()
    client.close()
    return result


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def solve(challenge):
    nonce, _, bits, _ = challenge.split(".")
    bits = int(bits)
    full, remainder = divmod(bits, 8)
    for counter in range(1 << 32):
        digest = hashlib.sha256(f"{nonce}:{counter}".encode()).digest()
        if not any(digest[:full]) and (not remainder or digest[full] >> (8 - remainder) == 0):
            return counter
    raise RuntimeError("proof of work search exhausted")


def command_line_pass(port, path):
    status, headers, _ = request(port, path, headers={"User-Agent": "curl/8.0"})
    require(status == 302, "throttled file did not request proof of work")
    marker = "/ankah/blocked/run-ankah-challenge-"
    location = headers.get("Location", "")
    require(location.startswith(marker), "challenge redirect missing")
    challenge = location[len(marker):]
    query = urllib.parse.urlencode({"challenge": challenge, "answer": solve(challenge)})
    status, headers, _ = request(port, "/ankah/open?" + query, "POST")
    require(status == 200 and "Set-Cookie" in headers, "challenge pass was not issued")
    return headers["Set-Cookie"].split(";", 1)[0]


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
        downloads = static / "downloads"
        downloads.mkdir()
        throttled_body = random.Random(41).randbytes(250000)
        (downloads / "one.bin").write_bytes(throttled_body)
        (downloads / "two.bin").write_bytes(throttled_body)
        archives = static / "archives"
        archives.mkdir()
        (archives / "three.bin").write_bytes(throttled_body)
        bundle = root / "bundle"
        subprocess.run([sys.executable, builder, "--project-root", str(root / "app"),
                        "--output", str(bundle)], check=True, capture_output=True)
        manifest = (bundle / "manifest.tsv").read_text()
        require(manifest.startswith("ANKAH_STATIC_V2\t/static/\n"), "wrong mount")
        require("\tgzip\t" in manifest and "\tbr\t" in manifest,
                "compressed variants missing")
        secret = root / "secret"
        secret.write_text("a" * 64)
        invalid_base = ["--listen", "127.0.0.1:1", "--public-origin", "http://localhost:1",
                        "--secret-file", str(secret), "--assets-dir", assets,
                        "--static-bundle", str(bundle)]
        for extra, reason in (
                (["--static-throttle-prefix", "/static/downloads/"], "prefix without limit"),
                (["--static-throttle-global-mbps", "1"], "limit without prefix"),
                (["--static-throttle-prefix", "/downloads/",
                  "--static-throttle-global-mbps", "1"], "prefix outside bundle"),
                (["--static-throttle-prefix", "/static/downloads",
                  "--static-throttle-global-mbps", "1"], "prefix without slash"),
                (["--static-throttle-prefix", "/static/downloads/",
                  "--static-throttle-global-connections", "225"], "connection reserve")):
            result = subprocess.run(gateway_command(executable, invalid_base + extra),
                                    capture_output=True, timeout=3)
            require(result.returncode == 2, "invalid throttle accepted: " + reason)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        process = subprocess.Popen(
            gateway_command(executable, ["--listen", f"127.0.0.1:{port}",
             "--public-origin", f"http://localhost:{port}",
             "--secret-file", str(secret), "--assets-dir", assets,
             "--static-bundle", str(bundle)]),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            for _ in range(250):
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
            require(headers.get("X-Content-Type-Options") == "nosniff",
                    "static type policy missing")
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
            status, language_headers, payload = request(port, "/static/large.txt", "HEAD", {
                "Accept-Encoding": "identity;q=0, br;q=0, gzip;q=0",
                "Accept-Language": "es-MX"})
            require(status == 406 and not payload and
                    language_headers.get("Content-Language") == "es" and
                    "Accept-Language" in language_headers.get("Vary", "") and
                    int(language_headers["Content-Length"]) ==
                    len("No hay una representación estática aceptable\n".encode()),
                    "unacceptable HEAD language metadata differs")
            status, headers, payload = request(port, "/static/large.txt", "HEAD")
            require(status == 200 and not payload and int(headers["Content-Length"]) == len(body),
                    "HEAD failed")
            status, cached_headers, payload = request(
                port, "/static/large.txt", headers={"If-None-Match": f'"{digest}"'})
            require(status == 304 and not payload, "conditional request failed")
            require(int(cached_headers["Content-Length"]) == len(body),
                    "conditional size differs")
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
            status, merged_headers, payload = request(port, "/static/large.txt", headers={
                "Range": "bytes=10-19,0-9,5-14"})
            require(status == 206 and payload == body[:20] and
                    merged_headers.get("Content-Range") == f"bytes 0-19/{len(body)}",
                    "overlapping ranges were not merged")
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
        shell = b"<h1>Ready</h1>\n" * 128
        (frontend / "index.html").write_bytes(shell)
        (frontend / "app.js").write_text("console.log('ready');\n")
        frontend_bundle = root / "frontend-bundle"
        subprocess.run([sys.executable, builder, "--project-root", str(frontend.parent),
                        "--output", str(frontend_bundle)], check=True, capture_output=True)
        require((frontend_bundle / "manifest.tsv").read_text().startswith(
                "ANKAH_STATIC_V2\t/assets/\n"), "frontend detection failed")
        root_bundle = root / "root-bundle"
        subprocess.run([sys.executable, builder, "--project-root", str(frontend.parent),
                        "--source", "dist", "--url-prefix", "/",
                        "--spa-fallback", "index.html", "--output", str(root_bundle)],
                       check=True, capture_output=True)
        require((root_bundle / "manifest.tsv").read_text().startswith(
                "ANKAH_STATIC_V3\t/\t/index.html\n"), "root SPA metadata missing")
        require("\n/\t" in (root_bundle / "manifest.tsv").read_text(),
                "root index alias missing")

        spa_bundle = root / "spa-bundle"
        subprocess.run([sys.executable, builder, "--project-root", str(frontend.parent),
                        "--source", "dist", "--url-prefix", "/dashboard/",
                        "--spa-fallback", "index.html", "--output", str(spa_bundle)],
                       check=True, capture_output=True)
        require((spa_bundle / "manifest.tsv").read_text().startswith(
                "ANKAH_STATIC_V3\t/dashboard/\t/dashboard/index.html\n"),
                "SPA fallback metadata missing")
        broken_bundle = root / "broken-spa-bundle"
        shutil.copytree(spa_bundle, broken_bundle)
        broken_manifest = (broken_bundle / "manifest.tsv").read_text().splitlines(True)
        broken_manifest[0] = "ANKAH_STATIC_V3\t/dashboard/\t/dashboard/missing.html\n"
        (broken_bundle / "manifest.tsv").write_text("".join(broken_manifest))
        broken = subprocess.run(
            gateway_command(executable, ["--listen", "127.0.0.1:1",
             "--public-origin", "http://localhost:1", "--secret-file", str(secret),
             "--assets-dir", assets, "--static-bundle", str(broken_bundle)]),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=3)
        require(broken.returncode != 0, "invalid SPA manifest was loaded")
        for value in ("missing.html", "app.js", "../index.html"):
            result = subprocess.run(
                [sys.executable, builder, "--project-root", str(frontend.parent),
                 "--source", "dist", "--url-prefix", "/dashboard/",
                 "--spa-fallback", value, "--output", str(root / ("bad-" + value.replace("/", "-")))],
                capture_output=True)
            require(result.returncode != 0, "invalid SPA fallback was accepted: " + value)

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            root_port = sock.getsockname()[1]
        root_process = subprocess.Popen(
            gateway_command(executable, ["--listen", f"127.0.0.1:{root_port}",
             "--public-origin", f"http://localhost:{root_port}",
             "--secret-file", str(secret), "--assets-dir", assets,
             "--static-bundle", str(root_bundle)]),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        navigation = {"Accept": "text/html,application/xhtml+xml;q=0.9",
                      "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
                      "User-Agent": "Mozilla/5.0"}
        try:
            for _ in range(250):
                if root_process.poll() is not None:
                    raise RuntimeError("root gateway exited: " + root_process.stderr.read().decode())
                try:
                    status, _, payload = request(root_port, "/")
                    break
                except OSError:
                    time.sleep(0.02)
            else:
                raise RuntimeError("root gateway did not listen")
            require(status == 200 and payload == shell,
                    "root index was not served")
            require(request(root_port, "/account/settings", headers=navigation)[0] == 428,
                    "root SPA fallback bypassed the challenge")
        finally:
            root_process.terminate()
            root_process.wait(timeout=3)

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            spa_port = sock.getsockname()[1]
        spa_process = subprocess.Popen(
            gateway_command(executable, ["--listen", f"127.0.0.1:{spa_port}",
             "--public-origin", f"http://localhost:{spa_port}",
             "--secret-file", str(secret), "--assets-dir", assets,
             "--static-bundle", str(spa_bundle)]),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            for _ in range(250):
                if spa_process.poll() is not None:
                    raise RuntimeError("SPA gateway exited: " + spa_process.stderr.read().decode())
                try:
                    status, _, _ = request(spa_port, "/dashboard/settings", headers=navigation)
                    break
                except OSError:
                    time.sleep(0.02)
            else:
                raise RuntimeError("SPA gateway did not listen")
            require(status == 428, "SPA fallback bypassed the challenge")
            status, _, payload = request(spa_port, "/dashboard/index.html")
            require(status == 200 and payload == shell,
                    "exact SPA shell was not public")
            status, _, payload = request(spa_port, "/dashboard/app.js")
            require(status == 200 and payload == b"console.log('ready');\n",
                    "exact SPA asset was not public")
        finally:
            spa_process.terminate()
            spa_process.wait(timeout=3)

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            allowed_spa_port = sock.getsockname()[1]
        allowed_spa_process = subprocess.Popen(
            gateway_command(executable, ["--listen", f"127.0.0.1:{allowed_spa_port}",
             "--public-origin", f"http://localhost:{allowed_spa_port}",
             "--secret-file", str(secret), "--assets-dir", assets,
             "--static-bundle", str(spa_bundle), "--allow-prefix", "/dashboard/",
             "--ankah-healthz=/dashboard/health"]),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            for _ in range(250):
                if allowed_spa_process.poll() is not None:
                    raise RuntimeError("allowed SPA gateway exited: " +
                                       allowed_spa_process.stderr.read().decode())
                try:
                    status, headers, payload = request(
                        allowed_spa_port, "/dashboard/settings?tab=profile", headers=navigation)
                    break
                except OSError:
                    time.sleep(0.02)
            else:
                raise RuntimeError("allowed SPA gateway did not listen")
            require(status == 200 and payload == shell,
                    "authorized SPA navigation did not receive the shell")
            require(headers.get("Cache-Control") == "private, no-cache" and
                    headers.get("Vary") ==
                    "Accept, Sec-Fetch-Mode, Sec-Fetch-Dest, Accept-Encoding",
                    "SPA fallback cache policy missing")
            etag = headers["ETag"]
            status, gzip_headers, payload = request(
                allowed_spa_port, "/dashboard/compressed", headers={
                    **navigation, "Accept-Encoding": "gzip"})
            require(status == 200 and gzip_headers.get("Content-Encoding") == "gzip" and
                    gzip.decompress(payload) == shell, "SPA fallback compression failed")
            status, _, payload = request(
                allowed_spa_port, "/dashboard/without-fetch-metadata",
                headers={"Accept": "text/html"})
            require(status == 200 and payload == shell,
                    "SPA fallback required optional fetch metadata")
            status, head_headers, payload = request(
                allowed_spa_port, "/dashboard/settings", "HEAD", navigation)
            require(status == 200 and not payload and
                    int(head_headers["Content-Length"]) == len(shell),
                    "SPA fallback HEAD failed")
            status, _, payload = request(
                allowed_spa_port, "/dashboard/settings", headers={
                    **navigation, "If-None-Match": etag})
            require(status == 304 and not payload, "SPA fallback conditional request failed")
            negative = [
                ("/dashboard/settings", {"Accept": "*/*"}),
                ("/dashboard/settings", {"Accept": "text/html;q=0, */*;q=1"}),
                ("/dashboard/settings", {**navigation, "Sec-Fetch-Dest": "script"}),
                ("/dashboard/settings", {**navigation, "Sec-Fetch-Mode": "cors"}),
                ("/dashboard/missing.js", navigation),
                ("/dashboard/missing%2Ejs", navigation),
                ("/dashboard/settings", {**navigation, "Range": "bytes=0-3"}),
            ]
            for path, request_headers in negative:
                status, _, payload = request(allowed_spa_port, path, headers=request_headers)
                require(status == 404 and payload != shell,
                        "non-navigation request received SPA HTML: " + path)
            status, _, payload = request(allowed_spa_port, "/dashboard/settings", "POST",
                                         navigation)
            require(status == 404 and payload != shell,
                    "SPA fallback accepted POST")
            status, _, payload = request(allowed_spa_port, "/dashboard/health",
                                         headers=navigation)
            require(status == 200 and payload == b"ok\n", "health route lost precedence")
            status, _, payload = request(allowed_spa_port, "/ankah/not-a-route",
                                         headers=navigation)
            require(payload != shell, "internal route received SPA HTML")
        finally:
            allowed_spa_process.terminate()
            allowed_spa_process.wait(timeout=3)

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
            gateway_command(executable, ["--listen", f"127.0.0.1:{legacy_port}",
             "--public-origin", f"http://localhost:{legacy_port}",
             "--secret-file", str(secret), "--assets-dir", assets,
             "--static-bundle", str(legacy), "--static-cache-mb", "0"]),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            for _ in range(250):
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
            gateway_command(executable, ["--listen", f"127.0.0.1:{cache_port}",
             "--public-origin", f"http://localhost:{cache_port}",
             "--secret-file", str(secret), "--assets-dir", assets,
             "--static-bundle", str(cache_bundle), "--static-cache-mb", "1"]),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            for _ in range(250):
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

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            throttle_port = sock.getsockname()[1]
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            throttle_dashboard = sock.getsockname()[1]
        throttle_token = root / "throttle-dashboard-token"
        throttle_token.write_text("b" * 64)
        throttle_process = subprocess.Popen(
            gateway_command(executable, ["--listen", f"127.0.0.1:{throttle_port}",
             "--public-origin", f"http://localhost:{throttle_port}",
             "--secret-file", str(secret), "--assets-dir", assets,
             "--static-bundle", str(bundle),
             "--static-throttle-prefix", "/static/downloads/",
             "--static-throttle-prefix", "/static/archives/",
             "--static-throttle-global-connections", "2",
             "--static-throttle-client-connections", "2",
             "--static-throttle-global-mbps", "1",
             "--static-throttle-client-mbps", "1",
             "--dashboard-listen", f"127.0.0.1:{throttle_dashboard}",
             "--dashboard-token-file", str(throttle_token), "--no-stats-file"]),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            for _ in range(250):
                if throttle_process.poll() is not None:
                    raise RuntimeError("throttle gateway exited: " +
                                       throttle_process.stderr.read().decode())
                try:
                    if request(throttle_port, "/static/large.txt")[0] == 200:
                        break
                except OSError:
                    time.sleep(.02)
            else:
                raise RuntimeError("throttle gateway did not listen")
            cookie = command_line_pass(throttle_port, "/static/downloads/one.bin")
            require(request(throttle_port, "/static/large.txt")[0] == 200,
                    "unconfigured static prefix was throttled")
            status, headers, payload = request(
                throttle_port, "/static/downloads/one.bin", "HEAD", {"Cookie": cookie})
            require(status == 200 and not payload and
                    int(headers["Content-Length"]) == len(throttled_body),
                    "throttled HEAD consumed a transfer")
            with ThreadPoolExecutor(max_workers=3) as workers:
                started = time.monotonic()
                first = workers.submit(request, throttle_port, "/static/downloads/one.bin",
                                       "GET", {"Cookie": cookie}, 6)
                second = workers.submit(request, throttle_port, "/static/downloads/two.bin",
                                        "GET", {"Cookie": cookie}, 6)
                time.sleep(.15)
                status, headers, page = request(
                    throttle_port, "/static/archives/three.bin",
                    headers={"Cookie": cookie, "Accept-Language": "es"})
                require(status == 429 and headers.get("Retry-After") == "1" and
                        headers.get("Content-Language") == "es" and
                        b"<html lang=es>" in page and
                        "Tu posición es 1 de 1.".encode() in page and
                        "RateLimit" not in headers,
                        "queued response metadata differs")
                first_status, _, first_body = first.result()
                second_status, _, second_body = second.result()
            elapsed = time.monotonic() - started
            require(first_status == 200 and second_status == 200 and
                    first_body == throttled_body and second_body == throttled_body and
                    elapsed >= 3.2,
                    "aggregate bandwidth cap or transfer sharing was not enforced")
            time.sleep(.05)
            status, _, payload = request(throttle_port, "/static/archives/three.bin",
                                         headers={"Cookie": cookie}, timeout=6)
            require(status == 200 and payload == throttled_body,
                    "queued request was not eventually admitted across prefixes")
            status, _, payload = request(
                throttle_dashboard, "/stats/live",
                headers={"Authorization": "Bearer " + "b" * 64})
            live = json.loads(payload)
            field = {name: index for index, name in enumerate(
                json.loads(request(throttle_dashboard, "/stats/schema", headers={
                    "Authorization": "Bearer " + "b" * 64})[2])["fields"])}
            require(status == 200 and live["v"] == 3 and
                    live["cumulative"][field["throttled_static_requests"]] >= 3 and
                    live["cumulative"][field["throttle_queue_responses"]] >= 1 and
                    live["cumulative"][field["throttle_queued_requests"]] >= 1 and
                    live["cumulative"][field["throttled_static_bytes"]] >=
                    len(throttled_body) * 3 and
                    live["gauges"]["throttle_connections"] == 0 and
                    live["gauges"]["throttle_queue"] == 0,
                    "throttle statistics differ")
            # Wine cannot deliver the POSIX graceful-shutdown signal to the child.
            if os.environ.get("ANKAH_TEST_WINDOWS_PATHS") != "1":
                with ThreadPoolExecutor(max_workers=1) as workers:
                    started = time.monotonic()
                    draining = workers.submit(
                        request, throttle_port, "/static/downloads/one.bin",
                        "GET", {"Cookie": cookie}, 6)
                    time.sleep(.15)
                    throttle_process.terminate()
                    drain_status, _, drain_body = draining.result()
                throttle_process.wait(timeout=3)
                require(drain_status == 200 and drain_body == throttled_body and
                        time.monotonic() - started < 1.5 and
                        throttle_process.returncode == 0,
                        "shutdown did not unthrottle an active download")
        finally:
            if throttle_process.poll() is None:
                throttle_process.terminate()
                throttle_process.wait(timeout=3)

        compressed_digest = next(row.split("\t")[2] for row in manifest.splitlines()[1:]
                                 if row.split("\t")[1] == "gzip")
        blob = bundle / "files" / compressed_digest
        blob.write_bytes(b"tampered")
        rejected = subprocess.run(
            gateway_command(executable, ["--listen", "127.0.0.1:0",
             "--public-origin", "http://localhost:8000", "--secret-file", str(secret),
             "--assets-dir", assets, "--static-bundle", str(bundle)]),
            capture_output=True, timeout=3,
        )
        require(rejected.returncode != 0, "tampered bundle was accepted")


if __name__ == "__main__":
    main()
