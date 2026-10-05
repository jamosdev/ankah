"""Exercise mascot encoding and background worker lifetime with fresh gateways."""

import contextlib
import http.client
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib

from process_support import start_gateway


TOKEN = "b" * 64
AUTH = {"Authorization": "Bearer " + TOKEN}


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def free_port():
    with socket.socket() as client:
        client.bind(("127.0.0.1", 0))
        return client.getsockname()[1]


def request(port, path, method="GET", body=None, headers=None):
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        client.request(method, path, body=body, headers={
            "Host": f"localhost:{port}", **AUTH, **(headers or {})})
        response = client.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        client.close()


def expect(response, status):
    check(response[0] == status,
          f"expected {status}, got status={response[0]} headers={response[1]} "
          f"body={response[2][:512]!r}")
    return response[2]


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def png(width=32, height=32):
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            i = y * width + x
            rows.extend((i % 256, (i >> 2) % 256, (i * 17) % 256,
                         0 if i % 4 == 0 else 128 if i % 4 == 1 else 255))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 0)) + chunk(b"IEND", b""))


def wait_file(path, process):
    deadline = time.monotonic() + 10
    while not path.exists():
        check(process.poll() is None, "gateway exited before worker synchronization")
        check(time.monotonic() < deadline, "worker synchronization timed out")
        time.sleep(.005)


@contextlib.contextmanager
def gateway(executable, assets, directory, fixture=None):
    public, dashboard = free_port(), free_port()
    secret, token = directory / "secret", directory / "token"
    secret.write_text("a" * 64)
    token.write_text(TOKEN)
    env = os.environ.copy()
    if fixture:
        env.update(LD_PRELOAD=fixture,
                   ANKAH_MASCOT_ENTERED=str(directory / "entered"),
                   ANKAH_MASCOT_RELEASE=str(directory / "release"),
                   ANKAH_MASCOT_CANCELLED=str(directory / "cancelled"),
                   ANKAH_MASCOT_FINISHED=str(directory / "finished"))
    arguments = ["--listen", f"127.0.0.1:{public}", "--upstream", "127.0.0.1:9",
                 "--public-origin", f"http://localhost:{public}",
                 "--assets-dir", str(assets), "--secret-file", str(secret),
                 "--dashboard-listen", f"127.0.0.1:{dashboard}",
                 "--dashboard-token-file", str(token), "--mascot-file", str(directory / "mascot.png"),
                 "--session-state-file", str(directory / "sessions"), "--no-stats-file"]
    process = start_gateway(executable, arguments, cwd=directory, env=env,
                            stdout=-3, stderr=-1)
    try:
        # Readiness probes use the dedicated dashboard listener and consume
        # no public admission tokens. Each scenario has a fresh gateway.
        deadline = time.monotonic() + 10
        while True:
            check(process.poll() is None, "gateway failed to start: " +
                  (process.stderr.read().decode() if process.poll() is not None else ""))
            try:
                expect(request(dashboard, "/settings/mascot"), 200)
                break
            except OSError:
                check(time.monotonic() < deadline, "gateway did not listen")
                time.sleep(.01)
        yield process, public, dashboard
    finally:
        (directory / "release").touch()
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        diagnostics = process.stderr.read().decode()
        check(process.returncode == 0, f"gateway exit={process.returncode}: {diagnostics}")


def upload_async(dashboard, data):
    result = []

    def upload():
        try:
            result.append(request(dashboard, "/settings/mascot", "PUT", data,
                                  {"Content-Type": "image/png"}))
        except Exception as error:
            result.append(error)

    thread = threading.Thread(target=upload)
    thread.start()
    return thread, result


def complete(thread, results):
    thread.join(timeout=30)
    check(not thread.is_alive(), "upload did not complete")
    check(results and isinstance(results[0], tuple), f"upload failed: {results}")
    expect(results[0], 204)


def saved_and_restart(executable, assets, directory):
    source = png()
    with gateway(executable, assets, directory) as (_, public, dashboard):
        expect(request(dashboard, "/settings/mascot", "PUT", source,
                       {"Content-Type": "image/png"}), 204)
        saved = (directory / "mascot.png").read_bytes()
        check(len(saved) < len(source) and saved[25] == 3 and saved[28] == 1,
              "upload is saved as a smaller indexed Adam7 PNG")
        check(expect(request(public, "/ankah/mascot.png"), 200) == saved,
              "public route serves optimized bytes")
        check(expect(request(dashboard, "/settings/mascot"), 200) == saved,
              "dashboard preview serves optimized bytes")
        # Uploading the same optimized output must be stable.
        expect(request(dashboard, "/settings/mascot", "PUT", saved,
                       {"Content-Type": "image/png"}), 204)
        check((directory / "mascot.png").read_bytes() == saved, "optimized input retains its bytes")
    with gateway(executable, assets, directory) as (_, public, dashboard):
        check(expect(request(public, "/ankah/mascot.png"), 200) == saved,
              "restart retains optimized bytes")
        expect(request(dashboard, "/settings/mascot", "DELETE"), 204)
        check(not (directory / "mascot.png").exists(), "restore removes override")


def passthrough(executable, assets, directory):
    with gateway(executable, assets, directory) as (_, _, dashboard):
        for source in ((assets / "phone-scan.png").read_bytes(), png(1025, 1)):
            expect(request(dashboard, "/settings/mascot", "PUT", source,
                           {"Content-Type": "image/png"}), 204)
            check((directory / "mascot.png").read_bytes() == source,
                  "profiled and large images retain original bytes")
        expect(request(dashboard, "/settings/mascot", "PUT", b"invalid",
                       {"Content-Type": "image/png"}), 400)


def worker_lifecycle(executable, assets, directory, fixture, scenario):
    with gateway(executable, assets, directory, fixture) as (process, public, dashboard):
        default = expect(request(dashboard, "/settings/mascot"), 200)
        thread, results = upload_async(dashboard, png())
        wait_file(directory / "entered", process)
        if scenario == "busy":
            check(expect(request(public, "/ankah/mascot.png"), 200) == default,
                  "current image remains readable during encoding")
            for method in ("PUT", "DELETE"):
                response = request(dashboard, "/settings/mascot", method,
                                   png() if method == "PUT" else None,
                                   {"Content-Type": "image/png"})
                check(expect(response, 503) == b"Mascot update in progress\n",
                      "busy rejection explains the reason")
            (directory / "release").touch()
            complete(thread, results)
            expect(request(dashboard, "/settings/mascot", "DELETE"), 204)
        elif scenario == "disable":
            expect(request(dashboard, "/settings/disable", "POST"), 204)
            (directory / "release").touch()
            thread.join(timeout=30)
            check(results and isinstance(results[0], tuple), f"disabled upload: {results}")
            expect(results[0], 503)
            check(expect(request(public, "/ankah/mascot.png"), 200) == default,
                  "disabled dashboard does not commit worker output")
        else:
            process.terminate()
            wait_file(directory / "cancelled", process)
            (directory / "release").touch()
            thread.join(timeout=30)
            process.wait(timeout=30)
        check(scenario == "busy" or not (directory / "mascot.png").exists(),
              "abandoned worker must not save its output")


def disconnect(executable, assets, directory, fixture):
    with gateway(executable, assets, directory, fixture) as (process, _, dashboard):
        data = png()
        client = socket.create_connection(("127.0.0.1", dashboard), timeout=10)
        client.sendall((f"PUT /settings/mascot HTTP/1.1\r\nHost: localhost:{dashboard}\r\n"
                        f"Authorization: Bearer {TOKEN}\r\nContent-Type: image/png\r\n"
                        f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data)
        wait_file(directory / "entered", process)
        client.shutdown(socket.SHUT_RDWR)
        client.close()
        # Wait for the main loop to close the disconnected socket before
        # allowing the worker to complete. No request probes or timing guesses.
        wait_file(directory / "cancelled", process)
        (directory / "release").touch()
        wait_file(directory / "finished", process)
        check(not (directory / "mascot.png").exists(), "disconnected upload is discarded")


def main():
    executable, root, *fixtures = sys.argv[1:]
    assets = pathlib.Path(root).resolve()
    fixture = fixtures[0] if fixtures and fixtures[0] else None
    cases = [("saved", lambda p: saved_and_restart(executable, assets, p)),
             ("passthrough", lambda p: passthrough(executable, assets, p))]
    if fixture:
        cases += [(name, lambda p, name=name: worker_lifecycle(executable, assets, p, fixture, name))
                  for name in ("busy", "disable", "shutdown")]
        cases.append(("disconnect", lambda p: disconnect(executable, assets, p, fixture)))
    for name, exercise in cases:
        with tempfile.TemporaryDirectory(prefix="ankah-mascot-" + name) as temp:
            exercise(pathlib.Path(temp))
    print("Mascot upload checks passed")


if __name__ == "__main__":
    main()
