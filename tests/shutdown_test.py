"""Exercise signal driven request draining and managed child shutdown."""

import http.client
import http.server
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

from process_support import gateway_command


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(port, path, timeout=5):
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    client.request("GET", path, headers={"Host": f"localhost:{port}"})
    reply = client.getresponse()
    result = reply.status, dict(reply.getheaders()), reply.read()
    client.close()
    return result


def wait_for(predicate, message, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.02)
    raise RuntimeError(message)


def child(port, started_path, release_path, terminated_path):
    started = pathlib.Path(started_path)
    release = pathlib.Path(release_path)
    terminated = pathlib.Path(terminated_path)

    class App(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/slow":
                started.write_text("started")
                while not release.exists():
                    time.sleep(.01)
            body = (self.path + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    def terminate(_number, _frame):
        terminated.write_text("terminated")
        os._exit(0)

    signal.signal(signal.SIGTERM, terminate)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), App)
    server.serve_forever()


def gateway(executable, assets, public, app, secret, paths):
    arguments = [
        "--listen", f"127.0.0.1:{public}",
        "--upstream", f"127.0.0.1:{app}",
        "--public-origin", f"http://localhost:{public}",
        "--secret-file", str(secret), "--assets-dir", assets,
        "--allow-prefix", "/",
        "--ankah-healthz", "--ankah-livez", "--ankah-readyz",
        "--", sys.executable, str(pathlib.Path(__file__).resolve()), "child",
        str(app), *(str(path) for path in paths),
    ]
    return subprocess.Popen(gateway_command(executable, arguments),
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def wait_for_gateway(process, port):
    def ready():
        if process.poll() is not None:
            raise RuntimeError("gateway exited: " + process.stderr.read().decode())
        try:
            return request(port, "/livez")[0] == 200
        except OSError:
            return False

    wait_for(ready, "gateway did not listen")

    def child_ready():
        try:
            return request(port, "/child-ready")[0] == 200
        except OSError:
            return False

    wait_for(child_ready, "managed child did not listen")


def exercise_drain(executable, assets, root):
    public, app = free_port(), free_port()
    paths = tuple(root / name for name in ("started", "release", "terminated"))
    secret = root / "secret"
    secret.write_text("a" * 64)
    process = gateway(executable, assets, public, app, secret, paths)
    result = {}

    def slow_request():
        try:
            result["response"] = request(public, "/slow", timeout=15)
        except Exception as error:
            result["error"] = error

    try:
        wait_for_gateway(process, public)
        worker = threading.Thread(target=slow_request)
        worker.start()
        wait_for(paths[0].exists, "child did not receive slow request")
        process.terminate()
        wait_for(lambda: request(public, "/readyz")[0] == 503,
                 "readiness did not fail during drain")
        status, headers, body = request(public, "/new")
        assert status == 503 and headers.get("Retry-After") == "1"
        assert headers.get("Connection") == "close" and body == b"Service shutting down\n"
        assert request(public, "/livez")[0] == 200
        assert request(public, "/healthz")[0] == 200
        assert not paths[2].exists(), "child stopped before its request drained"
        paths[1].write_text("release")
        worker.join(timeout=15)
        assert not worker.is_alive() and "error" not in result, result
        assert result["response"][0] == 200 and result["response"][2] == b"/slow\n"
        process.wait(timeout=5)
        assert process.returncode == 0
        assert paths[2].exists(), "managed child did not receive SIGTERM"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def exercise_forced_shutdown(executable, assets, root):
    public, app = free_port(), free_port()
    paths = tuple(root / name for name in ("force-started", "force-release", "force-term"))
    secret = root / "force-secret"
    secret.write_text("b" * 64)
    process = gateway(executable, assets, public, app, secret, paths)

    def ignore_failure():
        try:
            request(public, "/slow", timeout=15)
        except Exception:
            pass

    worker = threading.Thread(target=ignore_failure, daemon=True)
    try:
        wait_for_gateway(process, public)
        worker.start()
        wait_for(paths[0].exists, "forced-shutdown request did not start")
        process.send_signal(signal.SIGINT)
        wait_for(lambda: request(public, "/readyz")[0] == 503,
                 "forced-shutdown drain did not start")
        process.terminate()
        process.wait(timeout=5)
        assert process.returncode == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "child":
        child(int(sys.argv[2]), *sys.argv[3:])
        return
    executable, assets = sys.argv[1:]
    if os.environ.get("ANKAH_TEST_WINDOWS_PATHS") == "1":
        return
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        exercise_drain(executable, assets, root)
        exercise_forced_shutdown(executable, assets, root)


if __name__ == "__main__":
    main()
