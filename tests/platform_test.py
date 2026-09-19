"""Exercise child process handling on the target platform."""

import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

from process_support import gateway_command


def main():
    executable, assets = sys.argv[1:]
    windows = os.environ.get("ANKAH_TEST_WINDOWS_PATHS") == "1"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with tempfile.TemporaryDirectory() as temporary:
        secret = Path(temporary) / "secret"
        secret.write_text("a" * 64)
        child = ["cmd.exe", "/c", "exit 7"] if windows else ["/bin/sh", "-c", "exit 7"]
        command = gateway_command(executable, [
            "--listen", f"127.0.0.1:{port}",
            "--public-origin", f"http://localhost:{port}",
            "--secret-file", str(secret),
            "--assets-dir", assets,
            "--",
            *child,
        ])
        result = subprocess.run(command, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, timeout=10)
        output = result.stderr.decode(errors="replace")
        if "status=7" not in output:
            raise RuntimeError("child exit was not observed: " + output)


if __name__ == "__main__":
    main()
