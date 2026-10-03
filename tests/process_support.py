"""Launch gateways and run integration tests in isolated working directories."""

import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path


PATH_OPTIONS = {"--config", "--assets-dir", "--secret-file", "--static-bundle",
                "--mascot-file",
                "--tls-cert", "--tls-key", "--dashboard-token-file", "--stats-file",
                "--session-state-file",
                "--log-unknown-languages", "--dots-ca-file", "--dots-cert-file",
                "--dots-key-file"}


def windows_path(value):
    absolute = str(Path(value).absolute())
    return "Z:" + absolute.replace("/", "\\")


def gateway_command(executable, arguments):
    runner = shlex.split(os.environ.get("ANKAH_TEST_RUNNER", ""))
    windows_paths = os.environ.get("ANKAH_TEST_WINDOWS_PATHS") == "1"
    converted = []
    path_next = False
    for argument in arguments:
        if path_next and windows_paths and argument:
            converted.append(windows_path(argument))
        else:
            converted.append(str(argument))
        path_next = argument in PATH_OPTIONS
    return [*runner, executable, *converted]


def start_gateway(executable, arguments, **options):
    """Use console control, not forced termination, for Windows drain tests."""
    windows = os.name == "nt" or os.environ.get("ANKAH_TEST_WINDOWS_PATHS") == "1"
    command = gateway_command(executable, arguments)
    if not windows:
        return subprocess.Popen(command, **options)
    runner = shlex.split(os.environ.get("ANKAH_TEST_RUNNER", ""))
    helper = str(Path(executable).with_name("ankah-windows-process.exe"))
    child = command[len(runner):]
    if os.name != "nt":
        child[0] = windows_path(child[0])

    class ConsoleProcess(subprocess.Popen):
        def terminate(self):
            if self.poll() is None:
                self.stdin.write(b"q")
                self.stdin.flush()

        def kill(self):
            if self.poll() is None:
                self.stdin.write(b"k")
                self.stdin.flush()

    return ConsoleProcess([*runner, helper, *child], stdin=subprocess.PIPE, **options)


if __name__ == "__main__":
    # CTest supplies absolute paths. Each invocation, including repeated runs,
    # gets fresh default session/statistics paths while preserving the test's
    # environment, output, and exit status. Individual fixtures should still
    # give independent gateways their own persistence paths.
    with tempfile.TemporaryDirectory(prefix="ankah-test-") as work:
        result = subprocess.run([sys.executable, *sys.argv[1:]], cwd=work)
    sys.exit(result.returncode)
