"""Launch the gateway directly or through a configured test runner."""

import os
import shlex
from pathlib import Path


PATH_OPTIONS = {"--assets-dir", "--secret-file", "--static-bundle",
                "--tls-cert", "--tls-key"}


def windows_path(value):
    absolute = str(Path(value).absolute())
    return "Z:" + absolute.replace("/", "\\")


def gateway_command(executable, arguments):
    runner = shlex.split(os.environ.get("ANKAH_TEST_RUNNER", ""))
    windows_paths = os.environ.get("ANKAH_TEST_WINDOWS_PATHS") == "1"
    converted = []
    path_next = False
    for argument in arguments:
        if path_next and windows_paths:
            converted.append(windows_path(argument))
        else:
            converted.append(str(argument))
        path_next = argument in PATH_OPTIONS
    return [*runner, executable, *converted]
