#!/usr/bin/env python3
"""Create missing deployment credentials without replacing existing ones."""
import os
import pathlib
import secrets
import sys

directory = pathlib.Path(sys.argv[1])
directory.mkdir(mode=0o750, parents=True, exist_ok=True)
for name in ("gateway.secret", "dashboard.token"):
    try:
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        continue
    with os.fdopen(fd, "w") as output:
        output.write(secrets.token_hex(32) + "\n")
        output.flush()
        os.fsync(output.fileno())
