#!/usr/bin/env python3
"""Check every tracked text file destined for the public branch."""

import subprocess
import sys
from pathlib import Path

from check_commit_message import violations


EXCLUDED = (b".gitlab-ci.yml", b".githooks/", b"tools/")


def main() -> int:
    failed = False
    for name in subprocess.check_output(("git", "ls-files", "-z")).split(b"\0"):
        if not name or any(name == part or name.startswith(part) for part in EXCLUDED):
            continue
        path = Path(name.decode("utf-8", "surrogateescape"))
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for reason in violations(content):
            print(f"{path}: rejected source text: {reason}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
