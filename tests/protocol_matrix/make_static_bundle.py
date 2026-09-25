#!/usr/bin/env python3
"""Create the deterministic identity-only static bundle used by range tests."""

import argparse
import hashlib
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    body = bytes(range(256)) * 1024
    digest = hashlib.sha256(body).hexdigest()
    files = args.output / "files"
    files.mkdir(parents=True, exist_ok=True)
    (files / digest).write_bytes(body)
    manifest = ("ANKAH_STATIC_V2\t/static/\n"
                f"/static/range.bin\tidentity\t{digest}\t{len(body)}\t"
                "application/octet-stream\t0\n")
    (args.output / "manifest.tsv").write_text(manifest, encoding="ascii")


if __name__ == "__main__":
    main()
