#!/usr/bin/env python3
"""Package a web application's static files for Ankah at image build time."""

import argparse
import hashlib
import mimetypes
from pathlib import Path
import re
from urllib.parse import quote


VERSION = "ANKAH_STATIC_V1"
HASHED_NAME = re.compile(r"(?:^|[.-])[0-9a-fA-F]{8,}(?:[.-]|$)")
SKIP_PARTS = {".git", ".venv", "venv", "node_modules", "__pycache__"}


def detect(root):
    for name in ("staticfiles", "static"):
        path = root / name
        if path.is_dir():
            return path, "/static/"
    app_dirs = sorted(
        child / "static" for child in root.iterdir()
        if child.is_dir() and child.name not in SKIP_PARTS
        and not child.name.startswith(".") and (child / "static").is_dir()
    )
    if len(app_dirs) > 1:
        raise ValueError("multiple app static directories found; collect them first or use --source")
    if app_dirs:
        return app_dirs[0], "/static/"
    for name in ("public", "dist", "build"):
        path = root / name
        if path.is_dir():
            return path, "/assets/"
    raise ValueError("no static directory found; use --source")


def mime_type(path):
    value = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    if value.startswith("text/") or value in ("application/javascript", "application/json"):
        value += "; charset=utf-8"
    return value


def validate_prefix(prefix):
    if not prefix.startswith("/") or not prefix.endswith("/") or "//" in prefix:
        raise ValueError("URL prefix must start and end with / and contain no empty segments")
    if prefix.startswith("/ankah/") or any(part in (".", "..") for part in prefix.split("/")):
        raise ValueError("URL prefix conflicts with an internal or parent path")
    if any(ord(char) < 33 or ord(char) > 126 or char in "?#%\\" for char in prefix):
        raise ValueError("URL prefix contains an unsupported character")


def package(source, output, prefix):
    source = source.resolve(strict=True)
    output = output.resolve()
    if output == source or source in output.parents:
        raise ValueError("output directory must be outside the static source")
    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory must be empty")
    validate_prefix(prefix)
    files_dir = output / "files"
    files_dir.mkdir(parents=True, exist_ok=True)
    lines = [f"{VERSION}\t{prefix}\n"]
    count = 0
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if any(part.startswith(".") or part in SKIP_PARTS for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError(f"symbolic link in static directory: {path}")
        if not path.is_file():
            continue
        url = prefix + "/".join(quote(part, safe="-._~") for part in relative.parts)
        if len(url.encode("ascii")) >= 2048:
            raise ValueError(f"static URL is too long: {path}")
        digest = hashlib.sha256()
        temp = files_dir / f"pending-{count}"
        size = 0
        with path.open("rb") as src, temp.open("xb") as dest:
            for chunk in iter(lambda: src.read(1024 * 1024), b""):
                dest.write(chunk)
                digest.update(chunk)
                size += len(chunk)
        blob = files_dir / digest.hexdigest()
        if blob.exists():
            temp.unlink()
        else:
            temp.rename(blob)
        immutable = int(bool(HASHED_NAME.search(path.name)))
        record = f"\t{digest.hexdigest()}\t{size}\t{mime_type(path)}\t{immutable}\n"
        lines.append(url + record)
        if prefix == "/" and relative.parts == ("index.html",):
            lines.append("/" + record)
        count += 1
    (output / "manifest.tsv").write_text("".join(lines), encoding="ascii")
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path("."))
    parser.add_argument("--source", type=Path, help="static directory, relative to project root")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--url-prefix", help="public URL prefix; defaults to /static/ or /assets/")
    args = parser.parse_args()
    try:
        root = args.project_root.resolve(strict=True)
        if args.source:
            source = args.source if args.source.is_absolute() else root / args.source
            prefix = "/static/"
        else:
            source, prefix = detect(root)
        prefix = args.url_prefix or prefix
        count = package(source, args.output, prefix)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"Packaged {count} static file(s) from {source} at {prefix} into {args.output}")


if __name__ == "__main__":
    main()
