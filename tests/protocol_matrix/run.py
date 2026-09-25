#!/usr/bin/env python3
"""Stable entry point for the Ankah protocol matrix."""

import argparse
import hashlib
import importlib.metadata
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
COMPOSE = HERE / "compose.yml"
EXPECTED = {"pytest": "9.1.1", "httpx": "0.28.1", "aioquic": "1.3.0"}
LOCAL_IMAGES = ("ankah-protocol-native:local", "ankah-protocol-edge:local",
                "ankah-protocol-client:local")
SOURCE_HASH_ENV = "ANKAH_PROTOCOL_SOURCE_HASH"
SOURCE_HASH_LABEL = "org.opencontainers.image.revision"


def command(arguments, **kwargs):
    return subprocess.run([str(item) for item in arguments], check=True, **kwargs)


def check_host_dependencies():
    problems = []
    if sys.version_info[:2] != (3, 12):
        problems.append(f"Python 3.12 required, found {sys.version_info.major}."
                        f"{sys.version_info.minor}")
    for package, expected in EXPECTED.items():
        try:
            found = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            found = None
        if found != expected:
            problems.append(f"{package} {expected} required, found {found or 'missing'}")
    if problems:
        raise SystemExit("; ".join(problems) +
                         ". Install tests/protocol_matrix/requirements.lock with --require-hashes.")


def pytest_arguments(args, junit, suite=HERE):
    values = ["-m", "pytest", "-c", str(suite / "pytest.ini"), str(suite),
              "--profile", args.profile, "--protocol", args.protocol,
              "--ca-file", args.ca_file, f"--junitxml={junit}"]
    if args.edge_url:
        values.extend(["--edge-url", args.edge_url])
    if args.native_url:
        values.extend(["--native-url", args.native_url])
    return values


def external(args):
    check_host_dependencies()
    ca = Path(args.ca_file).resolve()
    if not ca.is_file():
        raise SystemExit(f"CA file does not exist: {ca}")
    args.ca_file = str(ca)
    for value in (args.edge_url, args.native_url):
        if value and not value.startswith("https://"):
            raise SystemExit("external endpoint URLs must use https://")
    reports = Path(args.artifacts_dir).resolve()
    reports.mkdir(parents=True, exist_ok=True)
    result = subprocess.run([sys.executable, *pytest_arguments(args, reports / "junit.xml")],
                            cwd=HERE)
    return result.returncode


def compose_command(project, *arguments):
    return ["docker", "compose", "-p", project, "-f", str(COMPOSE), *arguments]


def _hash_field(digest, value):
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _fingerprint_paths(root, paths):
    digest = hashlib.sha256()
    for relative in sorted(paths):
        encoded = os.fsencode(relative)
        path = root / os.fsdecode(relative)
        _hash_field(digest, encoded)
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            _hash_field(digest, b"missing")
            continue
        if stat.S_ISLNK(metadata.st_mode):
            kind = b"symlink"
            content = os.fsencode(os.readlink(path))
        elif stat.S_ISREG(metadata.st_mode):
            kind = b"executable" if metadata.st_mode & 0o111 else b"file"
            content = path.read_bytes()
        else:
            raise SystemExit(f"unsupported source path type: {path}")
        _hash_field(digest, kind)
        _hash_field(digest, content)
    return digest.hexdigest()


def source_fingerprint(root=ROOT):
    dockerignore = root / ".dockerignore"
    inventory = [
        "git", "ls-files", "--cached", "--others", "--exclude-standard",
    ]
    if dockerignore.is_file():
        inventory.append(f"--exclude-from={dockerignore}")
    inventory.append("-z")
    try:
        result = subprocess.run(inventory, cwd=root, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"cannot inventory source files for image fingerprint: {error}")
    paths = [item for item in result.stdout.split(b"\0") if item]
    return _fingerprint_paths(root, paths)


def require_offline_images(expected):
    missing = []
    stale = []
    for image in LOCAL_IMAGES:
        result = subprocess.run([
            "docker", "image", "inspect", image, "--format",
            f'{{{{ index .Config.Labels "{SOURCE_HASH_LABEL}" }}}}',
        ], capture_output=True, text=True)
        if result.returncode:
            missing.append(image)
        elif result.stdout.strip() != expected:
            stale.append(image)
    if missing:
        raise SystemExit("offline images are missing: " + ", ".join(missing) +
                         ". Run the compose command without --offline once.")
    if stale:
        raise SystemExit("offline images do not match the current source: " +
                         ", ".join(stale) +
                         ". Run the compose command without --offline once.")


def copy_report(container, reports):
    result = subprocess.run(["docker", "cp", f"{container}:/reports/junit.xml",
                             str(reports / "junit.xml")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def compose(args):
    project = f"ankah-protocol-{os.getpid()}-{secrets.token_hex(3)}"
    fingerprint = source_fingerprint()
    reports = Path(args.artifacts_dir).resolve()
    reports.mkdir(parents=True, exist_ok=True)
    test_container = f"{project}-tests"
    result = 1
    try:
        if args.offline:
            require_offline_images(fingerprint)
        else:
            environment = os.environ.copy()
            environment[SOURCE_HASH_ENV] = fingerprint
            command(compose_command(project, "build", "--pull", "native", "edge", "client"),
                    cwd=ROOT, env=environment)
        run_flags = ["--pull", "never"]
        up_flags = ["--pull", "never", "--no-build"]
        command(compose_command(project, "run", "--rm", "--no-deps", *run_flags,
                                "client", "certificates.py", "/run/ankah-protocol"), cwd=ROOT)
        command(compose_command(project, "up", "-d", *up_flags, "native", "edge"), cwd=ROOT)
        command(compose_command(project, "run", "--rm", "--no-deps", *run_flags,
                                "client", "wait_ready.py", "--ca-file",
                                "/run/ankah-protocol/ca.pem",
                                "https://edge.ankah.test", "https://native.ankah.test:8443"),
                cwd=ROOT)
        args.edge_url = "https://edge.ankah.test"
        args.native_url = "https://native.ankah.test:8443"
        args.ca_file = "/run/ankah-protocol/ca.pem"
        test_args = pytest_arguments(args, "/reports/junit.xml", Path("/suite"))
        completed = subprocess.run(compose_command(project, "run", "--name", test_container,
                                   "--no-deps", *run_flags, "client", *test_args), cwd=ROOT)
        result = completed.returncode
        copy_report(test_container, reports)
    except subprocess.CalledProcessError as error:
        result = error.returncode or 1
    finally:
        logs = subprocess.run(compose_command(project, "logs", "--no-color", "--timestamps"),
                              cwd=ROOT, capture_output=True, text=True)
        (reports / "compose.log").write_text(logs.stdout + logs.stderr, encoding="utf-8")
        subprocess.run(compose_command(project, "down", "--volumes", "--remove-orphans"),
                       cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result


def add_common(parser):
    parser.add_argument("--profile", choices=("edge", "native", "all"), default="all")
    parser.add_argument("--protocol", choices=("h1", "h2", "h3", "all"), default="all")
    parser.add_argument("--artifacts-dir", default=str(ROOT / "protocol-matrix-artifacts"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    compose_parser = subparsers.add_parser("compose")
    add_common(compose_parser)
    compose_parser.add_argument("--offline", action="store_true")
    external_parser = subparsers.add_parser("external")
    add_common(external_parser)
    external_parser.add_argument("--edge-url")
    external_parser.add_argument("--native-url")
    external_parser.add_argument("--ca-file", required=True)
    args = parser.parse_args()
    if args.mode == "external":
        if args.profile in ("edge", "all") and not args.edge_url:
            parser.error("--edge-url is required for the selected profile")
        if args.profile in ("native", "all") and not args.native_url:
            parser.error("--native-url is required for the selected profile")
        return external(args)
    return compose(args)


if __name__ == "__main__":
    raise SystemExit(main())
