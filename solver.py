"""Ankah's command-line proof-of-work solver. Python 3 standard library only."""

import hashlib
import http.cookiejar
import math
import os
from pathlib import Path
import sys
import time
import urllib.parse
import urllib.request


def solve(challenge):
    pieces = challenge.split(".")
    if len(pieces) != 4 or len(pieces[0]) != 32:
        raise ValueError("invalid challenge")
    nonce = pieces[0]
    bits = int(pieces[2])
    if bits < 8 or bits > 24:
        raise ValueError("unsupported difficulty")
    full, remainder = divmod(bits, 8)
    started = time.monotonic()
    next_report = started + 0.25
    for counter in range(1 << 35):
        digest = hashlib.sha256(f"{nonce}:{counter}".encode("ascii")).digest()
        if all(byte == 0 for byte in digest[:full]) and (
            remainder == 0 or digest[full] >> (8 - remainder) == 0
        ):
            return counter
        now = time.monotonic()
        if now >= next_report:
            guesses = counter + 1
            rate = guesses / max(now - started, 0.001)
            chance = -math.expm1(-guesses / (2**bits)) * 100
            print(
                f"\r{guesses:,} guesses  {rate:,.0f}/s  "
                f"{chance:.1f}% chance of success by now",
                end="" if sys.stderr.isatty() else "\n",
                file=sys.stderr,
                flush=True,
            )
            next_report = now + (0.25 if sys.stderr.isatty() else 5)
    raise RuntimeError("search exhausted")


def main():
    if len(sys.argv) != 3:
        raise ValueError("usage: solver.py ORIGIN CHALLENGE")
    origin, challenge = sys.argv[1:]
    parsed = urllib.parse.urlsplit(origin)
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}
    ):
        raise ValueError("challenge origin must use HTTPS")
    counter = solve(challenge)
    if sys.stderr.isatty():
        print(file=sys.stderr)
    print(f"Found answer {counter}; requesting pass...", file=sys.stderr)
    old_mask = os.umask(0o077)
    try:
        directory = Path.home() / ".ankah"
        directory.mkdir(mode=0o700, exist_ok=True)
        host = parsed.hostname.replace(".", "_")
        cookie_path = directory / f"{host}.cookies"
        jar = http.cookiejar.MozillaCookieJar(str(cookie_path))
        if cookie_path.exists():
            jar.load(ignore_discard=True, ignore_expires=True)
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        query = urllib.parse.urlencode({"challenge": challenge, "answer": counter})
        request = urllib.request.Request(
            origin.rstrip("/") + "/ankah/open?" + query,
            data=b"",
            method="POST",
        )
        with opener.open(request, timeout=20) as response:
            response.read()
        jar.save(ignore_discard=True, ignore_expires=True)
    finally:
        os.umask(old_mask)
    print(f"Pass saved to {cookie_path}")
    print(f"Retry your original request with: curl -b '{cookie_path}' URL")
    print(f"Or: wget --load-cookies='{cookie_path}' URL")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Ankah: {error}", file=sys.stderr)
        raise SystemExit(1)
