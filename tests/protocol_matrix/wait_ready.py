#!/usr/bin/env python3
"""Wait for the two verified TLS endpoints without weakening validation."""

import argparse
import ssl
import time

import httpx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("urls", nargs="+")
    args = parser.parse_args()
    context = ssl.create_default_context(cafile=args.ca_file)
    deadline = time.monotonic() + 45
    pending = set(args.urls)
    errors = {}
    while pending and time.monotonic() < deadline:
        for url in list(pending):
            try:
                response = httpx.get(url.rstrip("/") + "/matrix/_ready",
                                     verify=context, trust_env=False, timeout=2)
                if response.status_code == 200:
                    pending.remove(url)
                    continue
                errors[url] = f"HTTP {response.status_code}"
            except Exception as error:
                errors[url] = str(error)
        if pending:
            time.sleep(0.25)
    if pending:
        detail = ", ".join(f"{url}: {errors.get(url, 'no response')}" for url in pending)
        raise SystemExit(f"services did not become ready: {detail}")


if __name__ == "__main__":
    main()
