#!/usr/bin/env python3
"""Reject disallowed text in commit messages, locally or in GitLab CI."""

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


ZERO_SHA = "0" * 40
AI_TERMS = re.compile(
    r"(?i)(?<![\w])(?:co[ -]?author(?:ed)?|astra|fable|sol|gpt(?:-[0-9.]+)?|"
    r"chatgpt|claude|opus|copilot|codex|gemini|anthropic|openai)(?![\w])"
)
AGENT_LOGS_TRAILER = re.compile(r"(?im)^[ \t]*Agent-Logs-Url[ \t]*:")


def violations(message: str) -> list[str]:
    found = []
    if "\u2014" in message:
        found.append("em dash (U+2014)")
    match = AI_TERMS.search(message)
    if match:
        found.append(f"co-author or AI attribution term: {match.group()!r}")
    if AGENT_LOGS_TRAILER.search(message):
        found.append("Agent-Logs-Url trailer")
    return found


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def ci_commits() -> list[str]:
    head = os.environ["CI_COMMIT_SHA"]
    base = os.environ.get("CI_MERGE_REQUEST_DIFF_BASE_SHA") or os.environ.get(
        "CI_COMMIT_BEFORE_SHA", ""
    )
    if not base or base == ZERO_SHA:
        default = os.environ["CI_DEFAULT_BRANCH"]
        if os.environ.get("CI_COMMIT_BRANCH") == default:
            return [head]
        remote_ref = f"refs/remotes/origin/{default}"
        subprocess.run(
            ["git", "fetch", "--no-tags", "origin", f"refs/heads/{default}:{remote_ref}"],
            check=True,
        )
        base = git("merge-base", head, remote_ref)
    return git("rev-list", "--reverse", f"{base}..{head}").splitlines()


def all_history_messages() -> list[tuple[str, str]]:
    # -z separates records, and %x00 separates the object ID from its message.
    output = subprocess.check_output(["git", "log", "--all", "-z", "--format=%H%x00%B"])
    records = output.decode("utf-8").split("\0")
    return list(zip(records[0::2], records[1::2]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--message-file", type=Path, help="commit-msg hook input")
    mode.add_argument("--ci-range", action="store_true", help="check incoming CI commits")
    mode.add_argument("--all-history", action="store_true", help="audit commits reachable from local refs")
    args = parser.parse_args()

    try:
        if args.message_file:
            messages = [(str(args.message_file), args.message_file.read_text(encoding="utf-8"))]
        elif args.all_history:
            messages = all_history_messages()
        else:
            messages = [
                (sha, subprocess.check_output(["git", "show", "-s", "--format=%B", sha], text=True))
                for sha in ci_commits()
            ]
    except (OSError, UnicodeError, subprocess.CalledProcessError, KeyError) as exc:
        print(f"commit-message check could not read its input: {exc}", file=sys.stderr)
        return 2

    failed = False
    for source, message in messages:
        for reason in violations(message):
            print(f"{source}: rejected commit message: {reason}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
