#!/usr/bin/env python3
"""Focused checks for the commit-message policy."""

import unittest

from check_commit_message import violations


class CommitMessageTests(unittest.TestCase):
    def test_rejected_messages(self):
        for message in (
            "Fix loading — handle missing file",
            "Co-authored-by: Developer <dev@example.com>",
            "Fix loading\n\nAgent-Logs-Url: https://example.com/session/123",
            "Fix loading\n\nagent-logs-url: https://example.com/session/123",
            "Coauthor: Claude Fable 5",
            "co author: helper",
            "Generated with GPT-5",
            "Thanks to Astra, Sol, and Opus",
            "Pair programmed with Copilot",
        ):
            with self.subTest(message=message):
                self.assertTrue(violations(message))

    def test_allowed_messages(self):
        for message in (
            "Fix loading - handle missing file",
            "Correct solution for isolated files",
            "Handle an author field in metadata",
        ):
            with self.subTest(message=message):
                self.assertFalse(violations(message))


if __name__ == "__main__":
    unittest.main()
