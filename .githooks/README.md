# Commit message gate

The `commit-msg` hook and GitLab's `commit_message_verify` job use
`tools/check_commit_message.py`. They reject an em dash, a co-author marker,
or a standalone AI attribution term anywhere in a commit message, as well as
an `Agent-Logs-Url` trailer.

Install the local hook without changing `core.hooksPath` or replacing other
hooks:

```sh
ln -s ../../.githooks/commit-msg .git/hooks/commit-msg
```

Audit commits reachable from all refs available in the local clone:

```sh
python3 tools/check_commit_message.py --all-history
```

The audit exits with status 1 when it finds matches. Fetch any remote refs you
want included before running it. CI checks commits introduced by a push or
merge request; it does not recheck older commits on every pipeline.
