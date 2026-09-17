# Repository instructions

`mastah` is the working branch. GitLab CI checks it and publishes passing
application changes to `main`. GitLab mirrors `main` to GitHub.

## Text and attribution policy

Keep commit messages and publishable source free of typical AI attribution
markers. This includes the em dash character (U+2014), co-author markers,
`Agent-Logs-Url` trailers, and standalone tool or model names such as Codex,
Claude, ChatGPT, GPT, Copilot, Gemini, OpenAI, and Anthropic. Use ordinary
punctuation and describe the change itself in commit messages.

Do not add AI assistant configuration or transcript files to publishable
source. Examples include `CLAUDE.md`, nested `AGENTS.md`, `.codex/`,
`.claude/`, `.cursor/`, `.aider/`, and `.continue/`. The root `AGENTS.md` is a
maintenance document on `mastah`; CI removes it from `main`.

The maintenance paths `.gitlab-ci.yml`, `.githooks/`, and `tools/` also stay on
`mastah`. CI scans every tracked publishable text file and all new commit
messages, then merges passing changes to `main` without these paths. The local
commit hook checks messages using `tools/check_commit_message.py`.

Before pushing, run:

```sh
python3 tools/check_source.py
python3 -m unittest discover -s tools -p 'test_check_commit_message.py'
```
