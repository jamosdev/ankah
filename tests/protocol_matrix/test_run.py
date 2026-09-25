import os
from types import SimpleNamespace

import run as matrix_run


def test_source_fingerprint_tracks_content_mode_links_and_deletions(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("first", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to("source.txt")
    paths = [b"source.txt", b"link", b"deleted.txt"]

    initial = matrix_run._fingerprint_paths(tmp_path, paths)
    source.write_text("second", encoding="utf-8")
    assert matrix_run._fingerprint_paths(tmp_path, paths) != initial

    content_changed = matrix_run._fingerprint_paths(tmp_path, paths)
    source.chmod(source.stat().st_mode | 0o100)
    assert matrix_run._fingerprint_paths(tmp_path, paths) != content_changed

    executable_changed = matrix_run._fingerprint_paths(tmp_path, paths)
    link.unlink()
    link.symlink_to("elsewhere")
    assert matrix_run._fingerprint_paths(tmp_path, paths) != executable_changed

    link_changed = matrix_run._fingerprint_paths(tmp_path, paths)
    (tmp_path / "deleted.txt").write_bytes(os.urandom(4))
    assert matrix_run._fingerprint_paths(tmp_path, paths) != link_changed


def test_source_fingerprint_excludes_dockerignored_untracked_files(tmp_path,
                                                                   monkeypatch):
    source = tmp_path / "source.txt"
    source.write_text("source", encoding="utf-8")
    ignored = tmp_path / ".venv" / "state"
    ignored.parent.mkdir()
    ignored.write_text("first", encoding="utf-8")
    dockerignore = tmp_path / ".dockerignore"
    dockerignore.write_text(".venv\n", encoding="utf-8")
    calls = []

    def inventory(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return SimpleNamespace(stdout=b".dockerignore\0source.txt\0")

    monkeypatch.setattr(matrix_run.subprocess, "run", inventory)
    initial = matrix_run.source_fingerprint(tmp_path)
    ignored.write_text("second", encoding="utf-8")
    assert matrix_run.source_fingerprint(tmp_path) == initial

    arguments, kwargs = calls[0]
    assert f"--exclude-from={dockerignore}" in arguments
    assert kwargs["cwd"] == tmp_path
    source.write_text("changed", encoding="utf-8")
    assert matrix_run.source_fingerprint(tmp_path) != initial
