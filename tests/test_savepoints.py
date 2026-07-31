"""Tests for validated save points (thesis Phase 2)."""

from __future__ import annotations

from pathlib import Path

import pytest

from deadpush.journal import JournalStore
from deadpush.savepoints import SavePointStore, validate_working_tree


def test_create_list_restore_savepoint(temp_repo: Path):
    src = temp_repo / "src" / "app.py"
    src.parent.mkdir(parents=True)
    src.write_text("good\n", encoding="utf-8")

    store = SavePointStore(temp_repo)
    sp = store.create(label="after-feature")
    assert sp.file_count >= 1
    assert "src/app.py" in sp.files
    assert sp.label == "after-feature"
    assert sp.validated is True

    src.write_text("destroyed\n", encoding="utf-8")
    extra = temp_repo / "agent_new.py"
    extra.write_text("should go away\n", encoding="utf-8")
    result = store.restore(sp.id)
    assert "src/app.py" in result.restored
    assert "agent_new.py" in result.removed
    assert src.read_text(encoding="utf-8") == "good\n"
    assert not extra.exists()
    assert store.get(sp.id) is not None
    assert len(store.list()) == 1


def test_latest_validated_prefers_clean_tree(temp_repo: Path):
    (temp_repo / "ok.py").write_text("x = 1\n", encoding="utf-8")
    store = SavePointStore(temp_repo)
    clean = store.create(label="clean")
    assert clean.validated

    env = temp_repo / ".env"
    env.write_text("OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz012345\n", encoding="utf-8")
    dirty = store.create(label="dirty", validate=True)
    assert dirty.validated is False
    assert dirty.validation_errors

    latest = store.latest_validated()
    assert latest is not None
    assert latest.id == clean.id


def test_validate_working_tree_stub(temp_repo: Path):
    (temp_repo / "main.py").write_text("print(1)\n", encoding="utf-8")
    assert validate_working_tree(temp_repo) == []
    (temp_repo / ".env").write_text("SECRET_KEY=abc\n", encoding="utf-8")
    errs = validate_working_tree(temp_repo)
    assert errs
    assert any(".env" in e for e in errs)


def test_savepoint_seeds_journal_epoch(temp_repo: Path):
    f = temp_repo / "tracked.txt"
    f.write_text("base\n", encoding="utf-8")
    store = SavePointStore(temp_repo)
    sp = store.create(label="seed")
    assert sp.epoch

    journal = JournalStore(temp_repo)
    assert journal.epoch == sp.epoch
    # First-wins already seeded — mutating then restoring via journal returns base.
    f.write_text("mut\n", encoding="utf-8")
    entry = journal.capture(f)
    assert entry is not None
    journal.restore("tracked.txt")
    assert f.read_text(encoding="utf-8") == "base\n"


def test_restore_missing_blob_reported(temp_repo: Path):
    f = temp_repo / "z.txt"
    f.write_text("z\n", encoding="utf-8")
    store = SavePointStore(temp_repo)
    sp = store.create()
    # Corrupt: delete blob for z.txt
    digest = sp.files["z.txt"]
    blob = temp_repo / ".deadpush" / "journal" / "blobs" / digest
    blob.unlink()
    f.write_text("changed\n", encoding="utf-8")
    result = store.restore(sp.id)
    assert "z.txt" in result.missing_blobs


def test_restore_preflight_io_error_writes_nothing(temp_repo: Path, monkeypatch: pytest.MonkeyPatch):
    a = temp_repo / "a.txt"
    b = temp_repo / "b.txt"
    a.write_text("A\n", encoding="utf-8")
    b.write_text("B\n", encoding="utf-8")
    store = SavePointStore(temp_repo)
    sp = store.create()
    a.write_text("changed-a\n", encoding="utf-8")
    b.write_text("changed-b\n", encoding="utf-8")

    real_load = store.journal.load_bytes
    calls = {"n": 0}

    def flaky_load(digest: str) -> bytes:
        calls["n"] += 1
        if calls["n"] >= 2:
            raise OSError("simulated blob read failure")
        return real_load(digest)

    monkeypatch.setattr(store.journal, "load_bytes", flaky_load)
    with pytest.raises(OSError, match="simulated blob read failure"):
        store.restore(sp.id)

    assert a.read_text(encoding="utf-8") == "changed-a\n"
    assert b.read_text(encoding="utf-8") == "changed-b\n"
