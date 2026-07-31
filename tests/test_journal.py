"""Tests for write-ahead-style JournalStore (thesis Phase 1)."""

from __future__ import annotations

from pathlib import Path

from deadpush.journal import JournalStore


def test_capture_modify_and_restore(temp_repo: Path):
    target = temp_repo / "src" / "app.py"
    target.parent.mkdir(parents=True)
    target.write_text("v1\n", encoding="utf-8")

    journal = JournalStore(temp_repo)
    entry = journal.capture(target)
    assert entry is not None
    assert entry.kind == "modify"
    assert entry.rel == "src/app.py"
    assert entry.sha256

    target.write_text("v2-destroyed\n", encoding="utf-8")
    restored = journal.restore("src/app.py")
    assert restored.read_text(encoding="utf-8") == "v1\n"


def test_first_wins_within_epoch(temp_repo: Path):
    target = temp_repo / "a.txt"
    target.write_text("original\n", encoding="utf-8")
    journal = JournalStore(temp_repo)

    first = journal.capture(target)
    target.write_text("mutated\n", encoding="utf-8")
    second = journal.capture(target)

    assert first is not None and second is not None
    assert first.id == second.id
    assert len(journal.list_entries()) == 1

    journal.restore("a.txt")
    assert target.read_text(encoding="utf-8") == "original\n"


def test_create_kind_restores_by_deleting(temp_repo: Path):
    journal = JournalStore(temp_repo)
    ghost = temp_repo / "new_agent_file.py"
    entry = journal.capture(ghost)
    assert entry is not None
    assert entry.kind == "create"
    assert entry.sha256 is None

    ghost.write_text("agent created\n", encoding="utf-8")
    journal.restore("new_agent_file.py")
    assert not ghost.exists()


def test_skips_deadpush_internal_paths(temp_repo: Path):
    journal = JournalStore(temp_repo)
    internal = temp_repo / ".deadpush" / "journal" / "entries.jsonl"
    assert journal.capture(internal) is None
    q = temp_repo / ".deadpush-quarantine" / "x"
    q.parent.mkdir(parents=True, exist_ok=True)
    q.write_text("x\n", encoding="utf-8")
    assert journal.capture(q) is None


def test_content_addressed_blobs_dedupe(temp_repo: Path):
    a = temp_repo / "a.txt"
    b = temp_repo / "b.txt"
    a.write_text("same\n", encoding="utf-8")
    b.write_text("same\n", encoding="utf-8")
    journal = JournalStore(temp_repo)
    ea = journal.capture(a)
    journal.begin_epoch()
    eb = journal.capture(b)
    assert ea is not None and eb is not None
    assert ea.sha256 == eb.sha256
    blobs = list((temp_repo / ".deadpush" / "journal" / "blobs").iterdir())
    # Only real blobs, not tmp files
    blobs = [p for p in blobs if not p.name.startswith(".")]
    assert len(blobs) == 1


def test_restore_all(temp_repo: Path):
    f1 = temp_repo / "one.txt"
    f2 = temp_repo / "two.txt"
    f1.write_text("1\n", encoding="utf-8")
    f2.write_text("2\n", encoding="utf-8")
    journal = JournalStore(temp_repo)
    journal.capture_many([f1, f2])
    f1.write_text("bad1\n", encoding="utf-8")
    f2.write_text("bad2\n", encoding="utf-8")
    journal.restore_all()
    assert f1.read_text(encoding="utf-8") == "1\n"
    assert f2.read_text(encoding="utf-8") == "2\n"


def test_begin_epoch_allows_new_preimage(temp_repo: Path):
    target = temp_repo / "x.txt"
    target.write_text("a\n", encoding="utf-8")
    journal = JournalStore(temp_repo)
    journal.capture(target)
    target.write_text("b\n", encoding="utf-8")
    journal.begin_epoch()
    entry = journal.capture(target)
    assert entry is not None
    assert entry.kind == "modify"
    target.write_text("c\n", encoding="utf-8")
    journal.restore("x.txt")
    assert target.read_text(encoding="utf-8") == "b\n"


def test_persists_across_instances(temp_repo: Path):
    target = temp_repo / "p.txt"
    target.write_text("persist\n", encoding="utf-8")
    JournalStore(temp_repo).capture(target)
    target.write_text("gone\n", encoding="utf-8")
    JournalStore(temp_repo).restore("p.txt")
    assert target.read_text(encoding="utf-8") == "persist\n"
