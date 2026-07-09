"""Tests for the global multi-repo hub."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from urllib.request import urlopen

import pytest

from deadpush import hub, state


@pytest.fixture
def hub_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(state.Path, "home", staticmethod(lambda: home))
    state.reset_migration_flags()
    root = home / ".deadpush"
    root.mkdir(parents=True)
    yield root
    hub.stop_hub()


class TestCollectSnapshots:
    def test_empty_registry(self, hub_home):
        assert hub.collect_repo_snapshots() == []

    def test_repo_with_score(self, hub_home, tmp_path):
        repo = tmp_path / "myapp"
        repo.mkdir()
        rid = state.repo_id(repo)
        rdir = hub_home / "repos" / rid
        rdir.mkdir(parents=True)
        (rdir / "manifest.json").write_text(
            json.dumps({"path": str(repo.resolve()), "label": "myapp"}),
            encoding="utf-8",
        )
        (rdir / "safety_score.json").write_text(
            json.dumps({"score": 85, "last_updated": "2026-07-05T00:00:00"}),
            encoding="utf-8",
        )
        snaps = hub.collect_repo_snapshots()
        assert len(snaps) == 1
        assert snaps[0]["label"] == "myapp"
        assert snaps[0]["score"] == 85
        assert snaps[0]["score_class"] == "good"
        assert snaps[0]["running"] is False


class TestHubHTTP:
    def test_api_repos_and_page(self, hub_home, tmp_path):
        from http.server import HTTPServer

        repo = tmp_path / "proj"
        repo.mkdir()
        rid = state.repo_id(repo)
        rdir = hub_home / "repos" / rid
        rdir.mkdir(parents=True)
        (rdir / "manifest.json").write_text(
            json.dumps({"path": str(repo.resolve()), "label": "proj"}),
            encoding="utf-8",
        )

        server = hub.ThreadedHubServer(("127.0.0.1", 0), hub.HubHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urlopen(f"http://127.0.0.1:{port}/api/repos", timeout=2) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            assert len(data["repos"]) == 1
            assert data["repos"][0]["label"] == "proj"

            with urlopen(f"http://127.0.0.1:{port}/hub", timeout=2) as resp:
                html = resp.read().decode("utf-8")
            assert "deadpush Hub" in html
            assert "proj" in html
        finally:
            server.shutdown()
