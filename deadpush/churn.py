"""
Git Churn Analytics — detects files that are being rewritten excessively.

In vibe coding sessions, AI agents frequently rewrite the same files multiple
times in slightly different ways, creating instability. High churn is a strong
signal that a file is being "thrashed" and needs architectural attention.
"""

from __future__ import annotations

import json
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


CHURN_CACHE_FILE = Path.home() / ".deadpush" / "churn_cache.json"
CHURN_CACHE_MAX_AGE = 3600


@dataclass
class FileChurn:
    """Churn metrics for a single file."""
    path: str
    commit_count: int
    author_count: int
    first_commit: str
    last_commit: str
    churn_score: float  # 0-1 normalized
    flag_reason: str | None = None


@dataclass
class ChurnReport:
    """Complete churn analysis report."""
    total_files_analyzed: int
    high_churn_files: list[FileChurn] = field(default_factory=list)
    total_commits_in_window: int = 0
    generated_at: str = ""


class ChurnAnalyzer:
    """Analyzes git churn for a repository."""

    def __init__(self, repo_root: Path, window_days: int = 30):
        self.repo_root = repo_root
        self.window_days = window_days
        self._cache: dict[str, Any] = {}
        self._load_cache()

    def _load_cache(self):
        if CHURN_CACHE_FILE.exists():
            try:
                data = json.loads(CHURN_CACHE_FILE.read_text(encoding="utf-8"))
                now = time.time()
                self._cache = {
                    k: v for k, v in data.items()
                    if now - v.get("cached_at", 0) < CHURN_CACHE_MAX_AGE
                }
            except Exception:
                self._cache = {}

    def _save_cache(self, key: str, data: Any):
        try:
            CHURN_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            self._cache[key] = {"data": data, "cached_at": time.time()}
            CHURN_CACHE_FILE.write_text(
                json.dumps(self._cache, indent=2, default=str),
                encoding="utf-8",
            )
        except Exception:
            pass

    def _run_git_log(self) -> list[dict[str, Any]]:
        """Run git log and return per-file commit stats."""
        cache_key = f"churn_{self.repo_root}_{self.window_days}"
        if cache_key in self._cache:
            return self._cache[cache_key]["data"]

        since = f"--since={self.window_days}.days"
        try:
            result = subprocess.run(
                ["git", "log", "--name-only", "--pretty=format:%H|%an|%ai", since],
                capture_output=True, text=True, timeout=30,
                cwd=self.repo_root,
            )
            if result.returncode != 0:
                return []
            self._save_cache(cache_key, result.stdout)
            return self._parse_git_log(result.stdout)
        except Exception:
            return []

    def _parse_git_log(self, output: str) -> list[dict[str, Any]]:
        """Parse git log --name-only output into structured records."""
        records: list[dict[str, Any]] = []
        current_commit: dict[str, Any] | None = None

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if "|" in line and len(line.split("|")) == 3:
                parts = line.split("|")
                current_commit = {
                    "hash": parts[0],
                    "author": parts[1],
                    "date": parts[2],
                    "files": [],
                }
                records.append(current_commit)
            elif current_commit is not None and line:
                current_commit["files"].append(line)

        return records

    def analyze(self) -> ChurnReport:
        """Run churn analysis on the repository."""
        commits = self._run_git_log()
        if not commits:
            return ChurnReport(total_files_analyzed=0)

        # Per-file stats
        file_stats: dict[str, dict[str, Any]] = {}
        for commit in commits:
            for filepath in commit.get("files", []):
                if filepath not in file_stats:
                    file_stats[filepath] = {
                        "commit_count": 0,
                        "authors": set(),
                        "first_commit": commit["date"],
                        "last_commit": commit["date"],
                    }
                stat = file_stats[filepath]
                stat["commit_count"] += 1
                stat["authors"].add(commit["author"])
                if commit["date"] < stat["first_commit"]:
                    stat["first_commit"] = commit["date"]
                if commit["date"] > stat["last_commit"]:
                    stat["last_commit"] = commit["date"]

        # Compute churn scores
        if not file_stats:
            return ChurnReport(total_files_analyzed=0)

        max_commits = max(s["commit_count"] for s in file_stats.values())
        if max_commits == 0:
            return ChurnReport(total_files_analyzed=len(file_stats))

        high_churn: list[FileChurn] = []
        for filepath, stat in file_stats.items():
            # Normalize churn score: commits / max_commits in repo
            raw_score = stat["commit_count"] / max_commits

            # Boost score for files with many unique authors (many people touching = unstable)
            author_boost = min(len(stat["authors"]) / 5.0, 0.3)
            churn_score = min(raw_score + author_boost, 1.0)

            flag_reason = None
            if churn_score > 0.7:
                flag_reason = f"Very high modification frequency ({stat['commit_count']} changes by {len(stat['authors'])} author(s) in {self.window_days} days)"
            elif churn_score > 0.5:
                flag_reason = f"Elevated modification frequency ({stat['commit_count']} changes in {self.window_days} days)"

            fc = FileChurn(
                path=filepath,
                commit_count=stat["commit_count"],
                author_count=len(stat["authors"]),
                first_commit=stat["first_commit"],
                last_commit=stat["last_commit"],
                churn_score=round(churn_score, 3),
                flag_reason=flag_reason,
            )
            if flag_reason:
                high_churn.append(fc)

        # Sort by churn score descending
        high_churn.sort(key=lambda x: x.churn_score, reverse=True)

        return ChurnReport(
            total_files_analyzed=len(file_stats),
            high_churn_files=high_churn,
            total_commits_in_window=len(commits),
            generated_at=datetime.now().isoformat(),
        )
