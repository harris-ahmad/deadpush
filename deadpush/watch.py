"""
Watch mode for deadpush.

Continuously monitors the repository for new debris (especially dangerous ones like CLAUDE.md)
while the developer is actively coding with AI tools.

Usage:
    deadpush watch
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

from .config import load_config
from .crawler import iter_source_files
from .debris import DebrisDetector
from .ui import print_warning, print_success, print_error, is_rich_available


class DebrisEventHandler(FileSystemEventHandler):
    def __init__(self, config, callback: Callable):
        self.config = config
        self.callback = callback
        self.detector = DebrisDetector(config)

    def on_created(self, event):
        if event.is_directory:
            return
        self._check_file(Path(event.src_path))

    def on_modified(self, event):
        if event.is_directory:
            return
        self._check_file(Path(event.src_path))

    def _check_file(self, path: Path):
        # Only check relevant source/config files
        from .crawler import get_supported_extensions
        # always watch code + docs/config for debris
        code_exts = get_supported_extensions()
        if path.suffix.lower() not in code_exts | {".md", ".txt", ".env", ".toml", ".yaml", ".yml", ".json"}:
            return
        if any(x in str(path) for x in ["__pycache__", ".git", "node_modules", ".deadpush", ".deadpush-quarantine", ".deadpush-archive"]):
            return

        try:
            # Quick single file debris check
            from .crawler import FileInfo
            fi = FileInfo(
                path=path,
                rel_path=path.relative_to(self.config.repo_root),
                size=path.stat().st_size if path.exists() else 0,
                is_text=True,
                mtime=time.time()
            )
            debris = self.detector.scan([fi])
            blocking = [d for d in debris if d.block_push]

            if blocking:
                self.callback(blocking, path)
        except Exception:
            pass  # Never crash the watcher


def start_watch(callback: Callable | None = None, repo_root: Path | None = None):
    if not WATCHDOG_AVAILABLE:
        print_error("Watch mode requires 'watchdog'. Install with: pip install deadpush[watch]")
        return

    config = load_config(explicit_root=repo_root)
    print_success(f"Watching {config.repo_root} for new debris... (Ctrl+C to stop)")

    if callback is None:
        def default_callback(blocking_debris, changed_path):
            print_warning(f"\nNew blocking debris detected in {changed_path.name}!")
            for d in blocking_debris:
                print(f"  → {d.path} ({d.category})")
                print(f"    {d.suggestion}")
        callback = default_callback

    event_handler = DebrisEventHandler(config, callback)
    observer = Observer()
    observer.schedule(event_handler, str(config.repo_root), recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print_success("\nWatch mode stopped.")

    observer.join()
