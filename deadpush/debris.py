"""Guardian debris detection — filename and content signals for real-time blocking."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .config import Config
from .types import DebrisFile, FileInfo

LLM_CONTEXT_FILES = {
    "claude.md", "claude_context.md", ".claude_instructions",
    ".cursorrules", "cursor_rules.md", ".cursorignore",
    ".copilot-instructions.md", "agents.md", "windsurf_rules.md",
    "llm_context.txt", "ai_prompt.md", "system_prompt.txt",
}

VIBE_SCRATCHPAD_NAMES = {
    "scratch", "playground", "temp", "tmp", "untitled", "copy_of",
    "backup", "old", "new", "v2", "final", "todo_delete", "debug",
}

CHAT_PATTERNS = [
    r"^\s*(User|Assistant|Human|System):\s",
    r"^(Human|Assistant):",
]

SECRET_PATTERNS = [
    (r"(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]", "Hardcoded API key/secret"),
    (r"(?:sk-[a-zA-Z0-9]{20,}|pk-[a-zA-Z0-9]{20,})", "Hardcoded API token"),
    (r"AKIA[0-9A-Z]{16}", "Hardcoded AWS Access Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "Hardcoded GitHub token"),
]

PROMPT_INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", "Ignore-previous-instructions attempt"),
    (r"you\s+are\s+(now|an?\s+(AI|autonomous|unconstrained))", "AI role-play override"),
    (r"<\|im_start\|>|<\|im_end\|>", "Chat markup token"),
]


class DebrisDetector:
    """Real-time debris checks for the filesystem guardian."""

    def __init__(self, config: Config):
        self.config = config

    def scan(self, files: list[FileInfo]) -> list[DebrisFile]:
        results: list[DebrisFile] = []
        for f in files:
            flags = self._check_file(f)
            if flags:
                results.append(self._build_debris_file(f, flags))
        return sorted(results, key=lambda d: (not d.block_push, -d.confidence, d.path))

    def _check_file(self, f: FileInfo) -> list[dict[str, Any]]:
        flags = self._check_filename(f)
        if not f.is_text or f.size >= 2 * 1024 * 1024:
            return flags
        try:
            content = f.path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return flags
        flags += self._check_content(content)
        flags += self._detect_hardcoded_secrets(content)
        flags += self._check_prompt_injection(content)
        return flags

    def _check_filename(self, f: FileInfo) -> list[dict[str, Any]]:
        flags: list[dict[str, Any]] = []
        name_lower = f.path.name.lower()
        rel = str(f.rel_path).lower()

        if name_lower in LLM_CONTEXT_FILES or any(p in rel for p in LLM_CONTEXT_FILES):
            flags.append({
                "category": "llm_context_file",
                "confidence": 0.99,
                "reason": f"Known LLM/AI coding assistant context file: {f.path.name}",
                "block": True,
                "suggestion": "Add to .gitignore. These should never be committed.",
            })

        for bad in VIBE_SCRATCHPAD_NAMES:
            if bad in name_lower:
                flags.append({
                    "category": "vibe_scratchpad",
                    "confidence": 0.82,
                    "reason": f"Looks like a temporary/AI scratch file: {f.path.name}",
                    "block": False,
                    "suggestion": "Delete or move to a gitignored location.",
                })
                break

        return flags

    def _check_content(self, content: str) -> list[dict[str, Any]]:
        flags: list[dict[str, Any]] = []
        head = "\n".join(content.splitlines()[:55]).lower()
        if any(p in head for p in (
            "you are a helpful assistant", "you are an expert software engineer",
            "as an ai coding assistant", "cursor rules",
        )):
            flags.append({
                "category": "llm_context_file",
                "confidence": 0.96,
                "reason": "Contains AI system prompt or context instructions",
                "block": True,
                "suggestion": "This appears to be an exported AI context/prompt file.",
            })
        for pattern in CHAT_PATTERNS:
            if re.search(pattern, head, re.IGNORECASE | re.MULTILINE):
                flags.append({
                    "category": "chat_export",
                    "confidence": 0.95,
                    "reason": "Matches exported LLM chat log format",
                    "block": True,
                    "suggestion": "Remove chat export from the codebase.",
                })
                break
        return flags

    def _detect_hardcoded_secrets(self, content: str) -> list[dict[str, Any]]:
        flags: list[dict[str, Any]] = []
        for pattern, desc in SECRET_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                flags.append({
                    "category": "hardcoded_secret",
                    "confidence": 0.98,
                    "reason": desc,
                    "block": True,
                    "suggestion": "Use environment variables or a secrets manager.",
                })
                break
        return flags

    def _check_prompt_injection(self, content: str) -> list[dict[str, Any]]:
        flags: list[dict[str, Any]] = []
        for pattern, reason in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                flags.append({
                    "category": "prompt_injection",
                    "confidence": 0.9,
                    "reason": reason,
                    "block": False,
                    "suggestion": "Remove injected instructions from the codebase.",
                })
                break
        return flags

    def _build_debris_file(self, f: FileInfo, flags: list[dict[str, Any]]) -> DebrisFile:
        best = max(flags, key=lambda x: (x.get("block", False), x["confidence"]))
        category = best["category"]
        block = best.get("block", False)
        if self.config.should_block_debris_category(category):
            block = True
        elif self.config.should_warn_debris_category(category):
            block = False
        return DebrisFile(
            path=str(f.rel_path),
            category=category,
            confidence=best["confidence"],
            reasons=[fl["reason"] for fl in flags],
            block_push=block,
            suggestion=best.get("suggestion", ""),
        )
